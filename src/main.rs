use std::collections::HashMap;
use std::path::{Path, PathBuf};

use clap::Parser;

use bpf_verifier::analysis::{dataflow, stack_bounds};
use bpf_verifier::codegen::fstar::{generate_fstar, generate_fields_module};
use bpf_verifier::elf::parser::{parse_elf, BpfProgram, StructDef};
use bpf_verifier::verify::diagnostic::{Diagnostic, resolve_c_source};
use bpf_verifier::verify::runner::{FstarRunner, VerifyResult};

#[derive(Parser)]
#[command(name = "bpf-verifier")]
#[command(about = "Formally verify BPF programs against F*/Pulse specifications")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    Verify {
        #[arg(help = "Path to BPF object file")]
        program: PathBuf,

        #[arg(long, help = "Spec for a section (section:path.fst), repeatable")]
        spec: Vec<String>,

        #[arg(long, help = "Only verify these sections, repeatable")]
        section: Vec<String>,

        #[arg(long, help = "Show detailed verification output")]
        verbose: bool,

        #[arg(long, help = "Path to F* binary (overrides auto-detection)")]
        fstar_path: Option<PathBuf>,
    },
    Codegen {
        #[arg(help = "Path to BPF object file")]
        program: PathBuf,

        #[arg(long, help = "Section to generate code for (default: first)")]
        section: Option<String>,

        #[arg(long, help = "Path to F* spec file")]
        spec: Option<PathBuf>,
    },
}

fn project_root() -> PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        while let Some(d) = dir {
            if d.join("fstar").is_dir() {
                return d;
            }
            dir = d.parent().map(Path::to_path_buf);
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn parse_spec_args(specs: &[String]) -> Result<HashMap<String, PathBuf>, String> {
    let mut map = HashMap::new();
    for s in specs {
        if let Some((section, path)) = s.split_once(':') {
            map.insert(section.to_string(), PathBuf::from(path));
        } else {
            return Err(format!(
                "invalid --spec format '{s}': expected section:path.fst"
            ));
        }
    }
    Ok(map)
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify {
            program,
            spec,
            section,
            verbose,
            fstar_path,
        } => {
            let spec_map = match parse_spec_args(&spec) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(2);
                }
            };
            std::process::exit(run_verify(
                &program,
                &spec_map,
                &section,
                verbose,
                fstar_path.as_deref(),
            ));
        }
        Commands::Codegen {
            program,
            section,
            spec,
        } => {
            std::process::exit(run_codegen(&program, section.as_deref(), spec.as_deref()));
        }
    }
}

fn run_codegen(
    program_path: &Path,
    section: Option<&str>,
    spec_path: Option<&Path>,
) -> i32 {
    // spec_path is a simple path to a .fst file (no section: prefix)
    let elf_data = match std::fs::read(program_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("error: failed to read {}: {e}", program_path.display());
            return 2;
        }
    };

    let bpf_object = match parse_elf(&elf_data) {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("error: failed to parse ELF: {e}");
            return 2;
        }
    };

    let prog = if let Some(name) = section {
        match bpf_object.programs.iter().find(|p| p.section_name == name) {
            Some(p) => p,
            None => {
                eprintln!(
                    "error: section '{}' not found. available: {}",
                    name,
                    bpf_object.programs.iter()
                        .map(|p| p.section_name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                return 2;
            }
        }
    } else {
        match bpf_object.programs.first() {
            Some(p) => p,
            None => {
                eprintln!("error: no program sections in {}", program_path.display());
                return 2;
            }
        }
    };

    let safe_name = prog.section_name.replace('/', "_");

    let (spec_module, spec_name) = if let Some(path) = spec_path {
        let module = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Spec");
        (module.to_string(), "spec".to_string())
    } else {
        ("BPF.DefaultSpec".to_string(), "spec".to_string())
    };

    let sb_witness = stack_bounds::analyse(&prog.instructions);
    if !sb_witness.passed {
        eprintln!(
            "error: stack bounds check failed at instruction {}",
            sb_witness.failing_pc.unwrap_or(0)
        );
        return 1;
    }

    let df_result = dataflow::analyse(&prog.instructions);
    let fstar_source = generate_fstar(
        &safe_name, &prog.instructions, &prog.source_locs,
        &spec_module, &spec_name, &sb_witness, &df_result, &bpf_object.structs,
    );

    print!("{fstar_source}");
    0
}

fn run_verify(
    program_path: &Path,
    spec_map: &HashMap<String, PathBuf>,
    sections: &[String],
    verbose: bool,
    fstar_path_override: Option<&Path>,
) -> i32 {
    let elf_data = match std::fs::read(program_path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("error: failed to read {}: {e}", program_path.display());
            return 2;
        }
    };

    let bpf_object = match parse_elf(&elf_data) {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("error: failed to parse ELF: {e}");
            return 2;
        }
    };

    if bpf_object.programs.is_empty() {
        eprintln!("error: no program sections in {}", program_path.display());
        return 2;
    }

    let programs: Vec<&BpfProgram> = if sections.is_empty() {
        bpf_object.programs.iter().collect()
    } else {
        let mut selected = Vec::new();
        for name in sections {
            match bpf_object.programs.iter().find(|p| p.section_name == *name) {
                Some(p) => selected.push(p),
                None => {
                    eprintln!(
                        "error: section '{}' not found. available: {}",
                        name,
                        bpf_object
                            .programs
                            .iter()
                            .map(|p| p.section_name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    return 2;
                }
            }
        }
        selected
    };

    if programs.len() > 1 {
        eprintln!("Verifying {} programmes in {}...", programs.len(), program_path.display());
    }

    let root = project_root();
    let mut passed = 0;
    let mut failed = 0;

    for prog in &programs {
        let spec_path = spec_map.get(&prog.section_name).map(|p| p.as_path());
        match verify_program(prog, spec_path, program_path, &root, fstar_path_override, verbose, &bpf_object.structs) {
            Ok(true) => {
                let label = if spec_path.is_some() {
                    "satisfies spec"
                } else {
                    "verified (crash safety + safety layers)"
                };
                println!("  OK: {} {label}", prog.section_name);
                passed += 1;
            }
            Ok(false) => {
                println!("  FAIL: {} does not satisfy spec", prog.section_name);
                failed += 1;
            }
            Err(e) => {
                eprintln!("  error: {}: {e}", prog.section_name);
                return 2;
            }
        }
    }

    if programs.len() > 1 {
        eprintln!(
            "\n{} of {} programmes passed verification",
            passed,
            passed + failed
        );
    }

    if failed > 0 { 1 } else { 0 }
}

fn verify_program(
    prog: &BpfProgram,
    spec_path: Option<&Path>,
    program_path: &Path,
    project_root: &Path,
    fstar_path_override: Option<&Path>,
    verbose: bool,
    structs: &[StructDef],
) -> Result<bool, String> {
    let program_name = &prog.section_name;
    let safe_name = program_name.replace('/', "_");

    let (spec_module, spec_name) = if let Some(path) = spec_path {
        let module = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Spec");
        (module.to_string(), "spec".to_string())
    } else {
        ("BPF.DefaultSpec".to_string(), "spec".to_string())
    };

    let sb_witness = stack_bounds::analyse(&prog.instructions);
    if !sb_witness.passed {
        return Err(format!(
            "stack bounds check failed at instruction {}",
            sb_witness.failing_pc.unwrap_or(0)
        ));
    }

    let df_result = dataflow::analyse(&prog.instructions);
    let fstar_source = generate_fstar(&safe_name, &prog.instructions, &prog.source_locs, &spec_module, &spec_name, &sb_witness, &df_result, structs);

    if verbose {
        eprintln!("--- Generated F* source for {program_name} ---");
        eprintln!("{fstar_source}");
        eprintln!("--- End generated F* source ---");
    }

    let tmp_dir = tempfile::TempDir::new()
        .map_err(|e| format!("failed to create temp directory: {e}"))?;

    let fst_filename = format!("Verify_{safe_name}.fst");
    let fst_path = tmp_dir.path().join(&fst_filename);
    std::fs::write(&fst_path, &fstar_source)
        .map_err(|e| format!("failed to write generated F* file: {e}"))?;

    if !structs.is_empty() {
        let fields_source = generate_fields_module(structs);
        let fields_path = tmp_dir.path().join("Fields.fst");
        std::fs::write(&fields_path, &fields_source)
            .map_err(|e| format!("failed to write fields module: {e}"))?;
    }

    if let Some(path) = spec_path {
        let spec_dest = tmp_dir.path().join(
            path.file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("Spec.fst")),
        );
        std::fs::copy(path, &spec_dest)
            .map_err(|e| format!("failed to copy spec file {}: {e}", path.display()))?;
    }

    let include_dirs = vec![project_root.join("fstar"), tmp_dir.path().to_path_buf()];
    let cache_dir = project_root.join("fstar/.cache");
    let runner = if let Some(override_path) = fstar_path_override {
        FstarRunner::new(override_path.to_path_buf(), include_dirs)
    } else {
        FstarRunner::find_fstar(project_root, include_dirs)
            .map_err(|e| format!("{e}"))?
    }
    .with_cache(cache_dir);

    match runner.verify(&fst_path) {
        Ok(VerifyResult::Pass) => Ok(true),
        Ok(VerifyResult::Fail { message }) => {
            if verbose {
                eprintln!("{message}");
            }

            let spec_content = spec_path.and_then(|p| std::fs::read_to_string(p).ok());
            let spec_filename = spec_path
                .and_then(|p| p.file_name())
                .and_then(|n| n.to_str());

            if let Some(mut diag) = Diagnostic::from_fstar_output(
                &message,
                &fstar_source,
                spec_filename,
                spec_content.as_deref(),
            ) {
                if let Some(ref origin) = diag.r0_origin
                    && let Some(ref loc) = origin.source_loc
                    && let Some((path, content)) =
                        resolve_c_source(loc, &prog.source_locs, Some(program_path))
                {
                    let line = loc.rsplit_once(':')
                        .and_then(|(_, l)| l.parse::<u32>().ok())
                        .unwrap_or(1);
                    diag = diag.with_c_source(path, content, line);
                }
                eprint!("{}", diag.format());
            }

            Ok(false)
        }
        Err(e) => Err(format!("{e}")),
    }
}
