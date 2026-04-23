use std::collections::HashMap;
use std::path::{Path, PathBuf};

use clap::Parser;

use bpf_verifier::analysis::stack_bounds;
use bpf_verifier::codegen::fstar::generate_fstar;
use bpf_verifier::elf::parser::{parse_elf, BpfProgram};
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
    }
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
        match verify_program(prog, spec_path, &root, fstar_path_override, verbose) {
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
    project_root: &Path,
    fstar_path_override: Option<&Path>,
    verbose: bool,
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

    let fstar_source = generate_fstar(&safe_name, &prog.instructions, &prog.source_locs, &spec_module, &spec_name, &sb_witness);

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

    if let Some(path) = spec_path {
        let spec_dest = tmp_dir.path().join(
            path.file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("Spec.fst")),
        );
        std::fs::copy(path, &spec_dest)
            .map_err(|e| format!("failed to copy spec file {}: {e}", path.display()))?;
    }

    let include_dirs = vec![project_root.join("fstar"), tmp_dir.path().to_path_buf()];
    let runner = if let Some(override_path) = fstar_path_override {
        FstarRunner::new(override_path.to_path_buf(), include_dirs)
    } else {
        FstarRunner::find_fstar(project_root, include_dirs)
            .map_err(|e| format!("{e}"))?
    };

    match runner.verify(&fst_path) {
        Ok(VerifyResult::Pass) => Ok(true),
        Ok(VerifyResult::Fail { message }) => {
            if verbose {
                eprintln!("{message}");
            }
            Ok(false)
        }
        Err(e) => Err(format!("{e}")),
    }
}
