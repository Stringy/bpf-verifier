use std::collections::HashMap;
use std::path::{Path, PathBuf};

use clap::Parser;

use bpf_verifier::analysis::{dataflow, stack_bounds};
use bpf_verifier::ast;
use bpf_verifier::codegen::fstar::{generate_fstar, generate_fields_module};
use bpf_verifier::elf::parser::{parse_elf, BpfProgram, StructDef};
use bpf_verifier::kverify;
use bpf_verifier::verify::diagnostic::{Diagnostic, resolve_c_source};
use bpf_verifier::verify::runner::{FstarRunner, VerifyResult};

#[derive(Parser)]
#[command(name = "bpf-verifier")]
#[command(about = "Formally verify BPF programmes")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Object-level verification (operates on compiled .bpf.o files)
    Object {
        #[command(subcommand)]
        command: ObjectCommands,
    },
    /// AST-level verification (operates on C source files)
    Ast {
        #[command(subcommand)]
        command: AstCommands,
    },
}

#[derive(clap::Subcommand)]
enum ObjectCommands {
    /// Verify a BPF object against an F* spec
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
    /// Check a BPF object for safety (kernel-verifier-style, no root required)
    Check {
        #[arg(help = "Path to BPF object file")]
        program: PathBuf,

        #[arg(long, help = "Only check these sections, repeatable")]
        section: Vec<String>,

        #[arg(long, help = "Show detailed verification state")]
        verbose: bool,
    },
    /// Generate F* verification module from a BPF object (without running F*)
    Codegen {
        #[arg(help = "Path to BPF object file")]
        program: PathBuf,

        #[arg(long, help = "Section to generate code for (default: first)")]
        section: Option<String>,

        #[arg(long, help = "Path to F* spec file")]
        spec: Option<PathBuf>,
    },
}

#[derive(clap::Subcommand)]
enum AstCommands {
    /// Verify a BPF C source file at the AST level
    Verify {
        #[arg(help = "Path to BPF C source file")]
        source: PathBuf,

        #[arg(long, short, help = "Output F* module path (default: stdout)")]
        output: Option<PathBuf>,

        #[arg(long, help = "F* module name (derived from output if not given)")]
        module_name: Option<String>,

        #[arg(long, help = "Show generated F* source")]
        verbose: bool,
    },
    /// Generate F* AST module from a BPF C source file (without running F*)
    Codegen {
        #[arg(help = "Path to BPF C source file")]
        source: PathBuf,

        #[arg(long, short, help = "Output F* module path (default: stdout)")]
        output: Option<PathBuf>,

        #[arg(long, help = "F* module name (derived from output if not given)")]
        module_name: Option<String>,
    },
}

fn resolve_spec_module(spec_path: Option<&Path>) -> (String, String) {
    if let Some(path) = spec_path {
        let module = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("Spec");
        (module.to_string(), "spec".to_string())
    } else {
        ("BPF.DefaultSpec".to_string(), "spec".to_string())
    }
}

fn find_program<'a>(
    programs: &'a [BpfProgram],
    section: Option<&str>,
) -> Result<&'a BpfProgram, String> {
    let available = || {
        programs
            .iter()
            .map(|p| p.section_name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    };

    match section {
        Some(name) => programs
            .iter()
            .find(|p| p.section_name == name)
            .ok_or_else(|| {
                format!(
                    "section '{name}' not found. available: {}",
                    available()
                )
            }),
        None if programs.len() == 1 => Ok(&programs[0]),
        None if programs.is_empty() => Err("no programme sections found".to_string()),
        None => Err(format!(
            "multiple programme sections found, use --section to select one: {}",
            available()
        )),
    }
}

fn project_root() -> PathBuf {
    // Container install path (set in Containerfile)
    let install_prefix = PathBuf::from("/usr/local/share/bpf-verifier");
    if install_prefix.join("fstar").is_dir() {
        return install_prefix;
    }

    // Development: walk up from the binary to find fstar/
    if let Ok(exe) = std::env::current_exe() {
        let mut dir = exe.parent().map(Path::to_path_buf);
        while let Some(d) = dir {
            if d.join("fstar").is_dir() {
                return d;
            }
            dir = d.parent().map(Path::to_path_buf);
        }
    }

    // Fallback: current directory
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
    let exit_code = match cli.command {
        Commands::Object { command } => match command {
            ObjectCommands::Verify {
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
                run_verify(
                    &program,
                    &spec_map,
                    &section,
                    verbose,
                    fstar_path.as_deref(),
                )
            }
            ObjectCommands::Check {
                program,
                section,
                verbose,
            } => run_check(&program, &section, verbose),
            ObjectCommands::Codegen {
                program,
                section,
                spec,
            } => run_codegen(&program, section.as_deref(), spec.as_deref()),
        },
        Commands::Ast { command } => match command {
            AstCommands::Verify {
                source,
                output,
                module_name,
                verbose,
            } => run_ast_verify(
                &source,
                output.as_deref(),
                module_name.as_deref(),
                true,
                verbose,
            ),
            AstCommands::Codegen {
                source,
                output,
                module_name,
            } => run_ast_verify(
                &source,
                output.as_deref(),
                module_name.as_deref(),
                false,
                false,
            ),
        },
    };
    std::process::exit(exit_code);
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

    let prog = match find_program(&bpf_object.programs, section) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: {e}");
            return 2;
        }
    };

    let safe_name = prog.section_name.replace('/', "_");
    let (spec_module, spec_name) = resolve_spec_module(spec_path);

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
        eprintln!("error: no programme sections in {}", program_path.display());
        return 2;
    }

    let programs: Vec<&BpfProgram> = if sections.is_empty() {
        bpf_object.programs.iter().collect()
    } else {
        let mut selected = Vec::new();
        for name in sections {
            match find_program(&bpf_object.programs, Some(name)) {
                Ok(p) => selected.push(p),
                Err(e) => {
                    eprintln!("error: {e}");
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

    let (spec_module, spec_name) = resolve_spec_module(spec_path);

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

    let include_dirs = vec![project_root.join("fstar/obj"), tmp_dir.path().to_path_buf()];
    let cache_dir = project_root.join("fstar/obj/.cache");
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
                diag = diag.with_struct_fields(structs);
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

fn run_check(
    program_path: &Path,
    sections: &[String],
    verbose: bool,
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
        eprintln!("error: no programme sections in {}", program_path.display());
        return 2;
    }

    let programs: Vec<&BpfProgram> = if sections.is_empty() {
        bpf_object.programs.iter().collect()
    } else {
        let mut selected = Vec::new();
        for name in sections {
            match find_program(&bpf_object.programs, Some(name)) {
                Ok(p) => selected.push(p),
                Err(e) => {
                    eprintln!("error: {e}");
                    return 2;
                }
            }
        }
        selected
    };

    // Resolve C source files for diagnostic output.
    let mut c_sources: HashMap<String, String> = HashMap::new();
    for prog in &programs {
        for loc in prog.source_locs.iter().flatten() {
            if !c_sources.contains_key(&loc.path) {
                if let Ok(content) = std::fs::read_to_string(&loc.path) {
                    c_sources.insert(loc.path.clone(), content);
                } else if let Some(dir) = program_path.parent() {
                    let adjacent = dir.join(&loc.file);
                    if let Ok(content) = std::fs::read_to_string(&adjacent) {
                        c_sources.insert(loc.path.clone(), content);
                    }
                }
            }
        }
    }

    let mut passed = 0;
    let mut failed = 0;

    for prog in &programs {
        let result = kverify::check::check_with_relocs(
            &prog.instructions,
            &prog.source_locs,
            &prog.relocations,
        );

        if verbose {
            eprintln!(
                "  {} instructions visited for {}",
                result.instructions_visited, prog.section_name
            );
        }

        if result.passed() {
            println!("  OK: {} (safety check passed)", prog.section_name);
            passed += 1;
        } else {
            println!(
                "  FAIL: {} ({} error{})",
                prog.section_name,
                result.errors.len(),
                if result.errors.len() == 1 { "" } else { "s" }
            );
            let diagnostic = kverify::format_errors(
                &result.errors,
                &prog.source_locs,
                &c_sources,
            );
            eprint!("{diagnostic}");
            failed += 1;
        }
    }

    if programs.len() > 1 {
        eprintln!(
            "\n{} of {} programmes passed safety check",
            passed,
            passed + failed
        );
    }

    if failed > 0 { 1 } else { 0 }
}

fn run_ast_verify(
    source_path: &Path,
    output: Option<&Path>,
    module_name: Option<&str>,
    run_fstar: bool,
    verbose: bool,
) -> i32 {
    use std::process::Command;

    // Step 1: Run clang to get JSON AST
    let clang_output = Command::new("clang")
        .args([
            "-target", "bpf",
            "-Xclang", "-ast-dump=json",
            "-fsyntax-only",
        ])
        .arg(source_path)
        .output();

    let clang_output = match clang_output {
        Ok(o) if o.status.success() => o,
        Ok(o) => {
            eprintln!(
                "error: clang failed:\n{}",
                String::from_utf8_lossy(&o.stderr)
            );
            return 2;
        }
        Err(e) => {
            eprintln!("error: failed to run clang: {e}");
            return 2;
        }
    };

    // Step 2: Parse Clang JSON AST
    let root: ast::clang_ast::Node = match serde_json::from_slice(&clang_output.stdout) {
        Ok(n) => n,
        Err(e) => {
            eprintln!("error: failed to parse Clang JSON AST: {e}");
            return 2;
        }
    };

    // Step 3: Convert to our AST
    let source_name = source_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    let bpf_obj = match ast::convert::convert_translation_unit(&root, source_name) {
        Ok(obj) => obj,
        Err(e) => {
            eprintln!("error: AST conversion failed: {e}");
            return 2;
        }
    };

    eprintln!(
        "Converted {} ({} maps, {} progs)",
        source_name,
        bpf_obj.maps.len(),
        bpf_obj.progs.len()
    );

    // Step 4: Emit F* source
    let mod_name = module_name.unwrap_or_else(|| {
        output
            .and_then(|p| p.file_stem())
            .and_then(|s| s.to_str())
            .unwrap_or("BPF.Generated")
    });

    let fstar_source = ast::emit::emit_module(&bpf_obj, mod_name);

    if verbose {
        eprintln!("--- Generated F* ---");
        eprintln!("{fstar_source}");
        eprintln!("--- End ---");
    }

    // Step 5: Write output or verify
    if !run_fstar {
        if let Some(out) = output {
            if let Err(e) = std::fs::write(out, &fstar_source) {
                eprintln!("error: failed to write {}: {e}", out.display());
                return 2;
            }
            eprintln!("Wrote {}", out.display());
        } else {
            print!("{fstar_source}");
        }
        return 0;
    }

    // Step 6: Write to temp file and run F* verification.
    // F* requires the module name to match the filename, so we use the
    // module name to construct the temp file path.
    let tmp_dir = match tempfile::TempDir::new() {
        Ok(t) => t,
        Err(e) => {
            eprintln!("error: failed to create temp dir: {e}");
            return 2;
        }
    };
    let fst_filename = format!("{}.fst", mod_name.replace('.', "."));
    let fst_path = tmp_dir.path().join(&fst_filename);
    if let Err(e) = std::fs::write(&fst_path, &fstar_source) {
        eprintln!("error: failed to write {}: {e}", fst_path.display());
        return 2;
    }

    let root = project_root();
    let ast_fstar_dir = root.join("fstar/ast");
    let cache_dir = ast_fstar_dir.join("_cache");
    std::fs::create_dir_all(&cache_dir).ok();

    eprintln!("Verifying {}...", source_name);

    let fstar_result = Command::new("fstar.exe")
        .args([
            "--include", &ast_fstar_dir.to_string_lossy(),
            "--cache_checked_modules",
            "--cache_dir", &cache_dir.to_string_lossy(),
        ])
        .arg(&fst_path)
        .output();

    match fstar_result {
        Ok(o) if o.status.success() => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if stdout.contains("All verification conditions discharged") {
                println!("OK: AST verification passed for {}", source_name);
            } else {
                println!("OK: {}", stdout.trim());
            }
            0
        }
        Ok(o) => {
            let stderr = String::from_utf8_lossy(&o.stderr);
            let stdout = String::from_utf8_lossy(&o.stdout);
            eprintln!("FAIL: AST verification failed for {}", source_name);
            if !stdout.is_empty() {
                eprintln!("{stdout}");
            }
            if !stderr.is_empty() {
                eprintln!("{stderr}");
            }
            1
        }
        Err(e) => {
            eprintln!("error: failed to run fstar.exe: {e}");
            2
        }
    }
}
