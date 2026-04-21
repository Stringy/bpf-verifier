use std::path::{Path, PathBuf};

use clap::Parser;

use bpf_verifier::codegen::fstar::generate_fstar;
use bpf_verifier::elf::parser::parse_elf;
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

        #[arg(long, help = "Path to F* spec file")]
        spec: PathBuf,

        #[arg(long, help = "Show detailed verification output")]
        verbose: bool,

        #[arg(long, help = "Path to F* binary (overrides auto-detection)")]
        fstar_path: Option<PathBuf>,
    },
}

/// Walk up from the executable location to find the directory containing
/// `fstar/`, falling back to the current directory.
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

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify {
            program,
            spec,
            verbose,
            fstar_path,
        } => {
            std::process::exit(run_verify(&program, &spec, verbose, fstar_path.as_deref()));
        }
    }
}

fn run_verify(
    program_path: &Path,
    spec_path: &Path,
    verbose: bool,
    fstar_path_override: Option<&Path>,
) -> i32 {
    // 1. Read and parse the ELF file
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

    // 2. Take the first program section (Milestone A)
    let prog = &bpf_object.programs[0];
    let program_name = &prog.section_name;

    // 3. Derive spec module name from spec file path (file stem)
    let spec_module = spec_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Spec");

    // 4. Generate F* source
    let fstar_source = generate_fstar(program_name, &prog.instructions, spec_module, "spec");

    if verbose {
        eprintln!("--- Generated F* source ---");
        eprintln!("{fstar_source}");
        eprintln!("--- End generated F* source ---");
    }

    // 5. Write generated .fst to a temp directory
    let tmp_dir = match tempfile::TempDir::new() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: failed to create temp directory: {e}");
            return 2;
        }
    };

    let fst_filename = format!("Verify_{program_name}.fst");
    let fst_path = tmp_dir.path().join(&fst_filename);
    if let Err(e) = std::fs::write(&fst_path, &fstar_source) {
        eprintln!("error: failed to write generated F* file: {e}");
        return 2;
    }

    // 6. Copy the user's spec file into the temp dir so F* can find it
    let spec_dest = tmp_dir.path().join(
        spec_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("Spec.fst")),
    );
    if let Err(e) = std::fs::copy(spec_path, &spec_dest) {
        eprintln!(
            "error: failed to copy spec file {}: {e}",
            spec_path.display()
        );
        return 2;
    }

    // 7. Find F* binary
    let root = project_root();
    let mut runner = if let Some(override_path) = fstar_path_override {
        FstarRunner::new(override_path.to_path_buf(), Vec::new())
    } else {
        match FstarRunner::find_fstar(&root) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        }
    };

    // 8. Set up include dirs: [project_root/fstar, temp_dir]
    let fstar_lib_dir = root.join("fstar");
    runner = FstarRunner::new(
        runner.fstar_path.clone(),
        vec![fstar_lib_dir, tmp_dir.path().to_path_buf()],
    );

    // 9. Run verification
    match runner.verify(&fst_path) {
        Ok(VerifyResult::Pass) => {
            println!("OK: {program_name} satisfies spec");
            0
        }
        Ok(VerifyResult::Fail { message }) => {
            if verbose {
                eprintln!("{message}");
            }
            println!("FAIL: {program_name} does not satisfy spec");
            1
        }
        Err(e) => {
            eprintln!("error: {e}");
            2
        }
    }
}
