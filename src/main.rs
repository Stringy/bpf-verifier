use clap::Parser;
use std::path::PathBuf;

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
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Verify { program: _, spec: _, verbose: _ } => {
            eprintln!("verify not yet implemented");
            std::process::exit(2);
        }
    }
}
