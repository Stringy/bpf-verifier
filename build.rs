use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn compile_bpf(src: &Path, out: &Path) {
    let status = Command::new("clang")
        .args(["-target", "bpf"])
        .arg("-O2")
        .arg("-g")
        .arg("-c")
        .arg("-Wall")
        .arg("-Werror")
        .arg(src)
        .arg("-o")
        .arg(out)
        .status()
        .unwrap_or_else(|e| panic!("failed to invoke clang: {e}"));

    assert!(
        status.success(),
        "clang failed to compile {}",
        src.display()
    );
}

fn compile_corpus(corpus_dir: &Path, out_dir: &Path) {
    for entry in ["good", "bad"] {
        let dir = corpus_dir.join(entry);
        if !dir.exists() {
            continue;
        }

        let target_dir = out_dir.join(entry);
        fs::create_dir_all(&target_dir).unwrap();

        for file in fs::read_dir(&dir).unwrap() {
            let file = file.unwrap();
            let path = file.path();
            if path.extension().and_then(|e| e.to_str()) == Some("c") {
                let stem = path.file_stem().unwrap().to_str().unwrap();
                let out_file = target_dir.join(format!("{stem}.o"));
                compile_bpf(&path, &out_file);
                println!("cargo::rerun-if-changed={}", path.display());
            }
        }
    }
}

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap()).join("corpus");
    let corpus_dir = PathBuf::from("tests/corpus");

    if corpus_dir.exists() {
        compile_corpus(&corpus_dir, &out_dir);
    }

    println!("cargo::rerun-if-changed=tests/corpus");
}
