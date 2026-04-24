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
        fs::create_dir_all(&target_dir).expect("failed to create corpus output directory");

        for file in fs::read_dir(&dir).expect("failed to read corpus directory") {
            let file = file.expect("failed to read directory entry");
            let path = file.path();
            if path.extension().and_then(|e| e.to_str()) == Some("c") {
                let stem = path.file_stem()
                    .and_then(|s| s.to_str())
                    .expect("corpus file must have a valid UTF-8 stem");
                let out_file = target_dir.join(format!("{stem}.o"));
                compile_bpf(&path, &out_file);
                println!("cargo::rerun-if-changed={}", path.display());
            }
        }
    }
}

fn build_fstar_cache(fstar_dir: &Path, cache_dir: &Path) {
    let fstar = which("fstar.exe");
    let Some(fstar) = fstar else {
        eprintln!("warning: fstar.exe not found, skipping checked file cache");
        return;
    };

    fs::create_dir_all(cache_dir).expect("failed to create F* cache directory");

    // Modules in dependency order
    let modules = [
        "BPF.State",
        "BPF.Helpers",
        "BPF.Semantics",
        "BPF.Spec",
        "BPF.Verify",
        "BPF.Witness",
        "BPF.DefaultSpec",
        "BPF.Check.StackBounds",
        "BPF.Check.TypeSafety",
        "BPF.Check.NullSafety",
        "BPF.Exec.Safe",
        "BPF.Tactic",
        "BPF.Tactic.Layered",
    ];

    let mut must_rebuild = false;
    for module in modules {
        let fst_file = fstar_dir.join(format!("{module}.fst"));
        let checked_file = cache_dir.join(format!("{module}.fst.checked"));

        if !must_rebuild
            && let Ok(src_meta) = fs::metadata(&fst_file)
            && let Ok(cache_meta) = fs::metadata(&checked_file)
            && let Ok(src_time) = src_meta.modified()
            && let Ok(cache_time) = cache_meta.modified()
            && src_time <= cache_time
        {
            continue;
        }
        must_rebuild = true;
        let _ = fs::remove_file(&checked_file);

        let status = Command::new(&fstar)
            .arg("--include").arg(fstar_dir)
            .arg("--cache_checked_modules")
            .arg("--cache_dir").arg(cache_dir)
            .arg(&fst_file)
            .status();

        match status {
            Ok(s) if s.success() => {}
            Ok(_) => {
                eprintln!("warning: F* failed to check {module}, cache may be incomplete");
                break;
            }
            Err(e) => {
                eprintln!("warning: failed to invoke F*: {e}");
                break;
            }
        }
    }
}

fn which(name: &str) -> Option<PathBuf> {
    let output = Command::new("which").arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let path = String::from_utf8_lossy(&output.stdout);
    let path = path.trim();
    if path.is_empty() { None } else { Some(PathBuf::from(path)) }
}

fn main() {
    let out_dir_base = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR not set"));
    let corpus_out = out_dir_base.join("corpus");
    let corpus_dir = PathBuf::from("tests/corpus");

    if corpus_dir.exists() {
        compile_corpus(&corpus_dir, &corpus_out);
    }

    let fstar_dir = PathBuf::from("fstar");
    let cache_dir = fstar_dir.join(".cache");
    if fstar_dir.exists() {
        build_fstar_cache(&fstar_dir, &cache_dir);
    }

    println!("cargo::rerun-if-changed=tests/corpus");
    println!("cargo::rerun-if-changed=fstar");
    // When the cache dir doesn't exist, this triggers a rebuild
    println!("cargo::rerun-if-changed={}", cache_dir.display());
}
