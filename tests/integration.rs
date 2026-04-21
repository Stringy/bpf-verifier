use std::io::Write;
use std::path::PathBuf;

use assert_cmd::cargo::cargo_bin;

fn corpus_obj_dir() -> PathBuf {
    PathBuf::from(env!("OUT_DIR")).join("corpus")
}

fn corpus_spec_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/corpus")
}

fn verify_corpus(name: &str, category: &str, expect_pass: bool) {
    let obj = corpus_obj_dir()
        .join(category)
        .join(format!("{name}.bpf.o"));
    let spec = corpus_spec_dir()
        .join(category)
        .join(format!("{name}.fst"));

    assert!(obj.exists(), "missing object file: {}", obj.display());
    assert!(spec.exists(), "missing spec file: {}", spec.display());

    let output = std::process::Command::new(cargo_bin("bpf-verifier"))
        .arg("verify")
        .arg(&obj)
        .arg("--spec")
        .arg(&spec)
        .output()
        .unwrap_or_else(|e| panic!("failed to run bpf-verifier for {name}: {e}"));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if expect_pass {
        assert!(
            output.status.success(),
            "{name}: expected PASS but got exit {:?}\nstdout: {stdout}\nstderr: {stderr}",
            output.status.code(),
        );
    } else {
        assert!(
            !output.status.success(),
            "{name}: expected FAIL but got PASS\nstdout: {stdout}",
        );
    }
}

fn discover_corpus(category: &str) -> Vec<String> {
    let dir = corpus_spec_dir().join(category);
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", dir.display()))
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            if path.extension()?.to_str()? == "fst" {
                Some(path.file_stem()?.to_str()?.to_string())
            } else {
                None
            }
        })
        .collect();
    names.sort();
    names
}

#[test]
fn verify_good_corpus() {
    let names = discover_corpus("good");
    assert!(!names.is_empty(), "no good corpus entries found");
    for name in &names {
        verify_corpus(name, "good", true);
    }
}

#[test]
fn verify_bad_corpus() {
    let names = discover_corpus("bad");
    assert!(!names.is_empty(), "no bad corpus entries found");
    for name in &names {
        verify_corpus(name, "bad", false);
    }
}

#[test]
fn parse_invalid_elf_fails() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(b"not an elf file").unwrap();
    tmp.flush().unwrap();

    let spec = corpus_spec_dir().join("good/AddRegs.fst");

    let output = std::process::Command::new(cargo_bin("bpf-verifier"))
        .arg("verify")
        .arg(tmp.path())
        .arg("--spec")
        .arg(&spec)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
}
