use std::io::Write;
use std::path::PathBuf;

use assert_cmd::cargo::cargo_bin;

fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("OUT_DIR")).join("corpus")
}

fn spec_dir() -> PathBuf {
    project_root().join("tests/corpus")
}

#[test]
fn verify_add_regs_good_spec() {
    let obj = corpus_dir().join("good/AddRegs.bpf.o");
    let spec = spec_dir().join("good/AddRegs.fst");

    let output = std::process::Command::new(cargo_bin("bpf-verifier"))
        .arg("verify")
        .arg(&obj)
        .arg("--spec")
        .arg(&spec)
        .output()
        .expect("failed to run bpf-verifier");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "expected exit 0 but got {:?}\nstdout: {stdout}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        stdout.contains("OK"),
        "expected stdout to contain 'OK', got: {stdout}",
    );
}

#[test]
fn verify_wrong_return_bad_spec() {
    let obj = corpus_dir().join("bad/WrongReturn.bpf.o");
    let spec = spec_dir().join("bad/WrongReturn.fst");

    let output = std::process::Command::new(cargo_bin("bpf-verifier"))
        .arg("verify")
        .arg(&obj)
        .arg("--spec")
        .arg(&spec)
        .output()
        .expect("failed to run bpf-verifier");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !output.status.success(),
        "expected non-zero exit but got 0\nstdout: {stdout}",
    );
    assert!(
        stdout.contains("FAIL"),
        "expected stdout to contain 'FAIL', got: {stdout}",
    );
}

#[test]
fn parse_invalid_elf_fails() {
    let mut tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
    tmp.write_all(b"not an elf file")
        .expect("failed to write to temp file");
    tmp.flush().expect("failed to flush temp file");

    let spec = spec_dir().join("good/AddRegs.fst");

    let output = std::process::Command::new(cargo_bin("bpf-verifier"))
        .arg("verify")
        .arg(tmp.path())
        .arg("--spec")
        .arg(&spec)
        .output()
        .expect("failed to run bpf-verifier");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit code 2 for invalid ELF, got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
}
