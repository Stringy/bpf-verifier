mod helpers;

use std::io::Write;
use std::path::PathBuf;

use assert_cmd::cargo::cargo_bin;

use helpers::elf_builder::*;

/// Return the project root directory.
fn project_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Build a test ELF from raw instruction words and write it to a temporary file.
fn build_test_elf(instructions: &[u64]) -> tempfile::NamedTempFile {
    let elf_bytes = build_bpf_elf("test_prog", instructions);
    let mut tmp = tempfile::NamedTempFile::new().expect("failed to create temp file");
    tmp.write_all(&elf_bytes)
        .expect("failed to write ELF to temp file");
    tmp.flush().expect("failed to flush temp file");
    tmp
}

#[test]
#[ignore] // requires F* to be installed
fn verify_add_regs_good_spec() {
    let instructions = &[
        bpf_insn(BPF_ALU64_REG_MOV, 0, 1, 0, 0), // mov r0, r1
        bpf_insn(BPF_ALU64_REG_ADD, 0, 2, 0, 0),  // add r0, r2
        bpf_insn(BPF_EXIT, 0, 0, 0, 0),            // exit
    ];
    let elf_file = build_test_elf(instructions);
    let spec_path = project_root().join("tests/corpus/good/AddRegs.fst");

    let output = std::process::Command::new(cargo_bin("bpf-verifier"))
        .arg("verify")
        .arg(elf_file.path())
        .arg("--spec")
        .arg(&spec_path)
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
#[ignore] // requires F* to be installed
fn verify_add_regs_bad_spec() {
    let instructions = &[
        bpf_insn(BPF_ALU64_REG_MOV, 0, 1, 0, 0), // mov r0, r1
        bpf_insn(BPF_ALU64_REG_ADD, 0, 2, 0, 0),  // add r0, r2
        bpf_insn(BPF_EXIT, 0, 0, 0, 0),            // exit
    ];
    let elf_file = build_test_elf(instructions);
    let spec_path = project_root().join("tests/corpus/bad/WrongReturn.fst");

    let output = std::process::Command::new(cargo_bin("bpf-verifier"))
        .arg("verify")
        .arg(elf_file.path())
        .arg("--spec")
        .arg(&spec_path)
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

    let spec_path = project_root().join("tests/corpus/good/AddRegs.fst");

    let output = std::process::Command::new(cargo_bin("bpf-verifier"))
        .arg("verify")
        .arg(tmp.path())
        .arg("--spec")
        .arg(&spec_path)
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
