use std::io::Write;

use assert_cmd::cargo::cargo_bin;

#[test]
fn parse_invalid_elf_fails() {
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    tmp.write_all(b"not an elf file").unwrap();
    tmp.flush().unwrap();

    let spec = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/corpus/good/AddRegs.fst");

    let output = std::process::Command::new(cargo_bin("bpf-verifier"))
        .arg("verify")
        .arg(tmp.path())
        .arg("--spec")
        .arg(&spec)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
}
