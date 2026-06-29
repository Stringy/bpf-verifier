use std::path::Path;

use assert_cmd::cargo::cargo_bin;

fn verify_good(spec_path: &Path) -> datatest_stable::Result<()> {
    let name = spec_path.file_stem().unwrap().to_str().unwrap();
    let obj = Path::new(env!("OUT_DIR"))
        .join("corpus/good")
        .join(format!("{name}.bpf.o"));

    let spec_arg = format!("test:{}", spec_path.display());
    let output = std::process::Command::new(cargo_bin("bpf-verifier"))
        .args(["object", "verify"])
        .arg(&obj)
        .arg("--spec")
        .arg(&spec_arg)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "{name}: expected PASS but got exit {:?}\nstdout: {stdout}\nstderr: {stderr}",
        output.status.code(),
    );

    Ok(())
}

fn verify_bad(spec_path: &Path) -> datatest_stable::Result<()> {
    let name = spec_path.file_stem().unwrap().to_str().unwrap();
    let obj = Path::new(env!("OUT_DIR"))
        .join("corpus/bad")
        .join(format!("{name}.bpf.o"));

    let spec_arg = format!("test:{}", spec_path.display());
    let output = std::process::Command::new(cargo_bin("bpf-verifier"))
        .args(["object", "verify"])
        .arg(&obj)
        .arg("--spec")
        .arg(&spec_arg)
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        !output.status.success(),
        "{name}: expected FAIL but got PASS\nstdout: {stdout}",
    );

    Ok(())
}

datatest_stable::harness!(
    verify_good, "tests/corpus/good", r"\.fst$",
    verify_bad, "tests/corpus/bad", r"\.fst$",
);
