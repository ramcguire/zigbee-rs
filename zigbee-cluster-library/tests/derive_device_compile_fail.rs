#[test]
fn derive_device_validation_errors() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/derive_device/*.rs");
}

#[test]
fn derive_device_path_resolution_cases() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/derive_device_pass/*.rs");
}

#[test]
fn derive_device_supports_renamed_dependency() {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let fixture_dir = manifest_dir.join("tests/renamed_dependency");
    let status = std::process::Command::new(env!("CARGO"))
        .arg("check")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(fixture_dir.join("Cargo.toml"))
        .arg("--target-dir")
        .arg(fixture_dir.join("target"))
        .status()
        .expect("failed to run cargo check for renamed dependency fixture");

    assert!(status.success(), "renamed dependency fixture failed");
}
