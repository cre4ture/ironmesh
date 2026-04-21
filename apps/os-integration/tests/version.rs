use assert_cmd::Command;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
const EXPECTED_NAME: &str = "ironmesh-os-integration";

fn expected_version_outputs(binary_name: &str) -> [String; 2] {
    let build_revision = git_version::git_version!(
        fallback = "unknown",
        args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]
    );
    let clean_revision = build_revision.trim_end_matches("-dirty");
    [
        format!("{binary_name} {PACKAGE_VERSION}\nBuild revision: {clean_revision}\n"),
        format!("{binary_name} {PACKAGE_VERSION}\nBuild revision: {clean_revision}-dirty\n"),
    ]
}

#[test]
fn version_reports_public_entrypoint_name() {
    let output = Command::cargo_bin(EXPECTED_NAME)
        .expect("ironmesh-os-integration binary should build")
        .arg("--version")
        .output()
        .expect("ironmesh-os-integration --version should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("version output should be valid UTF-8");
    let expected = expected_version_outputs(EXPECTED_NAME);
    assert!(
        expected.iter().any(|candidate| candidate == &stdout),
        "unexpected stdout: {stdout}"
    );
}
