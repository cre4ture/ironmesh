use assert_cmd::Command;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

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
fn version_reports_package_version() {
    let output = Command::cargo_bin("ironmesh")
        .expect("ironmesh binary should build")
        .arg("--version")
        .output()
        .expect("ironmesh --version should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("version output should be valid UTF-8");
    let expected = expected_version_outputs("ironmesh");
    assert!(
        expected.iter().any(|candidate| candidate == &stdout),
        "unexpected stdout: {stdout}"
    );
}
