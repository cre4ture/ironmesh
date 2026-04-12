use assert_cmd::Command;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

fn expected_version_outputs(binary_name: &str) -> [String; 2] {
    let build_revision =
        git_version::git_version!(args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]);
    let clean_revision = build_revision.trim_end_matches("-dirty");
    [
        format!("{binary_name} {PACKAGE_VERSION}\nBuild revision: {clean_revision}\n"),
        format!("{binary_name} {PACKAGE_VERSION}\nBuild revision: {clean_revision}-dirty\n"),
    ]
}

#[cfg(windows)]
const EXPECTED_NAME: &str = "adapter-windows-cfapi";

#[cfg(not(windows))]
const EXPECTED_NAME: &str = "adapter-linux-fuse-mount";

#[test]
fn version_reports_nested_platform_cli_package_version() {
    let output = Command::cargo_bin("os-integration")
        .expect("os-integration binary should build")
        .arg("--version")
        .output()
        .expect("os-integration --version should run");

    assert!(output.status.success());

    let stdout = String::from_utf8(output.stdout).expect("version output should be valid UTF-8");
    let expected = expected_version_outputs(EXPECTED_NAME);
    assert!(
        expected.iter().any(|candidate| candidate == &stdout),
        "unexpected stdout: {stdout}"
    );
}
