use assert_cmd::Command;

const GIT_VERSION: &str =
    git_version::git_version!(args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]);

#[cfg(windows)]
const EXPECTED_NAME: &str = "adapter-windows-cfapi";

#[cfg(not(windows))]
const EXPECTED_NAME: &str = "adapter-linux-fuse-mount";

#[test]
fn version_reports_nested_platform_cli_git_descriptor() {
    Command::cargo_bin("os-integration")
        .expect("os-integration binary should build")
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("{EXPECTED_NAME} {GIT_VERSION}\n"));
}
