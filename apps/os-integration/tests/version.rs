use assert_cmd::Command;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(windows)]
const EXPECTED_NAME: &str = "adapter-windows-cfapi";

#[cfg(not(windows))]
const EXPECTED_NAME: &str = "adapter-linux-fuse-mount";

#[test]
fn version_reports_nested_platform_cli_package_version() {
    Command::cargo_bin("os-integration")
        .expect("os-integration binary should build")
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("{EXPECTED_NAME} {PACKAGE_VERSION}\n"));
}
