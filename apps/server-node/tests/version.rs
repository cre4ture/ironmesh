use assert_cmd::Command;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[test]
fn version_reports_package_version() {
    Command::cargo_bin("server-node")
        .expect("server-node binary should build")
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("server-node {PACKAGE_VERSION}\n"));
}
