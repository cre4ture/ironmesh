use assert_cmd::Command;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[test]
fn version_reports_package_version() {
    Command::cargo_bin("ironmesh-folder-agent")
        .expect("ironmesh-folder-agent binary should build")
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("ironmesh-folder-agent {PACKAGE_VERSION}\n"));
}
