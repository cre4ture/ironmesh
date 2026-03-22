use assert_cmd::Command;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[test]
fn version_reports_package_version() {
    Command::cargo_bin("rendezvous-service")
        .expect("rendezvous-service binary should build")
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("rendezvous-service {PACKAGE_VERSION}\n"));
}
