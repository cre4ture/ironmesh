use assert_cmd::Command;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_REVISION: &str =
    git_version::git_version!(args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]);

#[test]
fn version_reports_package_version() {
    Command::cargo_bin("server-node")
        .expect("server-node binary should build")
        .arg("--version")
        .assert()
        .success()
        .stdout(format!(
            "server-node {PACKAGE_VERSION}\nBuild revision: {BUILD_REVISION}\n"
        ));
}
