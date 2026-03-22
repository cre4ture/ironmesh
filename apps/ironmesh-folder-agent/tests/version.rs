use assert_cmd::Command;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_REVISION: &str =
    git_version::git_version!(args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]);

#[test]
fn version_reports_package_version() {
    Command::cargo_bin("ironmesh-folder-agent")
        .expect("ironmesh-folder-agent binary should build")
        .arg("--version")
        .assert()
        .success()
        .stdout(format!(
            "ironmesh-folder-agent {PACKAGE_VERSION}\nBuild revision: {BUILD_REVISION}\n"
        ));
}
