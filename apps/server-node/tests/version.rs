use assert_cmd::Command;

const GIT_VERSION: &str =
    git_version::git_version!(args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]);

#[test]
fn version_reports_git_descriptor() {
    Command::cargo_bin("server-node")
        .expect("server-node binary should build")
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("server-node {GIT_VERSION}\n"));
}
