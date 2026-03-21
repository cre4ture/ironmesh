use assert_cmd::Command;

const GIT_VERSION: &str =
    git_version::git_version!(args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]);

#[test]
fn version_reports_git_descriptor() {
    Command::cargo_bin("rendezvous-service")
        .expect("rendezvous-service binary should build")
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("rendezvous-service {GIT_VERSION}\n"));
}
