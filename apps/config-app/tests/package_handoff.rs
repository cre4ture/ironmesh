#![cfg(target_os = "linux")]

use assert_cmd::cargo::cargo_bin;
use reqwest::blocking::Client;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

struct BackgroundAppGuard {
    base_url: String,
    client: Client,
}

impl BackgroundAppGuard {
    fn new(base_url: String, client: Client) -> Self {
        Self { base_url, client }
    }

    fn shutdown(&self) {
        let _ = self
            .client
            .post(format!("{}/api/shutdown", self.base_url))
            .send();
    }

    fn shutdown_and_wait(&self, timeout: Duration) {
        self.shutdown();
        wait_until_unavailable(&self.client, &self.base_url, timeout);
    }
}

impl Drop for BackgroundAppGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[test]
fn background_config_app_restarts_after_packaged_binary_replacement() {
    let source_binary = cargo_bin("ironmesh-config-app");
    let temp_root = unique_temp_dir("config-app-package-handoff");
    let package_root = temp_root.join("package-root");
    let xdg_config_home = temp_root.join("xdg-config");
    let xdg_state_home = temp_root.join("xdg-state");
    let package_binary = package_root.join("ironmesh-config-app");
    let client = test_http_client();
    let port = reserve_local_port();
    let base_url = format!("http://127.0.0.1:{port}");
    let guard = BackgroundAppGuard::new(base_url.clone(), client.clone());

    fs::create_dir_all(&package_root).expect("package root should create");
    fs::create_dir_all(&xdg_config_home).expect("xdg config dir should create");
    fs::create_dir_all(&xdg_state_home).expect("xdg state dir should create");
    copy_binary(&source_binary, &package_binary);

    let mut child = Command::new(&package_binary)
        .arg("--background")
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .arg("--no-desktop-status")
        .env("XDG_CONFIG_HOME", &xdg_config_home)
        .env("XDG_STATE_HOME", &xdg_state_home)
        .spawn()
        .expect("background config app should start");

    wait_for_config_success(&client, &base_url, Duration::from_secs(15));

    replace_binary(&source_binary, &package_binary);

    let exit_status = wait_for_exit(&mut child, Duration::from_secs(20));
    assert!(
        exit_status.success(),
        "original background config app should exit cleanly: {exit_status}"
    );

    wait_for_config_success(&client, &base_url, Duration::from_secs(20));

    guard.shutdown_and_wait(Duration::from_secs(15));

    let _ = fs::remove_dir_all(&temp_root);
}

fn test_http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(1))
        .build()
        .expect("http client should build")
}

fn wait_for_config_success(client: &Client, base_url: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let url = format!("{base_url}/api/config");
    loop {
        if let Ok(response) = client.get(&url).send()
            && response.status().is_success()
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "config app at {url} did not become ready within {:?}",
            timeout
        );
        thread::sleep(Duration::from_millis(200));
    }
}

fn wait_until_unavailable(client: &Client, base_url: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let url = format!("{base_url}/api/config");
    loop {
        if client.get(&url).send().is_err() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "config app at {url} did not stop within {:?}",
            timeout
        );
        thread::sleep(Duration::from_millis(200));
    }
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("child status should read") {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "child process did not exit within {:?}",
            timeout
        );
        thread::sleep(Duration::from_millis(100));
    }
}

fn reserve_local_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("port reservation should bind");
    listener
        .local_addr()
        .expect("reserved listener address should exist")
        .port()
}

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "{prefix}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be after epoch")
            .as_millis()
    ));
    fs::create_dir_all(&path).expect("temp root should create");
    path
}

fn copy_binary(source: &Path, destination: &Path) {
    fs::copy(source, destination).expect("binary copy should succeed");
}

fn replace_binary(source: &Path, destination: &Path) {
    let replacement = destination.with_extension("replacement");
    fs::copy(source, &replacement).expect("replacement binary copy should succeed");
    fs::rename(&replacement, destination).expect("binary replacement rename should succeed");
}
