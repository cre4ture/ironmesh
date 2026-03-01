#![cfg(windows)]

use crate::framework::{ChildGuard, binary_path};
use anyhow::Context;
use anyhow::{Result, bail};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::sleep;

pub async fn start_cfapi_adapter(
    sync_root_id: &str,
    display_name: &str,
    root_path: &Path,
    server_base_url: &str,
) -> Result<ChildGuard> {
    start_cfapi_adapter_with_refresh(sync_root_id, display_name, root_path, server_base_url, 500)
        .await
}

pub async fn start_cfapi_adapter_with_refresh(
    sync_root_id: &str,
    display_name: &str,
    root_path: &Path,
    server_base_url: &str,
    remote_refresh_interval_ms: u64,
) -> Result<ChildGuard> {
    let os_integration_bin = binary_path("os-integration")?;
    let root_path_arg = root_path.to_string_lossy().to_string();

    let register_output = Command::new(&os_integration_bin)
        .arg("register")
        .arg("--sync-root-id")
        .arg(sync_root_id)
        .arg("--display-name")
        .arg(display_name)
        .arg("--root-path")
        .arg(&root_path_arg)
        .output()
        .await
        .context("failed to execute os-integration register")?;

    if !register_output.status.success() {
        bail!(
            "os-integration register failed: {}",
            String::from_utf8_lossy(&register_output.stderr)
        );
    }

    let child = Command::new(os_integration_bin)
        .arg("serve")
        .arg("--sync-root-id")
        .arg(sync_root_id)
        .arg("--display-name")
        .arg(display_name)
        .arg("--root-path")
        .arg(&root_path_arg)
        .arg("--server-base-url")
        .arg(server_base_url)
        .arg("--remote-refresh-interval-ms")
        .arg(remote_refresh_interval_ms.to_string())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn os-integration serve")?;

    sleep(Duration::from_secs(2)).await;
    Ok(ChildGuard::new(child))
}
