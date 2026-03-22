#![cfg(windows)]

use crate::framework::{ChildGuard, binary_path};
use anyhow::Context;
use anyhow::{Result, bail};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::sleep;

#[allow(dead_code)]
pub async fn start_cfapi_adapter(
    sync_root_id: &str,
    display_name: &str,
    root_path: &Path,
    server_base_url: &str,
) -> Result<ChildGuard> {
    start_cfapi_adapter_with_refresh_and_pairing(
        sync_root_id,
        display_name,
        root_path,
        server_base_url,
        500,
        None,
    )
    .await
}

#[allow(dead_code)]
pub async fn start_cfapi_adapter_with_refresh(
    sync_root_id: &str,
    display_name: &str,
    root_path: &Path,
    server_base_url: &str,
    remote_refresh_interval_ms: u64,
) -> Result<ChildGuard> {
    start_cfapi_adapter_with_refresh_and_pairing(
        sync_root_id,
        display_name,
        root_path,
        server_base_url,
        remote_refresh_interval_ms,
        None,
    )
    .await
}

#[allow(dead_code)]
pub async fn start_cfapi_adapter_with_refresh_and_pairing(
    sync_root_id: &str,
    display_name: &str,
    root_path: &Path,
    server_base_url: &str,
    remote_refresh_interval_ms: u64,
    pairing_token: Option<&str>,
) -> Result<ChildGuard> {
    start_cfapi_adapter_with_refresh_pairing_and_ca(
        sync_root_id,
        display_name,
        root_path,
        server_base_url,
        remote_refresh_interval_ms,
        pairing_token,
        None,
    )
    .await
}

#[allow(dead_code)]
pub async fn start_cfapi_adapter_with_refresh_pairing_and_ca(
    sync_root_id: &str,
    display_name: &str,
    root_path: &Path,
    server_base_url: &str,
    remote_refresh_interval_ms: u64,
    pairing_token: Option<&str>,
    server_ca_cert: Option<&Path>,
) -> Result<ChildGuard> {
    start_cfapi_adapter_with_resolved_inputs(
        sync_root_id,
        display_name,
        root_path,
        Some(server_base_url),
        remote_refresh_interval_ms,
        pairing_token,
        server_ca_cert,
        None,
    )
    .await
}

pub async fn start_cfapi_adapter_with_bootstrap(
    sync_root_id: &str,
    display_name: &str,
    root_path: &Path,
    remote_refresh_interval_ms: u64,
    bootstrap_file: &Path,
) -> Result<ChildGuard> {
    start_cfapi_adapter_with_resolved_inputs(
        sync_root_id,
        display_name,
        root_path,
        None,
        remote_refresh_interval_ms,
        None,
        None,
        Some(bootstrap_file),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn start_cfapi_adapter_with_resolved_inputs(
    sync_root_id: &str,
    display_name: &str,
    root_path: &Path,
    server_base_url: Option<&str>,
    remote_refresh_interval_ms: u64,
    pairing_token: Option<&str>,
    server_ca_cert: Option<&Path>,
    bootstrap_file: Option<&Path>,
) -> Result<ChildGuard> {
    let os_integration_bin = binary_path("os-integration")?;
    let root_path_arg = root_path.to_string_lossy().to_string();
    let unique_sync_root_id = {
        let mut hasher = DefaultHasher::new();
        root_path_arg.hash(&mut hasher);
        format!("{sync_root_id}.{:016x}", hasher.finish())
    };

    let register_output = Command::new(&os_integration_bin)
        .arg("register")
        .arg("--sync-root-id")
        .arg(&unique_sync_root_id)
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

    let mut command = Command::new(os_integration_bin);
    command
        .arg("serve")
        .arg("--sync-root-id")
        .arg(&unique_sync_root_id)
        .arg("--display-name")
        .arg(display_name)
        .arg("--root-path")
        .arg(&root_path_arg)
        .arg("--remote-refresh-interval-ms")
        .arg(remote_refresh_interval_ms.to_string());

    if let Some(server_base_url) = server_base_url {
        command.arg("--server-base-url").arg(server_base_url);
    }

    if let Some(pairing_token) = pairing_token {
        command.arg("--pairing-token").arg(pairing_token);
    }
    if let Some(server_ca_cert) = server_ca_cert {
        command.arg("--server-ca-cert").arg(server_ca_cert);
    }
    if let Some(bootstrap_file) = bootstrap_file {
        command.arg("--bootstrap-file").arg(bootstrap_file);
    }

    let child = command
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn os-integration serve")?;

    sleep(Duration::from_secs(2)).await;
    Ok(ChildGuard::new(child))
}

pub async fn pin_cfapi_placeholder(
    root_path: &Path,
    relative_path: &str,
    wait: bool,
) -> Result<()> {
    let os_integration_bin = binary_path("os-integration")?;
    let mut command = Command::new(os_integration_bin);
    command
        .arg("pin")
        .arg("--root-path")
        .arg(root_path)
        .arg("--path")
        .arg(relative_path)
        .arg("--timeout-ms")
        .arg("60000")
        .arg("--poll-interval-ms")
        .arg("200");
    if wait {
        command.arg("--wait");
    }

    let output = command
        .output()
        .await
        .context("failed to execute os-integration pin")?;
    if !output.status.success() {
        bail!(
            "os-integration pin failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(())
}
