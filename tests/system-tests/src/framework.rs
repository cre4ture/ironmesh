use anyhow::Context;
use anyhow::{Result, bail};
use reqwest::StatusCode;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, SystemTime};
use tokio::process::{Child, Command};
use tokio::time::sleep;

pub struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    pub fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }
}

pub async fn start_server(bind: &str) -> Result<ChildGuard> {
    let data_dir = fresh_data_dir("default-server");
    start_server_with_data_dir(bind, &data_dir).await
}

pub async fn start_server_with_data_dir(bind: &str, data_dir: &Path) -> Result<ChildGuard> {
    start_server_with_config(bind, data_dir, "", 3).await
}

pub async fn start_server_with_config(
    bind: &str,
    data_dir: &Path,
    node_id: &str,
    replication_factor: usize,
) -> Result<ChildGuard> {
    start_server_with_options(bind, data_dir, node_id, replication_factor, None, None).await
}

pub async fn start_server_with_options(
    bind: &str,
    data_dir: &Path,
    node_id: &str,
    replication_factor: usize,
    metadata_commit_mode: Option<&str>,
    heartbeat_timeout_secs: Option<u64>,
) -> Result<ChildGuard> {
    start_server_with_env_options(
        bind,
        data_dir,
        node_id,
        replication_factor,
        metadata_commit_mode,
        heartbeat_timeout_secs,
        &[],
    )
    .await
}

pub async fn start_server_with_env(
    bind: &str,
    data_dir: &Path,
    node_id: &str,
    replication_factor: usize,
    extra_env: &[(&str, &str)],
) -> Result<ChildGuard> {
    start_server_with_env_options(
        bind,
        data_dir,
        node_id,
        replication_factor,
        None,
        None,
        extra_env,
    )
    .await
}

pub async fn start_server_with_env_options(
    bind: &str,
    data_dir: &Path,
    node_id: &str,
    replication_factor: usize,
    metadata_commit_mode: Option<&str>,
    heartbeat_timeout_secs: Option<u64>,
    extra_env: &[(&str, &str)],
) -> Result<ChildGuard> {
    let server_bin = binary_path("server-node")?;

    let mut command = Command::new(server_bin);
    let command = command
        .env("IRONMESH_SERVER_BIND", bind)
        .env("IRONMESH_DATA_DIR", data_dir)
        .env(
            "IRONMESH_REPLICATION_FACTOR",
            replication_factor.to_string(),
        )
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if let Some(mode) = metadata_commit_mode {
        command.env("IRONMESH_METADATA_COMMIT_MODE", mode);
    }

    if let Some(timeout) = heartbeat_timeout_secs {
        command.env("IRONMESH_HEARTBEAT_TIMEOUT_SECS", timeout.to_string());
    }

    if !node_id.is_empty() {
        command.env("IRONMESH_NODE_ID", node_id);
    }

    command.env("IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED", "false");
    command.env("IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED", "false");

    for (key, value) in extra_env {
        command.env(key, value);
    }

    let child = command.spawn().context("failed to spawn server-node")?;

    wait_for_server(bind, 40).await?;
    Ok(ChildGuard::new(child))
}

pub async fn register_node(
    http: &reqwest::Client,
    controller_base: &str,
    node_id: &str,
    public_url: &str,
    dc: &str,
    rack: &str,
) -> Result<()> {
    let body = serde_json::json!({
        "public_url": public_url,
        "labels": {
            "region": "local",
            "dc": dc,
            "rack": rack
        },
        "capacity_bytes": 1_000_000,
        "free_bytes": 800_000
    });

    http.put(format!("{controller_base}/cluster/nodes/{node_id}"))
        .json(&body)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

pub async fn latest_snapshot_id(http: &reqwest::Client, base_url: &str) -> Result<String> {
    let payload = http
        .get(format!("{base_url}/snapshots"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    let parsed: serde_json::Value = serde_json::from_str(&payload)?;
    let first = parsed
        .as_array()
        .and_then(|arr| arr.first())
        .context("snapshots endpoint returned empty list")?;

    first
        .get("id")
        .and_then(|v| v.as_str())
        .map(ToString::to_string)
        .context("snapshot id missing in response")
}

pub async fn run_cli(args: &[&str]) -> Result<String> {
    let cli_bin = binary_path("cli-client")?;
    let output = Command::new(cli_bin)
        .args(args)
        .output()
        .await
        .context("failed to execute cli-client")?;

    if !output.status.success() {
        bail!(
            "cli-client failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub async fn start_cli_web(bind: &str) -> Result<ChildGuard> {
    let cli_bin = binary_path("cli-client")?;

    let child = Command::new(cli_bin)
        .arg("serve-web")
        .arg("--bind")
        .arg(bind)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .context("failed to spawn cli-client serve-web")?;

    wait_for_url_status(&format!("http://{bind}/api/ping"), StatusCode::OK, 40).await?;
    Ok(ChildGuard::new(child))
}

#[cfg(windows)]
pub async fn start_cfapi_adapter(
    sync_root_id: &str,
    display_name: &str,
    root_path: &Path,
    server_base_url: &str,
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
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .context("failed to spawn os-integration serve")?;

    sleep(Duration::from_secs(2)).await;
    Ok(ChildGuard::new(child))
}

pub async fn wait_for_server(bind: &str, retries: usize) -> Result<()> {
    let health_url = format!("http://{bind}/health");
    wait_for_url_status(&health_url, StatusCode::OK, retries).await
}

pub async fn wait_for_url_status(url: &str, expected: StatusCode, retries: usize) -> Result<()> {
    let http = reqwest::Client::new();

    for _ in 0..retries {
        if let Ok(resp) = http.get(url).send().await
            && resp.status() == expected
        {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }

    bail!("service did not return {expected} at {url}");
}

pub async fn wait_for_online_nodes(
    http: &reqwest::Client,
    base_url: &str,
    expected_online_nodes: u64,
    retries: usize,
) -> Result<()> {
    for _ in 0..retries {
        if let Ok(resp) = http.get(format!("{base_url}/cluster/status")).send().await
            && let Ok(ok_resp) = resp.error_for_status()
            && let Ok(payload) = ok_resp.json::<serde_json::Value>().await
        {
            let online_nodes = payload
                .get("online_nodes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            if online_nodes == expected_online_nodes {
                return Ok(());
            }
        }

        sleep(Duration::from_millis(100)).await;
    }

    bail!(
        "cluster did not report online_nodes={} at {base_url}/cluster/status",
        expected_online_nodes
    );
}

pub async fn wait_for_object_payload(
    http: &reqwest::Client,
    base_url: &str,
    key: &str,
    expected_payload: &str,
    retries: usize,
) -> Result<()> {
    for _ in 0..retries {
        if let Ok(resp) = http.get(format!("{base_url}/store/{key}")).send().await
            && resp.status() == StatusCode::OK
            && let Ok(body) = resp.text().await
            && body == expected_payload
        {
            return Ok(());
        }

        sleep(Duration::from_millis(100)).await;
    }

    bail!("object {key} did not replicate to expected payload at {base_url}/store/{key}");
}

pub fn binary_path(name: &str) -> Result<PathBuf> {
    let override_key = match name {
        "server-node" => "IRONMESH_SERVER_BIN",
        "cli-client" => "IRONMESH_CLI_BIN",
        "os-integration" => "IRONMESH_OS_INTEGRATION_BIN",
        _ => "",
    };

    if !override_key.is_empty()
        && let Ok(override_path) = std::env::var(override_key)
    {
        let path = PathBuf::from(override_path);
        if path.exists() {
            return Ok(path);
        }
        bail!(
            "{override_key} points to missing binary: {}",
            path.display()
        );
    }

    let artifact_path = match name {
        "server-node" => option_env!("CARGO_BIN_FILE_SERVER_NODE_server-node"),
        "cli-client" => option_env!("CARGO_BIN_FILE_CLI_CLIENT_cli-client"),
        "os-integration" => option_env!("CARGO_BIN_FILE_OS_INTEGRATION_os-integration"),
        _ => None,
    };

    if let Some(path) = artifact_path {
        return Ok(PathBuf::from(path));
    }

    let workspace_root = workspace_root()?;
    let path = workspace_root.join("target").join("debug").join(name);

    if !path.exists() {
        bail!(
            "expected binary does not exist: {} (artifact env missing; use nightly + artifact dependencies, or prebuild binaries, or set {}/{}/{} overrides)",
            path.display(),
            "IRONMESH_SERVER_BIN",
            "IRONMESH_CLI_BIN",
            "IRONMESH_OS_INTEGRATION_BIN"
        );
    }

    Ok(path)
}

pub fn workspace_root() -> Result<PathBuf> {
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    crate_dir
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .context("failed to resolve workspace root")
}

pub fn fresh_data_dir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("ironmesh-{name}-{unique}"));
    let _ = fs::remove_dir_all(&path);
    let _ = fs::create_dir_all(&path);
    path
}

pub fn first_chunk_file(root: PathBuf) -> Result<PathBuf> {
    let mut dirs = vec![root];

    while let Some(dir) = dirs.pop() {
        for entry in
            fs::read_dir(&dir).with_context(|| format!("failed to read dir {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();

            if path.is_dir() {
                dirs.push(path);
            } else {
                return Ok(path);
            }
        }
    }

    bail!("no chunk files found")
}
