use anyhow::Context;
use anyhow::{Result, bail};
use client_sdk::IronMeshClient;
use reqwest::StatusCode;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::OnceLock;
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::time::sleep;
use uuid::Uuid;

struct TestCa {
    ca_pem: String,
    issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
}

static TEST_CA: OnceLock<TestCa> = OnceLock::new();

fn test_ca() -> Result<&'static TestCa> {
    if let Some(ca) = TEST_CA.get() {
        return Ok(ca);
    }

    let ca_key = rcgen::KeyPair::generate().context("failed generating CA key")?;
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ironmesh-test-node-ca");
    params.key_usages = vec![
        rcgen::KeyUsagePurpose::KeyCertSign,
        rcgen::KeyUsagePurpose::CrlSign,
        rcgen::KeyUsagePurpose::DigitalSignature,
    ];

    let ca_cert = params
        .self_signed(&ca_key)
        .context("failed creating CA certificate")?;
    let ca_pem = ca_cert.pem();

    let issuer = rcgen::Issuer::new(params, ca_key);
    let _ = TEST_CA.set(TestCa { ca_pem, issuer });

    Ok(TEST_CA
        .get()
        .expect("TEST_CA was just initialized but is missing"))
}

fn issue_node_cert(node_id: &str) -> Result<(String, String)> {
    let ca = test_ca()?;

    let node_key = rcgen::KeyPair::generate().context("failed generating node key")?;
    let mut params = rcgen::CertificateParams::default();
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("ironmesh-node-{node_id}"),
    );

    let uri = format!("urn:ironmesh:node:{node_id}");
    params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::new(
            127, 0, 0, 1,
        ))));
    params.subject_alt_names.push(rcgen::SanType::URI(
        rcgen::string::Ia5String::try_from(uri.as_str()).context("invalid SAN URI")?,
    ));

    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];

    let cert = params
        .signed_by(&node_key, &ca.issuer)
        .context("failed signing node certificate")?;
    let cert_pem = cert.pem();
    let key_pem = node_key.serialize_pem();

    Ok((cert_pem, key_pem))
}

fn internal_bind_from_public_bind(public_bind: &str) -> Result<String> {
    let (host, port_str) = public_bind
        .rsplit_once(':')
        .context("invalid bind address (expected host:port)")?;
    let port: u16 = port_str.parse().context("invalid bind port")?;
    let internal_port = port
        .checked_add(10_000)
        .context("bind port too high to derive internal port")?;
    Ok(format!("{host}:{internal_port}"))
}

pub fn internal_base_url_from_public_bind(public_bind: &str) -> Result<String> {
    Ok(format!(
        "https://{}",
        internal_bind_from_public_bind(public_bind)?
    ))
}

pub fn mtls_client_from_data_dir(data_dir: &Path) -> Result<reqwest::Client> {
    let tls_dir = data_dir.join("tls");
    let ca_pem = fs::read(tls_dir.join("ca.pem")).context("failed reading ca.pem")?;
    let cert_pem = fs::read(tls_dir.join("node.pem")).context("failed reading node.pem")?;
    let key_pem = fs::read(tls_dir.join("node.key")).context("failed reading node.key")?;

    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).context("failed parsing ca.pem")?;

    let mut identity_pem = Vec::new();
    identity_pem.extend_from_slice(&cert_pem);
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(&key_pem);
    let identity =
        reqwest::Identity::from_pem(&identity_pem).context("failed parsing node identity pem")?;

    reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .build()
        .context("failed building mtls client")
}

pub fn https_client_with_root_from_data_dir(data_dir: &Path) -> Result<reqwest::Client> {
    let tls_dir = data_dir.join("tls");
    let ca_pem = fs::read(tls_dir.join("ca.pem")).context("failed reading ca.pem")?;
    let ca_cert = reqwest::Certificate::from_pem(&ca_pem).context("failed parsing ca.pem")?;
    reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .build()
        .context("failed building https client")
}

pub fn mtls_client_for_node_id(node_id: &str) -> Result<reqwest::Client> {
    let ca = test_ca()?;
    let ca_cert =
        reqwest::Certificate::from_pem(ca.ca_pem.as_bytes()).context("failed parsing CA pem")?;

    let (cert_pem, key_pem) = issue_node_cert(node_id)?;
    let mut identity_pem = Vec::new();
    identity_pem.extend_from_slice(cert_pem.as_bytes());
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(key_pem.as_bytes());
    let identity =
        reqwest::Identity::from_pem(&identity_pem).context("failed parsing node identity pem")?;

    reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .build()
        .context("failed building mtls client for node id")
}

pub struct ChildGuard {
    child: Option<Child>,
}

impl ChildGuard {
    pub fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    pub async fn stop(&mut self) -> Result<()> {
        if let Some(child) = self.child.as_mut() {
            child.kill().await.context("failed to kill child process")?;
            child
                .wait()
                .await
                .context("failed to wait for child process to exit")?;
            self.child = None;
        }
        Ok(())
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

    let node_id = if node_id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        node_id.to_string()
    };

    let public_url = format!("http://{bind}");
    let internal_bind = internal_bind_from_public_bind(bind)?;
    let internal_url = format!("https://{internal_bind}");

    let tls_dir = data_dir.join("tls");
    fs::create_dir_all(&tls_dir).context("failed creating tls dir")?;

    let ca_pem = test_ca()?.ca_pem.as_bytes().to_vec();
    let (node_cert_pem, node_key_pem) = issue_node_cert(&node_id)?;

    let ca_path = tls_dir.join("ca.pem");
    let cert_path = tls_dir.join("node.pem");
    let key_path = tls_dir.join("node.key");
    fs::write(&ca_path, ca_pem).context("failed writing CA pem")?;
    fs::write(&cert_path, node_cert_pem).context("failed writing node cert pem")?;
    fs::write(&key_path, node_key_pem).context("failed writing node key pem")?;

    let mut command = Command::new(server_bin);

    let stdout_log = data_dir.join("server-node.stdout.log");
    let stderr_log = data_dir.join("server-node.stderr.log");
    let stdout_file = std::fs::File::create(&stdout_log).context("failed creating stdout log")?;
    let stderr_file = std::fs::File::create(&stderr_log).context("failed creating stderr log")?;

    let command = command
        .env("IRONMESH_SERVER_BIND", bind)
        .env("IRONMESH_PUBLIC_URL", public_url)
        .env("IRONMESH_DATA_DIR", data_dir)
        .env("IRONMESH_NODE_ID", &node_id)
        .env("IRONMESH_INTERNAL_BIND", internal_bind)
        .env("IRONMESH_INTERNAL_URL", internal_url)
        .env("IRONMESH_INTERNAL_TLS_CA_CERT", ca_path)
        .env("IRONMESH_INTERNAL_TLS_CERT", cert_path)
        .env("IRONMESH_INTERNAL_TLS_KEY", key_path)
        .env(
            "IRONMESH_REPLICATION_FACTOR",
            replication_factor.to_string(),
        )
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    if let Some(mode) = metadata_commit_mode {
        command.env("IRONMESH_METADATA_COMMIT_MODE", mode);
    }

    if let Some(timeout) = heartbeat_timeout_secs {
        command.env("IRONMESH_HEARTBEAT_TIMEOUT_SECS", timeout.to_string());
    }

    command.env("IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED", "false");
    command.env("IRONMESH_AUTONOMOUS_REPLICATION_ON_PUT_ENABLED", "false");

    for (key, value) in extra_env {
        command.env(key, value);
    }

    let mut child = command.spawn().context("failed to spawn server-node")?;

    if let Err(err) = wait_for_server(bind, 40).await {
        if let Some(status) = child
            .try_wait()
            .context("failed to query server-node process state")?
        {
            let stderr_tail = std::fs::read_to_string(&stderr_log)
                .unwrap_or_default()
                .lines()
                .rev()
                .take(80)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect::<Vec<_>>()
                .join("\n");
            bail!(
                "server-node exited early on {bind} with status {status}: {err}\n--- stderr (tail) ---\n{stderr_tail}"
            );
        }
        bail!(
            "server-node did not become healthy on {bind}: {err} (logs at {} and {})",
            stdout_log.display(),
            stderr_log.display()
        );
    }
    if let Some(status) = child
        .try_wait()
        .context("failed to query server-node process state")?
    {
        bail!("server-node exited early on {bind} with status {status}");
    }
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
    let internal_url = {
        let trimmed = public_url.trim_end_matches('/');
        let host_port = trimmed
            .strip_prefix("http://")
            .or_else(|| trimmed.strip_prefix("https://"))
            .context("public_url must include http(s):// scheme")?;
        format!("https://{}", internal_bind_from_public_bind(host_port)?)
    };

    let body = serde_json::json!({
        "public_url": public_url,
        "internal_url": internal_url,
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
    let latest = parsed
        .as_array()
        .and_then(|arr| {
            arr.iter().max_by(|left, right| {
                let left_ts = left
                    .get("created_at_unix")
                    .and_then(|value| value.as_u64())
                    .unwrap_or(0);
                let right_ts = right
                    .get("created_at_unix")
                    .and_then(|value| value.as_u64())
                    .unwrap_or(0);
                left_ts.cmp(&right_ts).then_with(|| {
                    let left_id = left
                        .get("id")
                        .and_then(|value| value.as_str())
                        .unwrap_or("");
                    let right_id = right
                        .get("id")
                        .and_then(|value| value.as_str())
                        .unwrap_or("");
                    left_id.cmp(right_id)
                })
            })
        })
        .context("snapshots endpoint returned empty list")?;

    latest
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

#[allow(dead_code)]
pub async fn wait_for_store_index_entry(
    sdk: &IronMeshClient,
    prefix: Option<&str>,
    depth: usize,
    expected_path: &str,
    expected_entry_type: &str,
    present: bool,
    retries: usize,
) -> Result<()> {
    for _ in 0..retries {
        if let Ok(index) = sdk.store_index(prefix, depth, None).await {
            let found = index.entries.iter().any(|entry| {
                entry.path == expected_path && entry.entry_type == expected_entry_type
            });
            if found == present {
                return Ok(());
            }
        }

        sleep(Duration::from_millis(100)).await;
    }

    let expected_state = if present { "present" } else { "absent" };
    let prefix_label = prefix.unwrap_or("<root>");
    bail!(
        "store index did not report {expected_entry_type} path={expected_path} as {expected_state} for prefix={prefix_label} depth={depth}"
    );
}

pub async fn stop_server(child: &mut ChildGuard) {
    child.stop().await.ok();
}

pub fn binary_path(name: &str) -> Result<PathBuf> {
    let override_key = match name {
        "server-node" => "IRONMESH_SERVER_BIN",
        "cli-client" => "IRONMESH_CLI_BIN",
        "os-integration" => "IRONMESH_OS_INTEGRATION_BIN",
        "ironmesh-folder-agent" => "IRONMESH_FOLDER_AGENT_BIN",
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
        "ironmesh-folder-agent" => {
            option_env!("CARGO_BIN_FILE_IRONMESH_FOLDER_AGENT_ironmesh-folder-agent")
        }
        _ => None,
    };

    if let Some(path) = artifact_path {
        return Ok(PathBuf::from(path));
    }

    let workspace_root = workspace_root()?;
    let path = workspace_root.join("target").join("debug").join(name);

    if !path.exists() {
        bail!(
            "expected binary does not exist: {} (artifact env missing; use nightly + artifact dependencies, or prebuild binaries, or set {}/{}/{}/{} overrides)",
            path.display(),
            "IRONMESH_SERVER_BIN",
            "IRONMESH_CLI_BIN",
            "IRONMESH_OS_INTEGRATION_BIN",
            "IRONMESH_FOLDER_AGENT_BIN"
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
    let unique = Uuid::new_v4();
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
