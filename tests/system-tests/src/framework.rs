use anyhow::Context;
use anyhow::{Result, bail};
use client_sdk::{
    ClientIdentityMaterial, ConnectionBootstrap, IronMeshClient, enroll_connection_input_blocking,
};
use reqwest::StatusCode;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use tokio::time::sleep;
use uuid::Uuid;

pub const TEST_ADMIN_TOKEN: &str = "system-test-admin";

type ResourceMutex = Arc<AsyncMutex<()>>;

static TEST_RESOURCE_REGISTRY: OnceLock<Mutex<BTreeMap<String, ResourceMutex>>> = OnceLock::new();

fn test_resource_registry() -> &'static Mutex<BTreeMap<String, ResourceMutex>> {
    TEST_RESOURCE_REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn resource_mutex_for_key(key: &str) -> ResourceMutex {
    let mut registry = test_resource_registry()
        .lock()
        .expect("test resource registry lock poisoned");
    registry
        .entry(key.to_string())
        .or_insert_with(|| Arc::new(AsyncMutex::new(())))
        .clone()
}

#[derive(Debug)]
pub struct TestResourceGuard {
    _key: String,
    _guard: OwnedMutexGuard<()>,
}

pub async fn lock_test_resources<I, S>(keys: I) -> Vec<TestResourceGuard>
where
    I: IntoIterator<Item = S>,
    S: Into<String>,
{
    let mut ordered = keys.into_iter().map(Into::into).collect::<Vec<_>>();
    ordered.sort();
    ordered.dedup();

    let mut guards = Vec::with_capacity(ordered.len());
    for key in ordered {
        let mutex = resource_mutex_for_key(&key);
        let guard = mutex.lock_owned().await;
        guards.push(TestResourceGuard {
            _key: key,
            _guard: guard,
        });
    }
    guards
}

pub fn tcp_resource_key(bind: &str) -> String {
    format!("tcp:{bind}")
}

pub fn path_resource_key(path: &Path) -> String {
    format!("path:{}", path.display())
}

#[derive(Debug, Clone)]
pub struct EnrolledTestClient {
    pub bootstrap: ConnectionBootstrap,
    pub bootstrap_path: PathBuf,
    pub identity: ClientIdentityMaterial,
}

impl EnrolledTestClient {
    pub async fn build_client_async(&self) -> Result<IronMeshClient> {
        let bootstrap = self.bootstrap.clone();
        let identity = self.identity.clone();
        tokio::task::spawn_blocking(move || bootstrap.build_client_with_identity(&identity))
            .await
            .context("authenticated bootstrap client construction task panicked")?
    }
}

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

pub fn managed_runtime_mtls_client_from_data_dir(data_dir: &Path) -> Result<reqwest::Client> {
    let tls_dir = data_dir.join("managed").join("runtime").join("internal");
    let ca_pem = fs::read(tls_dir.join("cluster-ca.pem"))
        .context("failed reading managed cluster-ca.pem")?;
    let cert_pem = fs::read(tls_dir.join("node.pem")).context("failed reading managed node.pem")?;
    let key_pem = fs::read(tls_dir.join("node.key")).context("failed reading managed node.key")?;

    let ca_cert =
        reqwest::Certificate::from_pem(&ca_pem).context("failed parsing managed CA pem")?;

    let mut identity_pem = Vec::new();
    identity_pem.extend_from_slice(&cert_pem);
    identity_pem.extend_from_slice(b"\n");
    identity_pem.extend_from_slice(&key_pem);
    let identity = reqwest::Identity::from_pem(&identity_pem)
        .context("failed parsing managed node identity pem")?;

    reqwest::Client::builder()
        .add_root_certificate(ca_cert)
        .identity(identity)
        .build()
        .context("failed building managed runtime mtls client")
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

pub fn insecure_https_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .context("failed building insecure https client")
}

pub struct ChildGuard {
    child: Option<Child>,
    _resource_guards: Vec<TestResourceGuard>,
    cleanup_commands: Vec<CleanupCommand>,
}

#[derive(Debug)]
struct CleanupCommand {
    program: PathBuf,
    args: Vec<OsString>,
    description: String,
    max_attempts: usize,
    retry_delay: Duration,
}

impl CleanupCommand {
    #[cfg(windows)]
    fn new(
        program: impl Into<PathBuf>,
        args: Vec<OsString>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            program: program.into(),
            args,
            description: description.into(),
            max_attempts: 20,
            retry_delay: Duration::from_millis(250),
        }
    }

    async fn run_async(&self) -> Result<()> {
        let mut last_error = None;

        for attempt in 1..=self.max_attempts {
            let output = Command::new(&self.program)
                .args(&self.args)
                .output()
                .await
                .with_context(|| {
                    format!("failed to execute cleanup command {}", self.description)
                })?;

            if output.status.success() {
                return Ok(());
            }

            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            last_error = Some(anyhow::anyhow!(
                "cleanup command {} failed with status {:?}: {}",
                self.description,
                output.status.code(),
                stderr
            ));

            if attempt < self.max_attempts {
                sleep(self.retry_delay).await;
            }
        }

        Err(last_error
            .unwrap_or_else(|| anyhow::anyhow!("cleanup command {} failed", self.description)))
    }

    fn run_blocking(&self) -> Result<()> {
        let mut last_error = None;

        for attempt in 1..=self.max_attempts {
            let output = std::process::Command::new(&self.program)
                .args(&self.args)
                .output()
                .with_context(|| {
                    format!("failed to execute cleanup command {}", self.description)
                })?;

            if output.status.success() {
                return Ok(());
            }

            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            last_error = Some(anyhow::anyhow!(
                "cleanup command {} failed with status {:?}: {}",
                self.description,
                output.status.code(),
                stderr
            ));

            if attempt < self.max_attempts {
                std::thread::sleep(self.retry_delay);
            }
        }

        Err(last_error
            .unwrap_or_else(|| anyhow::anyhow!("cleanup command {} failed", self.description)))
    }
}

impl ChildGuard {
    pub fn with_resources(child: Child, resource_guards: Vec<TestResourceGuard>) -> Self {
        Self {
            child: Some(child),
            _resource_guards: resource_guards,
            cleanup_commands: Vec::new(),
        }
    }

    #[cfg(windows)]
    pub fn with_cleanup_command(
        mut self,
        program: impl Into<PathBuf>,
        args: Vec<OsString>,
        description: impl Into<String>,
    ) -> Self {
        self.cleanup_commands
            .push(CleanupCommand::new(program, args, description));
        self
    }

    pub async fn stop(&mut self) -> Result<()> {
        let mut stop_error = None;

        if let Some(child) = self.child.as_mut() {
            if let Err(error) = child.kill().await {
                stop_error =
                    Some(anyhow::Error::new(error).context("failed to kill child process"));
            } else if let Err(error) = child.wait().await {
                stop_error = Some(
                    anyhow::Error::new(error).context("failed to wait for child process to exit"),
                );
            }
            self.child = None;
        }

        for cleanup in std::mem::take(&mut self.cleanup_commands) {
            if let Err(error) = cleanup.run_async().await {
                if stop_error.is_none() {
                    stop_error = Some(error);
                } else {
                    eprintln!("cleanup warning: {error:#}");
                }
            }
        }

        self._resource_guards.clear();
        if let Some(error) = stop_error {
            return Err(error);
        }
        Ok(())
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub async fn stop_without_cleanup(&mut self) -> Result<()> {
        if let Some(child) = self.child.as_mut() {
            child.kill().await.context("failed to kill child process")?;
            child
                .wait()
                .await
                .context("failed to wait for child process to exit")?;
            self.child = None;
        }

        self.cleanup_commands.clear();
        self._resource_guards.clear();
        Ok(())
    }

}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
        for cleanup in std::mem::take(&mut self.cleanup_commands) {
            if let Err(error) = cleanup.run_blocking() {
                eprintln!("cleanup warning: {error:#}");
            }
        }
    }
}

#[allow(dead_code)]
pub async fn start_open_server(bind: &str) -> Result<ChildGuard> {
    let data_dir = fresh_data_dir("default-server");
    start_open_server_with_data_dir(bind, &data_dir).await
}

pub async fn start_authenticated_server(
    bind: &str,
    data_dir: &Path,
    node_id: &str,
    replication_factor: usize,
) -> Result<ChildGuard> {
    start_authenticated_server_with_env_options(
        bind,
        data_dir,
        node_id,
        replication_factor,
        None,
        None,
        &[],
    )
    .await
}

pub async fn start_authenticated_server_with_env_options(
    bind: &str,
    data_dir: &Path,
    node_id: &str,
    replication_factor: usize,
    metadata_commit_mode: Option<&str>,
    heartbeat_timeout_secs: Option<u64>,
    extra_env: &[(&str, &str)],
) -> Result<ChildGuard> {
    let env = [
        ("IRONMESH_ADMIN_TOKEN", TEST_ADMIN_TOKEN),
        ("IRONMESH_REQUIRE_CLIENT_AUTH", "true"),
    ];
    let mut merged_env = env.to_vec();
    merged_env.extend_from_slice(extra_env);
    start_open_server_with_env_options(
        bind,
        data_dir,
        node_id,
        replication_factor,
        metadata_commit_mode,
        heartbeat_timeout_secs,
        &merged_env,
    )
    .await
}

pub async fn start_zero_touch_server(bind: &str, data_dir: &Path) -> Result<ChildGuard> {
    let server_bin = binary_path("server-node")?;
    fs::create_dir_all(data_dir).context("failed creating zero-touch data dir")?;
    let resource_guards = lock_test_resources([
        tcp_resource_key(bind),
        tcp_resource_key(&internal_bind_from_public_bind(bind)?),
    ])
    .await;

    let stdout_log = data_dir.join("server-node.setup.stdout.log");
    let stderr_log = data_dir.join("server-node.setup.stderr.log");
    let stdout_file =
        std::fs::File::create(&stdout_log).context("failed creating setup stdout log")?;
    let stderr_file =
        std::fs::File::create(&stderr_log).context("failed creating setup stderr log")?;

    let mut command = Command::new(server_bin);
    command
        .env("IRONMESH_SERVER_BIND", bind)
        .env("IRONMESH_DATA_DIR", data_dir)
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    let mut child = command
        .spawn()
        .context("failed to spawn zero-touch server-node")?;

    let insecure_http = insecure_https_client()?;
    let health_url = format!("https://{bind}/health");
    if let Err(err) =
        wait_for_url_status_with_client(&insecure_http, &health_url, StatusCode::OK, 60).await
    {
        if let Some(status) = child
            .try_wait()
            .context("failed to query zero-touch server-node process state")?
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
                "zero-touch server-node exited early on {bind} with status {status}: {err}\n--- stderr (tail) ---\n{stderr_tail}"
            );
        }
        bail!(
            "zero-touch server-node did not become healthy on {bind}: {err} (logs at {} and {})",
            stdout_log.display(),
            stderr_log.display()
        );
    }

    if let Some(status) = child
        .try_wait()
        .context("failed to query zero-touch server-node process state")?
    {
        bail!("zero-touch server-node exited early on {bind} with status {status}");
    }

    Ok(ChildGuard::with_resources(child, resource_guards))
}

pub async fn start_open_server_with_data_dir(bind: &str, data_dir: &Path) -> Result<ChildGuard> {
    start_open_server_with_config(bind, data_dir, "", 3).await
}

pub async fn start_open_server_with_config(
    bind: &str,
    data_dir: &Path,
    node_id: &str,
    replication_factor: usize,
) -> Result<ChildGuard> {
    start_open_server_with_options(bind, data_dir, node_id, replication_factor, None, None).await
}

pub async fn start_open_server_with_options(
    bind: &str,
    data_dir: &Path,
    node_id: &str,
    replication_factor: usize,
    metadata_commit_mode: Option<&str>,
    heartbeat_timeout_secs: Option<u64>,
) -> Result<ChildGuard> {
    start_open_server_with_env_options(
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

pub async fn start_open_server_with_env(
    bind: &str,
    data_dir: &Path,
    node_id: &str,
    replication_factor: usize,
    extra_env: &[(&str, &str)],
) -> Result<ChildGuard> {
    start_open_server_with_env_options(
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

#[allow(dead_code)]
pub async fn start_open_server_with_public_https_env(
    bind: &str,
    data_dir: &Path,
    node_id: &str,
    replication_factor: usize,
    extra_env: &[(&str, &str)],
) -> Result<ChildGuard> {
    let mut merged_env = vec![("IRONMESH_REQUIRE_CLIENT_AUTH", "false")];
    merged_env.extend_from_slice(extra_env);
    start_server_with_env_options_inner(
        bind,
        data_dir,
        node_id,
        replication_factor,
        None,
        None,
        &merged_env,
        true,
    )
    .await
}

pub async fn start_open_server_with_env_options(
    bind: &str,
    data_dir: &Path,
    node_id: &str,
    replication_factor: usize,
    metadata_commit_mode: Option<&str>,
    heartbeat_timeout_secs: Option<u64>,
    extra_env: &[(&str, &str)],
) -> Result<ChildGuard> {
    let mut merged_env = vec![("IRONMESH_REQUIRE_CLIENT_AUTH", "false")];
    merged_env.extend_from_slice(extra_env);
    start_server_with_env_options_inner(
        bind,
        data_dir,
        node_id,
        replication_factor,
        metadata_commit_mode,
        heartbeat_timeout_secs,
        &merged_env,
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn start_server_with_env_options_inner(
    bind: &str,
    data_dir: &Path,
    node_id: &str,
    replication_factor: usize,
    metadata_commit_mode: Option<&str>,
    heartbeat_timeout_secs: Option<u64>,
    extra_env: &[(&str, &str)],
    public_https: bool,
) -> Result<ChildGuard> {
    let server_bin = binary_path("server-node")?;

    let node_id = if node_id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        node_id.to_string()
    };

    let public_scheme = if public_https { "https" } else { "http" };
    let public_url = format!("{public_scheme}://{bind}");
    let internal_bind = internal_bind_from_public_bind(bind)?;
    let internal_url = format!("https://{internal_bind}");
    let resource_guards =
        lock_test_resources([tcp_resource_key(bind), tcp_resource_key(&internal_bind)]).await;

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
        .env("IRONMESH_INTERNAL_TLS_CA_CERT", &ca_path)
        .env("IRONMESH_INTERNAL_TLS_CERT", &cert_path)
        .env("IRONMESH_INTERNAL_TLS_KEY", &key_path)
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

    if public_https {
        command
            .env("IRONMESH_PUBLIC_TLS_CERT", &cert_path)
            .env("IRONMESH_PUBLIC_TLS_KEY", &key_path)
            .env("IRONMESH_PUBLIC_TLS_CA_CERT", &ca_path);
    }

    let mut child = command.spawn().context("failed to spawn server-node")?;

    let startup_result = if public_https {
        wait_for_https_server(data_dir, bind, 40).await
    } else {
        wait_for_server(bind, 40).await
    };

    if let Err(err) = startup_result {
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
    Ok(ChildGuard::with_resources(child, resource_guards))
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
        "reachability": {
            "public_api_url": public_url,
            "peer_api_url": internal_url,
            "relay_required": false
        },
        "capabilities": {
            "public_api": true,
            "peer_api": true,
            "relay_tunnel": false
        },
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

pub async fn latest_snapshot_id_for_client(client: &IronMeshClient) -> Result<String> {
    let parsed = client.get_json_path("/snapshots").await?;
    latest_snapshot_id_from_value(parsed)
}

fn latest_snapshot_id_from_value(parsed: serde_json::Value) -> Result<String> {
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

#[allow(dead_code)]
pub async fn issue_pairing_token(
    http: &reqwest::Client,
    base_url: &str,
    admin_token: &str,
    label: Option<&str>,
    expires_in_secs: Option<u64>,
) -> Result<String> {
    let response: serde_json::Value = http
        .post(format!("{base_url}/auth/pairing-tokens/issue"))
        .header("x-ironmesh-admin-token", admin_token)
        .json(&serde_json::json!({
            "label": label,
            "expires_in_secs": expires_in_secs,
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    response
        .get("pairing_token")
        .and_then(|value| value.as_str())
        .map(ToString::to_string)
        .context("pairing token missing in response")
}

#[allow(dead_code)]
pub async fn issue_bootstrap_bundle(
    http: &reqwest::Client,
    base_url: &str,
    admin_token: &str,
    label: Option<&str>,
    expires_in_secs: Option<u64>,
) -> Result<client_sdk::ConnectionBootstrap> {
    http.post(format!("{base_url}/auth/bootstrap-bundles/issue"))
        .header("x-ironmesh-admin-token", admin_token)
        .json(&serde_json::json!({
            "label": label,
            "expires_in_secs": expires_in_secs,
        }))
        .send()
        .await?
        .error_for_status()?
        .json::<client_sdk::ConnectionBootstrap>()
        .await
        .context("failed to decode bootstrap bundle response")
}

pub fn default_client_identity_path(bootstrap_path: &Path) -> PathBuf {
    if let Some(stem) = bootstrap_path.file_stem() {
        let mut file_name = stem.to_os_string();
        file_name.push(".client-identity.json");
        return bootstrap_path.with_file_name(file_name);
    }
    bootstrap_path.with_file_name("ironmesh-client-identity.json")
}

pub async fn issue_bootstrap_bundle_and_enroll_client(
    http: &reqwest::Client,
    base_url: &str,
    admin_token: &str,
    client_dir: &Path,
    bootstrap_file_name: &str,
    label: Option<&str>,
    expires_in_secs: Option<u64>,
) -> Result<EnrolledTestClient> {
    let issued_bootstrap =
        issue_bootstrap_bundle(http, base_url, admin_token, label, expires_in_secs).await?;
    let bootstrap_path = client_dir.join(bootstrap_file_name);
    issued_bootstrap.write_to_path(&bootstrap_path)?;

    let bootstrap_json = issued_bootstrap.to_json_pretty()?;
    let label = label.map(ToString::to_string);
    let enrolled = tokio::task::spawn_blocking(move || {
        enroll_connection_input_blocking(&bootstrap_json, None, label.as_deref())
    })
    .await
    .context("bootstrap enrollment task panicked")??;

    let persisted_bootstrap_json = enrolled
        .connection_bootstrap_json
        .clone()
        .context("enrollment response did not include connection_bootstrap_json")?;
    let persisted_bootstrap = ConnectionBootstrap::from_json_str(&persisted_bootstrap_json)
        .context("failed to parse persisted bootstrap JSON from enrollment response")?;
    persisted_bootstrap.write_to_path(&bootstrap_path)?;

    let identity = enrolled
        .client_identity_material()
        .context("failed to build client identity material from enrollment response")?;
    let identity_path = default_client_identity_path(&bootstrap_path);
    identity.write_to_path(&identity_path)?;

    Ok(EnrolledTestClient {
        bootstrap: persisted_bootstrap,
        bootstrap_path,
        identity,
    })
}

#[allow(dead_code)]
pub async fn issue_bootstrap_claim(
    http: &reqwest::Client,
    base_url: &str,
    admin_token: &str,
    label: Option<&str>,
    expires_in_secs: Option<u64>,
    preferred_rendezvous_url: Option<&str>,
) -> Result<client_sdk::ClientBootstrapClaimIssueResponse> {
    http.post(format!("{base_url}/auth/bootstrap-claims/issue"))
        .header("x-ironmesh-admin-token", admin_token)
        .json(&serde_json::json!({
            "label": label,
            "expires_in_secs": expires_in_secs,
            "preferred_rendezvous_url": preferred_rendezvous_url,
        }))
        .send()
        .await?
        .error_for_status()?
        .json::<client_sdk::ClientBootstrapClaimIssueResponse>()
        .await
        .context("failed to decode bootstrap claim response")
}

pub async fn start_cli_web(bind: &str) -> Result<ChildGuard> {
    let cli_bin = binary_path("cli-client")?;
    let resource_guards = lock_test_resources([tcp_resource_key(bind)]).await;

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
    Ok(ChildGuard::with_resources(child, resource_guards))
}

pub async fn start_rendezvous_service(bind: &str) -> Result<ChildGuard> {
    start_rendezvous_service_with_env(bind, &[]).await
}

pub async fn start_rendezvous_service_with_env(
    bind: &str,
    extra_env: &[(&str, &str)],
) -> Result<ChildGuard> {
    let rendezvous_bin = binary_path("rendezvous-service")?;
    let resource_guards = lock_test_resources([tcp_resource_key(bind)]).await;
    let log_dir = fresh_data_dir("rendezvous-service");
    fs::create_dir_all(&log_dir).context("failed creating rendezvous log dir")?;

    let stdout_log = log_dir.join("rendezvous.stdout.log");
    let stderr_log = log_dir.join("rendezvous.stderr.log");
    let stdout_file =
        std::fs::File::create(&stdout_log).context("failed creating rendezvous stdout log")?;
    let stderr_file =
        std::fs::File::create(&stderr_log).context("failed creating rendezvous stderr log")?;

    let public_url = format!("http://{bind}");
    let mut command = Command::new(rendezvous_bin);
    command
        .env("IRONMESH_RENDEZVOUS_BIND", bind)
        .env("IRONMESH_RENDEZVOUS_PUBLIC_URL", &public_url)
        .env("IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP", "true")
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file));

    for (key, value) in extra_env {
        command.env(key, value);
    }

    let mut child = command
        .spawn()
        .context("failed to spawn rendezvous-service")?;

    if let Err(err) = wait_for_url_status(&format!("{public_url}/health"), StatusCode::OK, 40).await
    {
        if let Some(status) = child
            .try_wait()
            .context("failed to query rendezvous-service process state")?
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
                "rendezvous-service exited early on {bind} with status {status}: {err}\n--- stderr (tail) ---\n{stderr_tail}"
            );
        }
        bail!(
            "rendezvous-service did not become healthy on {bind}: {err} (logs at {} and {})",
            stdout_log.display(),
            stderr_log.display()
        );
    }

    if let Some(status) = child
        .try_wait()
        .context("failed to query rendezvous-service process state")?
    {
        bail!("rendezvous-service exited early on {bind} with status {status}");
    }

    Ok(ChildGuard::with_resources(child, resource_guards))
}

pub async fn wait_for_server(bind: &str, retries: usize) -> Result<()> {
    let health_url = format!("http://{bind}/health");
    wait_for_url_status(&health_url, StatusCode::OK, retries).await
}

pub async fn wait_for_https_server(data_dir: &Path, bind: &str, retries: usize) -> Result<()> {
    let health_url = format!("https://{bind}/health");
    let http = https_client_with_root_from_data_dir(data_dir)?;
    wait_for_url_status_with_client(&http, &health_url, StatusCode::OK, retries).await
}

pub async fn wait_for_url_status(url: &str, expected: StatusCode, retries: usize) -> Result<()> {
    let http = reqwest::Client::new();
    wait_for_url_status_with_client(&http, url, expected, retries).await
}

pub async fn wait_for_url_status_with_client(
    http: &reqwest::Client,
    url: &str,
    expected: StatusCode,
    retries: usize,
) -> Result<()> {
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
        if let Ok(resp) = http
            .get(format!("{base_url}/cluster/status"))
            .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
            .send()
            .await
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

pub async fn wait_for_rendezvous_registered_endpoints(
    base_url: &str,
    expected_registered_endpoints: u64,
    retries: usize,
) -> Result<()> {
    let http = reqwest::Client::new();

    for _ in 0..retries {
        if let Ok(resp) = http
            .get(format!("{base_url}/control/presence"))
            .send()
            .await
            && let Ok(ok_resp) = resp.error_for_status()
            && let Ok(payload) = ok_resp.json::<serde_json::Value>().await
        {
            let registered_endpoints = payload
                .get("registered_endpoints")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);

            if registered_endpoints == expected_registered_endpoints {
                return Ok(());
            }
        }

        sleep(Duration::from_millis(250)).await;
    }

    bail!(
        "rendezvous did not report registered_endpoints={} at {base_url}/control/presence",
        expected_registered_endpoints
    );
}

#[allow(dead_code)]
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

#[cfg_attr(not(windows), allow(dead_code))]
pub async fn stop_server_without_cleanup(child: &mut ChildGuard) {
    child.stop_without_cleanup().await.ok();
}

pub fn binary_path(name: &str) -> Result<PathBuf> {
    let override_key = match name {
        "server-node" => "IRONMESH_SERVER_BIN",
        "cli-client" => "IRONMESH_CLI_BIN",
        "os-integration" => "IRONMESH_OS_INTEGRATION_BIN",
        "ironmesh-folder-agent" => "IRONMESH_FOLDER_AGENT_BIN",
        "rendezvous-service" => "IRONMESH_RENDEZVOUS_BIN",
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
        "rendezvous-service" => {
            option_env!("CARGO_BIN_FILE_RENDEZVOUS_SERVICE_rendezvous-service")
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
            "expected binary does not exist: {} (artifact env missing; use nightly + artifact dependencies, or prebuild binaries, or set {}/{}/{}/{}/{} overrides)",
            path.display(),
            "IRONMESH_SERVER_BIN",
            "IRONMESH_CLI_BIN",
            "IRONMESH_OS_INTEGRATION_BIN",
            "IRONMESH_FOLDER_AGENT_BIN",
            "IRONMESH_RENDEZVOUS_BIN"
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
