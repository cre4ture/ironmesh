use anyhow::{Context, Result, bail};
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};
use serde::Serialize;
use server_node_sdk::EmbeddedManagedServerNodeConfig;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread;
use std::time::Duration;

const LOCAL_UI_HOST: &str = "127.0.0.1";
const STARTUP_POLL_ATTEMPTS: usize = 80;
const STARTUP_POLL_DELAY_MS: u64 = 250;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct AndroidServerNodeStatus {
    state: String,
    message: String,
    local_url: String,
    bind_addr: String,
    data_dir: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mode: Option<String>,
    healthy: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
}

impl Default for AndroidServerNodeStatus {
    fn default() -> Self {
        Self {
            state: "stopped".to_string(),
            message: "Server node is stopped".to_string(),
            local_url: String::new(),
            bind_addr: String::new(),
            data_dir: String::new(),
            mode: None,
            healthy: false,
            last_error: None,
        }
    }
}

struct RunningNode {
    bind_addr: SocketAddr,
    data_dir: PathBuf,
    local_url: String,
    shutdown_tx: Sender<()>,
    result_rx: Receiver<Result<()>>,
    thread: thread::JoinHandle<()>,
}

#[derive(Default)]
struct AndroidServerNodeManager {
    running: Option<RunningNode>,
    status: AndroidServerNodeStatus,
}

fn manager() -> &'static Mutex<AndroidServerNodeManager> {
    static MANAGER: OnceLock<Mutex<AndroidServerNodeManager>> = OnceLock::new();
    MANAGER.get_or_init(|| Mutex::new(AndroidServerNodeManager::default()))
}

fn local_ui_url(port: u16) -> String {
    format!("https://{LOCAL_UI_HOST}:{port}")
}

fn status_message_for_mode(mode: Option<&str>) -> String {
    match mode {
        Some("bootstrap_setup") => "Bootstrap setup UI is ready".to_string(),
        Some("runtime") => "Server node is running".to_string(),
        Some(other) => format!("Server node is running ({other})"),
        None => "Server node listener is responding".to_string(),
    }
}

fn throw_java_error(env: &mut JNIEnv, message: impl AsRef<str>) {
    let _ = env.throw_new("java/lang/RuntimeException", message.as_ref());
}

fn java_string_or_throw(env: &mut JNIEnv, value: String) -> jstring {
    match env.new_string(value) {
        Ok(value) => value.into_raw(),
        Err(err) => {
            throw_java_error(
                env,
                format!("failed to allocate java string for server-node status: {err:#}"),
            );
            null_mut()
        }
    }
}

fn bootstrap_ui_cert_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join("managed")
        .join("bootstrap-ui")
        .join("bootstrap-cert.pem")
}

fn runtime_public_ca_path(data_dir: &Path) -> PathBuf {
    data_dir
        .join("managed")
        .join("runtime")
        .join("public")
        .join("public-ca.pem")
}

fn load_certificate(path: &Path) -> Result<rustls::pki_types::CertificateDer<'static>> {
    use rustls::pki_types::pem::PemObject;

    let pem = std::fs::read(path).with_context(|| format!("failed reading {}", path.display()))?;
    rustls::pki_types::CertificateDer::from_pem_slice(&pem)
        .with_context(|| format!("failed parsing PEM from {}", path.display()))
}

#[derive(Debug)]
struct LocalNodeTlsVerifier {
    bootstrap_pinned_cert: Option<rustls::pki_types::CertificateDer<'static>>,
    runtime_verifier: Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>,
    supported_algs: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl rustls::client::danger::ServerCertVerifier for LocalNodeTlsVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if let Some(runtime_verifier) = &self.runtime_verifier
            && runtime_verifier
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .is_ok()
        {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        if let Some(bootstrap_pinned_cert) = &self.bootstrap_pinned_cert
            && end_entity.as_ref() == bootstrap_pinned_cert.as_ref()
        {
            return Ok(rustls::client::danger::ServerCertVerified::assertion());
        }

        Err(rustls::Error::General(
            "local server-node certificate did not match the expected bootstrap pin or runtime CA"
                .to_string(),
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

fn local_tls_verifier(
    data_dir: &Path,
    provider: Arc<rustls::crypto::CryptoProvider>,
) -> Result<LocalNodeTlsVerifier> {
    let bootstrap_cert_path = bootstrap_ui_cert_path(data_dir);
    let runtime_ca_path = runtime_public_ca_path(data_dir);
    let bootstrap_pinned_cert = bootstrap_cert_path
        .exists()
        .then(|| load_certificate(&bootstrap_cert_path))
        .transpose()?;
    let runtime_verifier = if runtime_ca_path.exists() {
        let runtime_ca = load_certificate(&runtime_ca_path)?;
        let mut roots = rustls::RootCertStore::empty();
        roots.add(runtime_ca).map_err(|err| {
            anyhow::anyhow!(
                "failed adding {} as a trust anchor: {err}",
                runtime_ca_path.display()
            )
        })?;
        Some(
            rustls::client::WebPkiServerVerifier::builder_with_provider(
                Arc::new(roots),
                provider.clone(),
            )
            .build()
            .with_context(|| {
                format!(
                    "failed building runtime TLS verifier from {}",
                    runtime_ca_path.display()
                )
            })? as Arc<dyn rustls::client::danger::ServerCertVerifier>,
        )
    } else {
        None
    };

    if bootstrap_pinned_cert.is_none() && runtime_verifier.is_none() {
        bail!(
            "no local TLS trust material found at {} or {}",
            bootstrap_cert_path.display(),
            runtime_ca_path.display()
        );
    }

    Ok(LocalNodeTlsVerifier {
        bootstrap_pinned_cert,
        runtime_verifier,
        supported_algs: provider.signature_verification_algorithms,
    })
}

fn local_health_check_client(data_dir: &Path) -> Result<reqwest::blocking::Client> {
    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
    let tls = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .context("failed to load default TLS protocol versions for Android server-node")?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(local_tls_verifier(data_dir, provider)?))
        .with_no_client_auth();

    reqwest::blocking::Client::builder()
        .timeout(Duration::from_millis(400))
        .use_preconfigured_tls(tls)
        .build()
        .context("failed to build Android server-node health-check client")
}

fn probe_health(local_url: &str, data_dir: &Path) -> Result<Option<String>> {
    let health_url = format!("{}/health", local_url.trim_end_matches('/'));
    let client = local_health_check_client(data_dir)?;
    let response = client
        .get(&health_url)
        .send()
        .with_context(|| format!("failed requesting {health_url}"))?;
    if !response.status().is_success() {
        bail!("health check returned HTTP {}", response.status());
    }
    let body = response
        .text()
        .with_context(|| format!("failed reading {health_url} response body"))?;
    let mode = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|value| {
            value
                .get("mode")
                .and_then(|mode| mode.as_str())
                .map(ToString::to_string)
        })
        .or_else(|| Some("runtime".to_string()));
    Ok(mode)
}

fn wait_for_server_ready(
    local_url: &str,
    data_dir: &Path,
    result_rx: &Receiver<Result<()>>,
) -> Result<Option<String>> {
    for _ in 0..STARTUP_POLL_ATTEMPTS {
        match result_rx.try_recv() {
            Ok(Ok(())) => bail!("server node exited before becoming healthy"),
            Ok(Err(err)) => return Err(err).context("server node failed during startup"),
            Err(TryRecvError::Disconnected) => bail!("server node startup channel disconnected"),
            Err(TryRecvError::Empty) => {}
        }

        if let Ok(mode) = probe_health(local_url, data_dir) {
            return Ok(mode);
        }

        thread::sleep(Duration::from_millis(STARTUP_POLL_DELAY_MS));
    }

    bail!("timed out waiting for local server-node listener at {local_url}")
}

fn start_embedded_server(
    data_dir: PathBuf,
    bind_addr: SocketAddr,
) -> Result<(RunningNode, Option<String>)> {
    let local_url = local_ui_url(bind_addr.port());
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>();
    let (result_tx, result_rx) = mpsc::channel::<Result<()>>();

    let thread_data_dir = data_dir.clone();
    let thread = thread::Builder::new()
        .name("ironmesh-android-server-node".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(err) => {
                    let _ = result_tx
                        .send(Err(err).context("failed to build Android server-node runtime"));
                    return;
                }
            };

            let config = EmbeddedManagedServerNodeConfig::new(thread_data_dir, bind_addr);
            runtime.block_on(async move {
                let mut task =
                    tokio::spawn(
                        async move { server_node_sdk::run_embedded_managed(config).await },
                    );

                tokio::select! {
                    outcome = &mut task => {
                        let outcome = match outcome {
                            Ok(result) => result,
                            Err(err) => Err(err).context("Android server-node task failed"),
                        };
                        let _ = result_tx.send(outcome);
                    }
                    _ = async {
                        let _ = shutdown_rx.recv();
                    } => {
                        task.abort();
                        let _ = task.await;
                        let _ = result_tx.send(Ok(()));
                    }
                }
            });
        })
        .context("failed to spawn Android server-node thread")?;

    match wait_for_server_ready(local_url.as_str(), &data_dir, &result_rx) {
        Ok(mode) => Ok((
            RunningNode {
                bind_addr,
                data_dir,
                local_url,
                shutdown_tx,
                result_rx,
                thread,
            },
            mode,
        )),
        Err(err) => {
            let _ = shutdown_tx.send(());
            let _ = thread.join();
            Err(err)
        }
    }
}

fn stopped_status(
    local_url: String,
    bind_addr: String,
    data_dir: String,
) -> AndroidServerNodeStatus {
    AndroidServerNodeStatus {
        state: "stopped".to_string(),
        message: "Server node is stopped".to_string(),
        local_url,
        bind_addr,
        data_dir,
        mode: None,
        healthy: false,
        last_error: None,
    }
}

fn error_status(
    local_url: String,
    bind_addr: String,
    data_dir: String,
    message: String,
) -> AndroidServerNodeStatus {
    AndroidServerNodeStatus {
        state: "error".to_string(),
        message: message.clone(),
        local_url,
        bind_addr,
        data_dir,
        mode: None,
        healthy: false,
        last_error: Some(message),
    }
}

fn snapshot_status() -> AndroidServerNodeStatus {
    let (probe, finished_thread, cached_status) = {
        let mut manager = match manager().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let mut finished_thread = None;
        let mut probe = None;

        if let Some(running) = manager.running.as_mut() {
            match running.result_rx.try_recv() {
                Ok(Ok(())) => {
                    if let Some(finished) = manager.running.take() {
                        manager.status = stopped_status(
                            finished.local_url.clone(),
                            finished.bind_addr.to_string(),
                            finished.data_dir.display().to_string(),
                        );
                        finished_thread = Some(finished.thread);
                    }
                }
                Ok(Err(err)) => {
                    if let Some(failed) = manager.running.take() {
                        manager.status = error_status(
                            failed.local_url.clone(),
                            failed.bind_addr.to_string(),
                            failed.data_dir.display().to_string(),
                            format!("Server node exited: {err:#}"),
                        );
                        finished_thread = Some(failed.thread);
                    }
                }
                Err(TryRecvError::Disconnected) => {
                    if let Some(failed) = manager.running.take() {
                        manager.status = error_status(
                            failed.local_url.clone(),
                            failed.bind_addr.to_string(),
                            failed.data_dir.display().to_string(),
                            "Server node worker disconnected unexpectedly".to_string(),
                        );
                        finished_thread = Some(failed.thread);
                    }
                }
                Err(TryRecvError::Empty) => {
                    probe = Some((
                        running.local_url.clone(),
                        running.bind_addr.to_string(),
                        running.data_dir.display().to_string(),
                    ));
                }
            }
        }

        (probe, finished_thread, manager.status.clone())
    };

    if let Some(thread) = finished_thread {
        let _ = thread.join();
    }

    let Some((local_url, bind_addr, data_dir)) = probe else {
        return cached_status;
    };

    let mut next_status = cached_status;
    next_status.local_url = local_url.clone();
    next_status.bind_addr = bind_addr.clone();
    next_status.data_dir = data_dir.clone();

    match probe_health(local_url.as_str(), Path::new(&data_dir)) {
        Ok(mode) => {
            next_status.state = "running".to_string();
            next_status.healthy = true;
            next_status.mode = mode.clone();
            next_status.last_error = None;
            next_status.message = status_message_for_mode(mode.as_deref());
        }
        Err(err) => {
            next_status.healthy = false;
            next_status.mode = None;
            if next_status.state == "starting" {
                next_status.message = "Starting local server node".to_string();
            } else if next_status.state != "error" {
                next_status.message = format!("Waiting for local listener: {err:#}");
            }
        }
    }

    let mut manager = match manager().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    manager.status = next_status.clone();
    next_status
}

fn start_node(data_dir: String, bind_host: String, bind_port: jint) -> Result<()> {
    let bind_port = u16::try_from(bind_port).context("bindPort must be in the u16 range")?;
    let bind_addr: SocketAddr = format!("{bind_host}:{bind_port}")
        .parse()
        .with_context(|| format!("invalid server-node bind address {bind_host}:{bind_port}"))?;
    let data_dir = PathBuf::from(data_dir);
    std::fs::create_dir_all(&data_dir)
        .with_context(|| format!("failed to create {}", data_dir.display()))?;

    {
        let mut manager = match manager().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if manager.running.is_some() {
            return Ok(());
        }
        manager.status = AndroidServerNodeStatus {
            state: "starting".to_string(),
            message: "Starting local server node".to_string(),
            local_url: local_ui_url(bind_port),
            bind_addr: bind_addr.to_string(),
            data_dir: data_dir.display().to_string(),
            mode: None,
            healthy: false,
            last_error: None,
        };
    }

    match start_embedded_server(data_dir.clone(), bind_addr) {
        Ok((running, mode)) => {
            let mut manager = match manager().lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            manager.status = AndroidServerNodeStatus {
                state: "running".to_string(),
                message: status_message_for_mode(mode.as_deref()),
                local_url: running.local_url.clone(),
                bind_addr: running.bind_addr.to_string(),
                data_dir: running.data_dir.display().to_string(),
                mode,
                healthy: true,
                last_error: None,
            };
            manager.running = Some(running);
            Ok(())
        }
        Err(err) => {
            let mut manager = match manager().lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            manager.status = AndroidServerNodeStatus {
                state: "error".to_string(),
                message: format!("Failed to start server node: {err:#}"),
                local_url: local_ui_url(bind_port),
                bind_addr: bind_addr.to_string(),
                data_dir: data_dir.display().to_string(),
                mode: None,
                healthy: false,
                last_error: Some(format!("{err:#}")),
            };
            Err(err)
        }
    }
}

fn stop_node() {
    let running = {
        let mut manager = match manager().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let running = manager.running.take();
        if let Some(running) = running.as_ref() {
            manager.status = stopped_status(
                running.local_url.clone(),
                running.bind_addr.to_string(),
                running.data_dir.display().to_string(),
            );
        } else {
            manager.status = AndroidServerNodeStatus::default();
        }
        running
    };

    if let Some(running) = running {
        let _ = running.shutdown_tx.send(());
        let _ = running.thread.join();
    }
}

/// # Safety
/// This function is intended to be called from Kotlin via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_servernode_android_RustServerNodeBridge_startNode(
    mut env: JNIEnv,
    _class: JClass,
    data_dir_path: JString,
    bind_host: JString,
    bind_port: jint,
) {
    let result = (|| -> Result<()> {
        let data_dir: String = env.get_string(&data_dir_path)?.into();
        let bind_host: String = env.get_string(&bind_host)?.into();
        start_node(data_dir, bind_host, bind_port)
    })();

    if let Err(err) = result {
        throw_java_error(&mut env, format!("rust startNode failed: {err:#}"));
    }
}

/// # Safety
/// This function is intended to be called from Kotlin via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_servernode_android_RustServerNodeBridge_stopNode(
    _env: JNIEnv,
    _class: JClass,
) {
    stop_node();
}

/// # Safety
/// This function is intended to be called from Kotlin via JNI.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "system" fn Java_io_ironmesh_servernode_android_RustServerNodeBridge_statusJson(
    mut env: JNIEnv,
    _class: JClass,
) -> jstring {
    match serde_json::to_string(&snapshot_status()) {
        Ok(json) => java_string_or_throw(&mut env, json),
        Err(err) => {
            throw_java_error(
                &mut env,
                format!("failed to serialize Android server-node status: {err:#}"),
            );
            null_mut()
        }
    }
}
