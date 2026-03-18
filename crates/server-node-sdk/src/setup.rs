use super::*;
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use axum::http::header::{CONTENT_TYPE, HeaderValue};
use axum::response::Html;
use axum_server::Handle;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use rcgen::BasicConstraints;
use sha2::Sha256;
use tokio::sync::mpsc;

const SETUP_STATE_VERSION: u32 = 1;
const MANAGED_SIGNER_BACKUP_VERSION: u32 = 1;
const MANAGED_SIGNER_BACKUP_SALT_LEN: usize = 16;
const MANAGED_SIGNER_BACKUP_NONCE_LEN: usize = 12;
const MANAGED_SIGNER_BACKUP_KEY_LEN: usize = 32;
const MANAGED_SIGNER_BACKUP_PBKDF2_ROUNDS: u32 = 600_000;
const SETUP_STATUS_HTML: &str = include_str!("ui/setup_index.html");
const SETUP_APP_JS: &str = include_str!("ui/setup_app.js");

#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub(crate) enum StartupMode {
    Runtime(ServerNodeConfig),
    Setup(SetupBootstrapConfig),
}

#[derive(Debug, Clone)]
pub(crate) struct SetupBootstrapConfig {
    data_dir: PathBuf,
    bind_addr: SocketAddr,
    state_path: PathBuf,
    bootstrap_cert_path: PathBuf,
    bootstrap_key_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum SetupLifecycleState {
    Uninitialized,
    PendingJoin,
    Online,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManagedSetupState {
    version: u32,
    state: SetupLifecycleState,
    updated_at_unix: u64,
    cluster_id: Option<ClusterId>,
    node_id: Option<NodeId>,
    runtime_node_enrollment_path: Option<String>,
    admin_password_hash: Option<String>,
    managed_rendezvous_bind_addr: Option<String>,
    managed_rendezvous_public_url: Option<String>,
    pending_join_request: Option<NodeJoinRequest>,
}

impl Default for ManagedSetupState {
    fn default() -> Self {
        Self {
            version: SETUP_STATE_VERSION,
            state: SetupLifecycleState::Uninitialized,
            updated_at_unix: unix_ts(),
            cluster_id: None,
            node_id: None,
            runtime_node_enrollment_path: None,
            admin_password_hash: None,
            managed_rendezvous_bind_addr: None,
            managed_rendezvous_public_url: None,
            pending_join_request: None,
        }
    }
}

#[derive(Clone)]
struct SetupServerState {
    config: SetupBootstrapConfig,
    managed_state: Arc<Mutex<ManagedSetupState>>,
    completion_tx: mpsc::Sender<SetupCompletion>,
}

#[derive(Debug)]
struct SetupCompletion {
    config: ServerNodeConfig,
}

struct SelfManagedClusterArtifacts {
    package: NodeEnrollmentPackage,
    ca_cert_pem: String,
    ca_key_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ManagedSignerBackup {
    pub version: u32,
    pub cluster_id: ClusterId,
    pub source_node_id: NodeId,
    pub exported_at_unix: u64,
    pub pbkdf2_rounds: u32,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ManagedSignerBackupPlaintext {
    cluster_id: ClusterId,
    source_node_id: NodeId,
    exported_at_unix: u64,
    ca_cert_pem: String,
    ca_key_pem: String,
}

#[derive(Debug, Serialize)]
struct SetupStatusResponse {
    state: SetupLifecycleState,
    data_dir: String,
    bind_addr: String,
    bootstrap_tls_cert_path: String,
    bootstrap_tls_fingerprint: Option<String>,
    cluster_id: Option<ClusterId>,
    node_id: Option<NodeId>,
    pending_join_request: Option<NodeJoinRequest>,
}

#[derive(Debug, Deserialize)]
struct SetupStartClusterRequest {
    admin_password: String,
    public_origin: String,
}

#[derive(Debug, Deserialize)]
struct SetupGenerateJoinRequest {
    public_origin: String,
}

#[derive(Debug, Deserialize)]
struct SetupImportEnrollmentRequest {
    admin_password: String,
    package_json: String,
}

#[derive(Debug, Serialize)]
struct SetupTransitionResponse {
    status: &'static str,
    cluster_id: ClusterId,
    node_id: NodeId,
    public_url: Option<String>,
    restart_required: bool,
}

pub(crate) fn load_startup_mode_from_env() -> Result<StartupMode> {
    if explicit_runtime_env_present() {
        return Ok(StartupMode::Runtime(ServerNodeConfig::from_env()?));
    }

    let config = default_setup_bootstrap_config()?;
    if let Some(managed_state) = read_managed_setup_state(&config.state_path)?
        && managed_state.state == SetupLifecycleState::Online
        && let Some(enrollment_path) = managed_state.runtime_node_enrollment_path.as_deref()
    {
        let resolved_path = resolve_materialized_path(&config.data_dir, enrollment_path);
        if resolved_path.exists() {
            let mut runtime = ServerNodeConfig::from_enrollment_path(&resolved_path)?;
            apply_managed_signer_paths(&config.data_dir, &mut runtime);
            apply_managed_rendezvous_config(&config.data_dir, &managed_state, &mut runtime);
            runtime.admin_password_hash = managed_state.admin_password_hash.clone();
            return Ok(StartupMode::Runtime(runtime));
        }
    }

    Ok(StartupMode::Setup(config))
}

pub(crate) async fn run_setup_mode(
    config: SetupBootstrapConfig,
    log_buffer: Arc<LogBuffer>,
) -> Result<()> {
    let initial_state =
        ensure_managed_setup_state(&config.state_path).context("failed preparing setup state")?;
    let tls_config = ensure_bootstrap_tls_config(&config).await?;
    let (completion_tx, mut completion_rx) = mpsc::channel::<SetupCompletion>(1);
    let app_state = SetupServerState {
        config: config.clone(),
        managed_state: Arc::new(Mutex::new(initial_state)),
        completion_tx,
    };

    let app = Router::new()
        .route("/", get(setup_index))
        .route("/health", get(setup_health))
        .route("/ui/app.css", get(ui::app_css))
        .route("/ui/app.js", get(setup_app_js))
        .route("/setup/status", get(get_setup_status))
        .route("/setup/start-cluster", post(start_new_cluster))
        .route("/setup/join/request", post(generate_join_request))
        .route("/setup/join/import", post(import_node_enrollment_package))
        .with_state(app_state);

    let handle = Handle::new();
    let server = axum_server::bind_rustls(config.bind_addr, tls_config)
        .handle(handle.clone())
        .serve(app.into_make_service());
    let server_task = tokio::spawn(server);

    info!(
        bind_addr = %config.bind_addr,
        data_dir = %config.data_dir.display(),
        "server node bootstrap setup listener"
    );

    let completion = completion_rx.recv().await;
    if completion.is_none() {
        let outcome = server_task
            .await
            .context("bootstrap setup server task join failure")?;
        return outcome.context("bootstrap setup server exited");
    }

    handle.graceful_shutdown(Some(Duration::from_secs(0)));
    let outcome = server_task
        .await
        .context("bootstrap setup server task join failure")?;
    outcome.context("bootstrap setup server exited during transition")?;

    let completion = completion.expect("checked is_some above");
    run_inner(completion.config, Some(log_buffer)).await
}

async fn setup_index() -> Html<&'static str> {
    Html(SETUP_STATUS_HTML)
}

async fn setup_health(State(state): State<SetupServerState>) -> impl IntoResponse {
    let managed = state.managed_state.lock().await;
    (
        StatusCode::OK,
        Json(json!({
            "mode": "bootstrap_setup",
            "state": managed.state,
            "data_dir": state.config.data_dir.display().to_string(),
        })),
    )
}

async fn setup_app_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("application/javascript; charset=utf-8"),
        )],
        SETUP_APP_JS,
    )
}

async fn get_setup_status(State(state): State<SetupServerState>) -> impl IntoResponse {
    let managed = state.managed_state.lock().await.clone();
    let fingerprint = parse_certificate_details_from_path(&state.config.bootstrap_cert_path)
        .ok()
        .map(|parsed| parsed.certificate_fingerprint);
    (
        StatusCode::OK,
        Json(SetupStatusResponse {
            state: managed.state,
            data_dir: state.config.data_dir.display().to_string(),
            bind_addr: state.config.bind_addr.to_string(),
            bootstrap_tls_cert_path: state.config.bootstrap_cert_path.display().to_string(),
            bootstrap_tls_fingerprint: fingerprint,
            cluster_id: managed.cluster_id,
            node_id: managed.node_id,
            pending_join_request: managed.pending_join_request,
        }),
    )
}

async fn start_new_cluster(
    State(state): State<SetupServerState>,
    Json(request): Json<SetupStartClusterRequest>,
) -> impl IntoResponse {
    if let Err(message) = validate_admin_password(&request.admin_password) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response();
    }

    {
        let managed = state.managed_state.lock().await;
        if managed.state == SetupLifecycleState::Online {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "node is already initialized" })),
            )
                .into_response();
        }
    }

    let public_origin = match normalize_https_origin(&request.public_origin) {
        Ok(origin) => origin,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    let runtime_enrollment_path = runtime_node_enrollment_path(&state.config.data_dir);
    let cluster_id = Uuid::now_v7();
    let node_id = NodeId::new_v4();
    let labels = default_setup_labels();
    let bind_addr = state.config.bind_addr;
    let internal_bind_addr = default_internal_bind_addr(bind_addr);
    let managed_rendezvous_bind_addr = default_managed_rendezvous_bind_addr(bind_addr);
    let public_url = origin_to_string(&public_origin);
    let internal_url = match derive_internal_url(&public_origin, internal_bind_addr.port()) {
        Ok(url) => url,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };
    let managed_rendezvous_public_url =
        match derive_managed_rendezvous_url(&public_origin, managed_rendezvous_bind_addr.port()) {
            Ok(url) => url,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": err.to_string() })),
                )
                    .into_response();
            }
        };

    let bootstrap = TransportNodeBootstrap {
        version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
        cluster_id,
        node_id,
        mode: NodeBootstrapMode::Cluster,
        data_dir: state.config.data_dir.display().to_string(),
        bind_addr: bind_addr.to_string(),
        public_url: Some(public_url.clone()),
        labels: labels.clone(),
        public_tls: Some(BootstrapServerTlsFiles {
            cert_path: "managed/runtime/public/public.pem".to_string(),
            key_path: "managed/runtime/public/public.key".to_string(),
        }),
        public_ca_cert_path: Some("managed/runtime/public/public-ca.pem".to_string()),
        public_peer_api_enabled: false,
        internal_bind_addr: Some(internal_bind_addr.to_string()),
        internal_url: Some(internal_url.clone()),
        internal_tls: Some(BootstrapTlsFiles {
            ca_cert_path: "managed/runtime/internal/cluster-ca.pem".to_string(),
            cert_path: "managed/runtime/internal/node.pem".to_string(),
            key_path: "managed/runtime/internal/node.key".to_string(),
        }),
        rendezvous_urls: vec![managed_rendezvous_public_url.clone()],
        rendezvous_mtls_required: true,
        direct_endpoints: vec![
            BootstrapEndpoint {
                url: public_url.clone(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: Some(node_id),
            },
            BootstrapEndpoint {
                url: internal_url.clone(),
                usage: Some(BootstrapEndpointUse::PeerApi),
                node_id: Some(node_id),
            },
        ],
        relay_mode: RelayMode::Fallback,
        trust_roots: BootstrapTrustRoots {
            cluster_ca_pem: None,
            public_api_ca_pem: None,
            rendezvous_ca_pem: None,
        },
        enrollment_issuer_url: Some(public_url.clone()),
    };

    let artifacts = match issue_self_managed_cluster_artifacts(bootstrap) {
        Ok(artifacts) => artifacts,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    if let Err(err) = artifacts.package.write_to_path(&runtime_enrollment_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }
    if let Err(err) = write_managed_signer_material(
        &state.config.data_dir,
        &artifacts.ca_cert_pem,
        &artifacts.ca_key_pem,
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }
    let (managed_rendezvous_cert_pem, managed_rendezvous_key_pem) =
        match issue_managed_rendezvous_tls_identity_from_ca(
            cluster_id,
            &managed_rendezvous_public_url,
            &artifacts.ca_cert_pem,
            &artifacts.ca_key_pem,
        ) {
            Ok(material) => material,
            Err(err) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({ "error": err.to_string() })),
                )
                    .into_response();
            }
        };
    if let Err(err) = write_managed_rendezvous_material(
        &state.config.data_dir,
        &managed_rendezvous_cert_pem,
        &managed_rendezvous_key_pem,
    ) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }

    let mut managed = state.managed_state.lock().await;
    managed.state = SetupLifecycleState::Online;
    managed.updated_at_unix = unix_ts();
    managed.cluster_id = Some(cluster_id);
    managed.node_id = Some(node_id);
    managed.runtime_node_enrollment_path = Some(runtime_enrollment_path.display().to_string());
    managed.admin_password_hash = Some(hash_token(&request.admin_password));
    managed.managed_rendezvous_bind_addr = Some(managed_rendezvous_bind_addr.to_string());
    managed.managed_rendezvous_public_url = Some(managed_rendezvous_public_url.clone());
    managed.pending_join_request = None;
    if let Err(err) = write_managed_setup_state(&state.config.state_path, &managed) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }
    let managed_snapshot = managed.clone();
    drop(managed);

    let mut config = match ServerNodeConfig::from_enrollment_path(&runtime_enrollment_path) {
        Ok(config) => config,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };
    apply_managed_signer_paths(&state.config.data_dir, &mut config);
    apply_managed_rendezvous_config(&state.config.data_dir, &managed_snapshot, &mut config);
    config.admin_password_hash = Some(hash_token(&request.admin_password));
    if state
        .completion_tx
        .send(SetupCompletion { config })
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "failed scheduling runtime transition" })),
        )
            .into_response();
    }

    (
        StatusCode::CREATED,
        Json(SetupTransitionResponse {
            status: "transitioning_to_online",
            cluster_id,
            node_id,
            public_url: Some(public_url),
            restart_required: false,
        }),
    )
        .into_response()
}

async fn generate_join_request(
    State(state): State<SetupServerState>,
    Json(request): Json<SetupGenerateJoinRequest>,
) -> impl IntoResponse {
    let public_origin = match normalize_https_origin(&request.public_origin) {
        Ok(origin) => origin,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };

    let mut managed = state.managed_state.lock().await;
    if managed.state == SetupLifecycleState::Online {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "node is already initialized" })),
        )
            .into_response();
    }
    let node_id = managed.node_id.unwrap_or_else(NodeId::new_v4);
    let internal_bind_addr = default_internal_bind_addr(state.config.bind_addr);
    let join_request = NodeJoinRequest {
        version: SETUP_STATE_VERSION,
        node_id,
        mode: NodeBootstrapMode::Cluster,
        data_dir: state.config.data_dir.display().to_string(),
        bind_addr: state.config.bind_addr.to_string(),
        public_url: Some(origin_to_string(&public_origin)),
        labels: default_setup_labels(),
        public_tls: Some(BootstrapServerTlsFiles {
            cert_path: "managed/runtime/public/public.pem".to_string(),
            key_path: "managed/runtime/public/public.key".to_string(),
        }),
        public_ca_cert_path: Some("managed/runtime/public/public-ca.pem".to_string()),
        public_peer_api_enabled: false,
        internal_bind_addr: Some(internal_bind_addr.to_string()),
        internal_url: Some(
            match derive_internal_url(&public_origin, internal_bind_addr.port()) {
                Ok(url) => url,
                Err(err) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(json!({ "error": err.to_string() })),
                    )
                        .into_response();
                }
            },
        ),
        internal_tls: Some(BootstrapTlsFiles {
            ca_cert_path: "managed/runtime/internal/cluster-ca.pem".to_string(),
            cert_path: "managed/runtime/internal/node.pem".to_string(),
            key_path: "managed/runtime/internal/node.key".to_string(),
        }),
    };
    managed.state = SetupLifecycleState::PendingJoin;
    managed.updated_at_unix = unix_ts();
    managed.node_id = Some(node_id);
    managed.pending_join_request = Some(join_request.clone());
    if let Err(err) = write_managed_setup_state(&state.config.state_path, &managed) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }

    (StatusCode::OK, Json(join_request)).into_response()
}

async fn import_node_enrollment_package(
    State(state): State<SetupServerState>,
    Json(request): Json<SetupImportEnrollmentRequest>,
) -> impl IntoResponse {
    if let Err(message) = validate_admin_password(&request.admin_password) {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": message }))).into_response();
    }

    let mut package = match NodeEnrollmentPackage::from_json_str(&request.package_json) {
        Ok(package) => package,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };
    package.bootstrap.data_dir = state.config.data_dir.display().to_string();

    let mut managed = state.managed_state.lock().await;
    if let Some(join_request) = managed.pending_join_request.as_ref()
        && package.bootstrap.node_id != join_request.node_id
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({ "error": "imported node enrollment does not match the pending join request" })),
        )
            .into_response();
    }

    let runtime_enrollment_path = runtime_node_enrollment_path(&state.config.data_dir);
    if let Err(err) = package.write_to_path(&runtime_enrollment_path) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }

    managed.state = SetupLifecycleState::Online;
    managed.updated_at_unix = unix_ts();
    managed.cluster_id = Some(package.bootstrap.cluster_id);
    managed.node_id = Some(package.bootstrap.node_id);
    managed.runtime_node_enrollment_path = Some(runtime_enrollment_path.display().to_string());
    managed.admin_password_hash = Some(hash_token(&request.admin_password));
    managed.managed_rendezvous_bind_addr = None;
    managed.managed_rendezvous_public_url = None;
    managed.pending_join_request = None;
    if let Err(err) = write_managed_setup_state(&state.config.state_path, &managed) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": err.to_string() })),
        )
            .into_response();
    }
    let managed_snapshot = managed.clone();
    drop(managed);

    let mut config = match ServerNodeConfig::from_enrollment_path(&runtime_enrollment_path) {
        Ok(config) => config,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": err.to_string() })),
            )
                .into_response();
        }
    };
    apply_managed_signer_paths(&state.config.data_dir, &mut config);
    apply_managed_rendezvous_config(&state.config.data_dir, &managed_snapshot, &mut config);
    config.admin_password_hash = Some(hash_token(&request.admin_password));
    if state
        .completion_tx
        .send(SetupCompletion { config })
        .await
        .is_err()
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({ "error": "failed scheduling runtime transition" })),
        )
            .into_response();
    }

    (
        StatusCode::CREATED,
        Json(SetupTransitionResponse {
            status: "transitioning_to_online",
            cluster_id: package.bootstrap.cluster_id,
            node_id: package.bootstrap.node_id,
            public_url: package.bootstrap.public_url.clone(),
            restart_required: false,
        }),
    )
        .into_response()
}

fn explicit_runtime_env_present() -> bool {
    [
        "IRONMESH_NODE_ENROLLMENT_FILE",
        "IRONMESH_NODE_BOOTSTRAP_FILE",
        "IRONMESH_NODE_MODE",
        "IRONMESH_NODE_ID",
        "IRONMESH_CLUSTER_ID",
        "IRONMESH_PUBLIC_URL",
        "IRONMESH_PUBLIC_TLS_CERT",
        "IRONMESH_PUBLIC_TLS_KEY",
        "IRONMESH_PUBLIC_TLS_CA_CERT",
        "IRONMESH_PUBLIC_TLS_CA_KEY",
        "IRONMESH_INTERNAL_BIND",
        "IRONMESH_INTERNAL_URL",
        "IRONMESH_INTERNAL_TLS_CA_CERT",
        "IRONMESH_INTERNAL_TLS_CERT",
        "IRONMESH_INTERNAL_TLS_KEY",
        "IRONMESH_INTERNAL_TLS_CA_KEY",
        "IRONMESH_RENDEZVOUS_URLS",
        "IRONMESH_RENDEZVOUS_CA_CERT",
        "IRONMESH_RENDEZVOUS_MTLS_REQUIRED",
        "IRONMESH_RELAY_MODE",
        "IRONMESH_ADMIN_TOKEN",
        "IRONMESH_REQUIRE_CLIENT_AUTH",
    ]
    .iter()
    .any(|key| {
        std::env::var(key)
            .ok()
            .is_some_and(|value| !value.trim().is_empty())
    })
}

fn default_setup_bootstrap_config() -> Result<SetupBootstrapConfig> {
    let data_dir = PathBuf::from(
        std::env::var("IRONMESH_DATA_DIR").unwrap_or_else(|_| "./data/server-node".to_string()),
    );
    let bind_addr: SocketAddr = std::env::var("IRONMESH_SERVER_BIND")
        .unwrap_or_else(|_| "0.0.0.0:8443".to_string())
        .parse()
        .context("invalid IRONMESH_SERVER_BIND for bootstrap setup mode")?;
    Ok(SetupBootstrapConfig {
        state_path: managed_setup_state_path(&data_dir),
        bootstrap_cert_path: bootstrap_setup_cert_path(&data_dir),
        bootstrap_key_path: bootstrap_setup_key_path(&data_dir),
        data_dir,
        bind_addr,
    })
}

fn managed_setup_dir(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("managed")
}

fn managed_setup_state_path(data_dir: &std::path::Path) -> PathBuf {
    managed_setup_dir(data_dir).join("setup-state.json")
}

fn bootstrap_setup_cert_path(data_dir: &std::path::Path) -> PathBuf {
    managed_setup_dir(data_dir)
        .join("bootstrap-ui")
        .join("bootstrap-cert.pem")
}

fn bootstrap_setup_key_path(data_dir: &std::path::Path) -> PathBuf {
    managed_setup_dir(data_dir)
        .join("bootstrap-ui")
        .join("bootstrap-key.pem")
}

fn runtime_node_enrollment_path(data_dir: &std::path::Path) -> PathBuf {
    managed_setup_dir(data_dir)
        .join("runtime")
        .join("node-enrollment.json")
}

pub(crate) fn managed_signer_dir(data_dir: &std::path::Path) -> PathBuf {
    managed_setup_dir(data_dir).join("signer")
}

pub(crate) fn managed_signer_ca_cert_path(data_dir: &std::path::Path) -> PathBuf {
    managed_signer_dir(data_dir).join("cluster-ca.pem")
}

pub(crate) fn managed_signer_ca_key_path(data_dir: &std::path::Path) -> PathBuf {
    managed_signer_dir(data_dir).join("cluster-ca.key")
}

fn managed_runtime_internal_ca_cert_path(data_dir: &std::path::Path) -> PathBuf {
    managed_setup_dir(data_dir)
        .join("runtime")
        .join("internal")
        .join("cluster-ca.pem")
}

fn managed_rendezvous_dir(data_dir: &std::path::Path) -> PathBuf {
    managed_setup_dir(data_dir).join("rendezvous")
}

fn managed_rendezvous_cert_path(data_dir: &std::path::Path) -> PathBuf {
    managed_rendezvous_dir(data_dir).join("rendezvous.pem")
}

fn managed_rendezvous_key_path(data_dir: &std::path::Path) -> PathBuf {
    managed_rendezvous_dir(data_dir).join("rendezvous.key")
}

fn ensure_managed_setup_state(path: &std::path::Path) -> Result<ManagedSetupState> {
    if let Some(existing) = read_managed_setup_state(path)? {
        return Ok(existing);
    }
    let state = ManagedSetupState::default();
    write_managed_setup_state(path, &state)?;
    Ok(state)
}

fn read_managed_setup_state(path: &std::path::Path) -> Result<Option<ManagedSetupState>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading {}", path.display()))?;
    let state = serde_json::from_str::<ManagedSetupState>(&raw)
        .with_context(|| format!("failed parsing {}", path.display()))?;
    if state.version != SETUP_STATE_VERSION {
        bail!("unsupported managed setup state version {}", state.version);
    }
    Ok(Some(state))
}

fn write_managed_setup_state(path: &std::path::Path, state: &ManagedSetupState) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    let payload =
        serde_json::to_string_pretty(state).context("failed serializing managed setup state")?;
    std::fs::write(path, payload).with_context(|| format!("failed writing {}", path.display()))
}

pub(crate) fn write_managed_signer_material(
    data_dir: &std::path::Path,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<()> {
    let signer_dir = managed_signer_dir(data_dir);
    std::fs::create_dir_all(&signer_dir)
        .with_context(|| format!("failed creating {}", signer_dir.display()))?;
    let cert_path = managed_signer_ca_cert_path(data_dir);
    let key_path = managed_signer_ca_key_path(data_dir);
    std::fs::write(&cert_path, ca_cert_pem)
        .with_context(|| format!("failed writing {}", cert_path.display()))?;
    std::fs::write(&key_path, ca_key_pem)
        .with_context(|| format!("failed writing {}", key_path.display()))?;
    Ok(())
}

pub(crate) fn apply_managed_signer_paths(
    data_dir: &std::path::Path,
    config: &mut ServerNodeConfig,
) {
    let key_path = managed_signer_ca_key_path(data_dir);
    if key_path.exists() {
        config.internal_ca_key_path = Some(key_path.clone());
        config.public_ca_key_path = Some(key_path);
    }
}

fn write_managed_rendezvous_material(
    data_dir: &std::path::Path,
    cert_pem: &str,
    key_pem: &str,
) -> Result<()> {
    let rendezvous_dir = managed_rendezvous_dir(data_dir);
    std::fs::create_dir_all(&rendezvous_dir)
        .with_context(|| format!("failed creating {}", rendezvous_dir.display()))?;
    let cert_path = managed_rendezvous_cert_path(data_dir);
    let key_path = managed_rendezvous_key_path(data_dir);
    std::fs::write(&cert_path, cert_pem)
        .with_context(|| format!("failed writing {}", cert_path.display()))?;
    std::fs::write(&key_path, key_pem)
        .with_context(|| format!("failed writing {}", key_path.display()))?;
    Ok(())
}

fn apply_managed_rendezvous_config(
    data_dir: &std::path::Path,
    managed_state: &ManagedSetupState,
    config: &mut ServerNodeConfig,
) {
    let Some(bind_addr) = managed_state
        .managed_rendezvous_bind_addr
        .as_deref()
        .and_then(|raw| raw.parse::<SocketAddr>().ok())
    else {
        return;
    };
    let Some(public_url) = managed_state.managed_rendezvous_public_url.clone() else {
        return;
    };

    let client_ca_cert_path = managed_runtime_internal_ca_cert_path(data_dir);
    let cert_path = managed_rendezvous_cert_path(data_dir);
    let key_path = managed_rendezvous_key_path(data_dir);
    if !client_ca_cert_path.exists() || !cert_path.exists() || !key_path.exists() {
        return;
    }

    if config
        .rendezvous_urls
        .iter()
        .all(|existing| existing != &public_url)
    {
        config.rendezvous_urls.push(public_url.clone());
    }
    config.rendezvous_registration_enabled = true;
    config.rendezvous_mtls_required = true;
    if config.rendezvous_ca_cert_path.is_none() {
        config.rendezvous_ca_cert_path = Some(client_ca_cert_path.clone());
    }
    config.managed_rendezvous = Some(ManagedRendezvousConfig {
        bind_addr,
        public_url,
        client_ca_cert_path,
        cert_path,
        key_path,
    });
}

fn validate_backup_passphrase(passphrase: &str) -> std::result::Result<(), &'static str> {
    if passphrase.trim().len() < 12 {
        return Err("backup passphrase must be at least 12 characters long");
    }
    Ok(())
}

fn derive_managed_signer_backup_key(
    passphrase: &str,
    salt: &[u8],
    rounds: u32,
) -> [u8; MANAGED_SIGNER_BACKUP_KEY_LEN] {
    let mut key = [0u8; MANAGED_SIGNER_BACKUP_KEY_LEN];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, rounds, &mut key);
    key
}

pub(crate) fn export_managed_signer_backup(
    cluster_id: ClusterId,
    source_node_id: NodeId,
    ca_cert_pem: &str,
    ca_key_pem: &str,
    passphrase: &str,
) -> Result<ManagedSignerBackup> {
    validate_backup_passphrase(passphrase).map_err(anyhow::Error::msg)?;
    let exported_at_unix = unix_ts();
    let plaintext = ManagedSignerBackupPlaintext {
        cluster_id,
        source_node_id,
        exported_at_unix,
        ca_cert_pem: ca_cert_pem.to_string(),
        ca_key_pem: ca_key_pem.to_string(),
    };
    let plaintext_json =
        serde_json::to_vec(&plaintext).context("failed serializing managed signer backup")?;

    let mut salt = [0u8; MANAGED_SIGNER_BACKUP_SALT_LEN];
    let mut nonce = [0u8; MANAGED_SIGNER_BACKUP_NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let key =
        derive_managed_signer_backup_key(passphrase, &salt, MANAGED_SIGNER_BACKUP_PBKDF2_ROUNDS);
    let cipher = Aes256GcmSiv::new_from_slice(&key)
        .context("failed initializing managed signer backup cipher")?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext_json.as_ref())
        .map_err(|_| anyhow!("failed encrypting managed signer backup"))?;

    Ok(ManagedSignerBackup {
        version: MANAGED_SIGNER_BACKUP_VERSION,
        cluster_id,
        source_node_id,
        exported_at_unix,
        pbkdf2_rounds: MANAGED_SIGNER_BACKUP_PBKDF2_ROUNDS,
        salt_b64: BASE64_STANDARD.encode(salt),
        nonce_b64: BASE64_STANDARD.encode(nonce),
        ciphertext_b64: BASE64_STANDARD.encode(ciphertext),
    })
}

pub(crate) fn import_managed_signer_backup(
    data_dir: &std::path::Path,
    backup: &ManagedSignerBackup,
    passphrase: &str,
    expected_cluster_id: Option<ClusterId>,
) -> Result<()> {
    if backup.version != MANAGED_SIGNER_BACKUP_VERSION {
        bail!(
            "unsupported managed signer backup version {}",
            backup.version
        );
    }

    let salt = BASE64_STANDARD
        .decode(backup.salt_b64.as_bytes())
        .context("failed decoding managed signer backup salt")?;
    if salt.len() != MANAGED_SIGNER_BACKUP_SALT_LEN {
        bail!("invalid managed signer backup salt length");
    }
    let nonce = BASE64_STANDARD
        .decode(backup.nonce_b64.as_bytes())
        .context("failed decoding managed signer backup nonce")?;
    if nonce.len() != MANAGED_SIGNER_BACKUP_NONCE_LEN {
        bail!("invalid managed signer backup nonce length");
    }
    let ciphertext = BASE64_STANDARD
        .decode(backup.ciphertext_b64.as_bytes())
        .context("failed decoding managed signer backup ciphertext")?;
    let key = derive_managed_signer_backup_key(passphrase, &salt, backup.pbkdf2_rounds);
    let cipher = Aes256GcmSiv::new_from_slice(&key)
        .context("failed initializing managed signer backup cipher")?;
    let plaintext_json = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("failed decrypting managed signer backup"))?;
    let plaintext = serde_json::from_slice::<ManagedSignerBackupPlaintext>(&plaintext_json)
        .context("failed parsing managed signer backup payload")?;

    if plaintext.cluster_id != backup.cluster_id {
        bail!("managed signer backup cluster ID mismatch");
    }
    if plaintext.source_node_id != backup.source_node_id {
        bail!("managed signer backup source node ID mismatch");
    }
    if let Some(expected_cluster_id) = expected_cluster_id
        && plaintext.cluster_id != expected_cluster_id
    {
        bail!(
            "managed signer backup belongs to cluster {} but this node is in cluster {}",
            plaintext.cluster_id,
            expected_cluster_id
        );
    }

    write_managed_signer_material(data_dir, &plaintext.ca_cert_pem, &plaintext.ca_key_pem)
}

async fn ensure_bootstrap_tls_config(config: &SetupBootstrapConfig) -> Result<RustlsConfig> {
    if !config.bootstrap_cert_path.exists() || !config.bootstrap_key_path.exists() {
        let (cert_pem, key_pem) = generate_bootstrap_tls_identity(config.bind_addr)?;
        if let Some(parent) = config.bootstrap_cert_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }
        std::fs::write(&config.bootstrap_cert_path, cert_pem).with_context(|| {
            format!(
                "failed writing bootstrap certificate {}",
                config.bootstrap_cert_path.display()
            )
        })?;
        std::fs::write(&config.bootstrap_key_path, key_pem).with_context(|| {
            format!(
                "failed writing bootstrap key {}",
                config.bootstrap_key_path.display()
            )
        })?;
    }

    RustlsConfig::from_pem_file(&config.bootstrap_cert_path, &config.bootstrap_key_path)
        .await
        .with_context(|| {
            format!(
                "failed building bootstrap TLS config from {} and {}",
                config.bootstrap_cert_path.display(),
                config.bootstrap_key_path.display()
            )
        })
}

fn generate_bootstrap_tls_identity(bind_addr: SocketAddr) -> Result<(String, String)> {
    let mut params = CertificateParams::new(Vec::new())
        .context("failed creating bootstrap TLS certificate params")?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, "ironmesh-bootstrap-ui");
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = OffsetDateTime::from_unix_timestamp(unix_ts().saturating_sub(300) as i64)
        .context("failed setting bootstrap TLS not_before")?;
    params.not_after =
        OffsetDateTime::from_unix_timestamp(unix_ts().saturating_add(30 * 24 * 60 * 60) as i64)
            .context("failed setting bootstrap TLS not_after")?;
    params.subject_alt_names.push(SanType::DnsName(
        "localhost"
            .try_into()
            .context("invalid localhost bootstrap SAN")?,
    ));
    params
        .subject_alt_names
        .push(SanType::IpAddress(Ipv4Addr::LOCALHOST.into()));
    if !bind_addr.ip().is_unspecified() {
        params
            .subject_alt_names
            .push(SanType::IpAddress(bind_addr.ip()));
    }
    if let Some(hostname) = std::env::var("COMPUTERNAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        params.subject_alt_names.push(SanType::DnsName(
            hostname
                .try_into()
                .context("invalid hostname bootstrap SAN")?,
        ));
    }
    let key_pair = KeyPair::generate().context("failed generating bootstrap TLS keypair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("failed self-signing bootstrap TLS certificate")?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

fn issue_self_managed_cluster_artifacts(
    mut bootstrap: TransportNodeBootstrap,
) -> Result<SelfManagedClusterArtifacts> {
    bootstrap.validate()?;
    let policy = build_tls_issue_policy(None, None)
        .map_err(|status| anyhow!("invalid TLS policy: {status}"))?;
    let (ca_cert_pem, ca_key_pem) = generate_cluster_ca(bootstrap.cluster_id)?;
    bootstrap.trust_roots = BootstrapTrustRoots {
        cluster_ca_pem: Some(ca_cert_pem.clone()),
        public_api_ca_pem: Some(ca_cert_pem.clone()),
        rendezvous_ca_pem: bootstrap
            .rendezvous_mtls_required
            .then(|| ca_cert_pem.clone()),
    };

    let internal_tls_material =
        issue_internal_node_tls_material_from_ca(&bootstrap, &ca_cert_pem, &ca_key_pem, policy)?;
    let public_tls_material =
        issue_public_node_tls_material_from_ca(&bootstrap, &ca_cert_pem, &ca_key_pem, policy)?;

    let package = NodeEnrollmentPackage {
        bootstrap,
        public_tls_material,
        internal_tls_material: Some(internal_tls_material),
    };
    package.validate()?;
    Ok(SelfManagedClusterArtifacts {
        package,
        ca_cert_pem,
        ca_key_pem,
    })
}

fn generate_cluster_ca(cluster_id: ClusterId) -> Result<(String, String)> {
    let mut params =
        CertificateParams::new(Vec::new()).context("failed creating cluster CA params")?;
    params.distinguished_name = DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("ironmesh-cluster-{cluster_id}"));
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.not_before = OffsetDateTime::from_unix_timestamp(unix_ts().saturating_sub(300) as i64)
        .context("failed setting cluster CA not_before")?;
    params.not_after =
        OffsetDateTime::from_unix_timestamp(unix_ts().saturating_add(3650 * 24 * 60 * 60) as i64)
            .context("failed setting cluster CA not_after")?;
    let key_pair = KeyPair::generate().context("failed generating cluster CA keypair")?;
    let cert = params
        .self_signed(&key_pair)
        .context("failed self-signing cluster CA")?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

fn issue_internal_node_tls_material_from_ca(
    bootstrap: &TransportNodeBootstrap,
    ca_cert_pem: &str,
    ca_key_pem: &str,
    policy: NodeTlsIssuePolicy,
) -> Result<BootstrapMutualTlsMaterial> {
    let issuer_key = KeyPair::from_pem(ca_key_pem).context("failed parsing cluster CA keypair")?;
    let issuer =
        Issuer::from_ca_cert_pem(ca_cert_pem, issuer_key).context("failed building CA issuer")?;
    let mut params =
        CertificateParams::new(Vec::new()).context("failed creating internal TLS params")?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(
        DnType::CommonName,
        format!("ironmesh-node-{}", bootstrap.node_id),
    );
    params.is_ca = IsCa::NoCa;
    params.not_before = OffsetDateTime::from_unix_timestamp(policy.not_before_unix as i64)
        .context("failed setting internal TLS not_before")?;
    params.not_after = OffsetDateTime::from_unix_timestamp(policy.not_after_unix as i64)
        .context("failed setting internal TLS not_after")?;
    params.extended_key_usages = vec![
        ExtendedKeyUsagePurpose::ClientAuth,
        ExtendedKeyUsagePurpose::ServerAuth,
    ];
    params.subject_alt_names = build_internal_node_subject_alt_names(bootstrap)?;
    let key_pair = KeyPair::generate().context("failed generating internal TLS keypair")?;
    let cert = params
        .signed_by(&key_pair, &issuer)
        .context("failed signing internal TLS certificate")?;
    let cert_pem = cert.pem();
    let metadata = build_tls_material_metadata(&cert_pem, policy)
        .map_err(|status| anyhow!("failed building internal TLS metadata: {status}"))?;
    Ok(BootstrapMutualTlsMaterial {
        ca_cert_pem: ca_cert_pem.to_string(),
        cert_pem,
        key_pem: key_pair.serialize_pem(),
        metadata,
    })
}

fn issue_public_node_tls_material_from_ca(
    bootstrap: &TransportNodeBootstrap,
    ca_cert_pem: &str,
    ca_key_pem: &str,
    policy: NodeTlsIssuePolicy,
) -> Result<Option<BootstrapMutualTlsMaterial>> {
    if bootstrap.public_tls.is_none() {
        return Ok(None);
    }
    let issuer_key = KeyPair::from_pem(ca_key_pem).context("failed parsing public CA keypair")?;
    let issuer =
        Issuer::from_ca_cert_pem(ca_cert_pem, issuer_key).context("failed building CA issuer")?;
    let mut params =
        CertificateParams::new(Vec::new()).context("failed creating public TLS params")?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(
        DnType::CommonName,
        format!("ironmesh-public-{}", bootstrap.node_id),
    );
    params.is_ca = IsCa::NoCa;
    params.not_before = OffsetDateTime::from_unix_timestamp(policy.not_before_unix as i64)
        .context("failed setting public TLS not_before")?;
    params.not_after = OffsetDateTime::from_unix_timestamp(policy.not_after_unix as i64)
        .context("failed setting public TLS not_after")?;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.subject_alt_names = build_public_node_subject_alt_names(bootstrap)?;
    let key_pair = KeyPair::generate().context("failed generating public TLS keypair")?;
    let cert = params
        .signed_by(&key_pair, &issuer)
        .context("failed signing public TLS certificate")?;
    let cert_pem = cert.pem();
    let metadata = build_tls_material_metadata(&cert_pem, policy)
        .map_err(|status| anyhow!("failed building public TLS metadata: {status}"))?;
    Ok(Some(BootstrapMutualTlsMaterial {
        ca_cert_pem: ca_cert_pem.to_string(),
        cert_pem,
        key_pem: key_pair.serialize_pem(),
        metadata,
    }))
}

fn default_setup_labels() -> HashMap<String, String> {
    let mut labels = HashMap::new();
    labels.insert("region".to_string(), "local".to_string());
    labels.insert("dc".to_string(), "bootstrap".to_string());
    labels.insert("rack".to_string(), "bootstrap".to_string());
    labels
}

fn default_internal_bind_addr(public_bind_addr: SocketAddr) -> SocketAddr {
    let public_port = public_bind_addr.port();
    let internal_port = if public_port <= u16::MAX - 10_000 {
        public_port + 10_000
    } else if public_port <= u16::MAX - 1_000 {
        public_port + 1_000
    } else {
        18_443
    };
    SocketAddr::new(public_bind_addr.ip(), internal_port)
}

fn default_managed_rendezvous_bind_addr(public_bind_addr: SocketAddr) -> SocketAddr {
    let public_port = public_bind_addr.port();
    let rendezvous_port = if public_port <= u16::MAX - 1_000 {
        public_port + 1_000
    } else if public_port < u16::MAX {
        public_port + 1
    } else {
        9_443
    };
    SocketAddr::new(public_bind_addr.ip(), rendezvous_port)
}

fn validate_admin_password(password: &str) -> std::result::Result<(), &'static str> {
    if password.trim().len() < 12 {
        return Err("admin password must be at least 12 characters long");
    }
    Ok(())
}

fn normalize_https_origin(raw: &str) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(raw.trim())
        .with_context(|| format!("invalid public origin {raw:?}"))?;
    if url.scheme() != "https" {
        bail!("public origin must use https");
    }
    url.set_query(None);
    url.set_fragment(None);
    url.set_path("");
    if url.host_str().is_none() {
        bail!("public origin must include a host");
    }
    Ok(url)
}

fn derive_internal_url(public_origin: &reqwest::Url, port: u16) -> Result<String> {
    let mut url = public_origin.clone();
    url.set_port(Some(port))
        .map_err(|_| anyhow!("failed deriving internal URL port"))?;
    Ok(origin_to_string(&url))
}

fn derive_managed_rendezvous_url(public_origin: &reqwest::Url, port: u16) -> Result<String> {
    let mut url = public_origin.clone();
    url.set_port(Some(port))
        .map_err(|_| anyhow!("failed deriving managed rendezvous URL port"))?;
    Ok(origin_to_string(&url))
}

fn issue_managed_rendezvous_tls_identity_from_ca(
    cluster_id: ClusterId,
    public_url: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
) -> Result<(String, String)> {
    let url = reqwest::Url::parse(public_url)
        .with_context(|| format!("invalid rendezvous URL {public_url:?}"))?;
    let host = url
        .host_str()
        .context("managed rendezvous URL must include a host")?;

    let issuer_key = KeyPair::from_pem(ca_key_pem).context("failed parsing cluster CA keypair")?;
    let issuer =
        Issuer::from_ca_cert_pem(ca_cert_pem, issuer_key).context("failed building CA issuer")?;
    let mut params =
        CertificateParams::new(Vec::new()).context("failed creating rendezvous TLS params")?;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(
        DnType::CommonName,
        format!("ironmesh-rendezvous-{cluster_id}"),
    );
    params.is_ca = IsCa::NoCa;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = OffsetDateTime::from_unix_timestamp(unix_ts().saturating_sub(300) as i64)
        .context("failed setting managed rendezvous TLS not_before")?;
    params.not_after =
        OffsetDateTime::from_unix_timestamp(unix_ts().saturating_add(3650 * 24 * 60 * 60) as i64)
            .context("failed setting managed rendezvous TLS not_after")?;
    if let Ok(ip_addr) = host.parse::<std::net::IpAddr>() {
        params.subject_alt_names.push(SanType::IpAddress(ip_addr));
    } else {
        params.subject_alt_names.push(SanType::DnsName(
            host.try_into()
                .context("invalid managed rendezvous DNS SAN")?,
        ));
    }
    if host.eq_ignore_ascii_case("localhost") {
        params
            .subject_alt_names
            .push(SanType::IpAddress(Ipv4Addr::LOCALHOST.into()));
    }
    let key_pair = KeyPair::generate().context("failed generating managed rendezvous keypair")?;
    let cert = params
        .signed_by(&key_pair, &issuer)
        .context("failed signing managed rendezvous certificate")?;
    Ok((cert.pem(), key_pair.serialize_pem()))
}

fn origin_to_string(url: &reqwest::Url) -> String {
    url.as_str().trim_end_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(name: &str) -> PathBuf {
        let unique = Uuid::now_v7();
        let path = std::env::temp_dir().join(format!("ironmesh-setup-{name}-{unique}"));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn managed_setup_state_roundtrip() {
        let dir = temp_dir("state-roundtrip");
        let path = managed_setup_state_path(&dir);
        let state = ManagedSetupState {
            version: SETUP_STATE_VERSION,
            state: SetupLifecycleState::PendingJoin,
            updated_at_unix: 123,
            cluster_id: Some(Uuid::now_v7()),
            node_id: Some(NodeId::new_v4()),
            runtime_node_enrollment_path: Some("managed/runtime/node-enrollment.json".to_string()),
            admin_password_hash: Some(hash_token("super-secret-password")),
            managed_rendezvous_bind_addr: Some("0.0.0.0:9443".to_string()),
            managed_rendezvous_public_url: Some("https://node-a.local:9443".to_string()),
            pending_join_request: Some(NodeJoinRequest {
                version: SETUP_STATE_VERSION,
                node_id: NodeId::new_v4(),
                mode: NodeBootstrapMode::Cluster,
                data_dir: dir.display().to_string(),
                bind_addr: "0.0.0.0:8443".to_string(),
                public_url: Some("https://node-a.local:8443".to_string()),
                labels: default_setup_labels(),
                public_tls: Some(BootstrapServerTlsFiles {
                    cert_path: "managed/runtime/public/public.pem".to_string(),
                    key_path: "managed/runtime/public/public.key".to_string(),
                }),
                public_ca_cert_path: Some("managed/runtime/public/public-ca.pem".to_string()),
                public_peer_api_enabled: false,
                internal_bind_addr: Some("0.0.0.0:18443".to_string()),
                internal_url: Some("https://node-a.local:18443".to_string()),
                internal_tls: Some(BootstrapTlsFiles {
                    ca_cert_path: "managed/runtime/internal/cluster-ca.pem".to_string(),
                    cert_path: "managed/runtime/internal/node.pem".to_string(),
                    key_path: "managed/runtime/internal/node.key".to_string(),
                }),
            }),
        };
        write_managed_setup_state(&path, &state).unwrap();
        let restored = read_managed_setup_state(&path).unwrap().unwrap();
        assert_eq!(restored.state, SetupLifecycleState::PendingJoin);
        assert_eq!(
            restored.admin_password_hash.as_deref(),
            Some(hash_token("super-secret-password").as_str())
        );
        assert_eq!(
            restored
                .pending_join_request
                .as_ref()
                .and_then(|request| request.public_url.as_deref()),
            Some("https://node-a.local:8443")
        );
        assert_eq!(
            restored.managed_rendezvous_public_url.as_deref(),
            Some("https://node-a.local:9443")
        );
    }

    #[test]
    fn self_managed_cluster_enrollment_is_valid() {
        let dir = temp_dir("start-cluster");
        let node_id = NodeId::new_v4();
        let cluster_id = Uuid::now_v7();
        let bootstrap = TransportNodeBootstrap {
            version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
            cluster_id,
            node_id,
            mode: NodeBootstrapMode::Cluster,
            data_dir: dir.display().to_string(),
            bind_addr: "0.0.0.0:8443".to_string(),
            public_url: Some("https://node-a.local:8443".to_string()),
            labels: default_setup_labels(),
            public_tls: Some(BootstrapServerTlsFiles {
                cert_path: "managed/runtime/public/public.pem".to_string(),
                key_path: "managed/runtime/public/public.key".to_string(),
            }),
            public_ca_cert_path: Some("managed/runtime/public/public-ca.pem".to_string()),
            public_peer_api_enabled: false,
            internal_bind_addr: Some("0.0.0.0:18443".to_string()),
            internal_url: Some("https://node-a.local:18443".to_string()),
            internal_tls: Some(BootstrapTlsFiles {
                ca_cert_path: "managed/runtime/internal/cluster-ca.pem".to_string(),
                cert_path: "managed/runtime/internal/node.pem".to_string(),
                key_path: "managed/runtime/internal/node.key".to_string(),
            }),
            rendezvous_urls: vec!["https://node-a.local:9443".to_string()],
            rendezvous_mtls_required: true,
            direct_endpoints: vec![
                BootstrapEndpoint {
                    url: "https://node-a.local:8443".to_string(),
                    usage: Some(BootstrapEndpointUse::PublicApi),
                    node_id: Some(node_id),
                },
                BootstrapEndpoint {
                    url: "https://node-a.local:18443".to_string(),
                    usage: Some(BootstrapEndpointUse::PeerApi),
                    node_id: Some(node_id),
                },
            ],
            relay_mode: RelayMode::Fallback,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: None,
                public_api_ca_pem: None,
                rendezvous_ca_pem: None,
            },
            enrollment_issuer_url: Some("https://node-a.local:8443".to_string()),
        };

        let package = issue_self_managed_cluster_artifacts(bootstrap)
            .unwrap()
            .package;
        package.validate().unwrap();
        assert!(package.public_tls_material.is_some());
        assert!(package.internal_tls_material.is_some());
        assert!(package.bootstrap.trust_roots.cluster_ca_pem.is_some());
        assert_eq!(
            package.bootstrap.rendezvous_urls,
            vec!["https://node-a.local:9443".to_string()]
        );
        assert!(package.bootstrap.trust_roots.rendezvous_ca_pem.is_some());
    }

    #[test]
    fn apply_managed_rendezvous_config_enables_embedded_listener() {
        let dir = temp_dir("managed-rendezvous-config");
        let runtime_internal_dir = managed_setup_dir(&dir).join("runtime").join("internal");
        std::fs::create_dir_all(&runtime_internal_dir).unwrap();
        std::fs::write(runtime_internal_dir.join("cluster-ca.pem"), "cluster-ca").unwrap();
        let rendezvous_dir = managed_rendezvous_dir(&dir);
        std::fs::create_dir_all(&rendezvous_dir).unwrap();
        std::fs::write(rendezvous_dir.join("rendezvous.pem"), "cert").unwrap();
        std::fs::write(rendezvous_dir.join("rendezvous.key"), "key").unwrap();

        let managed_state = ManagedSetupState {
            managed_rendezvous_bind_addr: Some("0.0.0.0:9443".to_string()),
            managed_rendezvous_public_url: Some("https://node-a.local:9443".to_string()),
            ..ManagedSetupState::default()
        };
        let mut config = ServerNodeConfig::local_edge(
            dir.join("data"),
            "127.0.0.1:28080".parse::<SocketAddr>().unwrap(),
        );

        apply_managed_rendezvous_config(&dir, &managed_state, &mut config);

        assert_eq!(
            config.rendezvous_urls,
            vec![
                format!("http://{}", config.bind_addr),
                "https://node-a.local:9443".to_string()
            ]
        );
        assert!(config.rendezvous_registration_enabled);
        assert!(config.rendezvous_mtls_required);
        assert_eq!(
            config
                .managed_rendezvous
                .as_ref()
                .map(|cfg| cfg.public_url.as_str()),
            Some("https://node-a.local:9443")
        );
    }

    #[test]
    fn apply_managed_signer_paths_sets_runtime_ca_key_paths() {
        let dir = temp_dir("managed-signer");
        write_managed_signer_material(&dir, "ca-cert", "ca-key").unwrap();
        let mut config = ServerNodeConfig::local_edge(
            dir.join("data"),
            "127.0.0.1:28080".parse::<SocketAddr>().unwrap(),
        );

        apply_managed_signer_paths(&dir, &mut config);

        assert_eq!(
            config.internal_ca_key_path.as_ref().map(|path| path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()),
            Some("cluster-ca.key".to_string())
        );
        assert_eq!(
            config.public_ca_key_path.as_ref().map(|path| path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()),
            Some("cluster-ca.key".to_string())
        );
    }

    #[test]
    fn managed_signer_backup_roundtrip_restores_signer_material() {
        let dir = temp_dir("managed-signer-backup");
        let cluster_id = ClusterId::new_v4();
        let source_node_id = NodeId::new_v4();
        let backup = export_managed_signer_backup(
            cluster_id,
            source_node_id,
            "cluster-ca-cert",
            "cluster-ca-key",
            "correct horse battery staple",
        )
        .unwrap();

        import_managed_signer_backup(
            &dir,
            &backup,
            "correct horse battery staple",
            Some(cluster_id),
        )
        .unwrap();

        assert_eq!(
            std::fs::read_to_string(managed_signer_ca_cert_path(&dir)).unwrap(),
            "cluster-ca-cert"
        );
        assert_eq!(
            std::fs::read_to_string(managed_signer_ca_key_path(&dir)).unwrap(),
            "cluster-ca-key"
        );
    }

    #[test]
    fn managed_signer_backup_rejects_wrong_passphrase() {
        let dir = temp_dir("managed-signer-backup-passphrase");
        let backup = export_managed_signer_backup(
            ClusterId::new_v4(),
            NodeId::new_v4(),
            "cluster-ca-cert",
            "cluster-ca-key",
            "correct horse battery staple",
        )
        .unwrap();

        let err = import_managed_signer_backup(
            &dir,
            &backup,
            "wrong passphrase",
            Some(backup.cluster_id),
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("failed decrypting managed signer backup")
        );
    }
}
