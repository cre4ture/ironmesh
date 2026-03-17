use super::{
    AdminControl, LocalNodeHandle, MetadataCommitMode, PeerHeartbeatConfig, RepairConfig,
    RepairExecutorState, ServerNodeConfig, ServerState, StartupRepairStatus,
    await_repair_busy_threshold, build_rendezvous_presence_registration, build_store_index_entries,
    cluster, constant_time_eq, jittered_backoff_secs, node_descriptor_from_presence_entry,
    plan_peer_transport, replication::build_internal_replication_put_url, resolve_peer_base_url,
    run, run_startup_replication_repair_once, should_trigger_autonomous_post_write_replication,
    token_matches,
};
use axum::Extension;
use axum_server::accept::Accept;
use common::NodeId;
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use std::fs::File;
use std::future::Future;
use std::io;
use std::io::BufReader;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;
use tokio_rustls::TlsConnector;

use super::storage::{PersistentStore, PutOptions, VersionConsistencyState};
use axum::Router;
use axum::body::Body;
use axum::body::to_bytes;
use axum::extract::{Json, Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use tokio::time::{Duration, Instant};
use tower::{Service, ServiceExt};

#[derive(Clone, Copy)]
enum MainTestBackend {
    Sqlite,
    #[cfg(feature = "turso-metadata")]
    Turso,
}

impl MainTestBackend {
    fn kind(self) -> super::storage::MetadataBackendKind {
        match self {
            Self::Sqlite => super::storage::MetadataBackendKind::Sqlite,
            #[cfg(feature = "turso-metadata")]
            Self::Turso => super::storage::MetadataBackendKind::Turso,
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::Sqlite => "sqlite",
            #[cfg(feature = "turso-metadata")]
            Self::Turso => "turso",
        }
    }
}

macro_rules! run_on_main_metadata_backends {
    ($body:ident, $sqlite_test:ident, $turso_test:ident) => {
        #[tokio::test]
        async fn $sqlite_test() {
            $body(MainTestBackend::Sqlite).await;
        }

        #[cfg(feature = "turso-metadata")]
        #[tokio::test]
        async fn $turso_test() {
            $body(MainTestBackend::Turso).await;
        }
    };
}

#[test]
fn jittered_backoff_is_deterministic_for_same_inputs() {
    let first = jittered_backoff_secs(30, "key@ver|node", 2);
    let second = jittered_backoff_secs(30, "key@ver|node", 2);
    assert_eq!(first, second);
}

#[test]
fn jittered_backoff_stays_within_expected_range() {
    let value = jittered_backoff_secs(40, "another-key|node", 3);
    assert!(value >= 40);
    assert!(value <= 60);
}

#[test]
fn constant_time_eq_compares_equal_and_non_equal_values() {
    assert!(constant_time_eq(b"secret", b"secret"));
    assert!(!constant_time_eq(b"secret", b"Secret"));
    assert!(!constant_time_eq(b"secret", b"secret-long"));
}

#[test]
fn metadata_backend_parser_accepts_sqlite() {
    let backend = super::parse_metadata_backend("sqlite").unwrap();
    assert!(matches!(
        backend,
        super::storage::MetadataBackendKind::Sqlite
    ));
}

#[test]
fn metadata_backend_parser_handles_turso_feature_gate() {
    let result = super::parse_metadata_backend("turso");
    #[cfg(feature = "turso-metadata")]
    assert!(matches!(
        result.unwrap(),
        super::storage::MetadataBackendKind::Turso
    ));
    #[cfg(not(feature = "turso-metadata"))]
    assert!(result.unwrap_err().to_string().contains("turso-metadata"));
}

fn sample_png_bytes() -> Vec<u8> {
    let image = image::DynamicImage::new_rgba8(4, 3);
    let mut cursor = std::io::Cursor::new(Vec::new());
    image
        .write_to(&mut cursor, image::ImageFormat::Png)
        .unwrap();
    cursor.into_inner()
}

fn free_bind_addr() -> SocketAddr {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    addr
}

fn generate_test_internal_ca() -> (String, String) {
    let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "ironmesh-test-cluster-ca");
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem(), key_pair.serialize_pem())
}

fn default_tls_issue_policy() -> super::NodeTlsIssuePolicy {
    super::build_tls_issue_policy(None, None).unwrap()
}

fn load_root_store_from_pem_file(path: &std::path::Path) -> RootCertStore {
    let mut reader = BufReader::new(File::open(path).unwrap());
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_reader_iter(&mut reader) {
        roots.add(cert.unwrap()).unwrap();
    }
    roots
}

fn load_client_identity_from_pem_files(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let mut cert_reader = BufReader::new(File::open(cert_path).unwrap());
    let cert_chain = CertificateDer::pem_reader_iter(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    let mut key_reader = BufReader::new(File::open(key_path).unwrap());
    let key = PrivateKeyDer::from_pem_reader(&mut key_reader).unwrap();
    (cert_chain, key)
}

async fn observe_peer_certificate_fingerprint(
    addr: SocketAddr,
    ca_cert_path: &std::path::Path,
    client_identity: Option<(&std::path::Path, &std::path::Path)>,
) -> String {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let roots = load_root_store_from_pem_file(ca_cert_path);
    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
    let config = match client_identity {
        Some((cert_path, key_path)) => {
            let (cert_chain, key) = load_client_identity_from_pem_files(cert_path, key_path);
            builder.with_client_auth_cert(cert_chain, key).unwrap()
        }
        None => builder.with_no_client_auth(),
    };

    let connector = TlsConnector::from(Arc::new(config));
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let server_name: ServerName<'static> = ServerName::from(addr.ip()).to_owned();
    let tls = connector.connect(server_name, stream).await.unwrap();
    let peer_cert = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .cloned()
        .unwrap();
    blake3::hash(peer_cert.as_ref()).to_hex().to_string()
}

#[derive(Clone)]
struct WithClientCertificateFingerprint<S> {
    inner: S,
    fingerprint: String,
}

impl<S> WithClientCertificateFingerprint<S> {
    fn new(inner: S, fingerprint: String) -> Self {
        Self { inner, fingerprint }
    }
}

impl<S, B> Service<Request<B>> for WithClientCertificateFingerprint<S>
where
    S: Service<Request<B>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = S::Future;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<B>) -> Self::Future {
        req.extensions_mut().insert(self.fingerprint.clone());
        self.inner.call(req)
    }
}

#[derive(Clone)]
struct ClientCertificateFingerprintAcceptor {
    inner: axum_server::tls_rustls::RustlsAcceptor,
}

impl ClientCertificateFingerprintAcceptor {
    fn new(config: axum_server::tls_rustls::RustlsConfig) -> Self {
        Self {
            inner: axum_server::tls_rustls::RustlsAcceptor::new(config),
        }
    }
}

impl<S> Accept<tokio::net::TcpStream, S> for ClientCertificateFingerprintAcceptor
where
    axum_server::tls_rustls::RustlsAcceptor: Accept<
            tokio::net::TcpStream,
            S,
            Stream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
        >,
    <axum_server::tls_rustls::RustlsAcceptor as Accept<tokio::net::TcpStream, S>>::Service:
        Send + 'static,
    <axum_server::tls_rustls::RustlsAcceptor as Accept<tokio::net::TcpStream, S>>::Future:
        Send + 'static,
    S: Send + 'static,
{
    type Stream = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Service = WithClientCertificateFingerprint<
        <axum_server::tls_rustls::RustlsAcceptor as Accept<tokio::net::TcpStream, S>>::Service,
    >;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let fut = self.inner.accept(stream, service);
        Box::pin(async move {
            let (tls_stream, service) = fut.await?;
            let fingerprint = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|cert| blake3::hash(cert.as_ref()).to_hex().to_string())
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "missing client certificate",
                    )
                })?;
            Ok((
                tls_stream,
                WithClientCertificateFingerprint::new(service, fingerprint),
            ))
        })
    }
}

async fn capture_mtls_health(
    State(captured_fingerprint): State<Arc<Mutex<Option<String>>>>,
    Extension(fingerprint): Extension<String>,
) -> StatusCode {
    *captured_fingerprint.lock().await = Some(fingerprint);
    StatusCode::OK
}

async fn capture_mtls_presence_register(
    State(captured_fingerprint): State<Arc<Mutex<Option<String>>>>,
    Extension(fingerprint): Extension<String>,
    Json(registration): Json<transport_sdk::PresenceRegistration>,
) -> Json<transport_sdk::RegisterPresenceResponse> {
    *captured_fingerprint.lock().await = Some(fingerprint);
    let updated_at_unix = super::unix_ts();
    Json(transport_sdk::RegisterPresenceResponse {
        accepted: true,
        updated_at_unix,
        entry: transport_sdk::PresenceEntry {
            registration,
            updated_at_unix,
        },
    })
}

fn spawn_mtls_client_fingerprint_capture_server(
    bind_addr: SocketAddr,
    ca_cert_path: &std::path::Path,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    captured_fingerprint: Arc<Mutex<Option<String>>>,
) -> tokio::task::JoinHandle<()> {
    let app = Router::new()
        .route("/health", get(capture_mtls_health))
        .route(
            "/control/presence/register",
            axum::routing::post(capture_mtls_presence_register),
        )
        .with_state(captured_fingerprint);
    let tls_config = super::build_internal_mtls_rustls_config(
        &ca_cert_path.to_path_buf(),
        &cert_path.to_path_buf(),
        &key_path.to_path_buf(),
    )
    .unwrap();
    let acceptor = ClientCertificateFingerprintAcceptor::new(tls_config);

    tokio::spawn(async move {
        axum_server::Server::bind(bind_addr)
            .acceptor(acceptor)
            .serve(app.into_make_service())
            .await
            .unwrap();
    })
}

fn generate_test_https_ca_and_server_material(
    bind_addr: SocketAddr,
    label: &str,
) -> (String, String, String, String) {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params.distinguished_name = rcgen::DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, format!("ironmesh-{label}-ca"));
    let ca_key_pair = rcgen::KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key_pair).unwrap();
    let ca_cert_pem = ca_cert.pem();
    let ca_key_pem = ca_key_pair.serialize_pem();

    let issuer_key = rcgen::KeyPair::from_pem(&ca_key_pem).unwrap();
    let issuer = rcgen::Issuer::from_ca_cert_pem(&ca_cert_pem, issuer_key).unwrap();
    let mut server_params = rcgen::CertificateParams::new(Vec::new()).unwrap();
    server_params.distinguished_name = rcgen::DistinguishedName::new();
    server_params.distinguished_name.push(
        rcgen::DnType::CommonName,
        format!("ironmesh-{label}-server"),
    );
    server_params.is_ca = rcgen::IsCa::NoCa;
    server_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    server_params
        .subject_alt_names
        .push(rcgen::SanType::IpAddress(bind_addr.ip()));
    let server_key_pair = rcgen::KeyPair::generate().unwrap();
    let server_cert = server_params.signed_by(&server_key_pair, &issuer).unwrap();

    (
        ca_cert_pem,
        ca_key_pem,
        server_cert.pem(),
        server_key_pair.serialize_pem(),
    )
}

async fn https_presence_register(
    Json(registration): Json<transport_sdk::PresenceRegistration>,
) -> Json<transport_sdk::RegisterPresenceResponse> {
    let updated_at_unix = super::unix_ts();
    Json(transport_sdk::RegisterPresenceResponse {
        accepted: true,
        updated_at_unix,
        entry: transport_sdk::PresenceEntry {
            registration,
            updated_at_unix,
        },
    })
}

fn spawn_https_rendezvous_server(
    bind_addr: SocketAddr,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> tokio::task::JoinHandle<()> {
    let cert_path = cert_path.to_path_buf();
    let key_path = key_path.to_path_buf();
    tokio::spawn(async move {
        let app = Router::new().route(
            "/control/presence/register",
            axum::routing::post(https_presence_register),
        );
        let tls = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .unwrap();
        axum_server::bind_rustls(bind_addr, tls)
            .serve(app.into_make_service())
            .await
            .unwrap();
    })
}

#[test]
fn token_matches_requires_exact_match() {
    assert!(!token_matches("secret", None));
    assert!(!token_matches("secret", Some("wrong")));
    assert!(token_matches("secret", Some("secret")));
}

async fn admin_authorization_requires_token_when_configured_impl(backend: MainTestBackend) {
    let mut state = build_test_state(1, false, backend).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let headers = HeaderMap::new();

    let result = super::authorize_admin_request(
        &state,
        &headers,
        "maintenance/tombstones/compact",
        true,
        true,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(result.err(), Some(axum::http::StatusCode::UNAUTHORIZED));

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    admin_authorization_requires_token_when_configured_impl,
    admin_authorization_requires_token_when_configured,
    admin_authorization_requires_token_when_configured_turso
);

async fn admin_authorization_requires_explicit_approval_for_destructive_action_impl(
    backend: MainTestBackend,
) {
    let mut state = build_test_state(1, false, backend).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let result = super::authorize_admin_request(
        &state,
        &headers,
        "maintenance/tombstones/archive/purge",
        false,
        false,
        serde_json::json!({}),
    )
    .await;
    assert_eq!(
        result.err(),
        Some(axum::http::StatusCode::PRECONDITION_FAILED)
    );

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    admin_authorization_requires_explicit_approval_for_destructive_action_impl,
    admin_authorization_requires_explicit_approval_for_destructive_action,
    admin_authorization_requires_explicit_approval_for_destructive_action_turso
);

async fn enroll_client_device_consumes_pairing_token_and_persists_device_impl(
    backend: MainTestBackend,
) {
    let state = build_test_state(1, false, backend).await;
    let now = super::unix_ts();
    {
        let mut auth = state.client_auth.lock().await;
        auth.pairing_tokens.push(super::PairingTokenRecord {
            token_id: "pair-1".to_string(),
            token_hash: super::hash_token("pair-secret"),
            label: Some("Pixel".to_string()),
            created_at_unix: now,
            expires_at_unix: now + 300,
            used_at_unix: None,
            enrolled_device_id: None,
        });
    }

    let response = super::enroll_client_device(
        State(state.clone()),
        Json(super::ClientDeviceEnrollRequest {
            cluster_id: state.cluster_id,
            pairing_token: "pair-secret".to_string(),
            device_id: Some("device-a".to_string()),
            label: None,
            public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                .to_string(),
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let enrolled: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(enrolled["device_id"], "device-a");
    assert!(
        enrolled["device_token"]
            .as_str()
            .unwrap()
            .starts_with("im-dev-")
    );

    let auth = state.client_auth.lock().await;
    assert_eq!(auth.devices.len(), 1);
    assert_eq!(auth.devices[0].device_id, "device-a");
    assert!(auth.pairing_tokens[0].used_at_unix.is_some());
    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    enroll_client_device_consumes_pairing_token_and_persists_device_impl,
    enroll_client_device_consumes_pairing_token_and_persists_device,
    enroll_client_device_consumes_pairing_token_and_persists_device_turso
);

#[tokio::test]
async fn issue_bootstrap_bundle_includes_rendezvous_security_metadata() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    state.public_ca_pem = Some("public-ca".to_string());
    state.cluster_ca_pem = Some("cluster-ca".to_string());
    state.rendezvous_ca_pem = Some("rendezvous-ca".to_string());
    state.rendezvous_urls = vec!["https://rendezvous.example".to_string()];
    state.rendezvous_registration_enabled = true;
    state.rendezvous_mtls_required = true;

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let response = super::issue_bootstrap_bundle(
        State(state.clone()),
        headers,
        Json(super::PairingTokenIssueRequest {
            label: Some("tablet".to_string()),
            expires_in_secs: Some(600),
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let bootstrap: transport_sdk::ClientBootstrap = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        bootstrap.rendezvous_urls,
        vec!["https://rendezvous.example".to_string()]
    );
    assert!(bootstrap.rendezvous_mtls_required);
    assert_eq!(
        bootstrap.trust_roots.rendezvous_ca_pem.as_deref(),
        Some("rendezvous-ca")
    );
    assert_eq!(
        bootstrap.trust_roots.public_api_ca_pem.as_deref(),
        Some("public-ca")
    );
    assert_eq!(
        bootstrap.trust_roots.cluster_ca_pem.as_deref(),
        Some("cluster-ca")
    );
    assert_eq!(bootstrap.device_label.as_deref(), Some("tablet"));
    assert!(bootstrap.pairing_token.is_some());

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn server_node_config_loads_from_node_bootstrap_file() {
    let root = fresh_test_dir("node-bootstrap-config");
    let bootstrap_path = root.join("node-bootstrap.json");
    let node_id = NodeId::new_v4();
    let cluster_id = uuid::Uuid::now_v7();
    transport_sdk::NodeBootstrap {
        version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
        cluster_id,
        node_id,
        mode: transport_sdk::NodeBootstrapMode::Cluster,
        data_dir: root.join("data").to_string_lossy().into_owned(),
        bind_addr: "127.0.0.1:28080".to_string(),
        public_url: Some("https://node-b.example".to_string()),
        labels: HashMap::from([("dc".to_string(), "edge-b".to_string())]),
        public_tls: Some(transport_sdk::BootstrapServerTlsFiles {
            cert_path: "tls/public.pem".to_string(),
            key_path: "tls/public.key".to_string(),
        }),
        public_ca_cert_path: Some("tls/public-ca.pem".to_string()),
        public_peer_api_enabled: true,
        internal_bind_addr: Some("127.0.0.1:38080".to_string()),
        internal_url: Some("https://10.0.0.12:38080".to_string()),
        internal_tls: Some(transport_sdk::BootstrapTlsFiles {
            ca_cert_path: "tls/cluster-ca.pem".to_string(),
            cert_path: "tls/internal.pem".to_string(),
            key_path: "tls/internal.key".to_string(),
        }),
        rendezvous_urls: vec!["https://rendezvous.example".to_string()],
        rendezvous_mtls_required: true,
        direct_endpoints: vec![
            transport_sdk::BootstrapEndpoint {
                url: "https://node-b.example".to_string(),
                usage: Some(transport_sdk::BootstrapEndpointUse::PublicApi),
            },
            transport_sdk::BootstrapEndpoint {
                url: "https://10.0.0.12:38080".to_string(),
                usage: Some(transport_sdk::BootstrapEndpointUse::PeerApi),
            },
        ],
        relay_mode: transport_sdk::RelayMode::Required,
        trust_roots: transport_sdk::BootstrapTrustRoots {
            cluster_ca_pem: Some("cluster-ca".to_string()),
            public_api_ca_pem: Some("public-ca".to_string()),
            rendezvous_ca_pem: Some("rendezvous-ca".to_string()),
        },
        upstream_public_url: Some("https://upstream.example".to_string()),
        enrollment_issuer_url: Some("https://issuer.example".to_string()),
    }
    .write_to_path(&bootstrap_path)
    .unwrap();

    let config = super::ServerNodeConfig::from_bootstrap_path(&bootstrap_path).unwrap();

    assert!(matches!(config.mode, super::ServerNodeMode::Cluster));
    assert_eq!(config.cluster_id, cluster_id);
    assert_eq!(config.node_id, node_id);
    assert_eq!(
        config.bind_addr,
        "127.0.0.1:28080".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(config.public_url.as_deref(), Some("https://node-b.example"));
    assert!(config.rendezvous_registration_enabled);
    assert!(config.rendezvous_mtls_required);
    assert_eq!(
        config.rendezvous_urls,
        vec!["https://rendezvous.example".to_string()]
    );
    assert_eq!(
        config
            .internal_tls
            .as_ref()
            .and_then(|tls| tls.internal_url.as_deref()),
        Some("https://10.0.0.12:38080")
    );
    assert_eq!(
        config
            .public_tls
            .as_ref()
            .map(|tls| tls.cert_path.to_string_lossy().into_owned()),
        Some("tls/public.pem".to_string())
    );
    assert_eq!(
        config
            .public_ca_cert_path
            .as_ref()
            .map(|path| path.to_string_lossy().into_owned()),
        Some("tls/public-ca.pem".to_string())
    );
    assert_eq!(
        config.upstream_public_url.as_deref(),
        Some("https://upstream.example")
    );
    assert_eq!(
        config.enrollment_issuer_url.as_deref(),
        Some("https://issuer.example")
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn issue_node_bootstrap_includes_runtime_and_rendezvous_metadata() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    state.public_ca_pem = Some("public-ca".to_string());
    state.cluster_ca_pem = Some("cluster-ca".to_string());
    state.rendezvous_ca_pem = Some("rendezvous-ca".to_string());
    state.rendezvous_urls = vec!["https://rendezvous.example".to_string()];
    state.rendezvous_registration_enabled = true;
    state.rendezvous_mtls_required = true;
    state.relay_mode = transport_sdk::RelayMode::Required;

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());
    let requested_node_id = NodeId::new_v4();

    let response = super::issue_node_bootstrap(
        State(state.clone()),
        headers,
        Json(super::NodeBootstrapIssueRequest {
            node_id: Some(requested_node_id),
            mode: Some(transport_sdk::NodeBootstrapMode::Cluster),
            data_dir: Some("./data/node-b".to_string()),
            bind_addr: Some("127.0.0.1:28080".to_string()),
            public_url: Some("https://node-b.example".to_string()),
            labels: Some(HashMap::from([("rack".to_string(), "rack-b".to_string())])),
            public_tls: Some(transport_sdk::BootstrapServerTlsFiles {
                cert_path: "tls/public.pem".to_string(),
                key_path: "tls/public.key".to_string(),
            }),
            public_ca_cert_path: Some("tls/public-ca.pem".to_string()),
            public_peer_api_enabled: Some(true),
            internal_bind_addr: Some("127.0.0.1:38080".to_string()),
            internal_url: Some("https://10.0.0.12:38080".to_string()),
            internal_tls: Some(transport_sdk::BootstrapTlsFiles {
                ca_cert_path: "tls/cluster-ca.pem".to_string(),
                cert_path: "tls/internal.pem".to_string(),
                key_path: "tls/internal.key".to_string(),
            }),
            upstream_public_url: Some("https://upstream.example".to_string()),
            enrollment_issuer_url: None,
            tls_validity_secs: None,
            tls_renewal_window_secs: None,
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let bootstrap: transport_sdk::NodeBootstrap = serde_json::from_slice(&body).unwrap();

    assert_eq!(bootstrap.node_id, requested_node_id);
    assert_eq!(bootstrap.cluster_id, state.cluster_id);
    assert_eq!(
        bootstrap.rendezvous_urls,
        vec!["https://rendezvous.example".to_string()]
    );
    assert!(bootstrap.rendezvous_mtls_required);
    assert_eq!(bootstrap.relay_mode, transport_sdk::RelayMode::Required);
    assert_eq!(
        bootstrap.trust_roots.rendezvous_ca_pem.as_deref(),
        Some("rendezvous-ca")
    );
    assert_eq!(
        bootstrap.trust_roots.public_api_ca_pem.as_deref(),
        Some("public-ca")
    );
    assert_eq!(
        bootstrap.trust_roots.cluster_ca_pem.as_deref(),
        Some("cluster-ca")
    );
    assert_eq!(
        bootstrap.public_url.as_deref(),
        Some("https://node-b.example")
    );
    assert_eq!(
        bootstrap.internal_url.as_deref(),
        Some("https://10.0.0.12:38080")
    );
    assert_eq!(
        bootstrap.enrollment_issuer_url.as_deref(),
        Some("http://127.0.0.1:39080")
    );
    assert_eq!(
        bootstrap.labels.get("rack").map(String::as_str),
        Some("rack-b")
    );
    assert_eq!(bootstrap.direct_endpoints.len(), 2);
    assert_eq!(
        bootstrap.direct_endpoints[0].usage,
        Some(transport_sdk::BootstrapEndpointUse::PublicApi)
    );
    assert_eq!(
        bootstrap.direct_endpoints[1].usage,
        Some(transport_sdk::BootstrapEndpointUse::PeerApi)
    );

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn issue_node_enrollment_includes_internal_and_public_tls_material() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let (cluster_ca_pem, internal_ca_key_pem) = generate_test_internal_ca();
    let (public_ca_pem, public_ca_key_pem) = generate_test_internal_ca();
    state.cluster_ca_pem = Some(cluster_ca_pem.clone());
    state.internal_ca_key_pem = Some(internal_ca_key_pem);
    state.public_ca_pem = Some(public_ca_pem.clone());
    state.public_ca_key_pem = Some(public_ca_key_pem);
    state.rendezvous_ca_pem = Some("rendezvous-ca".to_string());
    state.rendezvous_urls = vec!["https://rendezvous.example".to_string()];
    state.rendezvous_registration_enabled = true;
    state.rendezvous_mtls_required = true;

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let response = super::issue_node_enrollment(
        State(state.clone()),
        headers,
        Json(super::NodeBootstrapIssueRequest {
            node_id: Some(NodeId::new_v4()),
            mode: Some(transport_sdk::NodeBootstrapMode::Cluster),
            data_dir: Some("./data/node-b".to_string()),
            bind_addr: Some("127.0.0.1:28080".to_string()),
            public_url: Some("https://node-b.example".to_string()),
            labels: None,
            public_tls: Some(transport_sdk::BootstrapServerTlsFiles {
                cert_path: "tls/public.pem".to_string(),
                key_path: "tls/public.key".to_string(),
            }),
            public_ca_cert_path: Some("tls/public-ca.pem".to_string()),
            public_peer_api_enabled: Some(false),
            internal_bind_addr: Some("127.0.0.1:38080".to_string()),
            internal_url: Some("https://127.0.0.1:38080".to_string()),
            internal_tls: Some(transport_sdk::BootstrapTlsFiles {
                ca_cert_path: "tls/cluster-ca.pem".to_string(),
                cert_path: "tls/internal.pem".to_string(),
                key_path: "tls/internal.key".to_string(),
            }),
            upstream_public_url: None,
            enrollment_issuer_url: None,
            tls_validity_secs: None,
            tls_renewal_window_secs: None,
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let package: transport_sdk::NodeEnrollmentPackage = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        package
            .internal_tls_material
            .as_ref()
            .map(|material| material.ca_cert_pem.as_str()),
        Some(cluster_ca_pem.as_str())
    );
    assert!(
        package
            .internal_tls_material
            .as_ref()
            .unwrap()
            .cert_pem
            .contains("BEGIN CERTIFICATE")
    );
    assert!(
        package
            .internal_tls_material
            .as_ref()
            .unwrap()
            .key_pem
            .contains("PRIVATE KEY")
    );
    let internal_metadata = &package.internal_tls_material.as_ref().unwrap().metadata;
    assert!(internal_metadata.not_after_unix > internal_metadata.issued_at_unix);
    assert!(internal_metadata.renew_after_unix >= internal_metadata.issued_at_unix);
    assert!(!internal_metadata.certificate_fingerprint.is_empty());
    assert_eq!(
        package
            .public_tls_material
            .as_ref()
            .map(|material| material.ca_cert_pem.as_str()),
        Some(public_ca_pem.as_str())
    );
    assert!(
        package
            .public_tls_material
            .as_ref()
            .unwrap()
            .cert_pem
            .contains("BEGIN CERTIFICATE")
    );
    let public_metadata = &package.public_tls_material.as_ref().unwrap().metadata;
    assert!(public_metadata.not_after_unix > public_metadata.issued_at_unix);
    assert!(public_metadata.renew_after_unix >= public_metadata.issued_at_unix);
    assert!(!public_metadata.certificate_fingerprint.is_empty());

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn issue_node_enrollment_allows_local_edge_with_public_tls_only() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let (public_ca_pem, public_ca_key_pem) = generate_test_internal_ca();
    state.public_ca_pem = Some(public_ca_pem);
    state.public_ca_key_pem = Some(public_ca_key_pem);
    state.rendezvous_urls = vec!["https://rendezvous.example".to_string()];
    state.rendezvous_registration_enabled = true;

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let response = super::issue_node_enrollment(
        State(state.clone()),
        headers,
        Json(super::NodeBootstrapIssueRequest {
            node_id: Some(NodeId::new_v4()),
            mode: Some(transport_sdk::NodeBootstrapMode::LocalEdge),
            data_dir: Some("./data/edge-node".to_string()),
            bind_addr: Some("127.0.0.1:28080".to_string()),
            public_url: Some("https://edge.example".to_string()),
            labels: None,
            public_tls: Some(transport_sdk::BootstrapServerTlsFiles {
                cert_path: "tls/public.pem".to_string(),
                key_path: "tls/public.key".to_string(),
            }),
            public_ca_cert_path: Some("tls/public-ca.pem".to_string()),
            public_peer_api_enabled: Some(false),
            internal_bind_addr: None,
            internal_url: None,
            internal_tls: None,
            upstream_public_url: None,
            enrollment_issuer_url: None,
            tls_validity_secs: None,
            tls_renewal_window_secs: None,
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let package: transport_sdk::NodeEnrollmentPackage = serde_json::from_slice(&body).unwrap();

    assert!(package.public_tls_material.is_some());
    assert!(package.internal_tls_material.is_none());

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn server_node_config_loads_from_node_enrollment_file_and_materializes_tls_files() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    let (cluster_ca_pem, internal_ca_key_pem) = generate_test_internal_ca();
    let (public_ca_pem, public_ca_key_pem) = generate_test_internal_ca();
    state.cluster_ca_pem = Some(cluster_ca_pem);
    state.internal_ca_key_pem = Some(internal_ca_key_pem);
    state.public_ca_pem = Some(public_ca_pem.clone());
    state.public_ca_key_pem = Some(public_ca_key_pem);

    let root = fresh_test_dir("node-enrollment-config");
    let package_path = root.join("node-enrollment.json");
    let internal_bind_addr = free_bind_addr();
    let bootstrap = transport_sdk::NodeBootstrap {
        version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
        cluster_id: state.cluster_id,
        node_id: NodeId::new_v4(),
        mode: transport_sdk::NodeBootstrapMode::Cluster,
        data_dir: root.join("data").to_string_lossy().into_owned(),
        bind_addr: free_bind_addr().to_string(),
        public_url: Some("https://node-b.example".to_string()),
        labels: HashMap::new(),
        public_tls: Some(transport_sdk::BootstrapServerTlsFiles {
            cert_path: "tls/public.pem".to_string(),
            key_path: "tls/public.key".to_string(),
        }),
        public_ca_cert_path: Some("tls/public-ca.pem".to_string()),
        public_peer_api_enabled: false,
        internal_bind_addr: Some(internal_bind_addr.to_string()),
        internal_url: Some(format!("https://127.0.0.1:{}", internal_bind_addr.port())),
        internal_tls: Some(transport_sdk::BootstrapTlsFiles {
            ca_cert_path: "tls/cluster-ca.pem".to_string(),
            cert_path: "tls/internal.pem".to_string(),
            key_path: "tls/internal.key".to_string(),
        }),
        rendezvous_urls: vec!["https://rendezvous.example".to_string()],
        rendezvous_mtls_required: false,
        direct_endpoints: Vec::new(),
        relay_mode: transport_sdk::RelayMode::Fallback,
        trust_roots: transport_sdk::BootstrapTrustRoots {
            cluster_ca_pem: state.cluster_ca_pem.clone(),
            public_api_ca_pem: state.public_ca_pem.clone(),
            rendezvous_ca_pem: None,
        },
        upstream_public_url: None,
        enrollment_issuer_url: Some("https://issuer.example".to_string()),
    };
    let issue_policy = default_tls_issue_policy();
    let internal_material =
        super::issue_internal_node_tls_material(&state, &bootstrap, issue_policy).unwrap();
    let public_material = super::issue_public_node_tls_material(&state, &bootstrap, issue_policy)
        .unwrap()
        .unwrap();
    transport_sdk::NodeEnrollmentPackage {
        bootstrap,
        public_tls_material: Some(public_material.clone()),
        internal_tls_material: Some(internal_material.clone()),
    }
    .write_to_path(&package_path)
    .unwrap();

    let config = super::ServerNodeConfig::from_enrollment_path(&package_path).unwrap();
    let internal_tls = config.internal_tls.as_ref().unwrap();
    let public_tls = config.public_tls.as_ref().unwrap();
    let internal_metadata_path = internal_tls.metadata_path.as_ref().unwrap();
    let public_metadata_path = public_tls.metadata_path.as_ref().unwrap();

    assert!(internal_tls.ca_cert_path.exists());
    assert!(internal_tls.cert_path.exists());
    assert!(internal_tls.key_path.exists());
    assert!(internal_metadata_path.exists());
    assert_eq!(
        std::fs::read_to_string(&internal_tls.ca_cert_path).unwrap(),
        internal_material.ca_cert_pem
    );
    assert!(public_tls.cert_path.exists());
    assert!(public_tls.key_path.exists());
    assert!(public_metadata_path.exists());
    assert_eq!(
        std::fs::read_to_string(&public_tls.cert_path).unwrap(),
        public_material.cert_pem
    );
    assert_eq!(
        std::fs::read_to_string(config.public_ca_cert_path.as_ref().unwrap()).unwrap(),
        public_material.ca_cert_pem
    );
    let stored_internal_metadata: transport_sdk::BootstrapTlsMaterialMetadata =
        serde_json::from_str(&std::fs::read_to_string(internal_metadata_path).unwrap()).unwrap();
    let stored_public_metadata: transport_sdk::BootstrapTlsMaterialMetadata =
        serde_json::from_str(&std::fs::read_to_string(public_metadata_path).unwrap()).unwrap();
    assert_eq!(stored_internal_metadata, internal_material.metadata);
    assert_eq!(stored_public_metadata, public_material.metadata);

    cleanup_test_state(&state).await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn node_bootstrap_file_can_start_local_edge_node() {
    let root = fresh_test_dir("node-bootstrap-startup");
    let bootstrap_path = root.join("node-bootstrap.json");
    let bind_addr = free_bind_addr();
    let public_url = format!("http://{bind_addr}");

    transport_sdk::NodeBootstrap {
        version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
        cluster_id: uuid::Uuid::now_v7(),
        node_id: NodeId::new_v4(),
        mode: transport_sdk::NodeBootstrapMode::LocalEdge,
        data_dir: root.join("data").to_string_lossy().into_owned(),
        bind_addr: bind_addr.to_string(),
        public_url: Some(public_url.clone()),
        labels: HashMap::new(),
        public_tls: None,
        public_ca_cert_path: None,
        public_peer_api_enabled: false,
        internal_bind_addr: None,
        internal_url: None,
        internal_tls: None,
        rendezvous_urls: vec!["http://127.0.0.1:9".to_string()],
        rendezvous_mtls_required: false,
        direct_endpoints: vec![transport_sdk::BootstrapEndpoint {
            url: public_url.clone(),
            usage: Some(transport_sdk::BootstrapEndpointUse::PublicApi),
        }],
        relay_mode: transport_sdk::RelayMode::Fallback,
        trust_roots: transport_sdk::BootstrapTrustRoots {
            cluster_ca_pem: None,
            public_api_ca_pem: None,
            rendezvous_ca_pem: None,
        },
        upstream_public_url: None,
        enrollment_issuer_url: None,
    }
    .write_to_path(&bootstrap_path)
    .unwrap();

    let config = super::ServerNodeConfig::from_bootstrap_path(&bootstrap_path).unwrap();
    let http = reqwest::Client::new();
    let handle = tokio::spawn(async move { super::run(config).await });

    wait_for_http_status(
        &http,
        &format!("{public_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    handle.abort();
    let _ = handle.await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn node_enrollment_file_can_start_cluster_node_with_public_and_internal_tls() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    let (cluster_ca_pem, internal_ca_key_pem) = generate_test_internal_ca();
    let (public_ca_pem, public_ca_key_pem) = generate_test_internal_ca();
    state.cluster_ca_pem = Some(cluster_ca_pem);
    state.internal_ca_key_pem = Some(internal_ca_key_pem);
    state.public_ca_pem = Some(public_ca_pem.clone());
    state.public_ca_key_pem = Some(public_ca_key_pem);

    let root = fresh_test_dir("node-enrollment-startup");
    let package_path = root.join("node-enrollment.json");
    let bind_addr = free_bind_addr();
    let internal_bind_addr = free_bind_addr();
    let public_url = format!("https://127.0.0.1:{}", bind_addr.port());
    let internal_url = format!("https://127.0.0.1:{}", internal_bind_addr.port());
    let bootstrap = transport_sdk::NodeBootstrap {
        version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
        cluster_id: state.cluster_id,
        node_id: NodeId::new_v4(),
        mode: transport_sdk::NodeBootstrapMode::Cluster,
        data_dir: root.join("data").to_string_lossy().into_owned(),
        bind_addr: bind_addr.to_string(),
        public_url: Some(public_url.clone()),
        labels: HashMap::new(),
        public_tls: Some(transport_sdk::BootstrapServerTlsFiles {
            cert_path: "tls/public.pem".to_string(),
            key_path: "tls/public.key".to_string(),
        }),
        public_ca_cert_path: Some("tls/public-ca.pem".to_string()),
        public_peer_api_enabled: false,
        internal_bind_addr: Some(internal_bind_addr.to_string()),
        internal_url: Some(internal_url.clone()),
        internal_tls: Some(transport_sdk::BootstrapTlsFiles {
            ca_cert_path: "tls/cluster-ca.pem".to_string(),
            cert_path: "tls/internal.pem".to_string(),
            key_path: "tls/internal.key".to_string(),
        }),
        rendezvous_urls: vec!["http://127.0.0.1:9".to_string()],
        rendezvous_mtls_required: false,
        direct_endpoints: vec![transport_sdk::BootstrapEndpoint {
            url: public_url.clone(),
            usage: Some(transport_sdk::BootstrapEndpointUse::PublicApi),
        }],
        relay_mode: transport_sdk::RelayMode::Fallback,
        trust_roots: transport_sdk::BootstrapTrustRoots {
            cluster_ca_pem: state.cluster_ca_pem.clone(),
            public_api_ca_pem: state.public_ca_pem.clone(),
            rendezvous_ca_pem: None,
        },
        upstream_public_url: None,
        enrollment_issuer_url: Some("https://issuer.example".to_string()),
    };
    let issue_policy = default_tls_issue_policy();
    let internal_material =
        super::issue_internal_node_tls_material(&state, &bootstrap, issue_policy).unwrap();
    let public_material = super::issue_public_node_tls_material(&state, &bootstrap, issue_policy)
        .unwrap()
        .unwrap();
    transport_sdk::NodeEnrollmentPackage {
        bootstrap,
        public_tls_material: Some(public_material),
        internal_tls_material: Some(internal_material),
    }
    .write_to_path(&package_path)
    .unwrap();
    cleanup_test_state(&state).await;

    let config = super::ServerNodeConfig::from_enrollment_path(&package_path).unwrap();
    let internal_tls = config.internal_tls.clone().unwrap();
    let internal_http = super::build_internal_mtls_http_client(
        &internal_tls.ca_cert_path,
        &internal_tls.cert_path,
        &internal_tls.key_path,
    )
    .unwrap();
    let public_http = super::build_http_client_from_optional_pem(Some(&public_ca_pem)).unwrap();
    let handle = tokio::spawn(async move { super::run(config).await });

    wait_for_http_status(
        &public_http,
        &format!("{public_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;
    wait_for_http_status(
        &internal_http,
        &format!("{internal_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    handle.abort();
    let _ = handle.await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn renew_node_enrollment_reissues_tls_material_with_new_fingerprints() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let (cluster_ca_pem, internal_ca_key_pem) = generate_test_internal_ca();
    let (public_ca_pem, public_ca_key_pem) = generate_test_internal_ca();
    state.cluster_ca_pem = Some(cluster_ca_pem);
    state.internal_ca_key_pem = Some(internal_ca_key_pem);
    state.public_ca_pem = Some(public_ca_pem);
    state.public_ca_key_pem = Some(public_ca_key_pem);
    state.rendezvous_urls = vec!["https://rendezvous.example".to_string()];
    state.rendezvous_registration_enabled = true;

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());
    let issued = super::issue_node_enrollment(
        State(state.clone()),
        headers.clone(),
        Json(super::NodeBootstrapIssueRequest {
            node_id: Some(NodeId::new_v4()),
            mode: Some(transport_sdk::NodeBootstrapMode::Cluster),
            data_dir: Some("./data/node-renew".to_string()),
            bind_addr: Some("127.0.0.1:28080".to_string()),
            public_url: Some("https://node-renew.example".to_string()),
            labels: None,
            public_tls: Some(transport_sdk::BootstrapServerTlsFiles {
                cert_path: "tls/public.pem".to_string(),
                key_path: "tls/public.key".to_string(),
            }),
            public_ca_cert_path: Some("tls/public-ca.pem".to_string()),
            public_peer_api_enabled: Some(false),
            internal_bind_addr: Some("127.0.0.1:38080".to_string()),
            internal_url: Some("https://127.0.0.1:38080".to_string()),
            internal_tls: Some(transport_sdk::BootstrapTlsFiles {
                ca_cert_path: "tls/cluster-ca.pem".to_string(),
                cert_path: "tls/internal.pem".to_string(),
                key_path: "tls/internal.key".to_string(),
            }),
            upstream_public_url: None,
            enrollment_issuer_url: Some("https://issuer.example".to_string()),
            tls_validity_secs: Some(7 * 24 * 60 * 60),
            tls_renewal_window_secs: Some(24 * 60 * 60),
        }),
    )
    .await
    .into_response();
    assert_eq!(issued.status(), StatusCode::CREATED);
    let issued_body = to_bytes(issued.into_body(), usize::MAX).await.unwrap();
    let package: transport_sdk::NodeEnrollmentPackage =
        serde_json::from_slice(&issued_body).unwrap();

    let renewed = super::renew_node_enrollment(
        State(state.clone()),
        headers,
        Json(super::NodeEnrollmentRenewRequest {
            package: package.clone(),
            tls_validity_secs: Some(14 * 24 * 60 * 60),
            tls_renewal_window_secs: Some(2 * 24 * 60 * 60),
        }),
    )
    .await
    .into_response();
    assert_eq!(renewed.status(), StatusCode::CREATED);
    let renewed_body = to_bytes(renewed.into_body(), usize::MAX).await.unwrap();
    let renewed_package: transport_sdk::NodeEnrollmentPackage =
        serde_json::from_slice(&renewed_body).unwrap();

    assert_eq!(renewed_package.bootstrap.node_id, package.bootstrap.node_id);
    assert_ne!(
        renewed_package
            .internal_tls_material
            .as_ref()
            .unwrap()
            .metadata
            .certificate_fingerprint,
        package
            .internal_tls_material
            .as_ref()
            .unwrap()
            .metadata
            .certificate_fingerprint
    );
    assert_ne!(
        renewed_package
            .public_tls_material
            .as_ref()
            .unwrap()
            .metadata
            .certificate_fingerprint,
        package
            .public_tls_material
            .as_ref()
            .unwrap()
            .metadata
            .certificate_fingerprint
    );
    assert!(
        renewed_package
            .internal_tls_material
            .as_ref()
            .unwrap()
            .metadata
            .not_after_unix
            > package
                .internal_tls_material
                .as_ref()
                .unwrap()
                .metadata
                .not_after_unix
    );

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn automatic_node_enrollment_renewal_live_reloads_tls_and_clears_restart_required() {
    let root = fresh_test_dir("node-auto-renew");
    let issuer_dir = root.join("issuer");
    let issuer_bind_addr = free_bind_addr();
    let issuer_public_url = format!("http://{issuer_bind_addr}");
    let (cluster_ca_pem, internal_ca_key_pem) = generate_test_internal_ca();
    let cluster_ca_path = issuer_dir.join("cluster-ca.pem");
    let cluster_ca_key_path = issuer_dir.join("cluster-ca.key");
    std::fs::create_dir_all(&issuer_dir).unwrap();
    std::fs::write(&cluster_ca_path, &cluster_ca_pem).unwrap();
    std::fs::write(&cluster_ca_key_path, &internal_ca_key_pem).unwrap();

    let mut issuer_config = super::ServerNodeConfig::local_edge(&issuer_dir, issuer_bind_addr);
    issuer_config.admin_token = Some("admin-secret".to_string());
    issuer_config.public_url = Some(issuer_public_url.clone());
    issuer_config.public_ca_cert_path = Some(cluster_ca_path.clone());
    issuer_config.internal_ca_key_path = Some(cluster_ca_key_path.clone());
    let issuer_handle = tokio::spawn(async move { super::run(issuer_config).await });
    let http = reqwest::Client::new();
    wait_for_http_status(
        &http,
        &format!("{issuer_public_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.cluster_ca_pem = Some(cluster_ca_pem.clone());
    state.internal_ca_key_pem = Some(internal_ca_key_pem.clone());
    let package_path = root.join("node-enrollment.json");
    let internal_bind_addr = free_bind_addr();
    let bootstrap = transport_sdk::NodeBootstrap {
        version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
        cluster_id: state.cluster_id,
        node_id: NodeId::new_v4(),
        mode: transport_sdk::NodeBootstrapMode::Cluster,
        data_dir: root.join("node").to_string_lossy().into_owned(),
        bind_addr: free_bind_addr().to_string(),
        public_url: Some("https://node-auto-renew.example".to_string()),
        labels: HashMap::new(),
        public_tls: Some(transport_sdk::BootstrapServerTlsFiles {
            cert_path: "tls/public.pem".to_string(),
            key_path: "tls/public.key".to_string(),
        }),
        public_ca_cert_path: Some("tls/public-ca.pem".to_string()),
        public_peer_api_enabled: false,
        internal_bind_addr: Some(internal_bind_addr.to_string()),
        internal_url: Some(format!("https://127.0.0.1:{}", internal_bind_addr.port())),
        internal_tls: Some(transport_sdk::BootstrapTlsFiles {
            ca_cert_path: "tls/cluster-ca.pem".to_string(),
            cert_path: "tls/internal.pem".to_string(),
            key_path: "tls/internal.key".to_string(),
        }),
        rendezvous_urls: vec!["https://rendezvous.example".to_string()],
        rendezvous_mtls_required: false,
        direct_endpoints: Vec::new(),
        relay_mode: transport_sdk::RelayMode::Fallback,
        trust_roots: transport_sdk::BootstrapTrustRoots {
            cluster_ca_pem: Some(cluster_ca_pem.clone()),
            public_api_ca_pem: None,
            rendezvous_ca_pem: None,
        },
        upstream_public_url: None,
        enrollment_issuer_url: Some(issuer_public_url.clone()),
    };
    let issue_policy = default_tls_issue_policy();
    let mut internal_material =
        super::issue_internal_node_tls_material(&state, &bootstrap, issue_policy).unwrap();
    let mut public_material =
        super::issue_public_node_tls_material(&state, &bootstrap, issue_policy)
            .unwrap()
            .unwrap();
    internal_material.metadata.renew_after_unix = super::unix_ts().saturating_sub(1);
    public_material.metadata.renew_after_unix = super::unix_ts().saturating_sub(1);
    transport_sdk::NodeEnrollmentPackage {
        bootstrap,
        public_tls_material: Some(public_material.clone()),
        internal_tls_material: Some(internal_material.clone()),
    }
    .write_to_path(&package_path)
    .unwrap();

    let mut config = super::ServerNodeConfig::from_enrollment_path(&package_path).unwrap();
    config.enrollment_issuer_url = Some(issuer_public_url);
    config.node_enrollment_auto_renew_enabled = true;
    config.node_enrollment_renewal_admin_token = Some("admin-secret".to_string());
    let loaded_public_fingerprint =
        super::parse_certificate_details_from_path(&config.public_tls.as_ref().unwrap().cert_path)
            .unwrap()
            .certificate_fingerprint;
    let loaded_internal_fingerprint = super::parse_certificate_details_from_path(
        &config.internal_tls.as_ref().unwrap().cert_path,
    )
    .unwrap()
    .certificate_fingerprint;

    state.enrollment_issuer_url = config.enrollment_issuer_url.clone();
    state.node_enrollment_path = Some(package_path.clone());
    state.node_enrollment_auto_renew_enabled = true;
    state.public_tls_runtime = Some(super::PublicTlsRuntime {
        config: axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &config.public_tls.as_ref().unwrap().cert_path,
            &config.public_tls.as_ref().unwrap().key_path,
        )
        .await
        .unwrap(),
        cert_path: config.public_tls.as_ref().unwrap().cert_path.clone(),
        key_path: config.public_tls.as_ref().unwrap().key_path.clone(),
        metadata_path: config.public_tls.as_ref().unwrap().metadata_path.clone(),
    });
    state.internal_tls_runtime = Some(super::InternalTlsRuntime {
        config: super::build_internal_mtls_rustls_config(
            &config.internal_tls.as_ref().unwrap().ca_cert_path,
            &config.internal_tls.as_ref().unwrap().cert_path,
            &config.internal_tls.as_ref().unwrap().key_path,
        )
        .unwrap(),
        ca_cert_path: config.internal_tls.as_ref().unwrap().ca_cert_path.clone(),
        cert_path: config.internal_tls.as_ref().unwrap().cert_path.clone(),
        key_path: config.internal_tls.as_ref().unwrap().key_path.clone(),
        metadata_path: config.internal_tls.as_ref().unwrap().metadata_path.clone(),
    });
    {
        let mut renewal_state = state.node_enrollment_auto_renew_state.lock().await;
        renewal_state.loaded_public_tls_fingerprint = Some(loaded_public_fingerprint.clone());
        renewal_state.loaded_internal_tls_fingerprint = Some(loaded_internal_fingerprint.clone());
    }
    let public_config_before = state
        .public_tls_runtime
        .as_ref()
        .unwrap()
        .config
        .get_inner();
    let internal_config_before = state
        .internal_tls_runtime
        .as_ref()
        .unwrap()
        .config
        .get_inner();

    assert!(
        super::renew_node_enrollment_package_if_due(&config)
            .await
            .unwrap()
    );
    super::reload_live_tls_from_disk(&state).await.unwrap();

    let renewed_package = transport_sdk::NodeEnrollmentPackage::from_path(&package_path).unwrap();
    let renewed_public_fingerprint = renewed_package
        .public_tls_material
        .as_ref()
        .unwrap()
        .metadata
        .certificate_fingerprint
        .clone();
    let renewed_internal_fingerprint = renewed_package
        .internal_tls_material
        .as_ref()
        .unwrap()
        .metadata
        .certificate_fingerprint
        .clone();
    assert_ne!(
        renewed_internal_fingerprint,
        internal_material.metadata.certificate_fingerprint
    );
    assert_ne!(
        renewed_public_fingerprint,
        public_material.metadata.certificate_fingerprint
    );
    assert!(!Arc::ptr_eq(
        &public_config_before,
        &state
            .public_tls_runtime
            .as_ref()
            .unwrap()
            .config
            .get_inner()
    ));
    assert!(!Arc::ptr_eq(
        &internal_config_before,
        &state
            .internal_tls_runtime
            .as_ref()
            .unwrap()
            .config
            .get_inner()
    ));

    let auto_renew_state = state.node_enrollment_auto_renew_state.lock().await.clone();
    let status = super::collect_node_certificate_status(
        state
            .public_tls_runtime
            .as_ref()
            .map(|tls| tls.cert_path.as_path()),
        state
            .public_tls_runtime
            .as_ref()
            .and_then(|tls| tls.metadata_path.as_deref()),
        state
            .internal_tls_runtime
            .as_ref()
            .map(|tls| tls.cert_path.as_path()),
        state
            .internal_tls_runtime
            .as_ref()
            .and_then(|tls| tls.metadata_path.as_deref()),
        super::NodeCertificateAutoRenewStatusView {
            enabled: true,
            enrollment_path: Some(package_path.display().to_string()),
            issuer_url: config.enrollment_issuer_url.clone(),
            check_interval_secs: Some(config.node_enrollment_auto_renew_check_secs),
            last_attempt_unix: Some(super::unix_ts()),
            last_success_unix: Some(super::unix_ts()),
            last_error: None,
            restart_required: false,
        },
    );
    assert!(super::node_certificate_restart_required(
        &status.public_tls,
        &status.internal_tls,
        Some(loaded_public_fingerprint.as_str()),
        Some(loaded_internal_fingerprint.as_str()),
    ));
    assert!(!super::node_certificate_restart_required(
        &status.public_tls,
        &status.internal_tls,
        auto_renew_state.loaded_public_tls_fingerprint.as_deref(),
        auto_renew_state.loaded_internal_tls_fingerprint.as_deref(),
    ));
    assert_eq!(
        auto_renew_state.loaded_public_tls_fingerprint,
        Some(renewed_public_fingerprint)
    );
    assert_eq!(
        auto_renew_state.loaded_internal_tls_fingerprint,
        Some(renewed_internal_fingerprint)
    );

    cleanup_test_state(&state).await;
    issuer_handle.abort();
    let _ = issuer_handle.await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn automatic_node_enrollment_renewal_rotates_served_public_and_internal_certificates() {
    let root = fresh_test_dir("node-auto-renew-served-certs");
    let issuer_dir = root.join("issuer");
    let issuer_bind_addr = free_bind_addr();
    let issuer_public_url = format!("http://{issuer_bind_addr}");
    let (cluster_ca_pem, internal_ca_key_pem) = generate_test_internal_ca();
    let cluster_ca_path = issuer_dir.join("cluster-ca.pem");
    let cluster_ca_key_path = issuer_dir.join("cluster-ca.key");
    std::fs::create_dir_all(&issuer_dir).unwrap();
    std::fs::write(&cluster_ca_path, &cluster_ca_pem).unwrap();
    std::fs::write(&cluster_ca_key_path, &internal_ca_key_pem).unwrap();

    let mut issuer_config = super::ServerNodeConfig::local_edge(&issuer_dir, issuer_bind_addr);
    issuer_config.admin_token = Some("admin-secret".to_string());
    issuer_config.public_url = Some(issuer_public_url.clone());
    issuer_config.public_ca_cert_path = Some(cluster_ca_path.clone());
    issuer_config.internal_ca_key_path = Some(cluster_ca_key_path.clone());
    let issuer_handle = tokio::spawn(async move { super::run(issuer_config).await });
    let issuer_http = reqwest::Client::new();
    wait_for_http_status(
        &issuer_http,
        &format!("{issuer_public_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.cluster_ca_pem = Some(cluster_ca_pem.clone());
    state.internal_ca_key_pem = Some(internal_ca_key_pem.clone());

    let package_path = root.join("node-enrollment.json");
    let bind_addr = free_bind_addr();
    let internal_bind_addr = free_bind_addr();
    let bootstrap = transport_sdk::NodeBootstrap {
        version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
        cluster_id: state.cluster_id,
        node_id: NodeId::new_v4(),
        mode: transport_sdk::NodeBootstrapMode::Cluster,
        data_dir: root.join("node").to_string_lossy().into_owned(),
        bind_addr: bind_addr.to_string(),
        public_url: Some(format!("https://{bind_addr}")),
        labels: HashMap::new(),
        public_tls: Some(transport_sdk::BootstrapServerTlsFiles {
            cert_path: "tls/public.pem".to_string(),
            key_path: "tls/public.key".to_string(),
        }),
        public_ca_cert_path: Some("tls/public-ca.pem".to_string()),
        public_peer_api_enabled: false,
        internal_bind_addr: Some(internal_bind_addr.to_string()),
        internal_url: Some(format!("https://{internal_bind_addr}")),
        internal_tls: Some(transport_sdk::BootstrapTlsFiles {
            ca_cert_path: "tls/cluster-ca.pem".to_string(),
            cert_path: "tls/internal.pem".to_string(),
            key_path: "tls/internal.key".to_string(),
        }),
        rendezvous_urls: vec!["https://rendezvous.example".to_string()],
        rendezvous_mtls_required: false,
        direct_endpoints: Vec::new(),
        relay_mode: transport_sdk::RelayMode::Fallback,
        trust_roots: transport_sdk::BootstrapTrustRoots {
            cluster_ca_pem: Some(cluster_ca_pem.clone()),
            public_api_ca_pem: None,
            rendezvous_ca_pem: None,
        },
        upstream_public_url: None,
        enrollment_issuer_url: Some(issuer_public_url.clone()),
    };
    let issue_policy = default_tls_issue_policy();
    let mut internal_material =
        super::issue_internal_node_tls_material(&state, &bootstrap, issue_policy).unwrap();
    let mut public_material =
        super::issue_public_node_tls_material(&state, &bootstrap, issue_policy)
            .unwrap()
            .unwrap();
    let renew_after_unix = super::unix_ts().saturating_add(5);
    internal_material.metadata.renew_after_unix = renew_after_unix;
    public_material.metadata.renew_after_unix = renew_after_unix;
    transport_sdk::NodeEnrollmentPackage {
        bootstrap,
        public_tls_material: Some(public_material.clone()),
        internal_tls_material: Some(internal_material.clone()),
    }
    .write_to_path(&package_path)
    .unwrap();

    let mut config = super::ServerNodeConfig::from_enrollment_path(&package_path).unwrap();
    config.enrollment_issuer_url = Some(issuer_public_url.clone());
    config.node_enrollment_auto_renew_enabled = true;
    config.node_enrollment_auto_renew_check_secs = 1;
    config.node_enrollment_renewal_admin_token = Some("admin-secret".to_string());
    let public_ca_cert_path = config.public_ca_cert_path.clone().unwrap();
    let internal_tls = config.internal_tls.clone().unwrap();
    let public_health_url = format!("https://{bind_addr}/health");
    let internal_health_url = format!("https://{internal_bind_addr}/health");
    let node_handle = tokio::spawn(async move { super::run(config).await });

    let public_http = reqwest::Client::builder()
        .add_root_certificate(
            reqwest::Certificate::from_pem(&std::fs::read(&public_ca_cert_path).unwrap()).unwrap(),
        )
        .build()
        .unwrap();
    let internal_http = super::build_internal_mtls_http_client(
        &internal_tls.ca_cert_path,
        &internal_tls.cert_path,
        &internal_tls.key_path,
    )
    .unwrap();

    wait_for_http_status(
        &public_http,
        &public_health_url,
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;
    wait_for_http_status(
        &internal_http,
        &internal_health_url,
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let initial_public_fingerprint =
        observe_peer_certificate_fingerprint(bind_addr, &public_ca_cert_path, None).await;
    let initial_internal_fingerprint = observe_peer_certificate_fingerprint(
        internal_bind_addr,
        &internal_tls.ca_cert_path,
        Some((&internal_tls.cert_path, &internal_tls.key_path)),
    )
    .await;
    assert_eq!(
        initial_public_fingerprint,
        public_material.metadata.certificate_fingerprint
    );
    assert_eq!(
        initial_internal_fingerprint,
        internal_material.metadata.certificate_fingerprint
    );

    wait_for_condition(
        "served certificate rotation",
        Duration::from_secs(20),
        || {
            let package_path = package_path.clone();
            let public_ca_cert_path = public_ca_cert_path.clone();
            let internal_ca_cert_path = internal_tls.ca_cert_path.clone();
            let internal_cert_path = internal_tls.cert_path.clone();
            let internal_key_path = internal_tls.key_path.clone();
            let initial_public_fingerprint = initial_public_fingerprint.clone();
            let initial_internal_fingerprint = initial_internal_fingerprint.clone();
            async move {
                let package = match transport_sdk::NodeEnrollmentPackage::from_path(&package_path) {
                    Ok(package) => package,
                    Err(_) => return false,
                };
                let expected_public = match package.public_tls_material.as_ref() {
                    Some(material) => material.metadata.certificate_fingerprint.clone(),
                    None => return false,
                };
                let expected_internal = match package.internal_tls_material.as_ref() {
                    Some(material) => material.metadata.certificate_fingerprint.clone(),
                    None => return false,
                };
                if expected_public == initial_public_fingerprint
                    || expected_internal == initial_internal_fingerprint
                {
                    return false;
                }

                let observed_public =
                    observe_peer_certificate_fingerprint(bind_addr, &public_ca_cert_path, None)
                        .await;
                let observed_internal = observe_peer_certificate_fingerprint(
                    internal_bind_addr,
                    &internal_ca_cert_path,
                    Some((&internal_cert_path, &internal_key_path)),
                )
                .await;
                observed_public == expected_public && observed_internal == expected_internal
            }
        },
    )
    .await;

    let renewed_package = transport_sdk::NodeEnrollmentPackage::from_path(&package_path).unwrap();
    let served_public_fingerprint =
        observe_peer_certificate_fingerprint(bind_addr, &public_ca_cert_path, None).await;
    let served_internal_fingerprint = observe_peer_certificate_fingerprint(
        internal_bind_addr,
        &internal_tls.ca_cert_path,
        Some((&internal_tls.cert_path, &internal_tls.key_path)),
    )
    .await;
    assert_ne!(served_public_fingerprint, initial_public_fingerprint);
    assert_ne!(served_internal_fingerprint, initial_internal_fingerprint);
    assert_eq!(
        served_public_fingerprint,
        renewed_package
            .public_tls_material
            .as_ref()
            .unwrap()
            .metadata
            .certificate_fingerprint
    );
    assert_eq!(
        served_internal_fingerprint,
        renewed_package
            .internal_tls_material
            .as_ref()
            .unwrap()
            .metadata
            .certificate_fingerprint
    );

    wait_for_http_status(
        &public_http,
        &public_health_url,
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;
    wait_for_http_status(
        &internal_http,
        &internal_health_url,
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    cleanup_test_state(&state).await;
    node_handle.abort();
    let _ = node_handle.await;
    issuer_handle.abort();
    let _ = issuer_handle.await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn live_tls_reload_rebuilds_outbound_internal_and_rendezvous_clients() {
    let root = fresh_test_dir("node-auto-renew-outbound-clients");
    let issuer_dir = root.join("issuer");
    let issuer_bind_addr = free_bind_addr();
    let issuer_public_url = format!("http://{issuer_bind_addr}");
    let (cluster_ca_pem, internal_ca_key_pem) = generate_test_internal_ca();
    let cluster_ca_path = issuer_dir.join("cluster-ca.pem");
    let cluster_ca_key_path = issuer_dir.join("cluster-ca.key");
    std::fs::create_dir_all(&issuer_dir).unwrap();
    std::fs::write(&cluster_ca_path, &cluster_ca_pem).unwrap();
    std::fs::write(&cluster_ca_key_path, &internal_ca_key_pem).unwrap();

    let mut issuer_config = super::ServerNodeConfig::local_edge(&issuer_dir, issuer_bind_addr);
    issuer_config.admin_token = Some("admin-secret".to_string());
    issuer_config.public_url = Some(issuer_public_url.clone());
    issuer_config.public_ca_cert_path = Some(cluster_ca_path.clone());
    issuer_config.internal_ca_key_path = Some(cluster_ca_key_path.clone());
    let issuer_handle = tokio::spawn(async move { super::run(issuer_config).await });
    let issuer_http = reqwest::Client::new();
    wait_for_http_status(
        &issuer_http,
        &format!("{issuer_public_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.cluster_ca_pem = Some(cluster_ca_pem.clone());
    state.internal_ca_key_pem = Some(internal_ca_key_pem.clone());
    state.rendezvous_ca_pem = Some(cluster_ca_pem.clone());

    let package_path = root.join("node-enrollment.json");
    let internal_bind_addr = free_bind_addr();
    let bootstrap = transport_sdk::NodeBootstrap {
        version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
        cluster_id: state.cluster_id,
        node_id: NodeId::new_v4(),
        mode: transport_sdk::NodeBootstrapMode::Cluster,
        data_dir: root.join("node").to_string_lossy().into_owned(),
        bind_addr: free_bind_addr().to_string(),
        public_url: None,
        labels: HashMap::new(),
        public_tls: None,
        public_ca_cert_path: None,
        public_peer_api_enabled: false,
        internal_bind_addr: Some(internal_bind_addr.to_string()),
        internal_url: Some(format!("https://{internal_bind_addr}")),
        internal_tls: Some(transport_sdk::BootstrapTlsFiles {
            ca_cert_path: "tls/cluster-ca.pem".to_string(),
            cert_path: "tls/internal.pem".to_string(),
            key_path: "tls/internal.key".to_string(),
        }),
        rendezvous_urls: vec!["https://rendezvous.example".to_string()],
        rendezvous_mtls_required: true,
        direct_endpoints: Vec::new(),
        relay_mode: transport_sdk::RelayMode::Fallback,
        trust_roots: transport_sdk::BootstrapTrustRoots {
            cluster_ca_pem: Some(cluster_ca_pem.clone()),
            public_api_ca_pem: None,
            rendezvous_ca_pem: Some(cluster_ca_pem.clone()),
        },
        upstream_public_url: None,
        enrollment_issuer_url: Some(issuer_public_url.clone()),
    };
    let issue_policy = default_tls_issue_policy();
    let mut internal_material =
        super::issue_internal_node_tls_material(&state, &bootstrap, issue_policy).unwrap();
    internal_material.metadata.renew_after_unix = super::unix_ts().saturating_sub(1);
    transport_sdk::NodeEnrollmentPackage {
        bootstrap,
        public_tls_material: None,
        internal_tls_material: Some(internal_material.clone()),
    }
    .write_to_path(&package_path)
    .unwrap();

    let mut config = super::ServerNodeConfig::from_enrollment_path(&package_path).unwrap();
    config.enrollment_issuer_url = Some(issuer_public_url.clone());
    config.node_enrollment_auto_renew_enabled = true;
    config.node_enrollment_renewal_admin_token = Some("admin-secret".to_string());
    let internal_tls = config.internal_tls.clone().unwrap();
    let initial_internal_fingerprint =
        super::parse_certificate_details_from_path(&internal_tls.cert_path)
            .unwrap()
            .certificate_fingerprint;

    let capture_dir = root.join("capture");
    std::fs::create_dir_all(&capture_dir).unwrap();
    let capture_bind_addr = free_bind_addr();
    let capture_bootstrap = transport_sdk::NodeBootstrap {
        version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
        cluster_id: state.cluster_id,
        node_id: NodeId::new_v4(),
        mode: transport_sdk::NodeBootstrapMode::Cluster,
        data_dir: capture_dir.to_string_lossy().into_owned(),
        bind_addr: free_bind_addr().to_string(),
        public_url: None,
        labels: HashMap::new(),
        public_tls: None,
        public_ca_cert_path: None,
        public_peer_api_enabled: false,
        internal_bind_addr: Some(capture_bind_addr.to_string()),
        internal_url: Some(format!("https://{capture_bind_addr}")),
        internal_tls: Some(transport_sdk::BootstrapTlsFiles {
            ca_cert_path: "tls/capture-ca.pem".to_string(),
            cert_path: "tls/capture-internal.pem".to_string(),
            key_path: "tls/capture-internal.key".to_string(),
        }),
        rendezvous_urls: Vec::new(),
        rendezvous_mtls_required: true,
        direct_endpoints: Vec::new(),
        relay_mode: transport_sdk::RelayMode::Disabled,
        trust_roots: transport_sdk::BootstrapTrustRoots {
            cluster_ca_pem: Some(cluster_ca_pem.clone()),
            public_api_ca_pem: None,
            rendezvous_ca_pem: Some(cluster_ca_pem.clone()),
        },
        upstream_public_url: None,
        enrollment_issuer_url: None,
    };
    let capture_material =
        super::issue_internal_node_tls_material(&state, &capture_bootstrap, issue_policy).unwrap();
    let capture_ca_path = capture_dir.join("capture-ca.pem");
    let capture_cert_path = capture_dir.join("capture-internal.pem");
    let capture_key_path = capture_dir.join("capture-internal.key");
    std::fs::write(&capture_ca_path, &capture_material.ca_cert_pem).unwrap();
    std::fs::write(&capture_cert_path, &capture_material.cert_pem).unwrap();
    std::fs::write(&capture_key_path, &capture_material.key_pem).unwrap();

    let captured_fingerprint = Arc::new(Mutex::new(None));
    let capture_handle = spawn_mtls_client_fingerprint_capture_server(
        capture_bind_addr,
        &capture_ca_path,
        &capture_cert_path,
        &capture_key_path,
        captured_fingerprint.clone(),
    );
    wait_for_condition("capture server ready", Duration::from_secs(5), || {
        let capture_ca_path = capture_ca_path.clone();
        let capture_cert_path = capture_cert_path.clone();
        let capture_key_path = capture_key_path.clone();
        async move {
            let result = tokio::spawn(async move {
                observe_peer_certificate_fingerprint(
                    capture_bind_addr,
                    &capture_ca_path,
                    Some((&capture_cert_path, &capture_key_path)),
                )
                .await
            })
            .await;
            result.is_ok()
        }
    })
    .await;

    state.enrollment_issuer_url = config.enrollment_issuer_url.clone();
    state.node_enrollment_path = Some(package_path.clone());
    state.rendezvous_urls = vec![format!("https://{capture_bind_addr}")];
    state.rendezvous_registration_enabled = true;
    state.internal_tls_runtime = Some(super::InternalTlsRuntime {
        config: super::build_internal_mtls_rustls_config(
            &internal_tls.ca_cert_path,
            &internal_tls.cert_path,
            &internal_tls.key_path,
        )
        .unwrap(),
        ca_cert_path: internal_tls.ca_cert_path.clone(),
        cert_path: internal_tls.cert_path.clone(),
        key_path: internal_tls.key_path.clone(),
        metadata_path: internal_tls.metadata_path.clone(),
    });
    {
        let mut renewal_state = state.node_enrollment_auto_renew_state.lock().await;
        renewal_state.loaded_internal_tls_fingerprint = Some(initial_internal_fingerprint.clone());
    }
    {
        let outbound_clients = super::build_outbound_clients(&state).unwrap();
        *state.outbound_clients.write().await = outbound_clients;
    }

    let internal_http = super::current_internal_http(&state).await;
    let internal_health_url = format!("https://{capture_bind_addr}/health");
    let response = internal_http
        .get(&internal_health_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        captured_fingerprint.lock().await.clone(),
        Some(initial_internal_fingerprint.clone())
    );

    let rendezvous = super::current_rendezvous_control(&state).await.unwrap();
    let registration = transport_sdk::PresenceRegistration {
        cluster_id: state.cluster_id,
        identity: transport_sdk::PeerIdentity::Node(state.node_id),
        public_api_url: None,
        peer_api_url: Some(format!("https://{internal_bind_addr}")),
        direct_candidates: Vec::new(),
        labels: HashMap::new(),
        capacity_bytes: None,
        free_bytes: None,
        capabilities: vec![transport_sdk::TransportCapability::RelayTunnel],
        relay_mode: transport_sdk::RelayMode::Fallback,
        connected_at_unix: super::unix_ts(),
    };
    rendezvous.register_presence(&registration).await.unwrap();
    assert_eq!(
        captured_fingerprint.lock().await.clone(),
        Some(initial_internal_fingerprint.clone())
    );

    assert!(
        super::renew_node_enrollment_package_if_due(&config)
            .await
            .unwrap()
    );
    super::reload_live_tls_from_disk(&state).await.unwrap();

    let renewed_package = transport_sdk::NodeEnrollmentPackage::from_path(&package_path).unwrap();
    let renewed_internal_fingerprint = renewed_package
        .internal_tls_material
        .as_ref()
        .unwrap()
        .metadata
        .certificate_fingerprint
        .clone();
    assert_ne!(renewed_internal_fingerprint, initial_internal_fingerprint);

    let internal_http = super::current_internal_http(&state).await;
    let response = internal_http
        .get(&internal_health_url)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        captured_fingerprint.lock().await.clone(),
        Some(renewed_internal_fingerprint.clone())
    );

    let rendezvous = super::current_rendezvous_control(&state).await.unwrap();
    rendezvous.register_presence(&registration).await.unwrap();
    assert_eq!(
        captured_fingerprint.lock().await.clone(),
        Some(renewed_internal_fingerprint)
    );

    cleanup_test_state(&state).await;
    capture_handle.abort();
    let _ = capture_handle.await;
    issuer_handle.abort();
    let _ = issuer_handle.await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn reload_live_outbound_clients_picks_up_rotated_rendezvous_trust_root() {
    let root = fresh_test_dir("rendezvous-trust-root-rotation");
    let bind_addr = free_bind_addr();
    let package_path = root.join("node-enrollment.json");
    let rendezvous_dir = root.join("rendezvous");
    std::fs::create_dir_all(&rendezvous_dir).unwrap();

    let (ca1_pem, _, cert1_pem, key1_pem) =
        generate_test_https_ca_and_server_material(bind_addr, "rendezvous-a");
    let ca1_path = rendezvous_dir.join("ca1.pem");
    let cert1_path = rendezvous_dir.join("cert1.pem");
    let key1_path = rendezvous_dir.join("key1.pem");
    std::fs::write(&ca1_path, &ca1_pem).unwrap();
    std::fs::write(&cert1_path, &cert1_pem).unwrap();
    std::fs::write(&key1_path, &key1_pem).unwrap();

    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    let rendezvous_url = format!("https://{bind_addr}");
    state.rendezvous_urls = vec![rendezvous_url.clone()];
    state.rendezvous_registration_enabled = true;

    transport_sdk::NodeEnrollmentPackage {
        bootstrap: transport_sdk::NodeBootstrap {
            version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
            cluster_id: state.cluster_id,
            node_id: state.node_id,
            mode: transport_sdk::NodeBootstrapMode::LocalEdge,
            data_dir: root.join("node").to_string_lossy().into_owned(),
            bind_addr: free_bind_addr().to_string(),
            public_url: None,
            labels: HashMap::new(),
            public_tls: None,
            public_ca_cert_path: None,
            public_peer_api_enabled: false,
            internal_bind_addr: None,
            internal_url: None,
            internal_tls: None,
            rendezvous_urls: vec![rendezvous_url.clone()],
            rendezvous_mtls_required: false,
            direct_endpoints: Vec::new(),
            relay_mode: transport_sdk::RelayMode::Fallback,
            trust_roots: transport_sdk::BootstrapTrustRoots {
                cluster_ca_pem: None,
                public_api_ca_pem: None,
                rendezvous_ca_pem: Some(ca1_pem.clone()),
            },
            upstream_public_url: None,
            enrollment_issuer_url: None,
        },
        public_tls_material: None,
        internal_tls_material: None,
    }
    .write_to_path(&package_path)
    .unwrap();
    state.node_enrollment_path = Some(package_path.clone());

    let mut rendezvous_handle = spawn_https_rendezvous_server(bind_addr, &cert1_path, &key1_path);
    wait_for_condition(
        "first rendezvous server ready",
        Duration::from_secs(5),
        || {
            let ca1_path = ca1_path.clone();
            async move {
                tokio::spawn(async move {
                    observe_peer_certificate_fingerprint(bind_addr, &ca1_path, None).await
                })
                .await
                .is_ok()
            }
        },
    )
    .await;

    super::reload_live_outbound_clients(&state).await.unwrap();
    let registration = transport_sdk::PresenceRegistration {
        cluster_id: state.cluster_id,
        identity: transport_sdk::PeerIdentity::Node(state.node_id),
        public_api_url: None,
        peer_api_url: None,
        direct_candidates: Vec::new(),
        labels: HashMap::new(),
        capacity_bytes: None,
        free_bytes: None,
        capabilities: vec![transport_sdk::TransportCapability::RelayTunnel],
        relay_mode: transport_sdk::RelayMode::Fallback,
        connected_at_unix: super::unix_ts(),
    };
    let old_client = super::current_rendezvous_control(&state).await.unwrap();
    old_client.register_presence(&registration).await.unwrap();
    assert_eq!(
        super::bootstrap_trust_roots(&state)
            .unwrap()
            .rendezvous_ca_pem,
        Some(ca1_pem.clone())
    );

    rendezvous_handle.abort();
    let _ = rendezvous_handle.await;

    let (ca2_pem, _, cert2_pem, key2_pem) =
        generate_test_https_ca_and_server_material(bind_addr, "rendezvous-b");
    let ca2_path = rendezvous_dir.join("ca2.pem");
    let cert2_path = rendezvous_dir.join("cert2.pem");
    let key2_path = rendezvous_dir.join("key2.pem");
    std::fs::write(&ca2_path, &ca2_pem).unwrap();
    std::fs::write(&cert2_path, &cert2_pem).unwrap();
    std::fs::write(&key2_path, &key2_pem).unwrap();

    let mut package = transport_sdk::NodeEnrollmentPackage::from_path(&package_path).unwrap();
    package.bootstrap.trust_roots.rendezvous_ca_pem = Some(ca2_pem.clone());
    package.write_to_path(&package_path).unwrap();

    rendezvous_handle = spawn_https_rendezvous_server(bind_addr, &cert2_path, &key2_path);
    wait_for_condition(
        "second rendezvous server ready",
        Duration::from_secs(5),
        || {
            let ca2_path = ca2_path.clone();
            async move {
                tokio::spawn(async move {
                    observe_peer_certificate_fingerprint(bind_addr, &ca2_path, None).await
                })
                .await
                .is_ok()
            }
        },
    )
    .await;

    let stale_client = transport_sdk::RendezvousControlClient::new(
        transport_sdk::RendezvousClientConfig {
            cluster_id: state.cluster_id,
            rendezvous_urls: vec![rendezvous_url.clone()],
            heartbeat_interval_secs: 5,
        },
        Some(&ca1_pem),
        None,
    )
    .unwrap();
    assert!(stale_client.register_presence(&registration).await.is_err());

    super::reload_live_outbound_clients(&state).await.unwrap();
    let new_client = super::current_rendezvous_control(&state).await.unwrap();
    new_client.register_presence(&registration).await.unwrap();
    assert_eq!(
        super::bootstrap_trust_roots(&state)
            .unwrap()
            .rendezvous_ca_pem,
        Some(ca2_pem)
    );

    cleanup_test_state(&state).await;
    rendezvous_handle.abort();
    let _ = rendezvous_handle.await;
    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn collect_node_certificate_status_reports_renewal_due_from_sidecar_metadata() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    let (cluster_ca_pem, internal_ca_key_pem) = generate_test_internal_ca();
    state.cluster_ca_pem = Some(cluster_ca_pem);
    state.internal_ca_key_pem = Some(internal_ca_key_pem);

    let root = fresh_test_dir("node-cert-status");
    let package_path = root.join("node-enrollment.json");
    let internal_bind_addr = free_bind_addr();
    let bootstrap = transport_sdk::NodeBootstrap {
        version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
        cluster_id: state.cluster_id,
        node_id: NodeId::new_v4(),
        mode: transport_sdk::NodeBootstrapMode::Cluster,
        data_dir: root.join("data").to_string_lossy().into_owned(),
        bind_addr: free_bind_addr().to_string(),
        public_url: None,
        labels: HashMap::new(),
        public_tls: None,
        public_ca_cert_path: None,
        public_peer_api_enabled: false,
        internal_bind_addr: Some(internal_bind_addr.to_string()),
        internal_url: Some(format!("https://127.0.0.1:{}", internal_bind_addr.port())),
        internal_tls: Some(transport_sdk::BootstrapTlsFiles {
            ca_cert_path: "tls/cluster-ca.pem".to_string(),
            cert_path: "tls/internal.pem".to_string(),
            key_path: "tls/internal.key".to_string(),
        }),
        rendezvous_urls: vec!["https://rendezvous.example".to_string()],
        rendezvous_mtls_required: false,
        direct_endpoints: Vec::new(),
        relay_mode: transport_sdk::RelayMode::Fallback,
        trust_roots: transport_sdk::BootstrapTrustRoots {
            cluster_ca_pem: state.cluster_ca_pem.clone(),
            public_api_ca_pem: None,
            rendezvous_ca_pem: None,
        },
        upstream_public_url: None,
        enrollment_issuer_url: Some("https://issuer.example".to_string()),
    };
    let issue_policy = default_tls_issue_policy();
    let internal_material =
        super::issue_internal_node_tls_material(&state, &bootstrap, issue_policy).unwrap();
    transport_sdk::NodeEnrollmentPackage {
        bootstrap,
        public_tls_material: None,
        internal_tls_material: Some(internal_material),
    }
    .write_to_path(&package_path)
    .unwrap();

    let config = super::ServerNodeConfig::from_enrollment_path(&package_path).unwrap();
    let internal_tls = config.internal_tls.as_ref().unwrap();
    let metadata_path = internal_tls.metadata_path.as_ref().unwrap();
    let mut metadata: transport_sdk::BootstrapTlsMaterialMetadata =
        serde_json::from_str(&std::fs::read_to_string(metadata_path).unwrap()).unwrap();
    metadata.renew_after_unix = super::unix_ts().saturating_sub(1);
    std::fs::write(
        metadata_path,
        serde_json::to_string_pretty(&metadata).unwrap(),
    )
    .unwrap();

    let status = super::collect_node_certificate_status(
        None,
        None,
        Some(internal_tls.cert_path.as_path()),
        Some(metadata_path.as_path()),
        super::NodeCertificateAutoRenewStatusView {
            enabled: false,
            enrollment_path: None,
            issuer_url: None,
            check_interval_secs: None,
            last_attempt_unix: None,
            last_success_unix: None,
            last_error: None,
            restart_required: false,
        },
    );
    assert_eq!(
        status.internal_tls.state,
        super::NodeCertificateLifecycleState::RenewalDue
    );
    assert_eq!(status.internal_tls.metadata_matches_certificate, Some(true));

    cleanup_test_state(&state).await;
    let _ = std::fs::remove_dir_all(&root);
}

async fn client_auth_middleware_requires_valid_signature_when_enabled_impl(
    backend: MainTestBackend,
) {
    let mut state = build_test_state(1, false, backend).await;
    state.client_auth_control.require_client_auth = true;
    let mut identity =
        transport_sdk::ClientIdentityMaterial::generate(state.cluster_id, None, None).unwrap();
    let credential_pem = super::generate_client_credential_pem(
        state.cluster_id,
        &identity.device_id.to_string(),
        &identity.public_key_pem,
        super::unix_ts(),
        None,
    );
    identity.credential_pem = Some(credential_pem.clone());
    {
        let mut auth = state.client_auth.lock().await;
        auth.devices.push(super::DeviceAuthRecord {
            device_id: identity.device_id.to_string(),
            label: Some("Pixel".to_string()),
            token_hash: super::hash_token("legacy-device-secret"),
            public_key_pem: Some(identity.public_key_pem.clone()),
            issued_credential_pem: Some(credential_pem),
            created_at_unix: super::unix_ts(),
            revoked_at_unix: None,
        });
    }

    let app = Router::new()
        .route("/store/index", get(|| async { StatusCode::OK }))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            super::require_client_auth,
        ));
    let signed_headers = transport_sdk::build_signed_request_headers(
        &identity,
        "GET",
        "/store/index",
        super::unix_ts(),
        Some("nonce-a".to_string()),
    )
    .unwrap();

    let unauthorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/store/index")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

    let authorized = app
        .oneshot(
            Request::builder()
                .uri("/store/index")
                .header(
                    transport_sdk::HEADER_CLUSTER_ID,
                    signed_headers.cluster_id.to_string(),
                )
                .header(
                    transport_sdk::HEADER_DEVICE_ID,
                    signed_headers.device_id.as_str(),
                )
                .header(
                    transport_sdk::HEADER_CREDENTIAL_FINGERPRINT,
                    signed_headers.credential_fingerprint.as_str(),
                )
                .header(
                    transport_sdk::HEADER_AUTH_TIMESTAMP,
                    signed_headers.timestamp_unix.to_string(),
                )
                .header(
                    transport_sdk::HEADER_AUTH_NONCE,
                    signed_headers.nonce.as_str(),
                )
                .header(
                    transport_sdk::HEADER_AUTH_SIGNATURE,
                    signed_headers.signature_base64.as_str(),
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(authorized.status(), StatusCode::OK);

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    client_auth_middleware_requires_valid_signature_when_enabled_impl,
    client_auth_middleware_requires_valid_signature_when_enabled,
    client_auth_middleware_requires_valid_signature_when_enabled_turso
);

async fn client_auth_middleware_rejects_replayed_nonce_impl(backend: MainTestBackend) {
    let mut state = build_test_state(1, false, backend).await;
    state.client_auth_control.require_client_auth = true;
    let mut identity =
        transport_sdk::ClientIdentityMaterial::generate(state.cluster_id, None, None).unwrap();
    let credential_pem = super::generate_client_credential_pem(
        state.cluster_id,
        &identity.device_id.to_string(),
        &identity.public_key_pem,
        super::unix_ts(),
        None,
    );
    identity.credential_pem = Some(credential_pem.clone());
    {
        let mut auth = state.client_auth.lock().await;
        auth.devices.push(super::DeviceAuthRecord {
            device_id: identity.device_id.to_string(),
            label: None,
            token_hash: super::hash_token("legacy-device-secret"),
            public_key_pem: Some(identity.public_key_pem.clone()),
            issued_credential_pem: Some(credential_pem),
            created_at_unix: super::unix_ts(),
            revoked_at_unix: None,
        });
    }

    let app = Router::new()
        .route("/store/index", get(|| async { StatusCode::OK }))
        .with_state(state.clone())
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            super::require_client_auth,
        ));
    let signed_headers = transport_sdk::build_signed_request_headers(
        &identity,
        "GET",
        "/store/index",
        super::unix_ts(),
        Some("nonce-replay".to_string()),
    )
    .unwrap();

    let request = || {
        Request::builder()
            .uri("/store/index")
            .header(
                transport_sdk::HEADER_CLUSTER_ID,
                signed_headers.cluster_id.to_string(),
            )
            .header(
                transport_sdk::HEADER_DEVICE_ID,
                signed_headers.device_id.as_str(),
            )
            .header(
                transport_sdk::HEADER_CREDENTIAL_FINGERPRINT,
                signed_headers.credential_fingerprint.as_str(),
            )
            .header(
                transport_sdk::HEADER_AUTH_TIMESTAMP,
                signed_headers.timestamp_unix.to_string(),
            )
            .header(
                transport_sdk::HEADER_AUTH_NONCE,
                signed_headers.nonce.as_str(),
            )
            .header(
                transport_sdk::HEADER_AUTH_SIGNATURE,
                signed_headers.signature_base64.as_str(),
            )
            .body(Body::empty())
            .unwrap()
    };

    let first = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let replayed = app.oneshot(request()).await.unwrap();
    assert_eq!(replayed.status(), StatusCode::UNAUTHORIZED);

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    client_auth_middleware_rejects_replayed_nonce_impl,
    client_auth_middleware_rejects_replayed_nonce,
    client_auth_middleware_rejects_replayed_nonce_turso
);

async fn store_index_change_wait_unblocks_after_put_impl(backend: MainTestBackend) {
    let state = build_test_state(1, false, backend).await;

    let waiter_state = state.clone();
    let waiter = tokio::spawn(async move {
        let response = super::wait_for_store_index_change(
            State(waiter_state),
            Query(super::StoreIndexChangeWaitQuery {
                since: Some(0),
                timeout_ms: Some(2_000),
            }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice::<super::StoreIndexChangeWaitResponse>(&body).unwrap()
    });

    tokio::time::sleep(Duration::from_millis(100)).await;
    let response = super::put_object(
        State(state.clone()),
        axum::extract::Path("notify.txt".to_string()),
        Query(super::PutObjectQuery {
            state: None,
            parent: Vec::new(),
            version_id: None,
            internal_replication: false,
            recursive: false,
        }),
        Bytes::from_static(b"notify-payload"),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::CREATED);

    let payload = waiter.await.unwrap();
    assert!(payload.changed);
    assert!(payload.sequence >= 1);

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    store_index_change_wait_unblocks_after_put_impl,
    store_index_change_wait_unblocks_after_put,
    store_index_change_wait_unblocks_after_put_turso
);

async fn store_index_change_wait_times_out_without_mutation_impl(backend: MainTestBackend) {
    let state = build_test_state(1, false, backend).await;

    let response = super::wait_for_store_index_change(
        State(state.clone()),
        Query(super::StoreIndexChangeWaitQuery {
            since: Some(0),
            timeout_ms: Some(250),
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload = serde_json::from_slice::<super::StoreIndexChangeWaitResponse>(&body).unwrap();
    assert!(!payload.changed);
    assert_eq!(payload.sequence, 0);

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    store_index_change_wait_times_out_without_mutation_impl,
    store_index_change_wait_times_out_without_mutation,
    store_index_change_wait_times_out_without_mutation_turso
);

#[test]
fn store_index_depth_groups_prefixes() {
    let keys = vec![
        "docs/guide/intro.md".to_string(),
        "docs/guide/setup.md".to_string(),
        "docs/api/v1.json".to_string(),
    ];

    let entries = build_store_index_entries(&keys, "docs", 1);
    let paths = entries
        .into_iter()
        .map(|entry| entry.path)
        .collect::<Vec<_>>();
    assert_eq!(paths, vec!["docs/api/", "docs/guide/"]);
}

#[test]
fn store_index_prefix_returns_matching_keys() {
    let keys = vec![
        "images/cat.png".to_string(),
        "images/dogs/beagle.png".to_string(),
        "docs/readme.md".to_string(),
    ];

    let entries = build_store_index_entries(&keys, "images", 2);
    let mut key_paths = entries
        .into_iter()
        .filter(|entry| entry.entry_type == "key")
        .map(|entry| entry.path)
        .collect::<Vec<_>>();
    key_paths.sort();

    assert_eq!(key_paths, vec!["images/cat.png", "images/dogs/beagle.png"]);
}

#[test]
fn autonomous_post_write_replication_trigger_guard_blocks_internal_writes() {
    assert!(should_trigger_autonomous_post_write_replication(
        true, false
    ));
    assert!(!should_trigger_autonomous_post_write_replication(
        true, true
    ));
    assert!(!should_trigger_autonomous_post_write_replication(
        false, false
    ));
}

#[test]
fn internal_replication_put_url_sets_internal_flag() {
    let url = build_internal_replication_put_url(
        "http://127.0.0.1:18080",
        "hello",
        "confirmed",
        Some("ver-123"),
    );
    assert!(url.contains("/store/hello?"));
    assert!(url.contains("state=confirmed"));
    assert!(url.contains("version_id=ver-123"));
    assert!(url.contains("internal_replication=true"));
}

async fn repair_busy_threshold_returns_immediately_when_disabled_impl(backend: MainTestBackend) {
    let mut state = build_test_state(1, false, backend).await;
    state.repair_config.busy_throttle_enabled = false;
    state
        .inflight_requests
        .store(1_000, std::sync::atomic::Ordering::Relaxed);
    let start = Instant::now();

    await_repair_busy_threshold(&state).await;

    assert!(start.elapsed() < Duration::from_millis(10));
    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    repair_busy_threshold_returns_immediately_when_disabled_impl,
    repair_busy_threshold_returns_immediately_when_disabled,
    repair_busy_threshold_returns_immediately_when_disabled_turso
);

async fn repair_busy_threshold_waits_until_load_drops_impl(backend: MainTestBackend) {
    let mut state = build_test_state(1, false, backend).await;
    state.repair_config.busy_throttle_enabled = true;
    state.repair_config.busy_inflight_threshold = 1;
    state.repair_config.busy_wait_millis = 5;
    state
        .inflight_requests
        .store(5, std::sync::atomic::Ordering::Relaxed);

    let inflight_requests_for_release = Arc::clone(&state.inflight_requests);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        inflight_requests_for_release.store(0, std::sync::atomic::Ordering::Relaxed);
    });

    let start = Instant::now();
    await_repair_busy_threshold(&state).await;

    assert!(start.elapsed() >= Duration::from_millis(15));
    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    repair_busy_threshold_waits_until_load_drops_impl,
    repair_busy_threshold_waits_until_load_drops,
    repair_busy_threshold_waits_until_load_drops_turso
);

async fn startup_repair_noop_when_plan_is_empty_impl(backend: MainTestBackend) {
    let state = build_test_state(1, false, backend).await;

    let result = run_startup_replication_repair_once(&state, 0).await;
    assert!(result.is_none());

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    startup_repair_noop_when_plan_is_empty_impl,
    startup_repair_noop_when_plan_is_empty,
    startup_repair_noop_when_plan_is_empty_turso
);

async fn startup_repair_runs_when_gaps_exist_impl(backend: MainTestBackend) {
    let state = build_test_state(2, true, backend).await;

    let result = run_startup_replication_repair_once(&state, 0).await;
    assert!(result.is_some());

    let (plan, report) = result.unwrap();
    assert!(!plan.items.is_empty());
    assert!(
        report.attempted_transfers > 0,
        "startup repair should attempt transfers when replication gaps exist"
    );

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    startup_repair_runs_when_gaps_exist_impl,
    startup_repair_runs_when_gaps_exist,
    startup_repair_runs_when_gaps_exist_turso
);

async fn delete_object_handler_marks_tombstone_and_removes_current_key_impl(
    backend: MainTestBackend,
) {
    let state = build_test_state(1, false, backend).await;

    // put an object into underlying store
    let key = "handler-delete-key".to_string();
    {
        let mut locked = state.store.lock().await;
        locked
            .put_object_versioned(
                &key,
                bytes::Bytes::from_static(b"payload"),
                PutOptions::default(),
            )
            .await
            .unwrap();
    }

    // call handler directly
    let query = axum::extract::Query(super::PutObjectQuery {
        state: Some("confirmed".to_string()),
        parent: Vec::new(),
        version_id: None,
        internal_replication: false,
        recursive: false,
    });

    let resp = super::delete_object(
        axum::extract::State(state.clone()),
        axum::extract::Path(key.clone()),
        query,
    )
    .await;

    let response = axum::response::IntoResponse::into_response(resp);
    assert_eq!(response.status(), axum::http::StatusCode::CREATED);

    // ensure underlying store current keys no longer include the key
    let keys = {
        let store = state.store.lock().await;
        store.current_keys()
    };
    assert!(!keys.contains(&key));

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    delete_object_handler_marks_tombstone_and_removes_current_key_impl,
    delete_object_handler_marks_tombstone_and_removes_current_key,
    delete_object_handler_marks_tombstone_and_removes_current_key_turso
);

async fn delete_object_handler_recursively_tombstones_directory_subtree_impl(
    backend: MainTestBackend,
) {
    let state = build_test_state(1, false, backend).await;

    {
        let mut locked = state.store.lock().await;
        for (key, payload) in [
            ("docs/", bytes::Bytes::from_static(b"")),
            ("docs/a.txt", bytes::Bytes::from_static(b"a")),
            ("docs/nested/", bytes::Bytes::from_static(b"")),
            ("docs/nested/b.txt", bytes::Bytes::from_static(b"b")),
            ("other/keep.txt", bytes::Bytes::from_static(b"keep")),
        ] {
            locked
                .put_object_versioned(key, payload, PutOptions::default())
                .await
                .unwrap();
        }
    }

    let query = axum::extract::Query(super::PutObjectQuery {
        state: Some("confirmed".to_string()),
        parent: Vec::new(),
        version_id: None,
        internal_replication: false,
        recursive: true,
    });

    let resp = super::delete_object(
        axum::extract::State(state.clone()),
        axum::extract::Path("docs/".to_string()),
        query,
    )
    .await;

    let response = axum::response::IntoResponse::into_response(resp);
    assert_eq!(response.status(), axum::http::StatusCode::CREATED);

    let keys = {
        let store = state.store.lock().await;
        store.current_keys()
    };
    assert!(
        !keys
            .iter()
            .any(|key| key == "docs/" || key.starts_with("docs/"))
    );
    assert!(keys.contains(&"other/keep.txt".to_string()));

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    delete_object_handler_recursively_tombstones_directory_subtree_impl,
    delete_object_handler_recursively_tombstones_directory_subtree,
    delete_object_handler_recursively_tombstones_directory_subtree_turso
);

async fn delete_object_handler_allows_internal_versioned_tombstone_for_directory_marker_impl(
    backend: MainTestBackend,
) {
    let state = build_test_state(1, false, backend).await;

    {
        let mut locked = state.store.lock().await;
        locked
            .put_object_versioned(
                "docs/",
                bytes::Bytes::from_static(b""),
                PutOptions::default(),
            )
            .await
            .unwrap();
    }

    let query = axum::extract::Query(super::PutObjectQuery {
        state: Some("confirmed".to_string()),
        parent: Vec::new(),
        version_id: Some("repl-tomb-docs-marker".to_string()),
        internal_replication: true,
        recursive: false,
    });

    let resp = super::delete_object(
        axum::extract::State(state.clone()),
        axum::extract::Path("docs/".to_string()),
        query,
    )
    .await;

    let response = axum::response::IntoResponse::into_response(resp);
    assert_eq!(response.status(), axum::http::StatusCode::CREATED);

    let keys = {
        let store = state.store.lock().await;
        store.current_keys()
    };
    assert!(!keys.contains(&"docs/".to_string()));

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    delete_object_handler_allows_internal_versioned_tombstone_for_directory_marker_impl,
    delete_object_handler_allows_internal_versioned_tombstone_for_directory_marker,
    delete_object_handler_allows_internal_versioned_tombstone_for_directory_marker_turso
);

async fn list_store_index_includes_cached_media_metadata_for_images_impl(backend: MainTestBackend) {
    let state = build_test_state(1, false, backend).await;
    let put = {
        let mut locked = state.store.lock().await;
        locked
            .put_object_versioned(
                "gallery/cat.png",
                bytes::Bytes::from(sample_png_bytes()),
                PutOptions::default(),
            )
            .await
            .unwrap()
    };
    {
        let locked = state.store.lock().await;
        locked.ensure_media_cache(&put.manifest_hash).await.unwrap();
    }

    let response = axum::response::IntoResponse::into_response(
        super::list_store_index(
            axum::extract::State(state.clone()),
            axum::extract::Query(super::StoreIndexQuery {
                prefix: Some("gallery".to_string()),
                depth: Some(2),
                snapshot: None,
            }),
        )
        .await,
    );

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entries = payload["entries"].as_array().unwrap();
    let media = &entries[0]["media"];

    assert_eq!(entries[0]["path"], "gallery/cat.png");
    assert_eq!(media["status"], "ready");
    assert_eq!(media["mime_type"], "image/png");
    assert_eq!(media["width"], 4);
    assert_eq!(media["height"], 3);
    assert!(
        media["thumbnail"]["url"]
            .as_str()
            .unwrap()
            .contains("/media/thumbnail?key=gallery%2Fcat.png")
    );

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    list_store_index_includes_cached_media_metadata_for_images_impl,
    list_store_index_includes_cached_media_metadata_for_images,
    list_store_index_includes_cached_media_metadata_for_images_turso
);

async fn local_edge_mode_serves_health_without_internal_tls_impl(backend: MainTestBackend) {
    let bind_addr = free_bind_addr();
    let data_dir = std::env::temp_dir().join(format!(
        "ironmesh-local-edge-{}-{}-{}",
        backend.suffix(),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    let mut config = ServerNodeConfig::local_edge(&data_dir, bind_addr);
    config.public_url = Some(format!("http://{bind_addr}"));
    config.metadata_backend = backend.kind();

    let handle = tokio::spawn(async move { run(config).await });
    let client = reqwest::Client::new();
    let health_url = format!("http://{bind_addr}/health");

    let started = async {
        for _ in 0..50 {
            match client.get(&health_url).send().await {
                Ok(response) if response.status() == StatusCode::OK => return Ok(()),
                _ => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
        anyhow::bail!("local-edge server did not become healthy at {health_url}");
    }
    .await;

    handle.abort();
    let _ = handle.await;
    let _ = std::fs::remove_dir_all(&data_dir);

    started.unwrap();
}

run_on_main_metadata_backends!(
    local_edge_mode_serves_health_without_internal_tls_impl,
    local_edge_mode_serves_health_without_internal_tls,
    local_edge_mode_serves_health_without_internal_tls_turso
);

async fn local_edge_persists_objects_across_restart_impl(
    backend: super::storage::MetadataBackendKind,
    label: &str,
    payload: &str,
) {
    let bind_addr = free_bind_addr();
    let data_dir = std::env::temp_dir().join(format!(
        "ironmesh-local-edge-{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    let mut config = ServerNodeConfig::local_edge(&data_dir, bind_addr);
    config.public_url = Some(format!("http://{bind_addr}"));
    config.metadata_backend = backend;

    let handle = tokio::spawn(async move { run(config).await });
    let client = reqwest::Client::new();
    let base_url = format!("http://{bind_addr}");
    let health_url = format!("{base_url}/health");

    wait_for_http_status(&client, &health_url, StatusCode::OK, Duration::from_secs(5)).await;

    let put = client
        .put(format!("{base_url}/store/persist.txt"))
        .body(payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::CREATED);

    handle.abort();
    let _ = handle.await;

    let restart_bind_addr = free_bind_addr();
    let mut restart_config = ServerNodeConfig::local_edge(&data_dir, restart_bind_addr);
    restart_config.public_url = Some(format!("http://{restart_bind_addr}"));
    restart_config.metadata_backend = backend;

    let restart_handle = tokio::spawn(async move { run(restart_config).await });
    let restart_base_url = format!("http://{restart_bind_addr}");
    wait_for_http_status(
        &client,
        &format!("{restart_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let get = client
        .get(format!("{restart_base_url}/store/persist.txt"))
        .send()
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::OK);
    let body = get.text().await.unwrap();
    assert_eq!(body, payload);

    restart_handle.abort();
    let _ = restart_handle.await;
    let _ = std::fs::remove_dir_all(&data_dir);
}

#[tokio::test]
async fn local_edge_sqlite_persists_objects_across_restart() {
    local_edge_persists_objects_across_restart_impl(
        super::storage::MetadataBackendKind::Sqlite,
        "sqlite",
        "hello-sqlite",
    )
    .await;
}

#[cfg(feature = "turso-metadata")]
#[tokio::test]
async fn local_edge_turso_persists_objects_across_restart() {
    local_edge_persists_objects_across_restart_impl(
        super::storage::MetadataBackendKind::Turso,
        "turso",
        "hello-turso",
    )
    .await;
}

#[test]
fn local_node_handle_starts_and_reports_base_url() {
    let data_dir = std::env::temp_dir().join(format!(
        "ironmesh-local-edge-handle-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));

    let handle = LocalNodeHandle::start_local_edge(&data_dir).unwrap();
    let response = reqwest::blocking::get(format!("{}/health", handle.base_url())).unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    drop(handle);
    let _ = std::fs::remove_dir_all(&data_dir);
}

async fn local_edge_with_upstream_pulls_remote_content_and_pushes_local_writes_impl(
    backend: MainTestBackend,
) {
    let upstream_dir = fresh_test_dir(&format!("edge-upstream-source-{}", backend.suffix()));
    let upstream_bind_addr = free_bind_addr();
    let mut upstream_config = ServerNodeConfig::local_edge(&upstream_dir, upstream_bind_addr);
    upstream_config.public_url = Some(format!("http://{upstream_bind_addr}"));
    upstream_config.public_peer_api_enabled = true;
    upstream_config.replication_factor = 2;
    upstream_config.metadata_backend = backend.kind();
    let upstream_handle = tokio::spawn(async move { run(upstream_config).await });

    let http = reqwest::Client::new();
    let upstream_base_url = format!("http://{upstream_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;
    let remote_key = "remote.txt";
    let remote_payload = "from-upstream";
    let response = http
        .put(format!("{upstream_base_url}/store/{remote_key}"))
        .body(remote_payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let edge_dir = fresh_test_dir(&format!("edge-upstream-target-{}", backend.suffix()));
    let edge_bind_addr = free_bind_addr();
    let mut edge_config =
        ServerNodeConfig::local_edge_with_upstream(&edge_dir, edge_bind_addr, &upstream_base_url);
    edge_config.public_url = Some(format!("http://{edge_bind_addr}"));
    edge_config.replica_view_sync_interval_secs = 1;
    edge_config.startup_repair_delay_secs = 0;
    edge_config.metadata_backend = backend.kind();
    let edge_handle = tokio::spawn(async move { run(edge_config).await });
    let edge_base_url = format!("http://{edge_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{edge_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition("edge sees upstream node", Duration::from_secs(5), || {
        let http = http.clone();
        let edge_base_url = edge_base_url.clone();
        let upstream_base_url = upstream_base_url.clone();
        async move {
            let response = match http
                .get(format!("{edge_base_url}/cluster/nodes"))
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return false,
            };
            let Ok(nodes) = response.json::<Vec<cluster::NodeDescriptor>>().await else {
                return false;
            };

            nodes.iter().any(|node| {
                node.public_url == upstream_base_url || node.internal_url == upstream_base_url
            })
        }
    })
    .await;

    wait_for_condition(
        "edge sees remote replication gap",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let remote_key = remote_key.to_string();
            async move {
                let response = match http
                    .get(format!("{edge_base_url}/cluster/replication/plan"))
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(_) => return false,
                };
                let Ok(plan) = response.json::<cluster::ReplicationPlan>().await else {
                    return false;
                };
                plan.items.iter().any(|item| item.key == remote_key)
            }
        },
    )
    .await;

    let repair_response = http
        .post(format!("{edge_base_url}/cluster/replication/repair"))
        .send()
        .await
        .unwrap();
    assert_eq!(repair_response.status(), StatusCode::OK);

    wait_for_condition("edge pulls remote object", Duration::from_secs(5), || {
        let http = http.clone();
        let edge_base_url = edge_base_url.clone();
        let remote_key = remote_key.to_string();
        async move {
            match http
                .get(format!("{edge_base_url}/store/{remote_key}"))
                .send()
                .await
            {
                Ok(response) if response.status() == StatusCode::OK => {
                    match response.text().await {
                        Ok(body) => body == remote_payload,
                        Err(_) => false,
                    }
                }
                _ => false,
            }
        }
    })
    .await;

    let local_key = "local.txt";
    let local_payload = "from-edge";
    let response = http
        .put(format!("{edge_base_url}/store/{local_key}"))
        .body(local_payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let repair_response = http
        .post(format!("{edge_base_url}/cluster/replication/repair"))
        .send()
        .await
        .unwrap();
    assert_eq!(repair_response.status(), StatusCode::OK);

    wait_for_condition(
        "upstream receives pushed object",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let upstream_base_url = upstream_base_url.clone();
            let local_key = local_key.to_string();
            async move {
                match http
                    .get(format!("{upstream_base_url}/store/{local_key}"))
                    .send()
                    .await
                {
                    Ok(response) if response.status() == StatusCode::OK => {
                        match response.text().await {
                            Ok(body) => body == local_payload,
                            Err(_) => false,
                        }
                    }
                    _ => false,
                }
            }
        },
    )
    .await;

    edge_handle.abort();
    let _ = edge_handle.await;
    upstream_handle.abort();
    let _ = upstream_handle.await;
    let _ = std::fs::remove_dir_all(&edge_dir);
    let _ = std::fs::remove_dir_all(&upstream_dir);
}

run_on_main_metadata_backends!(
    local_edge_with_upstream_pulls_remote_content_and_pushes_local_writes_impl,
    local_edge_with_upstream_pulls_remote_content_and_pushes_local_writes,
    local_edge_with_upstream_pulls_remote_content_and_pushes_local_writes_turso
);

async fn local_edge_pulls_upstream_delete_after_repair_impl(backend: MainTestBackend) {
    let upstream_dir = fresh_test_dir(&format!("edge-upstream-delete-source-{}", backend.suffix()));
    let upstream_bind_addr = free_bind_addr();
    let mut upstream_config = ServerNodeConfig::local_edge(&upstream_dir, upstream_bind_addr);
    upstream_config.public_url = Some(format!("http://{upstream_bind_addr}"));
    upstream_config.public_peer_api_enabled = true;
    upstream_config.replication_factor = 2;
    upstream_config.metadata_backend = backend.kind();
    let upstream_handle = tokio::spawn(async move { run(upstream_config).await });

    let http = reqwest::Client::new();
    let upstream_base_url = format!("http://{upstream_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let remote_key = "remote-delete.txt";
    let remote_payload = "delete-from-upstream";
    let response = http
        .put(format!("{upstream_base_url}/store/{remote_key}"))
        .body(remote_payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let edge_dir = fresh_test_dir(&format!("edge-upstream-delete-target-{}", backend.suffix()));
    let edge_bind_addr = free_bind_addr();
    let mut edge_config =
        ServerNodeConfig::local_edge_with_upstream(&edge_dir, edge_bind_addr, &upstream_base_url);
    edge_config.public_url = Some(format!("http://{edge_bind_addr}"));
    edge_config.replica_view_sync_interval_secs = 1;
    edge_config.startup_repair_delay_secs = 0;
    edge_config.metadata_backend = backend.kind();
    let edge_handle = tokio::spawn(async move { run(edge_config).await });
    let edge_base_url = format!("http://{edge_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{edge_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition("edge sees upstream node", Duration::from_secs(5), || {
        let http = http.clone();
        let edge_base_url = edge_base_url.clone();
        let upstream_base_url = upstream_base_url.clone();
        async move {
            let response = match http
                .get(format!("{edge_base_url}/cluster/nodes"))
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return false,
            };
            let Ok(nodes) = response.json::<Vec<cluster::NodeDescriptor>>().await else {
                return false;
            };

            nodes.iter().any(|node| {
                node.public_url == upstream_base_url || node.internal_url == upstream_base_url
            })
        }
    })
    .await;

    let repair_response = http
        .post(format!("{edge_base_url}/cluster/replication/repair"))
        .send()
        .await
        .unwrap();
    assert_eq!(repair_response.status(), StatusCode::OK);

    wait_for_condition(
        "edge pulls upstream object before delete",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let remote_key = remote_key.to_string();
            async move {
                match http
                    .get(format!("{edge_base_url}/store/{remote_key}"))
                    .send()
                    .await
                {
                    Ok(response) if response.status() == StatusCode::OK => {
                        match response.text().await {
                            Ok(body) => body == remote_payload,
                            Err(_) => false,
                        }
                    }
                    _ => false,
                }
            }
        },
    )
    .await;

    let response = http
        .delete(format!("{upstream_base_url}/store/{remote_key}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    wait_for_condition(
        "upstream removes deleted object from current state",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let upstream_base_url = upstream_base_url.clone();
            let remote_key = remote_key.to_string();
            async move {
                match http
                    .get(format!("{upstream_base_url}/store/{remote_key}"))
                    .send()
                    .await
                {
                    Ok(response) => response.status() == StatusCode::NOT_FOUND,
                    Err(_) => false,
                }
            }
        },
    )
    .await;

    wait_for_condition(
        "edge removes upstream-deleted object after repair",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let remote_key = remote_key.to_string();
            async move {
                let _ = http
                    .post(format!("{edge_base_url}/cluster/replication/repair"))
                    .send()
                    .await;
                match http
                    .get(format!("{edge_base_url}/store/{remote_key}"))
                    .send()
                    .await
                {
                    Ok(response) => response.status() == StatusCode::NOT_FOUND,
                    Err(_) => false,
                }
            }
        },
    )
    .await;

    edge_handle.abort();
    let _ = edge_handle.await;
    upstream_handle.abort();
    let _ = upstream_handle.await;
    let _ = std::fs::remove_dir_all(&edge_dir);
    let _ = std::fs::remove_dir_all(&upstream_dir);
}

run_on_main_metadata_backends!(
    local_edge_pulls_upstream_delete_after_repair_impl,
    local_edge_pulls_upstream_delete_after_repair,
    local_edge_pulls_upstream_delete_after_repair_turso
);

async fn local_edge_pulls_upstream_copy_after_repair_impl(backend: MainTestBackend) {
    let upstream_dir = fresh_test_dir(&format!("edge-upstream-copy-source-{}", backend.suffix()));
    let upstream_bind_addr = free_bind_addr();
    let mut upstream_config = ServerNodeConfig::local_edge(&upstream_dir, upstream_bind_addr);
    upstream_config.public_url = Some(format!("http://{upstream_bind_addr}"));
    upstream_config.public_peer_api_enabled = true;
    upstream_config.replication_factor = 2;
    upstream_config.metadata_backend = backend.kind();
    let upstream_handle = tokio::spawn(async move { run(upstream_config).await });

    let http = reqwest::Client::new();
    let upstream_base_url = format!("http://{upstream_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let source_key = "copy-source.txt";
    let copy_key = "copy-target.txt";
    let payload = "copy-upstream-payload";
    let response = http
        .put(format!("{upstream_base_url}/store/{source_key}"))
        .body(payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    let edge_dir = fresh_test_dir(&format!("edge-upstream-copy-target-{}", backend.suffix()));
    let edge_bind_addr = free_bind_addr();
    let mut edge_config =
        ServerNodeConfig::local_edge_with_upstream(&edge_dir, edge_bind_addr, &upstream_base_url);
    edge_config.public_url = Some(format!("http://{edge_bind_addr}"));
    edge_config.replica_view_sync_interval_secs = 1;
    edge_config.startup_repair_delay_secs = 0;
    edge_config.metadata_backend = backend.kind();
    let edge_handle = tokio::spawn(async move { run(edge_config).await });
    let edge_base_url = format!("http://{edge_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{edge_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    http.post(format!("{edge_base_url}/cluster/replication/repair"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    wait_for_condition(
        "edge pulls upstream source before copy",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let source_key = source_key.to_string();
            async move {
                match http
                    .get(format!("{edge_base_url}/store/{source_key}"))
                    .send()
                    .await
                {
                    Ok(response) if response.status() == StatusCode::OK => response
                        .text()
                        .await
                        .map(|body| body == payload)
                        .unwrap_or(false),
                    _ => false,
                }
            }
        },
    )
    .await;

    http.post(format!("{upstream_base_url}/store/copy"))
        .json(&serde_json::json!({
            "from_path": source_key,
            "to_path": copy_key,
            "overwrite": false,
        }))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    wait_for_condition(
        "edge pulls upstream copy after repair",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let source_key = source_key.to_string();
            let copy_key = copy_key.to_string();
            async move {
                let source = http
                    .get(format!("{edge_base_url}/store/{source_key}"))
                    .send()
                    .await;
                let copy = http
                    .get(format!("{edge_base_url}/store/{copy_key}"))
                    .send()
                    .await;

                match (source, copy) {
                    (Ok(source_response), Ok(copy_response))
                        if source_response.status() == StatusCode::OK
                            && copy_response.status() == StatusCode::OK =>
                    {
                        let source_body = source_response.text().await.ok();
                        let copy_body = copy_response.text().await.ok();
                        source_body.as_deref() == Some(payload)
                            && copy_body.as_deref() == Some(payload)
                    }
                    _ => false,
                }
            }
        },
    )
    .await;

    edge_handle.abort();
    let _ = edge_handle.await;
    upstream_handle.abort();
    let _ = upstream_handle.await;
    let _ = std::fs::remove_dir_all(&edge_dir);
    let _ = std::fs::remove_dir_all(&upstream_dir);
}

run_on_main_metadata_backends!(
    local_edge_pulls_upstream_copy_after_repair_impl,
    local_edge_pulls_upstream_copy_after_repair,
    local_edge_pulls_upstream_copy_after_repair_turso
);

async fn local_edge_accepts_offline_write_and_syncs_after_upstream_restart_impl(
    backend: MainTestBackend,
) {
    let upstream_dir = fresh_test_dir(&format!(
        "edge-upstream-restart-source-{}",
        backend.suffix()
    ));
    let upstream_bind_addr = free_bind_addr();
    let upstream_base_url = format!("http://{upstream_bind_addr}");
    let upstream_node_id = NodeId::new_v4();
    let mut upstream_config = ServerNodeConfig::local_edge(&upstream_dir, upstream_bind_addr);
    upstream_config.node_id = upstream_node_id;
    upstream_config.public_url = Some(upstream_base_url.clone());
    upstream_config.public_peer_api_enabled = true;
    upstream_config.replication_factor = 2;
    upstream_config.metadata_backend = backend.kind();
    let upstream_restart_config = upstream_config.clone();
    let mut upstream_handle = tokio::spawn(async move { run(upstream_config).await });

    let http = reqwest::Client::new();
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let edge_dir = fresh_test_dir(&format!(
        "edge-upstream-restart-target-{}",
        backend.suffix()
    ));
    let edge_bind_addr = free_bind_addr();
    let mut edge_config =
        ServerNodeConfig::local_edge_with_upstream(&edge_dir, edge_bind_addr, &upstream_base_url);
    edge_config.public_url = Some(format!("http://{edge_bind_addr}"));
    edge_config.replica_view_sync_interval_secs = 1;
    edge_config.startup_repair_delay_secs = 0;
    edge_config.metadata_backend = backend.kind();
    let edge_handle = tokio::spawn(async move { run(edge_config).await });
    let edge_base_url = format!("http://{edge_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{edge_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition("edge sees upstream node", Duration::from_secs(5), || {
        let http = http.clone();
        let edge_base_url = edge_base_url.clone();
        let upstream_base_url = upstream_base_url.clone();
        async move {
            let response = match http
                .get(format!("{edge_base_url}/cluster/nodes"))
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return false,
            };
            let Ok(nodes) = response.json::<Vec<cluster::NodeDescriptor>>().await else {
                return false;
            };

            nodes.iter().any(|node| {
                node.public_url == upstream_base_url || node.internal_url == upstream_base_url
            })
        }
    })
    .await;

    upstream_handle.abort();
    let _ = upstream_handle.await;

    let offline_key = "offline-after-restart.txt";
    let offline_payload = "queued-while-upstream-offline";
    let response = http
        .put(format!("{edge_base_url}/store/{offline_key}"))
        .body(offline_payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    upstream_handle = tokio::spawn(async move { run(upstream_restart_config).await });
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition(
        "edge refreshes upstream peer after restart",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let upstream_base_url = upstream_base_url.clone();
            async move {
                let response = match http
                    .get(format!("{edge_base_url}/cluster/nodes"))
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(_) => return false,
                };
                let Ok(nodes) = response.json::<Vec<cluster::NodeDescriptor>>().await else {
                    return false;
                };

                nodes.iter().any(|node| {
                    (node.public_url == upstream_base_url || node.internal_url == upstream_base_url)
                        && node.status == cluster::NodeStatus::Online
                })
            }
        },
    )
    .await;

    let repair_response = http
        .post(format!("{edge_base_url}/cluster/replication/repair"))
        .send()
        .await
        .unwrap();
    assert_eq!(repair_response.status(), StatusCode::OK);

    wait_for_condition(
        "upstream receives offline object after repair",
        Duration::from_secs(10),
        || {
            let http = http.clone();
            let upstream_base_url = upstream_base_url.clone();
            let offline_key = offline_key.to_string();
            async move {
                match http
                    .get(format!("{upstream_base_url}/store/{offline_key}"))
                    .send()
                    .await
                {
                    Ok(response) if response.status() == StatusCode::OK => {
                        match response.text().await {
                            Ok(body) => body == offline_payload,
                            Err(_) => false,
                        }
                    }
                    _ => false,
                }
            }
        },
    )
    .await;

    edge_handle.abort();
    let _ = edge_handle.await;
    upstream_handle.abort();
    let _ = upstream_handle.await;
    let _ = std::fs::remove_dir_all(&edge_dir);
    let _ = std::fs::remove_dir_all(&upstream_dir);
}

run_on_main_metadata_backends!(
    local_edge_accepts_offline_write_and_syncs_after_upstream_restart_impl,
    local_edge_accepts_offline_write_and_syncs_after_upstream_restart,
    local_edge_accepts_offline_write_and_syncs_after_upstream_restart_turso
);

async fn local_edge_offline_write_survives_edge_restart_before_upstream_returns_impl(
    backend: MainTestBackend,
) {
    let upstream_dir = fresh_test_dir(&format!(
        "edge-upstream-restart-after-edge-restart-source-{}",
        backend.suffix()
    ));
    let upstream_bind_addr = free_bind_addr();
    let upstream_base_url = format!("http://{upstream_bind_addr}");
    let upstream_node_id = NodeId::new_v4();
    let mut upstream_config = ServerNodeConfig::local_edge(&upstream_dir, upstream_bind_addr);
    upstream_config.node_id = upstream_node_id;
    upstream_config.public_url = Some(upstream_base_url.clone());
    upstream_config.public_peer_api_enabled = true;
    upstream_config.replication_factor = 2;
    upstream_config.metadata_backend = backend.kind();
    let upstream_restart_config = upstream_config.clone();
    let mut upstream_handle = tokio::spawn(async move { run(upstream_config).await });

    let http = reqwest::Client::new();
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    let edge_dir = fresh_test_dir(&format!(
        "edge-upstream-restart-after-edge-restart-target-{}",
        backend.suffix()
    ));
    let edge_bind_addr = free_bind_addr();
    let edge_node_id = NodeId::new_v4();
    let mut edge_config =
        ServerNodeConfig::local_edge_with_upstream(&edge_dir, edge_bind_addr, &upstream_base_url);
    edge_config.node_id = edge_node_id;
    edge_config.public_url = Some(format!("http://{edge_bind_addr}"));
    edge_config.replica_view_sync_interval_secs = 1;
    edge_config.startup_repair_delay_secs = 0;
    edge_config.metadata_backend = backend.kind();
    let edge_restart_config = edge_config.clone();
    let mut edge_handle = tokio::spawn(async move { run(edge_config).await });
    let edge_base_url = format!("http://{edge_bind_addr}");
    wait_for_http_status(
        &http,
        &format!("{edge_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition("edge sees upstream node", Duration::from_secs(5), || {
        let http = http.clone();
        let edge_base_url = edge_base_url.clone();
        let upstream_base_url = upstream_base_url.clone();
        async move {
            let response = match http
                .get(format!("{edge_base_url}/cluster/nodes"))
                .send()
                .await
            {
                Ok(response) => response,
                Err(_) => return false,
            };
            let Ok(nodes) = response.json::<Vec<cluster::NodeDescriptor>>().await else {
                return false;
            };

            nodes.iter().any(|node| {
                node.public_url == upstream_base_url || node.internal_url == upstream_base_url
            })
        }
    })
    .await;

    upstream_handle.abort();
    let _ = upstream_handle.await;

    let offline_key = "offline-edge-restart-durable.txt";
    let offline_payload = "persisted-across-edge-restart";
    let response = http
        .put(format!("{edge_base_url}/store/{offline_key}"))
        .body(offline_payload.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    edge_handle.abort();
    let _ = edge_handle.await;

    edge_handle = tokio::spawn(async move { run(edge_restart_config).await });
    wait_for_http_status(
        &http,
        &format!("{edge_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    upstream_handle = tokio::spawn(async move { run(upstream_restart_config).await });
    wait_for_http_status(
        &http,
        &format!("{upstream_base_url}/health"),
        StatusCode::OK,
        Duration::from_secs(5),
    )
    .await;

    wait_for_condition(
        "restarted edge refreshes upstream peer after restart",
        Duration::from_secs(5),
        || {
            let http = http.clone();
            let edge_base_url = edge_base_url.clone();
            let upstream_base_url = upstream_base_url.clone();
            async move {
                let response = match http
                    .get(format!("{edge_base_url}/cluster/nodes"))
                    .send()
                    .await
                {
                    Ok(response) => response,
                    Err(_) => return false,
                };
                let Ok(nodes) = response.json::<Vec<cluster::NodeDescriptor>>().await else {
                    return false;
                };

                nodes.iter().any(|node| {
                    (node.public_url == upstream_base_url || node.internal_url == upstream_base_url)
                        && node.status == cluster::NodeStatus::Online
                })
            }
        },
    )
    .await;

    let repair_response = http
        .post(format!("{edge_base_url}/cluster/replication/repair"))
        .send()
        .await
        .unwrap();
    assert_eq!(repair_response.status(), StatusCode::OK);

    wait_for_condition(
        "upstream receives durable offline object after edge restart",
        Duration::from_secs(10),
        || {
            let http = http.clone();
            let upstream_base_url = upstream_base_url.clone();
            let offline_key = offline_key.to_string();
            async move {
                match http
                    .get(format!("{upstream_base_url}/store/{offline_key}"))
                    .send()
                    .await
                {
                    Ok(response) if response.status() == StatusCode::OK => {
                        match response.text().await {
                            Ok(body) => body == offline_payload,
                            Err(_) => false,
                        }
                    }
                    _ => false,
                }
            }
        },
    )
    .await;

    let versions: serde_json::Value = http
        .get(format!("{upstream_base_url}/versions/{offline_key}"))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();

    let version_count = versions
        .get("versions")
        .and_then(|value| value.as_array())
        .map(|entries| entries.len())
        .unwrap_or(0);
    assert_eq!(
        version_count, 1,
        "expected exactly one synced version after repair"
    );

    edge_handle.abort();
    let _ = edge_handle.await;
    upstream_handle.abort();
    let _ = upstream_handle.await;
    let _ = std::fs::remove_dir_all(&edge_dir);
    let _ = std::fs::remove_dir_all(&upstream_dir);
}

run_on_main_metadata_backends!(
    local_edge_offline_write_survives_edge_restart_before_upstream_returns_impl,
    local_edge_offline_write_survives_edge_restart_before_upstream_returns,
    local_edge_offline_write_survives_edge_restart_before_upstream_returns_turso
);

async fn build_test_state(
    replication_factor: usize,
    seed_gap: bool,
    backend: MainTestBackend,
) -> ServerState {
    let root = fresh_test_dir(&format!("startup-repair-main-{}", backend.suffix()));
    let local_node_id = NodeId::new_v4();

    let store = Arc::new(Mutex::new(
        PersistentStore::init_with_metadata_backend(root.clone(), backend.kind())
            .await
            .unwrap(),
    ));

    let mut service = cluster::ClusterService::new(
        local_node_id,
        cluster::ReplicationPolicy {
            replication_factor,
            ..cluster::ReplicationPolicy::default()
        },
        60,
    );

    service.register_node(cluster::NodeDescriptor {
        node_id: local_node_id,
        public_url: "http://127.0.0.1:39080".to_string(),
        internal_url: "https://127.0.0.1:49080".to_string(),
        labels: HashMap::new(),
        capacity_bytes: 1_000_000,
        free_bytes: 900_000,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    });

    if replication_factor > 1 {
        service.register_node(cluster::NodeDescriptor {
            node_id: NodeId::new_v4(),
            public_url: "http://127.0.0.1:9".to_string(),
            internal_url: "https://127.0.0.1:10009".to_string(),
            labels: HashMap::new(),
            capacity_bytes: 1_000_000,
            free_bytes: 800_000,
            last_heartbeat_unix: 0,
            status: cluster::NodeStatus::Online,
        });
    }

    let (namespace_change_tx, _) = tokio::sync::watch::channel(0);
    let state = ServerState {
        cluster_id: uuid::Uuid::now_v7(),
        node_id: local_node_id,
        store: store.clone(),
        cluster: Arc::new(Mutex::new(service)),
        client_auth: Arc::new(Mutex::new(super::storage::ClientAuthState::default())),
        public_ca_pem: None,
        public_ca_key_pem: None,
        cluster_ca_pem: None,
        internal_ca_key_pem: None,
        public_tls_runtime: None,
        internal_tls_runtime: None,
        rendezvous_ca_pem: None,
        rendezvous_urls: vec!["http://127.0.0.1:39080".to_string()],
        rendezvous_registration_enabled: false,
        rendezvous_mtls_required: false,
        relay_mode: super::RelayMode::Fallback,
        enrollment_issuer_url: None,
        node_enrollment_path: None,
        node_enrollment_auto_renew_enabled: false,
        node_enrollment_auto_renew_check_secs: 300,
        node_enrollment_auto_renew_state: Arc::new(Mutex::new(
            super::NodeEnrollmentAutoRenewState::default(),
        )),
        outbound_clients: Arc::new(tokio::sync::RwLock::new(super::OutboundClients {
            internal_http: reqwest::Client::new(),
            rendezvous_control: None,
        })),
        metadata_commit_mode: MetadataCommitMode::Local,
        autonomous_replication_on_put_enabled: false,
        inflight_requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        replication_audit_interval_secs: 3600,
        peer_heartbeat_config: PeerHeartbeatConfig {
            enabled: false,
            interval_secs: 15,
        },
        repair_config: RepairConfig {
            enabled: true,
            batch_size: 32,
            max_retries: 3,
            backoff_secs: 0,
            startup_repair_enabled: true,
            startup_repair_delay_secs: 0,
            busy_throttle_enabled: false,
            busy_inflight_threshold: 1,
            busy_wait_millis: 100,
        },
        log_buffer: Arc::new(super::LogBuffer::new(64)),
        startup_repair_status: Arc::new(Mutex::new(StartupRepairStatus::Scheduled)),
        repair_state: Arc::new(Mutex::new(RepairExecutorState::default())),
        namespace_change_sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        namespace_change_tx,
        admin_control: AdminControl::default(),
        client_auth_control: super::ClientAuthControl::default(),
        client_auth_replay_cache: Arc::new(Mutex::new(super::ClientAuthReplayCache::default())),
    };

    if seed_gap {
        let put = {
            let mut locked = store.lock().await;
            locked
                .put_object_versioned(
                    "startup-gap-key",
                    bytes::Bytes::from_static(b"payload"),
                    PutOptions {
                        parent_version_ids: Vec::new(),
                        state: VersionConsistencyState::Confirmed,
                        inherit_preferred_parent: true,
                        create_snapshot: true,
                        explicit_version_id: None,
                    },
                )
                .await
                .unwrap()
        };

        let mut cluster = state.cluster.lock().await;
        cluster.note_replica("startup-gap-key", local_node_id);
        cluster.note_replica(format!("startup-gap-key@{}", put.version_id), local_node_id);
    }

    state
}

#[tokio::test]
async fn rendezvous_presence_registration_includes_unique_direct_candidates() {
    let state = build_test_state(1, false, MainTestBackend::Sqlite).await;

    let registration = build_rendezvous_presence_registration(
        &state,
        Some("https://public.example/"),
        Some("https://public.example"),
        true,
        None,
    );

    assert_eq!(
        registration.identity,
        transport_sdk::PeerIdentity::Node(state.node_id)
    );
    assert_eq!(registration.direct_candidates.len(), 1);
    assert_eq!(
        registration.direct_candidates[0].kind,
        transport_sdk::CandidateKind::DirectHttps
    );
    assert_eq!(
        registration.direct_candidates[0].endpoint,
        "https://public.example"
    );
    assert!(
        registration
            .capabilities
            .contains(&transport_sdk::TransportCapability::DirectHttps)
    );
    assert!(
        registration
            .capabilities
            .contains(&transport_sdk::TransportCapability::RelayTunnel)
    );

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn rendezvous_presence_registration_omits_public_candidate_when_peer_api_disabled() {
    let state = build_test_state(1, false, MainTestBackend::Sqlite).await;

    let registration = build_rendezvous_presence_registration(
        &state,
        Some("https://public.example"),
        Some("https://internal.example"),
        false,
        None,
    );

    assert_eq!(registration.public_api_url, None);
    assert_eq!(
        registration.peer_api_url.as_deref(),
        Some("https://internal.example")
    );
    assert_eq!(registration.direct_candidates.len(), 1);
    assert_eq!(
        registration.direct_candidates[0].endpoint,
        "https://internal.example"
    );
    assert!(
        registration
            .capabilities
            .contains(&transport_sdk::TransportCapability::DirectHttps)
    );
    assert!(
        registration
            .capabilities
            .contains(&transport_sdk::TransportCapability::RelayTunnel)
    );

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn rendezvous_presence_entry_projects_into_node_descriptor() {
    let entry = transport_sdk::PresenceEntry {
        registration: transport_sdk::PresenceRegistration {
            cluster_id: uuid::Uuid::now_v7(),
            identity: transport_sdk::PeerIdentity::Node(NodeId::new_v4()),
            public_api_url: Some("https://public.example/".to_string()),
            peer_api_url: Some("https://internal.example/".to_string()),
            direct_candidates: vec![transport_sdk::ConnectionCandidate {
                kind: transport_sdk::CandidateKind::DirectHttps,
                endpoint: "https://internal.example/".to_string(),
                rtt_ms: None,
            }],
            labels: HashMap::from([("dc".to_string(), "edge-a".to_string())]),
            capacity_bytes: Some(100),
            free_bytes: Some(40),
            capabilities: vec![transport_sdk::TransportCapability::DirectHttps],
            relay_mode: transport_sdk::RelayMode::Fallback,
            connected_at_unix: 123,
        },
        updated_at_unix: 456,
    };

    let descriptor = node_descriptor_from_presence_entry(&entry)
        .expect("presence entry should project into a node descriptor");

    assert_eq!(
        descriptor.node_id,
        match entry.registration.identity {
            transport_sdk::PeerIdentity::Node(node_id) => node_id,
            _ => unreachable!("test uses node identity"),
        }
    );
    assert_eq!(descriptor.public_url, "https://public.example");
    assert_eq!(descriptor.internal_url, "https://internal.example");
    assert_eq!(
        descriptor.labels.get("dc").map(String::as_str),
        Some("edge-a")
    );
    assert_eq!(descriptor.capacity_bytes, 100);
    assert_eq!(descriptor.free_bytes, 40);
}

#[tokio::test]
async fn rendezvous_presence_entry_projects_relay_only_node_descriptor() {
    let node_id = NodeId::new_v4();
    let entry = transport_sdk::PresenceEntry {
        registration: transport_sdk::PresenceRegistration {
            cluster_id: uuid::Uuid::now_v7(),
            identity: transport_sdk::PeerIdentity::Node(node_id),
            public_api_url: None,
            peer_api_url: None,
            direct_candidates: Vec::new(),
            labels: HashMap::new(),
            capacity_bytes: None,
            free_bytes: None,
            capabilities: vec![transport_sdk::TransportCapability::RelayTunnel],
            relay_mode: transport_sdk::RelayMode::Fallback,
            connected_at_unix: 123,
        },
        updated_at_unix: 456,
    };

    let descriptor = node_descriptor_from_presence_entry(&entry)
        .expect("relay-only presence entry should still project into a node descriptor");

    assert_eq!(descriptor.node_id, node_id);
    assert!(descriptor.public_url.is_empty());
    assert!(descriptor.internal_url.is_empty());
}

#[tokio::test]
async fn resolve_peer_base_url_prefers_internal_url() {
    let state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    let node = cluster::NodeDescriptor {
        node_id: NodeId::new_v4(),
        public_url: "https://public.example".to_string(),
        internal_url: "https://internal.example".to_string(),
        labels: HashMap::new(),
        capacity_bytes: 0,
        free_bytes: 0,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    };

    let base_url =
        resolve_peer_base_url(&state, &node).expect("peer transport should resolve base URL");

    assert_eq!(base_url, "https://internal.example");
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn resolve_peer_base_url_rejects_missing_direct_candidates() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.relay_mode = super::RelayMode::Disabled;
    let node = cluster::NodeDescriptor {
        node_id: NodeId::new_v4(),
        public_url: String::new(),
        internal_url: String::new(),
        labels: HashMap::new(),
        capacity_bytes: 0,
        free_bytes: 0,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    };

    let error = resolve_peer_base_url(&state, &node)
        .expect_err("peer transport should fail without direct candidates");

    assert!(
        error
            .to_string()
            .contains("does not expose any usable peer transport candidates")
    );
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn plan_peer_transport_falls_back_to_relay_when_direct_urls_are_missing() {
    let state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    let node = cluster::NodeDescriptor {
        node_id: NodeId::new_v4(),
        public_url: String::new(),
        internal_url: String::new(),
        labels: HashMap::new(),
        capacity_bytes: 0,
        free_bytes: 0,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    };

    let plan = plan_peer_transport(&state, &node)
        .expect("peer transport should synthesize a relay path when rendezvous is available");

    assert_eq!(
        plan.path_kind,
        transport_sdk::TransportPathKind::RelayTunnel
    );
    assert_eq!(
        plan.candidate.as_ref().map(|candidate| candidate.kind),
        Some(transport_sdk::CandidateKind::Relay)
    );
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn plan_peer_transport_uses_relay_when_required_even_with_direct_urls() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.relay_mode = super::RelayMode::Required;
    let node = cluster::NodeDescriptor {
        node_id: NodeId::new_v4(),
        public_url: "https://public.example".to_string(),
        internal_url: "https://internal.example".to_string(),
        labels: HashMap::new(),
        capacity_bytes: 0,
        free_bytes: 0,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    };

    let plan =
        plan_peer_transport(&state, &node).expect("relay-required transport should still plan");

    assert_eq!(
        plan.path_kind,
        transport_sdk::TransportPathKind::RelayTunnel
    );
    assert_eq!(
        plan.candidate.as_ref().map(|candidate| candidate.kind),
        Some(transport_sdk::CandidateKind::Relay)
    );
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn execute_replication_cleanup_routes_remote_drop_through_relay() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.relay_mode = super::RelayMode::Required;

    let remote_node = {
        let mut cluster = state.cluster.lock().await;
        if let Some(node) = cluster
            .list_nodes()
            .into_iter()
            .find(|node| node.node_id != state.node_id)
        {
            node
        } else {
            let node = cluster::NodeDescriptor {
                node_id: NodeId::new_v4(),
                public_url: "https://relay-cleanup-remote.example".to_string(),
                internal_url: "https://relay-cleanup-remote-internal.example".to_string(),
                labels: HashMap::new(),
                capacity_bytes: 1_000_000,
                free_bytes: 800_000,
                last_heartbeat_unix: 0,
                status: cluster::NodeStatus::Online,
            };
            cluster.register_node(node.clone());
            node
        }
    };

    let relay_bind_addr = free_bind_addr();
    let relay_base_url = format!("http://{relay_bind_addr}");
    state.rendezvous_urls = vec![relay_base_url.clone()];

    let rendezvous_client = transport_sdk::RendezvousControlClient::new(
        transport_sdk::RendezvousClientConfig {
            cluster_id: state.cluster_id,
            rendezvous_urls: vec![relay_base_url.clone()],
            heartbeat_interval_secs: 15,
        },
        None,
        None,
    )
    .expect("rendezvous client should build");
    *state.outbound_clients.write().await = super::OutboundClients {
        internal_http: reqwest::Client::new(),
        rendezvous_control: Some(rendezvous_client),
    };

    let observed_paths = Arc::new(Mutex::new(Vec::<String>::new()));
    let relay_paths = observed_paths.clone();
    let expected_target = transport_sdk::PeerIdentity::Node(remote_node.node_id);
    let relay_app = Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route(
            "/control/relay/ticket",
            post({
                let relay_base_url = relay_base_url.clone();
                let expected_target = expected_target.clone();
                move |Json(request): Json<transport_sdk::RelayTicketRequest>| {
                    let relay_base_url = relay_base_url.clone();
                    let expected_target = expected_target.clone();
                    async move {
                        assert_eq!(request.target, expected_target);
                        Json(transport_sdk::RelayTicket {
                            cluster_id: request.cluster_id,
                            session_id: "cleanup-relay-session".to_string(),
                            source: request.source,
                            target: request.target,
                            relay_urls: vec![relay_base_url],
                            issued_at_unix: 1,
                            expires_at_unix: 301,
                        })
                    }
                }
            }),
        )
        .route(
            "/relay/http/request",
            post(
                move |Json(request): Json<transport_sdk::RelayHttpRequest>| {
                    let relay_paths = relay_paths.clone();
                    async move {
                        relay_paths
                            .lock()
                            .await
                            .push(request.path_and_query.clone());
                        Json(transport_sdk::RelayHttpResponse {
                            cluster_id: request.ticket.cluster_id,
                            session_id: request.ticket.session_id.clone(),
                            request_id: request.request_id,
                            responder: request.ticket.target,
                            status: StatusCode::OK.as_u16(),
                            headers: Vec::new(),
                            body_base64: None,
                        })
                    }
                },
            ),
        );
    let relay_listener = tokio::net::TcpListener::bind(relay_bind_addr)
        .await
        .expect("relay stub listener should bind");
    let relay_handle = tokio::spawn(async move {
        axum::serve(relay_listener, relay_app)
            .await
            .expect("relay stub should serve");
    });

    wait_for_condition("relay stub health", Duration::from_secs(5), || {
        let relay_base_url = relay_base_url.clone();
        async move {
            match reqwest::get(format!("{relay_base_url}/health")).await {
                Ok(response) => response.status() == StatusCode::OK,
                Err(_) => false,
            }
        }
    })
    .await;

    let key = "relay-cleanup-subject";
    let version_id = {
        let cluster = state.cluster.lock().await;
        (0..256)
            .map(|attempt| format!("relay-cleanup-version-{attempt}"))
            .find(|version_id| {
                cluster
                    .placement_for_key(&format!("{key}@{version_id}"))
                    .selected_nodes
                    .first()
                    == Some(&state.node_id)
            })
            .expect("expected a version subject placed on the local node")
    };

    {
        let mut store = state.store.lock().await;
        store
            .put_object_versioned(
                key,
                Bytes::from_static(b"relay-cleanup-payload"),
                PutOptions {
                    parent_version_ids: Vec::new(),
                    state: VersionConsistencyState::Confirmed,
                    inherit_preferred_parent: true,
                    create_snapshot: true,
                    explicit_version_id: Some(version_id.clone()),
                },
            )
            .await
            .expect("test object should store");
    }

    {
        let mut cluster = state.cluster.lock().await;
        cluster.note_replica(key, state.node_id);
        cluster.note_replica(format!("{key}@{version_id}"), state.node_id);
        cluster.note_replica(key, remote_node.node_id);
        cluster.note_replica(format!("{key}@{version_id}"), remote_node.node_id);
    }

    let response = super::execute_replication_cleanup(
        State(state.clone()),
        Query(super::ReplicationCleanupQuery {
            dry_run: Some(false),
            max_deletions: Some(1),
            retained_overhead_bytes: Some(0),
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("cleanup response body should read");
    let report: serde_json::Value =
        serde_json::from_slice(&body).expect("cleanup response should decode");
    assert_eq!(report["successful_deletions"].as_u64(), Some(1));
    assert_eq!(report["failed_deletions"].as_u64(), Some(0));

    let observed_paths = observed_paths.lock().await.clone();
    assert_eq!(observed_paths.len(), 1);
    assert_eq!(
        observed_paths[0],
        super::build_replication_drop_path(key, &version_id)
    );

    let replicas = {
        let cluster = state.cluster.lock().await;
        cluster.export_replicas_by_key()
    };
    assert_eq!(
        replicas.get(&format!("{key}@{version_id}")),
        Some(&vec![state.node_id])
    );

    relay_handle.abort();
    let _ = relay_handle.await;
    cleanup_test_state(&state).await;
}

async fn cleanup_test_state(state: &ServerState) {
    let root = {
        let store = state.store.lock().await;
        store.root_dir().to_path_buf()
    };
    let _ = tokio::fs::remove_dir_all(root).await;
}

fn fresh_test_dir(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!("ironmesh-{name}-{unique}"));
    let _ = std::fs::remove_dir_all(&path);
    let _ = std::fs::create_dir_all(&path);
    path
}

async fn wait_for_condition<F, Fut>(label: &str, timeout: Duration, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + timeout;

    loop {
        if condition().await {
            return;
        }

        assert!(
            Instant::now() < deadline,
            "{label} was not met within {:?}",
            timeout,
        );

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_http_status(
    http: &reqwest::Client,
    url: &str,
    expected_status: StatusCode,
    timeout: Duration,
) {
    wait_for_condition("http status", timeout, || {
        let http = http.clone();
        let url = url.to_string();
        async move {
            match http.get(url).send().await {
                Ok(response) => response.status() == expected_status,
                Err(_) => false,
            }
        }
    })
    .await;
}
