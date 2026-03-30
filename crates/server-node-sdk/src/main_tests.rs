use super::{
    AdminControl, LocalNodeHandle, MetadataCommitMode, PeerHeartbeatConfig, RepairConfig,
    RepairExecutorState, ServerNodeConfig, ServerState, StartupRepairStatus,
    await_repair_busy_threshold, build_rendezvous_presence_registration, build_store_index_entries,
    cluster, constant_time_eq, jittered_backoff_secs, lock_store, new_store_rwlock,
    node_descriptor_from_presence_entry, plan_peer_transport,
    replication::build_internal_replication_put_url, resolve_peer_base_url, run,
    run_startup_replication_repair_once, should_trigger_autonomous_post_write_replication,
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
use axum::extract::{Json, Path, Query, State};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use bytes::Bytes;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
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
fn normalize_rendezvous_url_list_deduplicates_trailing_slash_variants() {
    let normalized = super::normalize_rendezvous_url_list(&[
        "https://node-a.local:9443".to_string(),
        "https://node-a.local:9443/".to_string(),
        "https://node-b.local:9443/".to_string(),
    ])
    .unwrap();

    assert_eq!(
        normalized,
        vec![
            "https://node-a.local:9443/".to_string(),
            "https://node-b.local:9443/".to_string()
        ]
    );
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

fn sample_large_chunked_payload() -> Vec<u8> {
    let size = 2 * 1024 * 1024 + 1536;
    (0..size).map(|index| (index % 251) as u8).collect()
}

#[cfg(unix)]
fn sample_video_thumbnail_bytes() -> Vec<u8> {
    let mut image = image::RgbImage::new(256, 144);
    for y in 0..144 {
        for x in 0..256 {
            let pixel = if x < 128 {
                image::Rgb([28, 99, 193])
            } else {
                image::Rgb([244, 180, 0])
            };
            image.put_pixel(x, y, pixel);
        }
    }

    let mut jpeg = Vec::new();
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 90);
    encoder
        .encode_image(&image::DynamicImage::ImageRgb8(image))
        .unwrap();
    jpeg
}

#[cfg(unix)]
fn install_fake_video_tools(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    std::fs::create_dir_all(dir).unwrap();
    let poster_path = dir.join("poster.jpg");
    std::fs::write(&poster_path, sample_video_thumbnail_bytes()).unwrap();

    let ffprobe_path = dir.join("ffprobe");
    let ffprobe_script = r#"#!/bin/sh
set -eu
input=""
for arg in "$@"; do
  [ "$arg" != "-nostdin" ]
  input="$arg"
done
list="${input#concatf:}"
[ -f "$list" ]
line_count=$(wc -l < "$list" | tr -d ' ')
[ "$line_count" -ge 3 ]
grep -q '^file:' "$list"
printf '%s\n' '{"streams":[{"width":1920,"height":1080}],"format":{"format_name":"mov,mp4,m4a,3gp,3g2,mj2","duration":"42.0"}}'
"#;
    std::fs::write(&ffprobe_path, ffprobe_script).unwrap();

    let ffmpeg_path = dir.join("ffmpeg");
    let ffmpeg_script = format!(
        r#"#!/bin/sh
set -eu
input=""
prev=""
for arg in "$@"; do
  if [ "$prev" = "-i" ]; then
    input="$arg"
    break
  fi
  prev="$arg"
done
list="${{input#concatf:}}"
[ -f "$list" ]
line_count=$(wc -l < "$list" | tr -d ' ')
[ "$line_count" -ge 3 ]
grep -q '^file:' "$list"
cat '{}'
"#,
        poster_path.display()
    );
    std::fs::write(&ffmpeg_path, ffmpeg_script).unwrap();

    for path in [&ffprobe_path, &ffmpeg_path] {
        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    (ffprobe_path, ffmpeg_path)
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
        let mut auth = state.client_credentials.lock().await;
        auth.pairing_authorizations
            .push(super::PairingAuthorizationRecord {
                token_id: "pair-1".to_string(),
                pairing_secret_hash: super::hash_token("pair-secret"),
                label: Some("Pixel".to_string()),
                created_at_unix: now,
                expires_at_unix: now + 300,
                used_at_unix: None,
                consumed_by_device_id: None,
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
    assert!(enrolled["credential_pem"].as_str().is_some());

    let auth = state.client_credentials.lock().await;
    assert_eq!(auth.credentials.len(), 1);
    assert_eq!(auth.credentials[0].device_id, "device-a");
    assert!(auth.pairing_authorizations[0].used_at_unix.is_some());
    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    enroll_client_device_consumes_pairing_token_and_persists_device_impl,
    enroll_client_device_consumes_pairing_token_and_persists_device,
    enroll_client_device_consumes_pairing_token_and_persists_device_turso
);

#[tokio::test]
async fn enroll_client_device_issues_rendezvous_mtls_identity_when_required() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    let (cluster_ca_pem, internal_ca_key_pem) = generate_test_internal_ca();
    state.cluster_ca_pem = Some(cluster_ca_pem);
    state.internal_ca_key_pem = Some(internal_ca_key_pem);
    state.rendezvous_mtls_required = true;

    let now = super::unix_ts();
    {
        let mut auth = state.client_credentials.lock().await;
        auth.pairing_authorizations
            .push(super::PairingAuthorizationRecord {
                token_id: "pair-2".to_string(),
                pairing_secret_hash: super::hash_token("pair-secret-2"),
                label: Some("Laptop".to_string()),
                created_at_unix: now,
                expires_at_unix: now + 300,
                used_at_unix: None,
                consumed_by_device_id: None,
            });
    }

    let response = super::enroll_client_device(
        State(state.clone()),
        Json(super::ClientDeviceEnrollRequest {
            cluster_id: state.cluster_id,
            pairing_token: "pair-secret-2".to_string(),
            device_id: Some("device-b".to_string()),
            label: Some("Laptop".to_string()),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                .to_string(),
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let enrolled: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let rendezvous_identity_pem = enrolled["rendezvous_client_identity_pem"]
        .as_str()
        .expect("rendezvous client identity PEM should be present");
    assert!(rendezvous_identity_pem.contains("BEGIN CERTIFICATE"));
    assert!(rendezvous_identity_pem.contains("PRIVATE KEY"));

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn issue_bootstrap_bundle_includes_rendezvous_security_metadata() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    state.public_ca_pem = Some("public-ca".to_string());
    state.cluster_ca_pem = Some("cluster-ca".to_string());
    state.rendezvous_ca_pem = Some("rendezvous-ca".to_string());
    *state.rendezvous_urls.lock().unwrap() = vec!["https://rendezvous.example".to_string()];
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
            preferred_rendezvous_url: None,
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let bootstrap: transport_sdk::ClientBootstrap = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        bootstrap.rendezvous_urls,
        vec!["https://rendezvous.example/".to_string()]
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
    assert!(!bootstrap.direct_endpoints.is_empty());
    assert!(
        bootstrap
            .direct_endpoints
            .iter()
            .all(|endpoint| endpoint.node_id.is_some())
    );
    assert!(
        bootstrap
            .direct_endpoints
            .iter()
            .all(|endpoint| endpoint.node_id == Some(state.node_id))
    );
    assert_eq!(bootstrap.device_label.as_deref(), Some("tablet"));
    assert!(bootstrap.pairing_token.is_some());

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn issue_bootstrap_claim_returns_compact_qr_payload_and_publishes_to_rendezvous() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let (cluster_ca_pem, _) = generate_test_internal_ca();
    let (public_ca_pem, _) = generate_test_internal_ca();
    let (rendezvous_ca_pem, _) = generate_test_internal_ca();
    state.public_ca_pem = Some(public_ca_pem.clone());
    state.cluster_ca_pem = Some(cluster_ca_pem.clone());
    state.rendezvous_ca_pem = Some(rendezvous_ca_pem.clone());
    state.rendezvous_registration_enabled = true;
    state.rendezvous_mtls_required = true;

    let captured_publish = Arc::new(Mutex::new(
        None::<transport_sdk::ClientBootstrapClaimPublishRequest>,
    ));
    let captured_publish_state = captured_publish.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock rendezvous should bind");
    let rendezvous_addr = listener.local_addr().expect("mock rendezvous addr");
    let rendezvous_url = format!("http://{rendezvous_addr}");
    *state.rendezvous_urls.lock().unwrap() = vec![rendezvous_url.clone()];
    let rendezvous_server = tokio::spawn(async move {
        axum::serve(
            listener,
            Router::new().route(
                "/control/bootstrap-claims/publish",
                post(
                    move |Json(request): Json<
                        transport_sdk::ClientBootstrapClaimPublishRequest,
                    >| {
                        let captured_publish_state = captured_publish_state.clone();
                        async move {
                            *captured_publish_state.lock().await = Some(request.clone());
                            Json(transport_sdk::ClientBootstrapClaimPublishResponse {
                                accepted: true,
                                expires_at_unix: request.expires_at_unix,
                            })
                        }
                    },
                ),
            ),
        )
        .await
        .expect("mock rendezvous should serve");
    });

    let rendezvous_client = transport_sdk::RendezvousControlClient::new(
        transport_sdk::RendezvousClientConfig {
            cluster_id: state.cluster_id,
            rendezvous_urls: vec![rendezvous_url.clone()],
            heartbeat_interval_secs: 15,
        },
        None,
        None,
    )
    .expect("rendezvous client should build");
    *state.outbound_clients.write().await = super::OutboundClients {
        internal_http: reqwest::Client::new(),
        rendezvous_control: Some(rendezvous_client.clone()),
        rendezvous_controls: vec![super::RendezvousEndpointClient {
            url: rendezvous_url.clone(),
            control: rendezvous_client,
        }],
    };

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let response = super::issue_bootstrap_claim(
        State(state.clone()),
        headers,
        Json(super::PairingTokenIssueRequest {
            label: Some("tablet".to_string()),
            expires_in_secs: Some(600),
            preferred_rendezvous_url: None,
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let issued: transport_sdk::ClientBootstrapClaimIssueResponse =
        serde_json::from_slice(&body).unwrap();
    assert_eq!(issued.bootstrap_bundle.cluster_id, state.cluster_id);
    assert_eq!(
        issued.bootstrap_claim.rendezvous_url,
        format!("{rendezvous_url}/"),
    );
    assert_eq!(
        issued.bootstrap_claim.kind,
        transport_sdk::CLIENT_BOOTSTRAP_CLAIM_KIND
    );
    assert_eq!(
        issued.bootstrap_claim.trust.mode,
        transport_sdk::ClientBootstrapClaimTrustMode::RendezvousCaDerB64u
    );
    assert!(issued.bootstrap_claim.trust.ca_der_b64u.is_some());
    assert!(issued.bootstrap_claim.claim_token.starts_with("im-claim-"));
    assert!(issued.bootstrap_bundle.pairing_token.is_some());

    let published = captured_publish
        .lock()
        .await
        .clone()
        .expect("claim publish request should be captured");
    assert_eq!(published.cluster_id, state.cluster_id);
    assert_eq!(
        published.issuer,
        transport_sdk::PeerIdentity::Node(state.node_id)
    );
    assert_eq!(published.target_node_id, state.node_id);
    assert_eq!(
        published.claim_secret_hash,
        super::hash_token(&issued.bootstrap_claim.claim_token)
    );
    assert_eq!(published.bootstrap.cluster_id, state.cluster_id);
    assert_eq!(
        published.bootstrap.trust_roots.rendezvous_ca_pem.as_deref(),
        Some(rendezvous_ca_pem.as_str())
    );

    rendezvous_server.abort();
    let _ = rendezvous_server.await;
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn issue_bootstrap_claim_uses_selected_rendezvous_service_when_requested() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let (cluster_ca_pem, _) = generate_test_internal_ca();
    let (public_ca_pem, _) = generate_test_internal_ca();
    let (rendezvous_ca_pem, _) = generate_test_internal_ca();
    state.public_ca_pem = Some(public_ca_pem.clone());
    state.cluster_ca_pem = Some(cluster_ca_pem.clone());
    state.rendezvous_ca_pem = Some(rendezvous_ca_pem.clone());
    state.rendezvous_registration_enabled = true;
    state.rendezvous_mtls_required = true;

    let captured_publish_a = Arc::new(Mutex::new(
        None::<transport_sdk::ClientBootstrapClaimPublishRequest>,
    ));
    let captured_publish_b = Arc::new(Mutex::new(
        None::<transport_sdk::ClientBootstrapClaimPublishRequest>,
    ));

    let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock rendezvous A should bind");
    let rendezvous_addr_a = listener_a.local_addr().expect("mock rendezvous A addr");
    let rendezvous_url_a = format!("http://{rendezvous_addr_a}");
    let captured_publish_a_state = captured_publish_a.clone();
    let rendezvous_server_a = tokio::spawn(async move {
        axum::serve(
            listener_a,
            Router::new().route(
                "/control/bootstrap-claims/publish",
                post(
                    move |Json(request): Json<
                        transport_sdk::ClientBootstrapClaimPublishRequest,
                    >| {
                        let captured_publish_a_state = captured_publish_a_state.clone();
                        async move {
                            *captured_publish_a_state.lock().await = Some(request.clone());
                            Json(transport_sdk::ClientBootstrapClaimPublishResponse {
                                accepted: true,
                                expires_at_unix: request.expires_at_unix,
                            })
                        }
                    },
                ),
            ),
        )
        .await
        .expect("mock rendezvous A should serve");
    });

    let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock rendezvous B should bind");
    let rendezvous_addr_b = listener_b.local_addr().expect("mock rendezvous B addr");
    let rendezvous_url_b = format!("http://{rendezvous_addr_b}");
    let captured_publish_b_state = captured_publish_b.clone();
    let rendezvous_server_b = tokio::spawn(async move {
        axum::serve(
            listener_b,
            Router::new().route(
                "/control/bootstrap-claims/publish",
                post(
                    move |Json(request): Json<
                        transport_sdk::ClientBootstrapClaimPublishRequest,
                    >| {
                        let captured_publish_b_state = captured_publish_b_state.clone();
                        async move {
                            *captured_publish_b_state.lock().await = Some(request.clone());
                            Json(transport_sdk::ClientBootstrapClaimPublishResponse {
                                accepted: true,
                                expires_at_unix: request.expires_at_unix,
                            })
                        }
                    },
                ),
            ),
        )
        .await
        .expect("mock rendezvous B should serve");
    });

    *state.rendezvous_urls.lock().unwrap() =
        vec![rendezvous_url_a.clone(), rendezvous_url_b.clone()];
    let shared_rendezvous_client = transport_sdk::RendezvousControlClient::new(
        transport_sdk::RendezvousClientConfig {
            cluster_id: state.cluster_id,
            rendezvous_urls: vec![rendezvous_url_a.clone(), rendezvous_url_b.clone()],
            heartbeat_interval_secs: 15,
        },
        None,
        None,
    )
    .expect("shared rendezvous client should build");
    let rendezvous_client_a = transport_sdk::RendezvousControlClient::new(
        transport_sdk::RendezvousClientConfig {
            cluster_id: state.cluster_id,
            rendezvous_urls: vec![rendezvous_url_a.clone()],
            heartbeat_interval_secs: 15,
        },
        None,
        None,
    )
    .expect("rendezvous client A should build");
    let rendezvous_client_b = transport_sdk::RendezvousControlClient::new(
        transport_sdk::RendezvousClientConfig {
            cluster_id: state.cluster_id,
            rendezvous_urls: vec![rendezvous_url_b.clone()],
            heartbeat_interval_secs: 15,
        },
        None,
        None,
    )
    .expect("rendezvous client B should build");
    *state.outbound_clients.write().await = super::OutboundClients {
        internal_http: reqwest::Client::new(),
        rendezvous_control: Some(shared_rendezvous_client),
        rendezvous_controls: vec![
            super::RendezvousEndpointClient {
                url: format!("{rendezvous_url_a}/"),
                control: rendezvous_client_b.clone(),
            },
            super::RendezvousEndpointClient {
                url: format!("{rendezvous_url_b}/"),
                control: rendezvous_client_a.clone(),
            },
        ],
    };

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let response = super::issue_bootstrap_claim(
        State(state.clone()),
        headers,
        Json(super::PairingTokenIssueRequest {
            label: Some("tablet".to_string()),
            expires_in_secs: Some(600),
            preferred_rendezvous_url: Some(rendezvous_url_b.clone()),
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let issued: transport_sdk::ClientBootstrapClaimIssueResponse =
        serde_json::from_slice(&body).unwrap();
    assert_eq!(
        issued.bootstrap_claim.rendezvous_url,
        format!("{rendezvous_url_b}/"),
    );
    assert!(captured_publish_a.lock().await.is_none());
    assert!(captured_publish_b.lock().await.is_some());

    rendezvous_server_a.abort();
    let _ = rendezvous_server_a.await;
    rendezvous_server_b.abort();
    let _ = rendezvous_server_b.await;
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn issue_bootstrap_claim_automatic_mode_uses_rendezvous_that_accepts_the_publish() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let (cluster_ca_pem, _) = generate_test_internal_ca();
    let (public_ca_pem, _) = generate_test_internal_ca();
    let (rendezvous_ca_pem, _) = generate_test_internal_ca();
    state.public_ca_pem = Some(public_ca_pem.clone());
    state.cluster_ca_pem = Some(cluster_ca_pem.clone());
    state.rendezvous_ca_pem = Some(rendezvous_ca_pem.clone());
    state.rendezvous_registration_enabled = true;
    state.rendezvous_mtls_required = true;

    let captured_publish_b = Arc::new(Mutex::new(
        None::<transport_sdk::ClientBootstrapClaimPublishRequest>,
    ));

    let listener_a = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock rendezvous A should bind");
    let rendezvous_addr_a = listener_a.local_addr().expect("mock rendezvous A addr");
    let rendezvous_url_a = format!("http://{rendezvous_addr_a}");
    let rendezvous_server_a = tokio::spawn(async move {
        axum::serve(
            listener_a,
            Router::new().route(
                "/control/bootstrap-claims/publish",
                post(|| async { (StatusCode::BAD_GATEWAY, "unavailable") }),
            ),
        )
        .await
        .expect("mock rendezvous A should serve");
    });

    let listener_b = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock rendezvous B should bind");
    let rendezvous_addr_b = listener_b.local_addr().expect("mock rendezvous B addr");
    let rendezvous_url_b = format!("http://{rendezvous_addr_b}");
    let captured_publish_b_state = captured_publish_b.clone();
    let rendezvous_server_b = tokio::spawn(async move {
        axum::serve(
            listener_b,
            Router::new().route(
                "/control/bootstrap-claims/publish",
                post(
                    move |Json(request): Json<
                        transport_sdk::ClientBootstrapClaimPublishRequest,
                    >| {
                        let captured_publish_b_state = captured_publish_b_state.clone();
                        async move {
                            *captured_publish_b_state.lock().await = Some(request.clone());
                            Json(transport_sdk::ClientBootstrapClaimPublishResponse {
                                accepted: true,
                                expires_at_unix: request.expires_at_unix,
                            })
                        }
                    },
                ),
            ),
        )
        .await
        .expect("mock rendezvous B should serve");
    });

    *state.rendezvous_urls.lock().unwrap() =
        vec![rendezvous_url_a.clone(), rendezvous_url_b.clone()];
    let shared_rendezvous_client = transport_sdk::RendezvousControlClient::new(
        transport_sdk::RendezvousClientConfig {
            cluster_id: state.cluster_id,
            rendezvous_urls: vec![rendezvous_url_a.clone(), rendezvous_url_b.clone()],
            heartbeat_interval_secs: 15,
        },
        None,
        None,
    )
    .expect("shared rendezvous client should build");
    *state.outbound_clients.write().await = super::OutboundClients {
        internal_http: reqwest::Client::new(),
        rendezvous_control: Some(shared_rendezvous_client),
        rendezvous_controls: Vec::new(),
    };

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let response = super::issue_bootstrap_claim(
        State(state.clone()),
        headers,
        Json(super::PairingTokenIssueRequest {
            label: Some("tablet".to_string()),
            expires_in_secs: Some(600),
            preferred_rendezvous_url: None,
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let issued: transport_sdk::ClientBootstrapClaimIssueResponse =
        serde_json::from_slice(&body).unwrap();
    assert_eq!(
        issued.bootstrap_claim.rendezvous_url,
        format!("{rendezvous_url_b}/"),
    );
    assert!(captured_publish_b.lock().await.is_some());

    rendezvous_server_a.abort();
    let _ = rendezvous_server_a.await;
    rendezvous_server_b.abort();
    let _ = rendezvous_server_b.await;
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn issue_bootstrap_claim_returns_json_error_when_rendezvous_is_unavailable() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let (cluster_ca_pem, _) = generate_test_internal_ca();
    let (public_ca_pem, _) = generate_test_internal_ca();
    state.public_ca_pem = Some(public_ca_pem);
    state.cluster_ca_pem = Some(cluster_ca_pem);

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let response = super::issue_bootstrap_claim(
        State(state.clone()),
        headers,
        Json(super::PairingTokenIssueRequest {
            label: Some("tablet".to_string()),
            expires_in_secs: Some(600),
            preferred_rendezvous_url: None,
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        payload.get("error").and_then(|value| value.as_str()),
        Some("bootstrap claim issuance requires rendezvous to be configured on this node")
    );

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
                node_id: Some(node_id),
            },
            transport_sdk::BootstrapEndpoint {
                url: "https://10.0.0.12:38080".to_string(),
                usage: Some(transport_sdk::BootstrapEndpointUse::PeerApi),
                node_id: Some(node_id),
            },
        ],
        relay_mode: transport_sdk::RelayMode::Required,
        trust_roots: transport_sdk::BootstrapTrustRoots {
            cluster_ca_pem: Some("cluster-ca".to_string()),
            public_api_ca_pem: Some("public-ca".to_string()),
            rendezvous_ca_pem: Some("rendezvous-ca".to_string()),
        },
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
        config.enrollment_issuer_url.as_deref(),
        Some("https://issuer.example")
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn local_edge_bootstrap_with_rendezvous_enables_cluster_sync_defaults() {
    let root = fresh_test_dir("local-edge-bootstrap-config");
    let bootstrap_path = root.join("node-bootstrap.json");
    let node_id = NodeId::new_v4();
    let cluster_id = uuid::Uuid::now_v7();
    transport_sdk::NodeBootstrap {
        version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
        cluster_id,
        node_id,
        mode: transport_sdk::NodeBootstrapMode::LocalEdge,
        data_dir: root.join("data").to_string_lossy().into_owned(),
        bind_addr: "127.0.0.1:28080".to_string(),
        public_url: Some("https://edge.example".to_string()),
        labels: HashMap::new(),
        public_tls: None,
        public_ca_cert_path: None,
        public_peer_api_enabled: true,
        internal_bind_addr: None,
        internal_url: None,
        internal_tls: None,
        rendezvous_urls: vec!["https://rendezvous.example".to_string()],
        rendezvous_mtls_required: false,
        direct_endpoints: vec![
            transport_sdk::BootstrapEndpoint {
                url: "https://edge.example".to_string(),
                usage: Some(transport_sdk::BootstrapEndpointUse::PublicApi),
                node_id: Some(node_id),
            },
            transport_sdk::BootstrapEndpoint {
                url: "https://edge.example".to_string(),
                usage: Some(transport_sdk::BootstrapEndpointUse::PeerApi),
                node_id: Some(node_id),
            },
        ],
        relay_mode: transport_sdk::RelayMode::Fallback,
        trust_roots: transport_sdk::BootstrapTrustRoots {
            cluster_ca_pem: Some("cluster-ca".to_string()),
            public_api_ca_pem: Some("public-ca".to_string()),
            rendezvous_ca_pem: Some("rendezvous-ca".to_string()),
        },
        enrollment_issuer_url: Some("https://issuer.example".to_string()),
    }
    .write_to_path(&bootstrap_path)
    .unwrap();

    let config = super::ServerNodeConfig::from_bootstrap_path(&bootstrap_path).unwrap();

    assert!(matches!(config.mode, super::ServerNodeMode::LocalEdge));
    assert!(config.rendezvous_registration_enabled);
    assert!(config.public_peer_api_enabled);
    assert_eq!(config.replication_factor, 2);
    assert_eq!(config.audit_interval_secs, 5);
    assert!(config.autonomous_replication_on_put_enabled);
    assert!(config.replication_repair_enabled);
    assert!(config.startup_repair_enabled);

    let _ = std::fs::remove_dir_all(&root);
}

#[tokio::test]
async fn issue_node_bootstrap_includes_runtime_and_rendezvous_metadata() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    state.public_ca_pem = Some("public-ca".to_string());
    state.cluster_ca_pem = Some("cluster-ca".to_string());
    state.rendezvous_ca_pem = Some("rendezvous-ca".to_string());
    *state.rendezvous_urls.lock().unwrap() = vec!["https://rendezvous.example".to_string()];
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
        vec!["https://rendezvous.example/".to_string()]
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
        bootstrap.direct_endpoints[0].node_id,
        Some(requested_node_id)
    );
    assert_eq!(
        bootstrap.direct_endpoints[1].usage,
        Some(transport_sdk::BootstrapEndpointUse::PeerApi)
    );
    assert_eq!(
        bootstrap.direct_endpoints[1].node_id,
        Some(requested_node_id)
    );

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn issue_local_edge_bootstrap_defaults_public_peer_api_when_rendezvous_is_enabled() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    state.public_ca_pem = Some("public-ca".to_string());
    state.cluster_ca_pem = Some("cluster-ca".to_string());
    state.rendezvous_ca_pem = Some("rendezvous-ca".to_string());
    *state.rendezvous_urls.lock().unwrap() = vec!["https://rendezvous.example".to_string()];
    state.rendezvous_registration_enabled = true;
    state.relay_mode = transport_sdk::RelayMode::Fallback;

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let response = super::issue_node_bootstrap(
        State(state.clone()),
        headers,
        Json(super::NodeBootstrapIssueRequest {
            node_id: Some(NodeId::new_v4()),
            mode: Some(transport_sdk::NodeBootstrapMode::LocalEdge),
            data_dir: Some("./data/edge".to_string()),
            bind_addr: Some("127.0.0.1:28080".to_string()),
            public_url: Some("https://edge.example".to_string()),
            labels: None,
            public_tls: None,
            public_ca_cert_path: None,
            public_peer_api_enabled: None,
            internal_bind_addr: None,
            internal_url: None,
            internal_tls: None,
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

    assert!(matches!(
        bootstrap.mode,
        transport_sdk::NodeBootstrapMode::LocalEdge
    ));
    assert!(bootstrap.public_peer_api_enabled);
    assert_eq!(bootstrap.direct_endpoints.len(), 2);
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
    *state.rendezvous_urls.lock().unwrap() = vec!["https://rendezvous.example".to_string()];
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
async fn issue_node_enrollment_from_join_request_returns_enrollment_package() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let (cluster_ca_pem, internal_ca_key_pem) = generate_test_internal_ca();
    state.cluster_ca_pem = Some(cluster_ca_pem.clone());
    state.public_ca_pem = Some(cluster_ca_pem);
    state.internal_ca_key_pem = Some(internal_ca_key_pem);

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());
    let join_request = transport_sdk::NodeJoinRequest {
        version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
        node_id: NodeId::new_v4(),
        mode: transport_sdk::NodeBootstrapMode::Cluster,
        data_dir: "./data/node-join".to_string(),
        bind_addr: "127.0.0.1:28080".to_string(),
        public_url: Some("https://node-join.example".to_string()),
        labels: HashMap::from([("rack".to_string(), "rack-join".to_string())]),
        public_tls: Some(transport_sdk::BootstrapServerTlsFiles {
            cert_path: "managed/runtime/public/public.pem".to_string(),
            key_path: "managed/runtime/public/public.key".to_string(),
        }),
        public_ca_cert_path: Some("managed/runtime/public/public-ca.pem".to_string()),
        public_peer_api_enabled: false,
        internal_bind_addr: Some("127.0.0.1:38080".to_string()),
        internal_url: Some("https://node-join.example:38080".to_string()),
        internal_tls: Some(transport_sdk::BootstrapTlsFiles {
            ca_cert_path: "managed/runtime/internal/cluster-ca.pem".to_string(),
            cert_path: "managed/runtime/internal/node.pem".to_string(),
            key_path: "managed/runtime/internal/node.key".to_string(),
        }),
    };

    let response = super::issue_node_enrollment_from_join_request(
        State(state.clone()),
        headers,
        Json(super::NodeJoinEnrollmentIssueRequest {
            join_request: join_request.clone(),
            tls_validity_secs: None,
            tls_renewal_window_secs: None,
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let package: transport_sdk::NodeEnrollmentPackage = serde_json::from_slice(&body).unwrap();
    assert_eq!(package.bootstrap.node_id, join_request.node_id);
    assert_eq!(package.bootstrap.bind_addr, join_request.bind_addr);
    assert_eq!(package.bootstrap.public_url, join_request.public_url);
    assert_eq!(package.bootstrap.internal_url, join_request.internal_url);
    assert_eq!(
        package.bootstrap.labels.get("rack").map(String::as_str),
        Some("rack-join")
    );
    assert!(package.public_tls_material.is_some());
    assert!(package.internal_tls_material.is_some());

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn export_managed_signer_backup_returns_encrypted_backup() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let (cluster_ca_pem, internal_ca_key_pem) = generate_test_internal_ca();
    state.cluster_ca_pem = Some(cluster_ca_pem);
    state.internal_ca_key_pem = Some(internal_ca_key_pem);

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());
    let response = super::export_managed_signer_backup_handler(
        State(state.clone()),
        headers,
        Json(super::ManagedSignerBackupExportRequest {
            passphrase: "correct horse battery staple".to_string(),
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let backup: super::ManagedSignerBackup = serde_json::from_slice(&body).unwrap();
    assert_eq!(backup.cluster_id, state.cluster_id);
    assert_eq!(backup.source_node_id, state.node_id);
    assert!(!backup.ciphertext_b64.is_empty());
    assert!(!backup.salt_b64.is_empty());
    assert!(!backup.nonce_b64.is_empty());

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn admin_password_login_creates_session_cookie() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_password_hash = Some(super::hash_token("super-secret-password"));

    let response = super::login_admin_session(
        State(state.clone()),
        HeaderMap::new(),
        Json(super::AdminLoginRequest {
            password: "super-secret-password".to_string(),
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::OK);
    let set_cookie = response
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    assert!(set_cookie.contains("ironmesh_admin_session="));
    assert!(set_cookie.contains("HttpOnly"));

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn admin_session_cookie_authorizes_admin_request() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_password_hash = Some(super::hash_token("super-secret-password"));

    let login_response = super::login_admin_session(
        State(state.clone()),
        HeaderMap::new(),
        Json(super::AdminLoginRequest {
            password: "super-secret-password".to_string(),
        }),
    )
    .await
    .into_response();
    let set_cookie = login_response
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    let cookie_header = set_cookie.split(';').next().unwrap().to_string();

    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::COOKIE, cookie_header.parse().unwrap());
    let response = super::list_client_credentials(State(state.clone()), headers)
        .await
        .into_response();

    assert_eq!(response.status(), StatusCode::OK);

    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn import_managed_signer_backup_persists_signer_material_and_requires_restart() {
    let mut exporter = build_test_state(1, false, MainTestBackend::Sqlite).await;
    exporter.admin_control.admin_token = Some("admin-secret".to_string());
    let (cluster_ca_pem, internal_ca_key_pem) = generate_test_internal_ca();
    exporter.cluster_ca_pem = Some(cluster_ca_pem.clone());
    exporter.internal_ca_key_pem = Some(internal_ca_key_pem.clone());
    let backup = super::setup::export_managed_signer_backup(
        exporter.cluster_id,
        exporter.node_id,
        &cluster_ca_pem,
        &internal_ca_key_pem,
        "correct horse battery staple",
    )
    .unwrap();

    let mut importer = build_test_state(1, false, MainTestBackend::Sqlite).await;
    importer.cluster_id = exporter.cluster_id;
    importer.admin_control.admin_token = Some("admin-secret".to_string());

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());
    let response = super::import_managed_signer_backup_handler(
        State(importer.clone()),
        headers,
        Json(super::ManagedSignerBackupImportRequest {
            passphrase: "correct horse battery staple".to_string(),
            backup,
        }),
    )
    .await
    .into_response();

    assert_eq!(response.status(), StatusCode::CREATED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: super::ManagedSignerBackupImportResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload.cluster_id, importer.cluster_id);
    assert_eq!(payload.source_node_id, exporter.node_id);
    assert!(payload.restart_required);

    let signer_cert_path = importer
        .data_dir
        .join("managed")
        .join("signer")
        .join("cluster-ca.pem");
    let signer_key_path = importer
        .data_dir
        .join("managed")
        .join("signer")
        .join("cluster-ca.key");
    assert_eq!(
        std::fs::read_to_string(signer_cert_path).unwrap(),
        cluster_ca_pem
    );
    assert_eq!(
        std::fs::read_to_string(signer_key_path).unwrap(),
        internal_ca_key_pem
    );

    cleanup_test_state(&exporter).await;
    cleanup_test_state(&importer).await;
}

#[tokio::test]
async fn issue_node_enrollment_allows_local_edge_with_public_tls_only() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let (public_ca_pem, public_ca_key_pem) = generate_test_internal_ca();
    state.public_ca_pem = Some(public_ca_pem);
    state.public_ca_key_pem = Some(public_ca_key_pem);
    *state.rendezvous_urls.lock().unwrap() = vec!["https://rendezvous.example".to_string()];
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
            node_id: Some(NodeId::new_v4()),
        }],
        relay_mode: transport_sdk::RelayMode::Fallback,
        trust_roots: transport_sdk::BootstrapTrustRoots {
            cluster_ca_pem: None,
            public_api_ca_pem: None,
            rendezvous_ca_pem: None,
        },
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
            node_id: Some(NodeId::new_v4()),
        }],
        relay_mode: transport_sdk::RelayMode::Fallback,
        trust_roots: transport_sdk::BootstrapTrustRoots {
            cluster_ca_pem: state.cluster_ca_pem.clone(),
            public_api_ca_pem: state.public_ca_pem.clone(),
            rendezvous_ca_pem: None,
        },
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
    *state.rendezvous_urls.lock().unwrap() = vec!["https://rendezvous.example".to_string()];
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
    *state.rendezvous_urls.lock().unwrap() = vec![format!("https://{capture_bind_addr}")];
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
    *state.rendezvous_urls.lock().unwrap() = vec![rendezvous_url.clone()];
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
        let mut auth = state.client_credentials.lock().await;
        auth.credentials.push(super::ClientCredentialRecord {
            device_id: identity.device_id.to_string(),
            label: Some("Pixel".to_string()),
            public_key_pem: Some(identity.public_key_pem.clone()),
            public_key_fingerprint: None,
            issued_credential_pem: Some(credential_pem),
            credential_fingerprint: None,
            created_at_unix: super::unix_ts(),
            revocation_reason: None,
            revoked_by_actor: None,
            revoked_by_source_node: None,
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
        let mut auth = state.client_credentials.lock().await;
        auth.credentials.push(super::ClientCredentialRecord {
            device_id: identity.device_id.to_string(),
            label: None,
            public_key_pem: Some(identity.public_key_pem.clone()),
            public_key_fingerprint: None,
            issued_credential_pem: Some(credential_pem),
            credential_fingerprint: None,
            created_at_unix: super::unix_ts(),
            revocation_reason: None,
            revoked_by_actor: None,
            revoked_by_source_node: None,
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

async fn list_client_credentials_returns_fingerprint_metadata_impl(backend: MainTestBackend) {
    let mut state = build_test_state(1, false, backend).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    {
        let mut auth = state.client_credentials.lock().await;
        auth.credentials.push(super::ClientCredentialRecord {
            device_id: "device-list".to_string(),
            label: Some("Surface".to_string()),
            public_key_pem: Some(
                "-----BEGIN PUBLIC KEY-----\nlist-test\n-----END PUBLIC KEY-----".to_string(),
            ),
            public_key_fingerprint: Some("pub-fingerprint".to_string()),
            issued_credential_pem: Some(
                "-----BEGIN IRONMESH CLIENT CREDENTIAL-----\nlist-test\n-----END IRONMESH CLIENT CREDENTIAL-----\n"
                    .to_string(),
            ),
            credential_fingerprint: Some("cred-fingerprint".to_string()),
            created_at_unix: 123,
            revocation_reason: Some("rotated".to_string()),
            revoked_by_actor: Some("qa-operator".to_string()),
            revoked_by_source_node: Some("node-admin".to_string()),
            revoked_at_unix: Some(456),
        });
    }

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let response = super::list_client_credentials(State(state.clone()), headers)
        .await
        .into_response();
    assert_eq!(response.status(), StatusCode::OK);

    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let listed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(listed[0]["device_id"], "device-list");
    assert_eq!(listed[0]["label"], "Surface");
    assert_eq!(listed[0]["public_key_fingerprint"], "pub-fingerprint");
    assert_eq!(listed[0]["credential_fingerprint"], "cred-fingerprint");
    assert_eq!(listed[0]["created_at_unix"], 123);
    assert_eq!(listed[0]["revocation_reason"], "rotated");
    assert_eq!(listed[0]["revoked_by_actor"], "qa-operator");
    assert_eq!(listed[0]["revoked_by_source_node"], "node-admin");
    assert_eq!(listed[0]["revoked_at_unix"], 456);

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    list_client_credentials_returns_fingerprint_metadata_impl,
    list_client_credentials_returns_fingerprint_metadata,
    list_client_credentials_returns_fingerprint_metadata_turso
);

async fn revoke_client_credential_persists_reason_and_admin_metadata_impl(
    backend: MainTestBackend,
) {
    let mut state = build_test_state(1, false, backend).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    {
        let mut auth = state.client_credentials.lock().await;
        auth.credentials.push(super::ClientCredentialRecord {
            device_id: "device-revoke".to_string(),
            label: Some("Laptop".to_string()),
            public_key_pem: None,
            public_key_fingerprint: Some("pub-1".to_string()),
            issued_credential_pem: None,
            credential_fingerprint: Some("cred-1".to_string()),
            created_at_unix: 456,
            revocation_reason: None,
            revoked_by_actor: None,
            revoked_by_source_node: None,
            revoked_at_unix: None,
        });
    }

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());
    headers.insert("x-ironmesh-admin-actor", "qa-operator".parse().unwrap());
    headers.insert("x-ironmesh-node-id", "node-admin".parse().unwrap());

    let response = super::revoke_client_credential(
        State(state.clone()),
        headers,
        Path("device-revoke".to_string()),
        Query(super::RevokeClientCredentialQuery {
            reason: Some("device retired".to_string()),
        }),
    )
    .await
    .into_response();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let auth = state.client_credentials.lock().await;
    let revoked = auth
        .credentials
        .iter()
        .find(|credential| credential.device_id == "device-revoke")
        .expect("credential should still exist after revocation");
    assert_eq!(revoked.revocation_reason.as_deref(), Some("device retired"));
    assert_eq!(revoked.revoked_by_actor.as_deref(), Some("qa-operator"));
    assert_eq!(
        revoked.revoked_by_source_node.as_deref(),
        Some("node-admin")
    );
    assert!(revoked.revoked_at_unix.is_some());

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    revoke_client_credential_persists_reason_and_admin_metadata_impl,
    revoke_client_credential_persists_reason_and_admin_metadata,
    revoke_client_credential_persists_reason_and_admin_metadata_turso
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
fn store_index_prefix_respects_path_boundaries() {
    let keys = vec![
        "images/cat.png".to_string(),
        "images-1/alpha.png".to_string(),
        "images-2/bravo.png".to_string(),
    ];

    let paths = build_store_index_entries(&keys, "images", 1)
        .into_iter()
        .map(|entry| entry.path)
        .collect::<Vec<_>>();

    assert_eq!(paths, vec!["images/cat.png"]);
}

#[test]
fn store_index_object_map_filter_respects_prefix_boundaries() {
    let (hashes, object_ids) = super::filter_store_index_object_maps_for_prefix(
        HashMap::from([
            ("images/cat.png".to_string(), "hash-cat".to_string()),
            ("images-raw/cat.png".to_string(), "hash-raw".to_string()),
            ("images/dogs/beagle.png".to_string(), "hash-dog".to_string()),
            ("docs/readme.md".to_string(), "hash-doc".to_string()),
        ]),
        HashMap::from([
            ("images/cat.png".to_string(), "obj-cat".to_string()),
            ("images-raw/cat.png".to_string(), "obj-raw".to_string()),
            ("images/dogs/beagle.png".to_string(), "obj-dog".to_string()),
            ("docs/readme.md".to_string(), "obj-doc".to_string()),
        ]),
        "images",
    );

    assert_eq!(hashes.len(), 2);
    assert!(hashes.contains_key("images/cat.png"));
    assert!(hashes.contains_key("images/dogs/beagle.png"));
    assert!(!hashes.contains_key("images-raw/cat.png"));
    assert_eq!(object_ids.len(), 2);
    assert!(object_ids.contains_key("images/cat.png"));
    assert!(object_ids.contains_key("images/dogs/beagle.png"));
}

#[test]
fn collapse_store_index_entries_for_tree_view_deduplicates_folder_markers() {
    let entries = vec![
        super::StoreIndexEntry {
            path: "images/".to_string(),
            entry_type: "prefix".to_string(),
            version: None,
            content_hash: None,
            size_bytes: None,
            modified_at_unix: None,
            content_fingerprint: None,
            media: None,
        },
        super::StoreIndexEntry {
            path: "images/".to_string(),
            entry_type: "key".to_string(),
            version: None,
            content_hash: Some("marker".to_string()),
            size_bytes: Some(0),
            modified_at_unix: None,
            content_fingerprint: None,
            media: None,
        },
        super::StoreIndexEntry {
            path: "images/cat.png".to_string(),
            entry_type: "key".to_string(),
            version: None,
            content_hash: Some("content".to_string()),
            size_bytes: Some(123),
            modified_at_unix: None,
            content_fingerprint: None,
            media: None,
        },
    ];

    let collapsed = super::collapse_store_index_entries_for_tree_view(entries);

    assert_eq!(collapsed.len(), 2);
    assert_eq!(collapsed[0].path, "images/");
    assert_eq!(collapsed[0].entry_type, "prefix");
    assert_eq!(collapsed[0].content_hash, None);
    assert_eq!(collapsed[1].path, "images/cat.png");
    assert_eq!(collapsed[1].entry_type, "key");
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
        let mut locked = lock_store(&state, "tests.state.store").await;
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
        let store = lock_store(&state, "tests.state.store").await;
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
        let mut locked = lock_store(&state, "tests.state.store").await;
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
        let store = lock_store(&state, "tests.state.store").await;
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
        let mut locked = lock_store(&state, "tests.state.store").await;
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
        let store = lock_store(&state, "tests.state.store").await;
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
        let mut locked = lock_store(&state, "tests.state.store").await;
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
        let locked = lock_store(&state, "tests.state.store").await;
        locked.ensure_media_cache(&put.manifest_hash).await.unwrap();
    }

    let response = axum::response::IntoResponse::into_response(
        super::list_store_index(
            axum::extract::State(state.clone()),
            axum::extract::Query(super::StoreIndexQuery {
                prefix: Some("gallery".to_string()),
                depth: Some(2),
                snapshot: None,
                view: None,
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

#[cfg(unix)]
async fn list_store_index_includes_cached_media_metadata_for_videos_impl(backend: MainTestBackend) {
    let state = build_test_state(1, false, backend).await;
    let put = {
        let mut locked = lock_store(&state, "tests.state.store").await;
        let tools_dir = locked.root_dir().join("test-video-tools");
        let (ffprobe_path, ffmpeg_path) = install_fake_video_tools(&tools_dir);
        locked.set_media_tool_paths_for_test(ffprobe_path, ffmpeg_path);
        locked
            .put_object_versioned(
                "gallery/clip.mp4",
                bytes::Bytes::from(sample_large_chunked_payload()),
                PutOptions::default(),
            )
            .await
            .unwrap()
    };
    {
        let locked = lock_store(&state, "tests.state.store").await;
        locked.ensure_media_cache(&put.manifest_hash).await.unwrap();
    }

    let response = axum::response::IntoResponse::into_response(
        super::list_store_index(
            axum::extract::State(state.clone()),
            axum::extract::Query(super::StoreIndexQuery {
                prefix: Some("gallery".to_string()),
                depth: Some(2),
                snapshot: None,
                view: None,
            }),
        )
        .await,
    );

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entries = payload["entries"].as_array().unwrap();
    let media = &entries[0]["media"];

    assert_eq!(entries[0]["path"], "gallery/clip.mp4");
    assert_eq!(media["status"], "ready");
    assert_eq!(media["media_type"], "video");
    assert_eq!(media["mime_type"], "video/mp4");
    assert_eq!(media["width"], 1920);
    assert_eq!(media["height"], 1080);
    assert!(
        media["thumbnail"]["url"]
            .as_str()
            .unwrap()
            .contains("/media/thumbnail?key=gallery%2Fclip.mp4")
    );

    cleanup_test_state(&state).await;
}

#[cfg(unix)]
run_on_main_metadata_backends!(
    list_store_index_includes_cached_media_metadata_for_videos_impl,
    list_store_index_includes_cached_media_metadata_for_videos,
    list_store_index_includes_cached_media_metadata_for_videos_turso
);

async fn metadata_import_makes_store_index_visible_without_marking_local_replica_impl(
    backend: MainTestBackend,
) {
    let source = build_test_state(1, false, backend).await;
    let target = build_test_state(1, false, backend).await;

    let put = {
        let mut locked = lock_store(&source, "tests.source.store").await;
        locked
            .put_object_versioned(
                "photos/cat.png",
                bytes::Bytes::from(sample_png_bytes()),
                PutOptions::default(),
            )
            .await
            .unwrap()
    };

    let bundle = {
        let locked = lock_store(&source, "tests.source.store").await;
        locked
            .export_metadata_bundle(
                "photos/cat.png",
                None,
                super::storage::ObjectReadMode::Preferred,
            )
            .await
            .unwrap()
            .unwrap()
    };

    {
        let mut locked = lock_store(&target, "tests.target.store").await;
        let changed = locked.import_metadata_bundle(&bundle).await.unwrap();
        assert!(changed);

        let metadata_subjects = locked.list_metadata_subjects().await.unwrap();
        assert!(metadata_subjects.contains(&"photos/cat.png".to_string()));
        assert!(metadata_subjects.contains(&format!("photos/cat.png@{}", put.version_id)));

        let replica_subjects = locked
            .replication_subject_inspector()
            .list_replication_subjects()
            .await
            .unwrap();
        assert!(!replica_subjects.contains(&"photos/cat.png".to_string()));
        assert!(!replica_subjects.contains(&format!("photos/cat.png@{}", put.version_id)));
    }

    let response = axum::response::IntoResponse::into_response(
        super::list_store_index(
            axum::extract::State(target.clone()),
            axum::extract::Query(super::StoreIndexQuery {
                prefix: Some("photos".to_string()),
                depth: Some(2),
                snapshot: None,
                view: None,
            }),
        )
        .await,
    );

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entries = payload["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["path"], "photos/cat.png");
    assert_eq!(entries[0]["content_hash"], put.manifest_hash);
    assert_eq!(
        entries[0]["size_bytes"].as_u64().unwrap(),
        sample_png_bytes().len() as u64
    );
    assert!(entries[0]["modified_at_unix"].as_u64().unwrap() > 0);

    let read_error = {
        let locked = lock_store(&target, "tests.target.store").await;
        locked
            .get_object(
                "photos/cat.png",
                None,
                None,
                super::storage::ObjectReadMode::Preferred,
            )
            .await
            .unwrap_err()
    };
    assert!(matches!(
        read_error,
        super::storage::StoreReadError::Corrupt(_)
    ));

    cleanup_test_state(&source).await;
    cleanup_test_state(&target).await;
}

run_on_main_metadata_backends!(
    metadata_import_makes_store_index_visible_without_marking_local_replica_impl,
    metadata_import_makes_store_index_visible_without_marking_local_replica,
    metadata_import_makes_store_index_visible_without_marking_local_replica_turso
);

async fn read_through_fetch_serves_object_without_declaring_local_replica_impl(
    backend: MainTestBackend,
) {
    let source = build_test_state(1, false, backend).await;
    let target = build_test_state(1, false, backend).await;

    let put = {
        let mut locked = lock_store(&source, "tests.source.store").await;
        locked
            .put_object_versioned(
                "photos/cat.png",
                bytes::Bytes::from(sample_png_bytes()),
                PutOptions::default(),
            )
            .await
            .unwrap()
    };

    {
        let mut cluster = source.cluster.lock().await;
        cluster.note_replica("photos/cat.png", source.node_id);
        cluster.note_replica(format!("photos/cat.png@{}", put.version_id), source.node_id);
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_base_url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route(
            "/cluster/replication/chunk/{hash}",
            get(super::get_replication_chunk),
        )
        .with_state(source.clone());
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("chunk route should serve");
    });

    {
        let mut cluster = target.cluster.lock().await;
        cluster.register_node(super::cluster::NodeDescriptor {
            node_id: source.node_id,
            reachability: super::cluster::NodeReachability {
                public_api_url: Some(peer_base_url.clone()),
                peer_api_url: Some(peer_base_url.clone()),
                relay_required: false,
            },
            capabilities: super::cluster::NodeCapabilities {
                public_api: true,
                peer_api: true,
                relay_tunnel: false,
            },
            labels: HashMap::new(),
            capacity_bytes: 1_000_000,
            free_bytes: 900_000,
            storage_stats: None,
            last_heartbeat_unix: super::unix_ts(),
            status: super::cluster::NodeStatus::Online,
        });
        cluster.note_replica("photos/cat.png", source.node_id);
        cluster.note_replica(format!("photos/cat.png@{}", put.version_id), source.node_id);
    }

    let bundle = {
        let locked = lock_store(&source, "tests.source.store").await;
        locked
            .export_metadata_bundle(
                "photos/cat.png",
                None,
                super::storage::ObjectReadMode::Preferred,
            )
            .await
            .unwrap()
            .unwrap()
    };

    {
        let mut locked = lock_store(&target, "tests.target.store").await;
        locked.import_metadata_bundle(&bundle).await.unwrap();
    }

    let before_subjects = axum::response::IntoResponse::into_response(
        super::local_available_subjects(axum::extract::State(target.clone())).await,
    );
    let before_payload: serde_json::Value = serde_json::from_slice(
        &to_bytes(before_subjects.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(before_payload["subject_count"].as_u64().unwrap(), 0);

    let response = super::get_object_response(
        &target,
        "photos/cat.png",
        super::ObjectGetQuery {
            snapshot: None,
            version: None,
            read_mode: None,
        },
        &HeaderMap::new(),
        false,
    )
    .await;

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(body.as_ref(), sample_png_bytes().as_slice());

    {
        let cluster = target.cluster.lock().await;
        let cluster_subjects = cluster.subjects_for_node(target.node_id);
        assert_eq!(cluster_subjects.len(), 0);
    }

    super::refresh_local_availability_view_once(&target).await;

    let after_subjects = axum::response::IntoResponse::into_response(
        super::local_available_subjects(axum::extract::State(target.clone())).await,
    );
    let after_payload: serde_json::Value = serde_json::from_slice(
        &to_bytes(after_subjects.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(after_payload["subject_count"].as_u64().unwrap(), 2);
    let after_subject_list = after_payload["subjects"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>();
    assert!(after_subject_list.contains(&"photos/cat.png"));
    assert!(after_subject_list.contains(&format!("photos/cat.png@{}", put.version_id).as_str()));

    handle.abort();
    let _ = handle.await;
    cleanup_test_state(&source).await;
    cleanup_test_state(&target).await;
}

run_on_main_metadata_backends!(
    read_through_fetch_serves_object_without_declaring_local_replica_impl,
    read_through_fetch_serves_object_without_declaring_local_replica,
    read_through_fetch_serves_object_without_declaring_local_replica_turso
);

async fn read_through_range_fetch_serves_partial_content_without_declaring_local_replica_impl(
    backend: MainTestBackend,
) {
    let source = build_test_state(1, false, backend).await;
    let target = build_test_state(1, false, backend).await;
    let payload = sample_large_chunked_payload();
    let range_start = 1024 * 1024 + 128;
    let range_end_inclusive = range_start + 383;

    let put = {
        let mut locked = lock_store(&source, "tests.source.store").await;
        locked
            .put_object_versioned(
                "photos/range.bin",
                bytes::Bytes::from(payload.clone()),
                PutOptions::default(),
            )
            .await
            .unwrap()
    };

    {
        let mut cluster = source.cluster.lock().await;
        cluster.note_replica("photos/range.bin", source.node_id);
        cluster.note_replica(
            format!("photos/range.bin@{}", put.version_id),
            source.node_id,
        );
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let peer_base_url = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route(
            "/cluster/replication/chunk/{hash}",
            get(super::get_replication_chunk),
        )
        .with_state(source.clone());
    let handle = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("chunk route should serve");
    });

    {
        let mut cluster = target.cluster.lock().await;
        cluster.register_node(super::cluster::NodeDescriptor {
            node_id: source.node_id,
            reachability: super::cluster::NodeReachability {
                public_api_url: Some(peer_base_url.clone()),
                peer_api_url: Some(peer_base_url.clone()),
                relay_required: false,
            },
            capabilities: super::cluster::NodeCapabilities {
                public_api: true,
                peer_api: true,
                relay_tunnel: false,
            },
            labels: HashMap::new(),
            capacity_bytes: 1_000_000,
            free_bytes: 900_000,
            storage_stats: None,
            last_heartbeat_unix: super::unix_ts(),
            status: super::cluster::NodeStatus::Online,
        });
        cluster.note_replica("photos/range.bin", source.node_id);
        cluster.note_replica(
            format!("photos/range.bin@{}", put.version_id),
            source.node_id,
        );
    }

    let bundle = {
        let locked = lock_store(&source, "tests.source.store").await;
        locked
            .export_metadata_bundle(
                "photos/range.bin",
                None,
                super::storage::ObjectReadMode::Preferred,
            )
            .await
            .unwrap()
            .unwrap()
    };

    {
        let mut locked = lock_store(&target, "tests.target.store").await;
        locked.import_metadata_bundle(&bundle).await.unwrap();
    }

    let before_subjects = axum::response::IntoResponse::into_response(
        super::local_available_subjects(axum::extract::State(target.clone())).await,
    );
    let before_payload: serde_json::Value = serde_json::from_slice(
        &to_bytes(before_subjects.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(before_payload["subject_count"].as_u64().unwrap(), 0);

    let head_response = axum::response::IntoResponse::into_response(
        super::head_object(
            axum::extract::State(target.clone()),
            HeaderMap::new(),
            axum::extract::Path("photos/range.bin".to_string()),
            axum::extract::Query(super::ObjectGetQuery {
                snapshot: None,
                version: None,
                read_mode: None,
            }),
        )
        .await,
    );
    assert_eq!(head_response.status(), StatusCode::OK);
    let etag = head_response
        .headers()
        .get(axum::http::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();

    let mut range_headers = HeaderMap::new();
    range_headers.insert(
        axum::http::header::RANGE,
        format!("bytes={range_start}-{range_end_inclusive}")
            .parse()
            .unwrap(),
    );
    range_headers.insert(axum::http::header::IF_RANGE, etag.parse().unwrap());
    let range_response = axum::response::IntoResponse::into_response(
        super::get_object(
            axum::extract::State(target.clone()),
            range_headers,
            axum::extract::Path("photos/range.bin".to_string()),
            axum::extract::Query(super::ObjectGetQuery {
                snapshot: None,
                version: None,
                read_mode: None,
            }),
        )
        .await,
    );

    assert_eq!(range_response.status(), StatusCode::PARTIAL_CONTENT);
    assert_eq!(
        range_response
            .headers()
            .get(axum::http::header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok()),
        Some(
            format!(
                "bytes {range_start}-{range_end_inclusive}/{}",
                payload.len()
            )
            .as_str()
        )
    );
    let range_body = to_bytes(range_response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(
        range_body.as_ref(),
        &payload[range_start..range_end_inclusive + 1]
    );

    let after_subjects = axum::response::IntoResponse::into_response(
        super::local_available_subjects(axum::extract::State(target.clone())).await,
    );
    let after_payload: serde_json::Value = serde_json::from_slice(
        &to_bytes(after_subjects.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(after_payload["subject_count"].as_u64().unwrap(), 0);

    {
        let cluster = target.cluster.lock().await;
        let cluster_subjects = cluster.subjects_for_node(target.node_id);
        assert!(cluster_subjects.is_empty());
    }

    {
        let locked = lock_store(&target, "tests.target.store").await;
        let cached = locked.list_cached_chunk_records_for_test().await.unwrap();
        assert_eq!(cached.len(), 1);
        assert_eq!(cached[0].cache_class, "read_through");
        assert!(cached[0].access_count >= 1);
    }

    handle.abort();
    let _ = handle.await;
    cleanup_test_state(&source).await;
    cleanup_test_state(&target).await;
}

run_on_main_metadata_backends!(
    read_through_range_fetch_serves_partial_content_without_declaring_local_replica_impl,
    read_through_range_fetch_serves_partial_content_without_declaring_local_replica,
    read_through_range_fetch_serves_partial_content_without_declaring_local_replica_turso
);

async fn list_store_index_admin_uses_admin_thumbnail_route_impl(backend: MainTestBackend) {
    let mut state = build_test_state(1, false, backend).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let put = {
        let mut locked = lock_store(&state, "tests.state.store").await;
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
        let locked = lock_store(&state, "tests.state.store").await;
        locked.ensure_media_cache(&put.manifest_hash).await.unwrap();
    }

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let response = axum::response::IntoResponse::into_response(
        super::list_store_index_admin(
            axum::extract::State(state.clone()),
            headers,
            axum::extract::Query(super::StoreIndexQuery {
                prefix: Some("gallery".to_string()),
                depth: Some(2),
                snapshot: None,
                view: None,
            }),
        )
        .await,
    );

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        payload["entries"][0]["media"]["thumbnail"]["url"],
        "/auth/media/thumbnail?key=gallery%2Fcat.png"
    );

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    list_store_index_admin_uses_admin_thumbnail_route_impl,
    list_store_index_admin_uses_admin_thumbnail_route,
    list_store_index_admin_uses_admin_thumbnail_route_turso
);

async fn get_media_thumbnail_admin_requires_auth_and_serves_image_impl(backend: MainTestBackend) {
    let mut state = build_test_state(1, false, backend).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let put = {
        let mut locked = lock_store(&state, "tests.state.store").await;
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
        let locked = lock_store(&state, "tests.state.store").await;
        locked.ensure_media_cache(&put.manifest_hash).await.unwrap();
    }

    let query = super::MediaThumbnailQuery {
        key: "gallery/cat.png".to_string(),
        snapshot: None,
        version: None,
        read_mode: None,
    };

    let unauthorized = axum::response::IntoResponse::into_response(
        super::get_media_thumbnail_admin(
            axum::extract::State(state.clone()),
            HeaderMap::new(),
            axum::extract::Query(query.clone()),
        )
        .await,
    );
    assert_eq!(unauthorized.status(), axum::http::StatusCode::UNAUTHORIZED);

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let response = axum::response::IntoResponse::into_response(
        super::get_media_thumbnail_admin(
            axum::extract::State(state.clone()),
            headers,
            axum::extract::Query(query),
        )
        .await,
    );

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("image/jpeg")
    );
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert!(!body.is_empty());

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    get_media_thumbnail_admin_requires_auth_and_serves_image_impl,
    get_media_thumbnail_admin_requires_auth_and_serves_image,
    get_media_thumbnail_admin_requires_auth_and_serves_image_turso
);

async fn clear_media_cache_admin_requires_auth_and_clears_cached_media_impl(
    backend: MainTestBackend,
) {
    let mut state = build_test_state(1, false, backend).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let (manifest_hash, thumb_path) = {
        let mut locked = lock_store(&state, "tests.state.store").await;
        let put = locked
            .put_object_versioned(
                "gallery/cat.png",
                bytes::Bytes::from(sample_png_bytes()),
                PutOptions::default(),
            )
            .await
            .unwrap();
        let metadata = locked
            .ensure_media_cache(&put.manifest_hash)
            .await
            .unwrap()
            .unwrap();
        let thumb = metadata.thumbnail.as_ref().expect("expected thumbnail");
        let thumb_path = locked.media_thumbnail_path(&metadata.content_fingerprint, &thumb.profile);
        (put.manifest_hash, thumb_path)
    };

    let orphan_dir = state
        .data_dir
        .join("state")
        .join("media_cache")
        .join("thumbnails")
        .join("orphan");
    std::fs::create_dir_all(&orphan_dir).unwrap();
    let orphan_path = orphan_dir.join("stale.jpg");
    std::fs::write(&orphan_path, sample_png_bytes()).unwrap();

    let unauthorized = axum::response::IntoResponse::into_response(
        super::clear_media_cache_admin(
            axum::extract::State(state.clone()),
            HeaderMap::new(),
            axum::extract::Query(super::ApprovalQuery {
                approve: Some(true),
            }),
        )
        .await,
    );
    assert_eq!(unauthorized.status(), axum::http::StatusCode::UNAUTHORIZED);

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let missing_approval = axum::response::IntoResponse::into_response(
        super::clear_media_cache_admin(
            axum::extract::State(state.clone()),
            headers.clone(),
            axum::extract::Query(super::ApprovalQuery {
                approve: Some(false),
            }),
        )
        .await,
    );
    assert_eq!(
        missing_approval.status(),
        axum::http::StatusCode::PRECONDITION_FAILED
    );

    let response = axum::response::IntoResponse::into_response(
        super::clear_media_cache_admin(
            axum::extract::State(state.clone()),
            headers,
            axum::extract::Query(super::ApprovalQuery {
                approve: Some(true),
            }),
        )
        .await,
    );

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(payload["deleted_metadata_records"], 1);
    assert_eq!(payload["deleted_thumbnail_files"], 2);
    assert!(payload["deleted_thumbnail_bytes"].as_u64().unwrap() > 0);

    let rebuilt = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let metadata = {
                let locked = lock_store(&state, "tests.state.store").await;
                locked
                    .lookup_media_cache(&manifest_hash)
                    .await
                    .unwrap()
                    .unwrap()
                    .metadata
            };
            if let Some(metadata) = metadata {
                break metadata;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("background media metadata rebuild should finish");
    assert_eq!(rebuilt.status, super::storage::MediaCacheStatus::Ready);
    assert!(rebuilt.thumbnail.is_none());
    assert!(!thumb_path.exists());
    assert!(!orphan_path.exists());

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    clear_media_cache_admin_requires_auth_and_clears_cached_media_impl,
    clear_media_cache_admin_requires_auth_and_clears_cached_media,
    clear_media_cache_admin_requires_auth_and_clears_cached_media_turso
);

async fn get_object_admin_returns_bytes_with_admin_token_impl(backend: MainTestBackend) {
    let mut state = build_test_state(1, false, backend).await;
    state.admin_control.admin_token = Some("admin-secret".to_string());
    let payload = bytes::Bytes::from(sample_png_bytes());
    {
        let mut locked = lock_store(&state, "tests.state.store").await;
        locked
            .put_object_versioned("gallery/cat.png", payload.clone(), PutOptions::default())
            .await
            .unwrap();
    }

    let mut headers = HeaderMap::new();
    headers.insert("x-ironmesh-admin-token", "admin-secret".parse().unwrap());

    let response = axum::response::IntoResponse::into_response(
        super::get_object_admin(
            axum::extract::State(state.clone()),
            headers,
            axum::extract::Path("gallery/cat.png".to_string()),
            axum::extract::Query(super::ObjectGetQuery {
                snapshot: None,
                version: None,
                read_mode: None,
            }),
        )
        .await,
    );

    assert_eq!(response.status(), axum::http::StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    assert_eq!(body.as_ref(), payload.as_ref());

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    get_object_admin_returns_bytes_with_admin_token_impl,
    get_object_admin_returns_bytes_with_admin_token,
    get_object_admin_returns_bytes_with_admin_token_turso
);

async fn get_object_supports_range_requests_impl(backend: MainTestBackend) {
    let state = build_test_state(1, false, backend).await;
    let payload = Bytes::from(
        (0..8192)
            .map(|index| b'a' + (index % 26) as u8)
            .collect::<Vec<_>>(),
    );
    {
        let mut locked = lock_store(&state, "tests.state.store").await;
        locked
            .put_object_versioned("docs/range.txt", payload.clone(), PutOptions::default())
            .await
            .unwrap();
    }

    let head_response = axum::response::IntoResponse::into_response(
        super::head_object(
            axum::extract::State(state.clone()),
            HeaderMap::new(),
            axum::extract::Path("docs/range.txt".to_string()),
            axum::extract::Query(super::ObjectGetQuery {
                snapshot: None,
                version: None,
                read_mode: None,
            }),
        )
        .await,
    );
    assert_eq!(head_response.status(), axum::http::StatusCode::OK);
    let etag = head_response
        .headers()
        .get(axum::http::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .unwrap()
        .to_string();
    assert_eq!(
        head_response
            .headers()
            .get(axum::http::header::ACCEPT_RANGES)
            .and_then(|value| value.to_str().ok()),
        Some("bytes")
    );

    let mut range_headers = HeaderMap::new();
    range_headers.insert(axum::http::header::RANGE, "bytes=128-511".parse().unwrap());
    range_headers.insert(axum::http::header::IF_RANGE, etag.parse().unwrap());
    let range_response = axum::response::IntoResponse::into_response(
        super::get_object(
            axum::extract::State(state.clone()),
            range_headers,
            axum::extract::Path("docs/range.txt".to_string()),
            axum::extract::Query(super::ObjectGetQuery {
                snapshot: None,
                version: None,
                read_mode: None,
            }),
        )
        .await,
    );

    assert_eq!(
        range_response.status(),
        axum::http::StatusCode::PARTIAL_CONTENT
    );
    assert_eq!(
        range_response
            .headers()
            .get(axum::http::header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok()),
        Some("bytes 128-511/8192")
    );
    let range_body = to_bytes(range_response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(range_body.as_ref(), &payload[128..512]);

    let mut stale_headers = HeaderMap::new();
    stale_headers.insert(axum::http::header::RANGE, "bytes=128-511".parse().unwrap());
    stale_headers.insert(
        axum::http::header::IF_RANGE,
        "\"stale-etag\"".parse().unwrap(),
    );
    let stale_response = axum::response::IntoResponse::into_response(
        super::get_object(
            axum::extract::State(state.clone()),
            stale_headers,
            axum::extract::Path("docs/range.txt".to_string()),
            axum::extract::Query(super::ObjectGetQuery {
                snapshot: None,
                version: None,
                read_mode: None,
            }),
        )
        .await,
    );

    assert_eq!(stale_response.status(), axum::http::StatusCode::OK);
    let stale_body = to_bytes(stale_response.into_body(), usize::MAX)
        .await
        .unwrap();
    assert_eq!(stale_body.as_ref(), payload.as_ref());

    cleanup_test_state(&state).await;
}

run_on_main_metadata_backends!(
    get_object_supports_range_requests_impl,
    get_object_supports_range_requests,
    get_object_supports_range_requests_turso
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

async fn build_test_state(
    replication_factor: usize,
    seed_gap: bool,
    backend: MainTestBackend,
) -> ServerState {
    let root = fresh_test_dir(&format!("startup-repair-main-{}", backend.suffix()));
    let local_node_id = NodeId::new_v4();

    let store = new_store_rwlock(
        PersistentStore::init_with_metadata_backend(root.clone(), backend.kind())
            .await
            .unwrap(),
    );
    let upload_chunk_ingestor = {
        let store_guard = store.read("test.build_state.chunk_ingestor").await;
        store_guard.chunk_ingestor()
    };

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
        reachability: cluster::NodeReachability {
            public_api_url: Some("http://127.0.0.1:39080".to_string()),
            peer_api_url: Some("https://127.0.0.1:49080".to_string()),
            relay_required: false,
        },
        capabilities: cluster::NodeCapabilities {
            public_api: true,
            peer_api: true,
            relay_tunnel: true,
        },
        labels: HashMap::new(),
        capacity_bytes: 1_000_000,
        free_bytes: 900_000,
        storage_stats: None,
        last_heartbeat_unix: 0,
        status: cluster::NodeStatus::Online,
    });

    if replication_factor > 1 {
        service.register_node(cluster::NodeDescriptor {
            node_id: NodeId::new_v4(),
            reachability: cluster::NodeReachability {
                public_api_url: Some("http://127.0.0.1:9".to_string()),
                peer_api_url: Some("https://127.0.0.1:10009".to_string()),
                relay_required: false,
            },
            capabilities: cluster::NodeCapabilities {
                public_api: true,
                peer_api: true,
                relay_tunnel: true,
            },
            labels: HashMap::new(),
            capacity_bytes: 1_000_000,
            free_bytes: 800_000,
            storage_stats: None,
            last_heartbeat_unix: 0,
            status: cluster::NodeStatus::Online,
        });
    }

    let (namespace_change_tx, _) = tokio::sync::watch::channel(0);
    let state = ServerState {
        data_dir: root.clone(),
        cluster_id: uuid::Uuid::now_v7(),
        node_id: local_node_id,
        local_edge_mode: false,
        store: store.clone(),
        upload_chunk_ingestor,
        cluster: Arc::new(Mutex::new(service)),
        client_credentials: Arc::new(Mutex::new(super::storage::ClientCredentialState::default())),
        upload_sessions: super::new_upload_sessions_rwlock(super::UploadSessionStore {
            path: root.join("state").join("upload_sessions.json"),
            sessions: HashMap::new(),
        }),
        upload_sessions_dirty: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        upload_sessions_persist_notify: Arc::new(tokio::sync::Notify::new()),
        public_ca_pem: None,
        public_ca_key_pem: None,
        cluster_ca_pem: None,
        internal_ca_key_pem: None,
        public_tls_runtime: None,
        internal_tls_runtime: None,
        rendezvous_ca_pem: None,
        rendezvous_urls: Arc::new(std::sync::Mutex::new(vec![
            "http://127.0.0.1:39080".to_string(),
        ])),
        rendezvous_registration_enabled: false,
        rendezvous_mtls_required: false,
        managed_rendezvous_public_url: None,
        rendezvous_registration_state: Arc::new(Mutex::new(HashMap::from([(
            "http://127.0.0.1:39080".to_string(),
            super::RendezvousEndpointRegistrationRuntime::default(),
        )]))),
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
            rendezvous_controls: Vec::new(),
        })),
        metadata_commit_mode: MetadataCommitMode::Local,
        autonomous_replication_on_put_enabled: false,
        inflight_requests: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
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
        local_availability_refresh_lock: Arc::new(Mutex::new(())),
        local_availability_refresh_notify: Arc::new(tokio::sync::Notify::new()),
        storage_stats_runtime: Arc::new(Mutex::new(super::StorageStatsRuntime::default())),
        namespace_change_sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        namespace_change_tx,
        admin_control: AdminControl::default(),
        admin_sessions: Arc::new(Mutex::new(super::AdminSessionStore::default())),
        client_auth_control: super::ClientAuthControl::default(),
        client_auth_replay_cache: Arc::new(Mutex::new(super::ClientAuthReplayCache::default())),
    };

    if seed_gap {
        let put = {
            let mut locked = store.write("tests.store").await;
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
async fn upload_session_chunk_ingest_does_not_wait_on_store_lock() {
    let state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    let upload_id = "upload-chunk-lock-bypass".to_string();
    let payload = vec![b'U'; 1024];
    let now = super::unix_ts();

    {
        let mut sessions = super::write_upload_sessions(&state, "tests.upload_sessions.seed").await;
        sessions.sessions.insert(
            upload_id.clone(),
            super::UploadSessionRecord {
                upload_id: upload_id.clone(),
                owner_device_id: None,
                key: "uploads/test.bin".to_string(),
                total_size_bytes: payload.len() as u64,
                chunk_size_bytes: payload.len(),
                chunk_count: 1,
                state: VersionConsistencyState::Confirmed,
                parent_version_ids: Vec::new(),
                explicit_version_id: None,
                received_chunks: vec![None],
                created_at_unix: now,
                updated_at_unix: now,
                expires_at_unix: now + 300,
                finalizing: false,
                completed: false,
                completed_result: None,
            },
        );
    }

    let _store_guard = lock_store(&state, "tests.state.store").await;
    let response = tokio::time::timeout(
        Duration::from_millis(250),
        super::upload_session_chunk(
            State(state.clone()),
            HeaderMap::new(),
            Path((upload_id.clone(), 0)),
            Bytes::from(payload.clone()),
        ),
    )
    .await
    .expect("chunk upload should not wait on the global store lock")
    .into_response();

    assert_eq!(response.status(), StatusCode::OK);

    let sessions = super::read_upload_sessions(&state, "tests.upload_sessions.assert").await;
    let session = sessions
        .sessions
        .get(&upload_id)
        .expect("upload session should remain present");
    let chunk = session.received_chunks[0]
        .as_ref()
        .expect("chunk should be recorded");
    assert_eq!(chunk.size_bytes, payload.len());
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
    assert_eq!(descriptor.public_api_url(), Some("https://public.example"));
    assert_eq!(descriptor.peer_api_url(), Some("https://internal.example"));
    assert!(descriptor.capabilities.public_api);
    assert!(descriptor.capabilities.peer_api);
    assert!(!descriptor.relay_required());
    assert_eq!(
        descriptor.labels.get("dc").map(String::as_str),
        Some("edge-a")
    );
    assert_eq!(descriptor.capacity_bytes, 100);
    assert_eq!(descriptor.free_bytes, 40);
}

#[tokio::test]
async fn register_node_uses_structured_reachability_payload() {
    let state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    let node_id = NodeId::new_v4();

    let response = axum::response::IntoResponse::into_response(
        super::register_node(
            State(state.clone()),
            Path(node_id.to_string()),
            Json(super::RegisterNodeRequest {
                reachability: cluster::NodeReachability {
                    public_api_url: Some("https://public.example".to_string()),
                    peer_api_url: Some("https://internal.example".to_string()),
                    relay_required: true,
                },
                capabilities: Some(cluster::NodeCapabilities {
                    public_api: true,
                    peer_api: true,
                    relay_tunnel: true,
                }),
                labels: HashMap::from([("dc".to_string(), "edge-a".to_string())]),
                capacity_bytes: Some(100),
                free_bytes: Some(40),
                storage_stats: None,
            }),
        )
        .await,
    );

    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let node = {
        let cluster = state.cluster.lock().await;
        cluster
            .list_nodes()
            .into_iter()
            .find(|node| node.node_id == node_id)
            .expect("registered node should exist")
    };

    assert_eq!(node.public_api_url(), Some("https://public.example"));
    assert_eq!(node.peer_api_url(), Some("https://internal.example"));
    assert!(node.relay_required());
    assert!(node.relay_capable());
    assert_eq!(node.capacity_bytes, 100);
    assert_eq!(node.free_bytes, 40);

    cleanup_test_state(&state).await;
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
    assert_eq!(descriptor.public_api_url(), None);
    assert_eq!(descriptor.peer_api_url(), None);
    assert!(descriptor.relay_capable());
}

#[tokio::test]
async fn resolve_peer_base_url_prefers_internal_url() {
    let state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    let node = cluster::NodeDescriptor {
        node_id: NodeId::new_v4(),
        reachability: cluster::NodeReachability {
            public_api_url: Some("https://public.example".to_string()),
            peer_api_url: Some("https://internal.example".to_string()),
            relay_required: false,
        },
        capabilities: cluster::NodeCapabilities {
            public_api: true,
            peer_api: true,
            relay_tunnel: true,
        },
        labels: HashMap::new(),
        capacity_bytes: 0,
        free_bytes: 0,
        storage_stats: None,
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
        reachability: cluster::NodeReachability::default(),
        capabilities: cluster::NodeCapabilities::default(),
        labels: HashMap::new(),
        capacity_bytes: 0,
        free_bytes: 0,
        storage_stats: None,
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
        reachability: cluster::NodeReachability::default(),
        capabilities: cluster::NodeCapabilities {
            public_api: false,
            peer_api: false,
            relay_tunnel: true,
        },
        labels: HashMap::new(),
        capacity_bytes: 0,
        free_bytes: 0,
        storage_stats: None,
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
        reachability: cluster::NodeReachability {
            public_api_url: Some("https://public.example".to_string()),
            peer_api_url: Some("https://internal.example".to_string()),
            relay_required: false,
        },
        capabilities: cluster::NodeCapabilities {
            public_api: true,
            peer_api: true,
            relay_tunnel: true,
        },
        labels: HashMap::new(),
        capacity_bytes: 0,
        free_bytes: 0,
        storage_stats: None,
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
                reachability: cluster::NodeReachability {
                    public_api_url: Some("https://relay-cleanup-remote.example".to_string()),
                    peer_api_url: Some("https://relay-cleanup-remote-internal.example".to_string()),
                    relay_required: false,
                },
                capabilities: cluster::NodeCapabilities {
                    public_api: true,
                    peer_api: true,
                    relay_tunnel: true,
                },
                labels: HashMap::new(),
                capacity_bytes: 1_000_000,
                free_bytes: 800_000,
                storage_stats: None,
                last_heartbeat_unix: 0,
                status: cluster::NodeStatus::Online,
            };
            cluster.register_node(node.clone());
            node
        }
    };

    let relay_bind_addr = free_bind_addr();
    let relay_base_url = format!("http://{relay_bind_addr}");
    *state.rendezvous_urls.lock().unwrap() = vec![relay_base_url.clone()];

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
        rendezvous_control: Some(rendezvous_client.clone()),
        rendezvous_controls: vec![super::RendezvousEndpointClient {
            url: relay_base_url.clone(),
            control: rendezvous_client,
        }],
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
        let mut store = lock_store(&state, "tests.state.store").await;
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

#[tokio::test]
async fn rendezvous_presence_heartbeat_retries_all_endpoints_until_all_connected() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.rendezvous_registration_enabled = true;
    state.peer_heartbeat_config = PeerHeartbeatConfig {
        enabled: false,
        interval_secs: 30,
    };

    let bind_addr_a = free_bind_addr();
    let bind_addr_b = free_bind_addr();
    let rendezvous_url_a = format!("http://{bind_addr_a}");
    let rendezvous_url_b = format!("http://{bind_addr_b}");
    *state.rendezvous_urls.lock().unwrap() =
        vec![rendezvous_url_a.clone(), rendezvous_url_b.clone()];
    *state.rendezvous_registration_state.lock().await = HashMap::from([
        (
            rendezvous_url_a.clone(),
            super::RendezvousEndpointRegistrationRuntime::default(),
        ),
        (
            rendezvous_url_b.clone(),
            super::RendezvousEndpointRegistrationRuntime::default(),
        ),
    ]);

    let shared_client = transport_sdk::RendezvousControlClient::new(
        transport_sdk::RendezvousClientConfig {
            cluster_id: state.cluster_id,
            rendezvous_urls: vec![rendezvous_url_a.clone(), rendezvous_url_b.clone()],
            heartbeat_interval_secs: 30,
        },
        None,
        None,
    )
    .expect("shared rendezvous client should build");
    let client_a = transport_sdk::RendezvousControlClient::new(
        transport_sdk::RendezvousClientConfig {
            cluster_id: state.cluster_id,
            rendezvous_urls: vec![rendezvous_url_a.clone()],
            heartbeat_interval_secs: 30,
        },
        None,
        None,
    )
    .expect("endpoint A rendezvous client should build");
    let client_b = transport_sdk::RendezvousControlClient::new(
        transport_sdk::RendezvousClientConfig {
            cluster_id: state.cluster_id,
            rendezvous_urls: vec![rendezvous_url_b.clone()],
            heartbeat_interval_secs: 30,
        },
        None,
        None,
    )
    .expect("endpoint B rendezvous client should build");
    *state.outbound_clients.write().await = super::OutboundClients {
        internal_http: reqwest::Client::new(),
        rendezvous_control: Some(shared_client),
        rendezvous_controls: vec![
            super::RendezvousEndpointClient {
                url: rendezvous_url_a.clone(),
                control: client_a,
            },
            super::RendezvousEndpointClient {
                url: rendezvous_url_b.clone(),
                control: client_b,
            },
        ],
    };

    let registrations_a = Arc::new(Mutex::new(0u64));
    let registrations_a_state = registrations_a.clone();
    let app_a = Router::new().route(
        "/control/presence/register",
        post(
            move |Json(registration): Json<transport_sdk::PresenceRegistration>| {
                let registrations_a_state = registrations_a_state.clone();
                async move {
                    *registrations_a_state.lock().await += 1;
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
            },
        ),
    );
    let listener_a = tokio::net::TcpListener::bind(bind_addr_a)
        .await
        .expect("endpoint A listener should bind");
    let handle_a = tokio::spawn(async move {
        axum::serve(listener_a, app_a)
            .await
            .expect("endpoint A should serve");
    });

    let heartbeat_handle = super::spawn_rendezvous_presence_heartbeat(
        state.clone(),
        Some("http://127.0.0.1:39080".to_string()),
        Some("https://127.0.0.1:49080".to_string()),
        true,
        30,
    );

    wait_for_condition(
        "first endpoint receives degraded retries",
        Duration::from_secs(4),
        || {
            let registrations_a = registrations_a.clone();
            async move { *registrations_a.lock().await >= 2 }
        },
    )
    .await;

    {
        let registration_state = state.rendezvous_registration_state.lock().await;
        let endpoint_b = registration_state
            .get(&rendezvous_url_b)
            .expect("endpoint B state should exist");
        assert!(
            endpoint_b.consecutive_failures >= 1,
            "endpoint B should have at least one failed registration before it starts"
        );
    }

    let registrations_b = Arc::new(Mutex::new(0u64));
    let registrations_b_state = registrations_b.clone();
    let app_b = Router::new().route(
        "/control/presence/register",
        post(
            move |Json(registration): Json<transport_sdk::PresenceRegistration>| {
                let registrations_b_state = registrations_b_state.clone();
                async move {
                    *registrations_b_state.lock().await += 1;
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
            },
        ),
    );
    let listener_b = tokio::net::TcpListener::bind(bind_addr_b)
        .await
        .expect("endpoint B listener should bind");
    let handle_b = tokio::spawn(async move {
        axum::serve(listener_b, app_b)
            .await
            .expect("endpoint B should serve");
    });

    wait_for_condition(
        "all rendezvous endpoints connected",
        Duration::from_secs(4),
        || {
            let registrations_a = registrations_a.clone();
            let registrations_b = registrations_b.clone();
            let state = state.clone();
            let rendezvous_url_a = rendezvous_url_a.clone();
            let rendezvous_url_b = rendezvous_url_b.clone();
            async move {
                if *registrations_a.lock().await < 2 || *registrations_b.lock().await < 1 {
                    return false;
                }

                let registration_state = state.rendezvous_registration_state.lock().await;
                registration_state
                    .get(&rendezvous_url_a)
                    .is_some_and(|entry| {
                        entry.consecutive_failures == 0 && entry.last_success_unix.is_some()
                    })
                    && registration_state
                        .get(&rendezvous_url_b)
                        .is_some_and(|entry| {
                            entry.consecutive_failures == 0 && entry.last_success_unix.is_some()
                        })
            }
        },
    )
    .await;

    heartbeat_handle.abort();
    let _ = heartbeat_handle.await;
    handle_a.abort();
    let _ = handle_a.await;
    handle_b.abort();
    let _ = handle_b.await;
    cleanup_test_state(&state).await;
}

#[tokio::test]
async fn rendezvous_config_view_includes_endpoint_registration_state() {
    let mut state = build_test_state(1, false, MainTestBackend::Sqlite).await;
    state.rendezvous_registration_enabled = true;
    state.peer_heartbeat_config = PeerHeartbeatConfig {
        enabled: false,
        interval_secs: 17,
    };

    let rendezvous_url_a = "https://rendezvous-a.example:9443/".to_string();
    let rendezvous_url_b = "https://rendezvous-b.example:9443/".to_string();
    *state.rendezvous_urls.lock().unwrap() =
        vec![rendezvous_url_a.clone(), rendezvous_url_b.clone()];
    *state.rendezvous_registration_state.lock().await = HashMap::from([
        (
            rendezvous_url_a.clone(),
            super::RendezvousEndpointRegistrationRuntime {
                last_attempt_unix: Some(10),
                last_success_unix: Some(10),
                consecutive_failures: 0,
                last_error: None,
            },
        ),
        (
            rendezvous_url_b.clone(),
            super::RendezvousEndpointRegistrationRuntime {
                last_attempt_unix: Some(11),
                last_success_unix: Some(8),
                consecutive_failures: 3,
                last_error: Some("connection refused".to_string()),
            },
        ),
    ]);

    let view = super::build_rendezvous_config_view(&state, false).await;

    assert_eq!(view.registration_interval_secs, 17);
    assert_eq!(
        view.disconnected_retry_interval_secs,
        super::RENDEZVOUS_REGISTRATION_RETRY_INTERVAL_SECS
    );
    assert_eq!(view.endpoint_registrations.len(), 2);
    assert_eq!(view.endpoint_registrations[0].url, rendezvous_url_a);
    assert_eq!(
        format!("{:?}", view.endpoint_registrations[0].status),
        "Connected"
    );
    assert_eq!(view.endpoint_registrations[1].url, rendezvous_url_b);
    assert_eq!(
        format!("{:?}", view.endpoint_registrations[1].status),
        "Disconnected"
    );
    assert_eq!(
        view.endpoint_registrations[1].last_error.as_deref(),
        Some("connection refused")
    );

    cleanup_test_state(&state).await;
}

async fn cleanup_test_state(state: &ServerState) {
    let root = {
        let store = lock_store(state, "tests.state.store").await;
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
