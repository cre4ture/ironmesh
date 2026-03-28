use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::extract::DefaultBodyLimit;
use axum::extract::FromRequestParts;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::CACHE_CONTROL;
use axum::routing::{get, post};
use axum::{Json, Router};
use common::{DeviceId, NodeId};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use serde::{Deserialize, Serialize};
use tokio_rustls::server::TlsStream;
use tower::Service;
use tracing::info;
use transport_sdk::peer::PeerIdentity;
use transport_sdk::rendezvous::{
    PresenceListResponse, PresenceRegistration, RegisterPresenceResponse,
};
use transport_sdk::{
    BootstrapClaimBroker, ClientBootstrapClaimPublishRequest, ClientBootstrapClaimPublishResponse,
    ClientBootstrapClaimRedeemRequest, ClientBootstrapClaimRedeemResponse, ClientEnrollmentRequest,
    PresenceRegistry, RELAY_HTTP_JSON_BODY_LIMIT_BYTES, RelayBroker, RelayHttpPollRequest,
    RelayHttpPollResponse, RelayHttpRequest, RelayHttpResponse, RelayTicket, RelayTicketRequest,
    encode_optional_body_base64, issue_relay_ticket as issue_runtime_relay_ticket,
};
use uuid::Uuid;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

#[derive(Debug, Clone)]
pub(crate) struct EmbeddedRendezvousConfig {
    pub bind_addr: SocketAddr,
    pub public_url: String,
    pub client_ca_cert_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Clone)]
struct AppState {
    config: EmbeddedRendezvousConfig,
    presence: PresenceRegistry,
    relay: RelayBroker,
    bootstrap_claims: BootstrapClaimBroker,
}

impl AppState {
    fn new(config: EmbeddedRendezvousConfig) -> Self {
        Self {
            config,
            presence: PresenceRegistry::new(),
            relay: RelayBroker::new(),
            bootstrap_claims: BootstrapClaimBroker::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    public_url: String,
    registered_endpoints: usize,
}

#[derive(Debug, Deserialize)]
struct RelayedEnrollmentResponse {
    cluster_id: uuid::Uuid,
    device_id: String,
    label: Option<String>,
    public_key_pem: String,
    credential_pem: String,
    rendezvous_client_identity_pem: Option<String>,
    created_at_unix: Option<u64>,
    expires_at_unix: Option<u64>,
}

pub(crate) async fn run_listener(config: EmbeddedRendezvousConfig) -> Result<()> {
    let state = AppState::new(config.clone());
    let relay_router = Router::new()
        .route("/relay/http/request", post(submit_relay_http_request))
        .route("/relay/http/poll", post(poll_relay_http_request))
        .route("/relay/http/respond", post(complete_relay_http_request))
        .layer(DefaultBodyLimit::max(RELAY_HTTP_JSON_BODY_LIMIT_BYTES));
    let app = Router::new()
        .route("/health", get(health))
        .route("/control/presence", get(list_presence))
        .route("/control/presence/register", post(register_presence))
        .route("/control/relay/ticket", post(issue_relay_ticket))
        .route(
            "/control/bootstrap-claims/publish",
            post(publish_bootstrap_claim),
        )
        .route("/bootstrap-claims/redeem", post(redeem_bootstrap_claim))
        .merge(relay_router)
        .with_state(state);

    info!(
        bind_addr = %config.bind_addr,
        public_url = %config.public_url,
        "embedded managed rendezvous listener"
    );

    let tls_config = build_mtls_rustls_config(
        &config.client_ca_cert_path,
        &config.cert_path,
        &config.key_path,
    )?;
    axum_server::bind(config.bind_addr)
        .acceptor(MtlsAuthenticatedPeerAcceptor::new(tls_config))
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        public_url: state.config.public_url,
        registered_endpoints: state.presence.len(),
    })
}

async fn register_presence(
    State(state): State<AppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
    Json(request): Json<PresenceRegistration>,
) -> std::result::Result<Json<RegisterPresenceResponse>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ensure_authenticated_peer_identity(
        &authenticated_peer,
        &request.identity,
        "presence registration identity",
    )
    .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;

    let entry = state.presence.register(request);
    Ok(Json(RegisterPresenceResponse {
        accepted: true,
        updated_at_unix: entry.updated_at_unix,
        entry,
    }))
}

async fn list_presence(
    State(state): State<AppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
) -> std::result::Result<Json<PresenceListResponse>, (StatusCode, String)> {
    require_authenticated_node(&authenticated_peer)
        .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;
    let entries = state.presence.list();
    Ok(Json(PresenceListResponse {
        registered_endpoints: entries.len(),
        entries,
    }))
}

async fn issue_relay_ticket(
    State(state): State<AppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
    Json(request): Json<RelayTicketRequest>,
) -> std::result::Result<Json<RelayTicket>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ensure_authenticated_peer_identity(&authenticated_peer, &request.source, "relay ticket source")
        .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;

    let ticket =
        issue_runtime_relay_ticket(request, std::slice::from_ref(&state.config.public_url));
    ticket
        .validate()
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(Json(ticket))
}

async fn publish_bootstrap_claim(
    State(state): State<AppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
    Json(request): Json<ClientBootstrapClaimPublishRequest>,
) -> std::result::Result<Json<ClientBootstrapClaimPublishResponse>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ensure_authenticated_peer_identity(
        &authenticated_peer,
        &request.issuer,
        "bootstrap claim issuer",
    )
    .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;

    let response = state
        .bootstrap_claims
        .publish(request)
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
    Ok(Json(response))
}

async fn redeem_bootstrap_claim(
    State(state): State<AppState>,
    Json(request): Json<ClientBootstrapClaimRedeemRequest>,
) -> std::result::Result<impl axum::response::IntoResponse, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let claim_token = request.claim_token.clone();
    let claim = state
        .bootstrap_claims
        .take_for_redeem(&claim_token)
        .await
        .map_err(|_| {
            (
                StatusCode::NOT_FOUND,
                "bootstrap claim is unavailable".to_string(),
            )
        })?;

    let pairing_token = claim
        .bootstrap
        .pairing_token
        .clone()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "bootstrap claim is missing a pairing token".to_string(),
            )
        })?;

    let device_id = request
        .device_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value.parse().map_err(|_| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid device_id {value}"),
                )
            })
        })
        .transpose()?;
    let label = request
        .label
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let enroll_request = ClientEnrollmentRequest {
        cluster_id: claim.bootstrap.cluster_id,
        pairing_token,
        device_id,
        label,
        public_key_pem: request.public_key_pem.clone(),
    };
    enroll_request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let relay_request = RelayHttpRequest {
        ticket: issue_runtime_relay_ticket(
            RelayTicketRequest {
                cluster_id: claim.bootstrap.cluster_id,
                source: claim.issuer.clone(),
                target: PeerIdentity::Node(claim.target_node_id),
                requested_expires_in_secs: Some(30),
            },
            std::slice::from_ref(&state.config.public_url),
        ),
        request_id: Uuid::now_v7().to_string(),
        method: "POST".to_string(),
        path_and_query: "/auth/device/enroll".to_string(),
        headers: vec![transport_sdk::RelayHttpHeader {
            name: "content-type".to_string(),
            value: "application/json".to_string(),
        }],
        body_base64: encode_optional_body_base64(
            serde_json::to_vec(&enroll_request)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
                .as_slice(),
        ),
    };

    let relay_response = match state.relay.submit_and_await(relay_request).await {
        Ok(response) => response,
        Err(err) => {
            state.bootstrap_claims.restore(&claim_token, claim).await;
            return Err((StatusCode::BAD_GATEWAY, err.to_string()));
        }
    };

    let relay_status =
        StatusCode::from_u16(relay_response.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let relay_body = relay_response
        .body_bytes()
        .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
    if relay_status.is_server_error() {
        state.bootstrap_claims.restore(&claim_token, claim).await;
        return Err((
            StatusCode::BAD_GATEWAY,
            String::from_utf8_lossy(&relay_body).to_string(),
        ));
    }
    if !relay_status.is_success() {
        return Err((
            relay_status,
            String::from_utf8_lossy(&relay_body).trim().to_string(),
        ));
    }

    let enrolled = serde_json::from_slice::<RelayedEnrollmentResponse>(&relay_body)
        .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
    let mut bootstrap = claim.bootstrap.clone();
    bootstrap.pairing_token = None;
    bootstrap.device_id = enrolled.device_id.parse().ok();
    bootstrap.device_label = enrolled.label.clone();

    let response = ClientBootstrapClaimRedeemResponse {
        bootstrap,
        cluster_id: enrolled.cluster_id,
        device_id: enrolled.device_id,
        label: enrolled.label,
        public_key_pem: enrolled.public_key_pem,
        credential_pem: enrolled.credential_pem,
        rendezvous_client_identity_pem: enrolled.rendezvous_client_identity_pem,
        created_at_unix: enrolled.created_at_unix,
        expires_at_unix: enrolled.expires_at_unix,
    };
    response
        .validate()
        .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;

    Ok(([(CACHE_CONTROL, "no-store")], Json(response)))
}

async fn submit_relay_http_request(
    State(state): State<AppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
    Json(request): Json<RelayHttpRequest>,
) -> std::result::Result<Json<RelayHttpResponse>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ensure_authenticated_peer_identity(
        &authenticated_peer,
        &request.ticket.source,
        "relay HTTP request source",
    )
    .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;

    let response = state
        .relay
        .submit_and_await(request)
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
    Ok(Json(response))
}

async fn poll_relay_http_request(
    State(state): State<AppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
    Json(request): Json<RelayHttpPollRequest>,
) -> std::result::Result<Json<RelayHttpPollResponse>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ensure_authenticated_peer_identity(
        &authenticated_peer,
        &request.target,
        "relay HTTP poll target",
    )
    .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;
    let response = state
        .relay
        .poll(request)
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
    Ok(Json(response))
}

async fn complete_relay_http_request(
    State(state): State<AppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
    Json(response): Json<RelayHttpResponse>,
) -> std::result::Result<Json<serde_json::Value>, (StatusCode, String)> {
    response
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ensure_authenticated_peer_identity(
        &authenticated_peer,
        &response.responder,
        "relay HTTP response responder",
    )
    .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;
    let completed = state
        .relay
        .respond(response)
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
    if !completed {
        return Err((
            StatusCode::NOT_FOUND,
            "relay request is no longer waiting".to_string(),
        ));
    }
    Ok(Json(serde_json::json!({ "accepted": true })))
}

#[derive(Debug, Clone)]
struct AuthenticatedPeer {
    identity: PeerIdentity,
}

#[derive(Debug, Clone, Default)]
struct MaybeAuthenticatedPeer(Option<AuthenticatedPeer>);

impl MaybeAuthenticatedPeer {
    fn identity(&self) -> Option<&PeerIdentity> {
        self.0.as_ref().map(|peer| &peer.identity)
    }
}

impl<S> FromRequestParts<S> for MaybeAuthenticatedPeer
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = std::result::Result<Self, Self::Rejection>> + Send {
        let authenticated = parts.extensions.get::<AuthenticatedPeer>().cloned();
        std::future::ready(Ok(Self(authenticated)))
    }
}

fn require_authenticated_node(authenticated_peer: &MaybeAuthenticatedPeer) -> Result<NodeId> {
    match authenticated_peer.identity() {
        Some(PeerIdentity::Node(node_id)) => Ok(*node_id),
        Some(PeerIdentity::Device(device_id)) => bail!(
            "embedded rendezvous mTLS requires an authenticated node certificate, got device:{device_id}"
        ),
        None => bail!("embedded rendezvous mTLS requires an authenticated peer certificate"),
    }
}

fn ensure_authenticated_peer_identity(
    authenticated_peer: &MaybeAuthenticatedPeer,
    identity: &PeerIdentity,
    field_name: &str,
) -> Result<()> {
    let Some(authenticated_identity) = authenticated_peer.identity() else {
        bail!("embedded rendezvous mTLS requires an authenticated peer certificate");
    };
    if authenticated_identity == identity {
        Ok(())
    } else {
        bail!(
            "{field_name} {identity} does not match authenticated embedded rendezvous client {authenticated_identity}"
        )
    }
}

#[derive(Clone)]
struct WithAuthenticatedPeer<S> {
    inner: S,
    authenticated_peer: Option<AuthenticatedPeer>,
}

impl<S> WithAuthenticatedPeer<S> {
    fn new(inner: S, authenticated_peer: Option<AuthenticatedPeer>) -> Self {
        Self {
            inner,
            authenticated_peer,
        }
    }
}

impl<S, B> Service<axum::http::Request<B>> for WithAuthenticatedPeer<S>
where
    S: Service<axum::http::Request<B>>,
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

    fn call(&mut self, mut req: axum::http::Request<B>) -> Self::Future {
        if let Some(authenticated_peer) = self.authenticated_peer.clone() {
            req.extensions_mut().insert(authenticated_peer);
        }
        self.inner.call(req)
    }
}

#[derive(Clone)]
struct MtlsAuthenticatedPeerAcceptor {
    inner: axum_server::tls_rustls::RustlsAcceptor,
}

impl MtlsAuthenticatedPeerAcceptor {
    fn new(config: axum_server::tls_rustls::RustlsConfig) -> Self {
        Self {
            inner: axum_server::tls_rustls::RustlsAcceptor::new(config),
        }
    }
}

impl<S> axum_server::accept::Accept<tokio::net::TcpStream, S> for MtlsAuthenticatedPeerAcceptor
where
    axum_server::tls_rustls::RustlsAcceptor: axum_server::accept::Accept<
            tokio::net::TcpStream,
            S,
            Stream = TlsStream<tokio::net::TcpStream>,
        >,
    <axum_server::tls_rustls::RustlsAcceptor as axum_server::accept::Accept<
        tokio::net::TcpStream,
        S,
    >>::Service: Send + 'static,
    <axum_server::tls_rustls::RustlsAcceptor as axum_server::accept::Accept<
        tokio::net::TcpStream,
        S,
    >>::Future: Send + 'static,
    S: Send + 'static,
{
    type Stream = TlsStream<tokio::net::TcpStream>;
    type Service = WithAuthenticatedPeer<
        <axum_server::tls_rustls::RustlsAcceptor as axum_server::accept::Accept<
            tokio::net::TcpStream,
            S,
        >>::Service,
    >;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: tokio::net::TcpStream, service: S) -> Self::Future {
        let fut = self.inner.accept(stream, service);
        Box::pin(async move {
            let (tls_stream, service) = fut.await?;
            let authenticated_peer = authenticated_peer_from_tls_stream(&tls_stream)
                .map_err(|err| io::Error::new(io::ErrorKind::PermissionDenied, err))?;
            Ok((
                tls_stream,
                WithAuthenticatedPeer::new(service, authenticated_peer),
            ))
        })
    }
}

fn authenticated_peer_from_tls_stream<T>(
    tls_stream: &TlsStream<T>,
) -> Result<Option<AuthenticatedPeer>> {
    let (_, conn) = tls_stream.get_ref();
    let Some(certs) = conn.peer_certificates() else {
        return Ok(None);
    };
    let identity = extract_peer_identity_from_peer_certs(certs)?;
    Ok(Some(AuthenticatedPeer { identity }))
}

fn build_mtls_rustls_config(
    client_ca_cert_path: &PathBuf,
    cert_path: &PathBuf,
    key_path: &PathBuf,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use std::fs::File;
    use std::io::BufReader;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let mut ca_reader = BufReader::new(
        File::open(client_ca_cert_path)
            .with_context(|| format!("failed reading {}", client_ca_cert_path.display()))?,
    );
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_reader_iter(&mut ca_reader) {
        let cert = cert.context("failed parsing rendezvous client CA certificate")?;
        roots
            .add(cert)
            .context("failed adding rendezvous client CA certificate to trust store")?;
    }

    let mut cert_reader = BufReader::new(
        File::open(cert_path).with_context(|| format!("failed reading {}", cert_path.display()))?,
    );
    let cert_chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_reader_iter(&mut cert_reader)
            .collect::<std::result::Result<Vec<_>, _>>()
            .context("failed parsing rendezvous TLS certificate chain")?;

    let mut key_reader = BufReader::new(
        File::open(key_path).with_context(|| format!("failed reading {}", key_path.display()))?,
    );
    let key: PrivateKeyDer<'static> = PrivateKeyDer::from_pem_reader(&mut key_reader)
        .context("failed parsing rendezvous TLS private key")?;

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
        .context("failed creating rendezvous client certificate verifier")?;
    let mut config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .context("failed creating embedded rendezvous rustls server config")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(config),
    ))
}

fn extract_peer_identity_from_peer_certs(certs: &[CertificateDer<'_>]) -> Result<PeerIdentity> {
    let cert = certs
        .first()
        .context("missing end-entity peer certificate")?;
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert.as_ref())
        .context("failed parsing peer certificate")?;
    for extension in parsed.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = name
                    && let Some(identity) = parse_peer_identity_from_san_uri(uri)
                {
                    return Ok(identity);
                }
            }
        }
    }
    bail!("missing urn:ironmesh:(node|device):<uuid> SAN URI in peer certificate")
}

fn parse_peer_identity_from_san_uri(uri: &str) -> Option<PeerIdentity> {
    if let Some(rest) = uri.strip_prefix("urn:ironmesh:node:") {
        return rest.trim().parse::<NodeId>().ok().map(PeerIdentity::Node);
    }
    if let Some(rest) = uri.strip_prefix("urn:ironmesh:device:") {
        return rest
            .trim()
            .parse::<DeviceId>()
            .ok()
            .map(PeerIdentity::Device);
    }
    None
}
