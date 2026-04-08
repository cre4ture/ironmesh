use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use axum::extract::FromRequestParts;
use axum::extract::State;
use axum::extract::WebSocketUpgrade;
use axum::extract::ws::{Message, WebSocket};
use axum::http::StatusCode;
use axum::http::header::CACHE_CONTROL;
use axum::routing::{get, post};
use axum::{Json, Router};
use common::{DeviceId, NodeId};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use serde::Serialize;
use tokio_rustls::server::TlsStream;
use tower::Service;
use tracing::{info, warn};
use transport_sdk::peer::PeerIdentity;
use transport_sdk::rendezvous::{
    PresenceListResponse, PresenceRegistration, RegisterPresenceResponse,
};
use transport_sdk::{
    BufferedTransportRequest, ClientBootstrapClaimRedeemRequest,
    ClientBootstrapClaimRedeemResponse, MultiplexConfig, MultiplexMode, PresenceRegistry,
    RelayTicket, RelayTicketRequest, RelayTunnelBroker, RelayTunnelControlMessage,
    RelayTunnelFrame,
    RelayTunnelSessionKind, TransportHeader, TransportSessionControlMessage,
    TransportSessionRole, TransportStreamKind, TRANSPORT_PROTOCOL_VERSION,
    issue_relay_ticket as issue_runtime_relay_ticket, perform_transport_client_handshake,
    read_buffered_transport_response, write_buffered_transport_request,
};
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
    relay_tunnel: RelayTunnelBroker,
}

impl AppState {
    fn new(config: EmbeddedRendezvousConfig) -> Self {
        Self {
            config,
            presence: PresenceRegistry::new(),
            relay_tunnel: RelayTunnelBroker::new(),
        }
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    public_url: String,
    registered_endpoints: usize,
}

pub(crate) async fn run_listener(config: EmbeddedRendezvousConfig) -> Result<()> {
    let state = AppState::new(config.clone());
    let relay_router = Router::new().route("/relay/tunnel/ws", get(relay_tunnel_ws));
    let app = Router::new()
        .route("/health", get(health))
        .route("/control/presence", get(list_presence))
        .route("/control/presence/register", post(register_presence))
        .route("/control/relay/ticket", post(issue_relay_ticket))
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

async fn redeem_bootstrap_claim(
    State(state): State<AppState>,
    Json(request): Json<ClientBootstrapClaimRedeemRequest>,
) -> std::result::Result<impl axum::response::IntoResponse, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let response = relay_bootstrap_claim_redeem_over_tunnel(&state, &request).await?;

    Ok(([(CACHE_CONTROL, "no-store")], Json(response)))
}

fn bootstrap_claim_relay_source_identity(
    request: &ClientBootstrapClaimRedeemRequest,
) -> PeerIdentity {
    request
        .device_id
        .as_deref()
        .and_then(|value| value.trim().parse::<DeviceId>().ok())
        .map(PeerIdentity::Device)
        .unwrap_or(PeerIdentity::Node(request.target_node_id))
}

fn bootstrap_claim_transport_request(
    request: &ClientBootstrapClaimRedeemRequest,
) -> std::result::Result<BufferedTransportRequest, (StatusCode, String)> {
    let body = serde_json::to_vec(request).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed encoding bootstrap claim redeem request: {err}"),
        )
    })?;
    Ok(BufferedTransportRequest::new(
        TransportStreamKind::Rpc,
        "POST",
        "/auth/bootstrap-claims/redeem",
        vec![TransportHeader {
            name: "content-type".to_string(),
            value: "application/json".to_string(),
        }],
        body,
    ))
}

async fn relay_bootstrap_claim_redeem_over_tunnel(
    state: &AppState,
    request: &ClientBootstrapClaimRedeemRequest,
) -> std::result::Result<ClientBootstrapClaimRedeemResponse, (StatusCode, String)> {
    let target = PeerIdentity::Node(request.target_node_id);
    let target_presence = state.presence.entry_for_identity(&target).ok_or_else(|| {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "bootstrap claim target node {} is not currently connected to rendezvous",
                request.target_node_id
            ),
        )
    })?;

    let ticket = issue_runtime_relay_ticket(
        RelayTicketRequest {
            cluster_id: target_presence.registration.cluster_id,
            source: bootstrap_claim_relay_source_identity(request),
            target,
            session_kind: RelayTunnelSessionKind::MultiplexTransport,
            requested_expires_in_secs: Some(30),
        },
        std::slice::from_ref(&state.config.public_url),
    );
    let source = bootstrap_claim_relay_source_identity(request);
    let transport_request = bootstrap_claim_transport_request(request)?;
    let (relay_session, session) = state
        .relay_tunnel
        .connect_source(ticket)
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?
        .into_multiplexed_session(MultiplexMode::Client, MultiplexConfig::default())
        .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
    perform_transport_client_handshake(
        &session,
        TransportSessionControlMessage::Hello {
            protocol_version: TRANSPORT_PROTOCOL_VERSION,
            cluster_id: target_presence.registration.cluster_id,
            role: TransportSessionRole::Client,
            peer: source,
            target: Some(PeerIdentity::Node(request.target_node_id)),
        },
    )
    .await
    .map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!(
                "failed completing bootstrap-claim relay handshake for session {}: {err}",
                relay_session.session_id
            ),
        )
    })?;

    let response = async {
        let mut stream = session
            .open_stream()
            .await
            .map_err(|err| anyhow::anyhow!("failed opening bootstrap-claim relay stream: {err}"))?;
        write_buffered_transport_request(&mut stream, &transport_request)
            .await
            .map_err(|err| anyhow::anyhow!("failed writing bootstrap-claim relay request: {err}"))?;
        read_buffered_transport_response(&mut stream)
            .await
            .map_err(|err| anyhow::anyhow!("failed reading bootstrap-claim relay response: {err}"))
    }
    .await
    .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
    let _ = session.close().await;

    let response_status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY);
    if response_status.is_server_error() {
        return Err((
            StatusCode::BAD_GATEWAY,
            String::from_utf8_lossy(&response.body).trim().to_string(),
        ));
    }
    if !response_status.is_success() {
        return Err((
            response_status,
            String::from_utf8_lossy(&response.body).trim().to_string(),
        ));
    }

    let redeemed = serde_json::from_slice::<ClientBootstrapClaimRedeemResponse>(&response.body)
        .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
    redeemed
        .validate()
        .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
    Ok(redeemed)
}

async fn relay_tunnel_ws(
    State(state): State<AppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
    websocket: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    websocket.on_upgrade(move |socket| async move {
        serve_relay_tunnel_websocket(state, authenticated_peer, socket).await;
    })
}

async fn serve_relay_tunnel_websocket(
    state: AppState,
    authenticated_peer: MaybeAuthenticatedPeer,
    mut socket: WebSocket,
) {
    if let Err(err) = run_relay_tunnel_websocket(&state, &authenticated_peer, &mut socket).await {
        warn!(error = %err, "embedded relay tunnel websocket failed");
        let _ = send_relay_tunnel_control(
            &mut socket,
            &RelayTunnelControlMessage::Error {
                message: err.to_string(),
            },
        )
        .await;
    }
    let _ = socket.send(Message::Close(None)).await;
}

async fn run_relay_tunnel_websocket(
    state: &AppState,
    authenticated_peer: &MaybeAuthenticatedPeer,
    socket: &mut WebSocket,
) -> anyhow::Result<()> {
    let initial = read_relay_tunnel_initial_message(socket).await?;
    let mut endpoint = establish_relay_tunnel_endpoint(state, authenticated_peer, initial).await?;
    send_relay_tunnel_control(
        socket,
        &RelayTunnelControlMessage::Paired {
            session: endpoint.session().clone(),
        },
    )
    .await?;

    loop {
        tokio::select! {
            message = socket.recv() => {
                match message {
                    Some(Ok(Message::Binary(bytes))) => {
                        endpoint.send(RelayTunnelFrame::Data(bytes.to_vec())).await?;
                    }
                    Some(Ok(Message::Text(text))) => match parse_relay_tunnel_control(&text)? {
                        RelayTunnelControlMessage::CloseWrite => {
                            endpoint.send(RelayTunnelFrame::CloseWrite).await?;
                        }
                        other => {
                            anyhow::bail!(
                                "unexpected embedded relay tunnel control after pairing: {}",
                                serde_json::to_string(&other)
                                    .unwrap_or_else(|_| "<unserializable>".to_string())
                            );
                        }
                    },
                    Some(Ok(Message::Ping(payload))) => {
                        socket
                            .send(Message::Pong(payload))
                            .await
                            .context("failed sending embedded relay tunnel pong")?;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(err)) => {
                        return Err(err).context("embedded relay tunnel websocket read failed");
                    }
                }
            }
            frame = endpoint.recv() => {
                match frame {
                    Some(RelayTunnelFrame::Data(bytes)) => {
                        socket
                            .send(Message::Binary(bytes.into()))
                            .await
                            .context("failed sending embedded relay tunnel data frame")?;
                    }
                    Some(RelayTunnelFrame::CloseWrite) => {
                        send_relay_tunnel_control(socket, &RelayTunnelControlMessage::CloseWrite)
                            .await?;
                    }
                    None => break,
                }
            }
        }
    }

    Ok(())
}

async fn read_relay_tunnel_initial_message(
    socket: &mut WebSocket,
) -> anyhow::Result<RelayTunnelControlMessage> {
    loop {
        let message = socket
            .recv()
            .await
            .ok_or_else(|| {
                anyhow::anyhow!("embedded relay tunnel websocket closed before pairing")
            })?
            .context("embedded relay tunnel websocket read failed before pairing")?;
        match message {
            Message::Text(text) => return parse_relay_tunnel_control(&text),
            Message::Ping(payload) => {
                socket
                    .send(Message::Pong(payload))
                    .await
                    .context("failed sending embedded relay tunnel pong")?;
            }
            Message::Pong(_) => {}
            Message::Close(_) => {
                anyhow::bail!("embedded relay tunnel websocket closed before pairing");
            }
            Message::Binary(_) => {
                anyhow::bail!("embedded relay tunnel websocket sent data before pairing");
            }
        }
    }
}

async fn establish_relay_tunnel_endpoint(
    state: &AppState,
    authenticated_peer: &MaybeAuthenticatedPeer,
    control: RelayTunnelControlMessage,
) -> anyhow::Result<transport_sdk::RelayTunnelEndpoint> {
    match control {
        RelayTunnelControlMessage::ConnectSource { ticket } => {
            ensure_authenticated_peer_identity(
                authenticated_peer,
                &ticket.source,
                "relay tunnel source",
            )?;
            state.relay_tunnel.connect_source(ticket).await
        }
        RelayTunnelControlMessage::AcceptTarget { request } => {
            ensure_authenticated_peer_identity(
                authenticated_peer,
                &request.target,
                "relay tunnel target",
            )?;
            state.relay_tunnel.accept_target(request).await
        }
        RelayTunnelControlMessage::Paired { .. }
        | RelayTunnelControlMessage::CloseWrite
        | RelayTunnelControlMessage::Error { .. } => {
            anyhow::bail!("unexpected embedded relay tunnel control before pairing");
        }
    }
}

fn parse_relay_tunnel_control(text: &str) -> anyhow::Result<RelayTunnelControlMessage> {
    serde_json::from_str(text).context("failed parsing embedded relay tunnel control message")
}

async fn send_relay_tunnel_control(
    socket: &mut WebSocket,
    control: &RelayTunnelControlMessage,
) -> anyhow::Result<()> {
    let payload =
        serde_json::to_string(control).context("failed encoding embedded relay tunnel control")?;
    socket
        .send(Message::Text(payload.into()))
        .await
        .context("failed sending embedded relay tunnel control message")
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
