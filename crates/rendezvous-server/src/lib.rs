mod auth;

use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::http::Uri;
use axum::http::header::CACHE_CONTROL;
use axum::routing::{get, post};
use axum::{Json, Router};
use common::{ClusterId, DeviceId, NodeId};
use serde::{Deserialize, Serialize};
use tracing::warn;
use transport_sdk::peer::PeerIdentity;
use transport_sdk::rendezvous::{
    DiscoveryResponse, PresenceListResponse, PresenceRegistration, RegisterPresenceResponse,
    RendezvousClientConfig, RendezvousControlClient, RendezvousRuntimeState,
};
use transport_sdk::{
    BufferedTransportRequest, CandidateKind, ClientBootstrapClaimRedeemRequest,
    ClientBootstrapClaimRedeemResponse, ConnectionCandidate, MultiplexConfig, MultiplexMode,
    PresenceRegistry, RelayTicket, RelayTicketRequest, RelayTunnelBroker,
    RelayTunnelControlMessage, RelayTunnelFrame, RelayTunnelSessionKind, RelayWakeControlMessage,
    RelayWakeRegistration, TRANSPORT_PROTOCOL_VERSION, TransportHeader,
    TransportSessionControlMessage, TransportSessionRole, TransportStreamKind,
    WakeRegistrationHandle, issue_relay_ticket as issue_runtime_relay_ticket,
    perform_transport_client_handshake, rank_candidates, read_buffered_transport_response,
    write_buffered_transport_request,
};

use crate::auth::{
    MaybeAuthenticatedPeer, MaybeObservedPeerAddr, MtlsAuthenticatedPeerAcceptor,
    build_mtls_rustls_config, ensure_authenticated_peer_identity, require_any_authenticated_peer,
};

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone)]
pub enum RendezvousServerTlsIdentity {
    Files {
        cert_path: PathBuf,
        key_path: PathBuf,
    },
    InlinePem {
        cert_pem: String,
        key_pem: String,
    },
}

#[derive(Debug, Clone)]
pub enum RendezvousClientCa {
    File { cert_path: PathBuf },
    InlinePem { cert_pem: String },
}

#[derive(Debug, Clone)]
pub struct RendezvousMtlsConfig {
    pub client_ca: RendezvousClientCa,
    pub server_identity: RendezvousServerTlsIdentity,
}

#[derive(Debug, Clone)]
pub struct RendezvousServerConfig {
    pub bind_addr: SocketAddr,
    pub public_url: String,
    pub relay_public_urls: Vec<String>,
    pub peer_rendezvous_urls: Vec<String>,
    pub mtls: Option<RendezvousMtlsConfig>,
}

#[derive(Clone)]
pub struct RendezvousAppState {
    pub config: RendezvousServerConfig,
    pub presence: PresenceRegistry,
    pub relay_tunnel: RelayTunnelBroker,
    pub mesh_peers: Option<RendezvousControlClient>,
}

impl RendezvousAppState {
    pub fn new(config: RendezvousServerConfig) -> Result<Self> {
        Ok(Self {
            mesh_peers: build_mesh_probe_client(&config)?,
            config,
            presence: PresenceRegistry::new(),
            relay_tunnel: RelayTunnelBroker::new(),
        })
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    public_url: String,
    registered_endpoints: usize,
    software_version: &'static str,
}

pub fn build_router(state: RendezvousAppState) -> Router {
    let relay_router = Router::new()
        .route("/relay/tunnel/ws", get(relay_tunnel_ws))
        .route("/relay/wake/ws", get(relay_wake_ws));

    Router::new()
        .route("/health", get(health))
        .route("/control/mesh", get(mesh_status))
        .route("/control/discovery", get(discovery))
        .route("/control/presence", get(list_presence))
        .route("/control/presence/register", post(register_presence))
        .route("/control/relay/ticket", post(issue_relay_ticket))
        .route("/bootstrap-claims/redeem", post(redeem_bootstrap_claim))
        .merge(relay_router)
        .with_state(state)
}

pub async fn serve(state: RendezvousAppState) -> Result<()> {
    let bind_addr = state.config.bind_addr;
    let app = build_router(state.clone());
    spawn_mesh_probe_task(state.mesh_peers.clone());

    if let Some(mtls) = state.config.mtls.as_ref() {
        let tls_config = build_mtls_rustls_config(mtls)?;
        axum_server::bind(bind_addr)
            .acceptor(MtlsAuthenticatedPeerAcceptor::new(tls_config))
            .serve(app.into_make_service())
            .await?;
        Ok(())
    } else {
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
        Ok(())
    }
}

async fn health(State(state): State<RendezvousAppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        public_url: state.config.public_url,
        registered_endpoints: state.presence.len(),
        software_version: PACKAGE_VERSION,
    })
}

async fn mesh_status(
    State(state): State<RendezvousAppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
) -> std::result::Result<Json<RendezvousRuntimeState>, (StatusCode, String)> {
    require_any_authenticated_peer(state.config.mtls.is_some(), &authenticated_peer)
        .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;
    Ok(Json(
        state
            .mesh_peers
            .as_ref()
            .map(RendezvousControlClient::runtime_state)
            .unwrap_or_else(empty_rendezvous_runtime_state),
    ))
}

#[derive(Debug, Deserialize)]
struct DiscoveryQuery {
    #[serde(default)]
    node_id: Option<NodeId>,
}

async fn discovery(
    State(state): State<RendezvousAppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
    Query(query): Query<DiscoveryQuery>,
) -> std::result::Result<Json<DiscoveryResponse>, (StatusCode, String)> {
    require_any_authenticated_peer(state.config.mtls.is_some(), &authenticated_peer)
        .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;
    Ok(Json(discovery_response(&state, query.node_id)))
}

async fn register_presence(
    State(state): State<RendezvousAppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
    observed_peer_addr: MaybeObservedPeerAddr,
    Json(request): Json<PresenceRegistration>,
) -> std::result::Result<Json<RegisterPresenceResponse>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ensure_authenticated_peer_identity(
        state.config.mtls.is_some(),
        &authenticated_peer,
        &request.identity,
        "presence registration identity",
    )
    .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;

    let entry = state
        .presence
        .register(request, observed_peer_addr.socket_addr());
    let entry = response_presence_entry(entry);
    Ok(Json(RegisterPresenceResponse {
        accepted: true,
        software_version: Some(PACKAGE_VERSION.to_string()),
        updated_at_unix: entry.updated_at_unix,
        entry,
    }))
}

async fn list_presence(
    State(state): State<RendezvousAppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
) -> std::result::Result<Json<PresenceListResponse>, (StatusCode, String)> {
    require_any_authenticated_peer(state.config.mtls.is_some(), &authenticated_peer)
        .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;
    let entries = state
        .presence
        .list()
        .into_iter()
        .map(response_presence_entry)
        .collect::<Vec<_>>();
    Ok(Json(PresenceListResponse {
        registered_endpoints: entries.len(),
        entries,
    }))
}

fn response_presence_entry(
    mut entry: transport_sdk::PresenceEntry,
) -> transport_sdk::PresenceEntry {
    let Some(candidate) = synthesize_server_reflexive_candidate(&entry) else {
        return entry;
    };

    if has_candidate_endpoint(&entry.registration.direct_candidates, &candidate.endpoint) {
        return entry;
    }

    let mut candidates = entry.registration.direct_candidates.clone();
    candidates.push(candidate);
    entry.registration.direct_candidates = rank_candidates(&candidates);
    entry
}

fn synthesize_server_reflexive_candidate(
    entry: &transport_sdk::PresenceEntry,
) -> Option<ConnectionCandidate> {
    let observed_source_addr = entry.observed_source_addr?;
    let port = entry
        .registration
        .peer_api_url
        .as_deref()
        .and_then(url_port)
        .or_else(|| {
            entry
                .registration
                .public_api_url
                .as_deref()
                .and_then(url_port)
        })?;
    Some(ConnectionCandidate {
        kind: CandidateKind::ServerReflexive,
        endpoint: server_reflexive_endpoint(observed_source_addr.ip(), port),
        rtt_ms: None,
    })
}

fn url_port(value: &str) -> Option<u16> {
    value
        .parse::<Uri>()
        .ok()?
        .authority()
        .and_then(|authority| authority.port_u16())
}

fn server_reflexive_endpoint(ip: IpAddr, port: u16) -> String {
    match ip {
        IpAddr::V4(ip) => format!("https://{ip}:{port}"),
        IpAddr::V6(ip) => format!("https://[{ip}]:{port}"),
    }
}

fn has_candidate_endpoint(candidates: &[ConnectionCandidate], endpoint: &str) -> bool {
    candidates
        .iter()
        .any(|candidate| candidate.endpoint.trim_end_matches('/') == endpoint)
}

fn build_mesh_probe_client(
    config: &RendezvousServerConfig,
) -> Result<Option<RendezvousControlClient>> {
    if config.peer_rendezvous_urls.is_empty() {
        return Ok(None);
    }

    // Mesh health probes are cluster-agnostic, but the shared rendezvous client
    // still validates that a non-nil cluster_id is present.
    let cluster_id = ClusterId::now_v7();
    let server_ca_pem = rendezvous_mesh_server_ca_pem(config.mtls.as_ref())?;
    Ok(Some(RendezvousControlClient::new(
        RendezvousClientConfig {
            cluster_id,
            rendezvous_urls: config.peer_rendezvous_urls.clone(),
            heartbeat_interval_secs: 15,
        },
        server_ca_pem.as_deref(),
        None,
    )?))
}

fn rendezvous_mesh_server_ca_pem(mtls: Option<&RendezvousMtlsConfig>) -> Result<Option<String>> {
    let Some(mtls) = mtls else {
        return Ok(None);
    };

    match &mtls.client_ca {
        RendezvousClientCa::File { cert_path } => Ok(Some(
            std::fs::read_to_string(cert_path)
                .with_context(|| format!("failed reading {}", cert_path.display()))?,
        )),
        RendezvousClientCa::InlinePem { cert_pem } => Ok(Some(cert_pem.clone())),
    }
}

fn spawn_mesh_probe_task(mesh_peers: Option<RendezvousControlClient>) {
    let Some(mesh_peers) = mesh_peers else {
        return;
    };

    tokio::spawn(async move {
        let interval_secs = mesh_peers.config().heartbeat_interval_secs.max(1);
        let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
        ticker.tick().await;

        loop {
            if let Err(err) = mesh_peers.probe_health_endpoints().await {
                warn!(
                    error = %err,
                    rendezvous_urls = ?mesh_peers.config().rendezvous_urls,
                    "failed to probe rendezvous mesh peers"
                );
            }
            ticker.tick().await;
        }
    });
}

fn empty_rendezvous_runtime_state() -> RendezvousRuntimeState {
    RendezvousRuntimeState {
        active_url: None,
        endpoint_statuses: Vec::new(),
    }
}

fn discovery_response(state: &RendezvousAppState, node_id: Option<NodeId>) -> DiscoveryResponse {
    let rendezvous_peers = state
        .mesh_peers
        .as_ref()
        .map(RendezvousControlClient::runtime_state)
        .unwrap_or_else(empty_rendezvous_runtime_state)
        .endpoint_statuses;

    let (node_candidates, node_relay_capable) = node_id
        .and_then(|node_id| {
            state
                .presence
                .entry_for_identity(&PeerIdentity::Node(node_id))
                .map(response_presence_entry)
        })
        .map(|entry| {
            let relay_capable = entry
                .registration
                .capabilities
                .contains(&transport_sdk::TransportCapability::RelayTunnel)
                || entry.registration.relay_mode != transport_sdk::RelayMode::Disabled;
            (Some(entry.registration.direct_candidates), relay_capable)
        })
        .unwrap_or((None, false));

    DiscoveryResponse {
        rendezvous_peers,
        node_candidates,
        node_relay_capable,
    }
}

async fn issue_relay_ticket(
    State(state): State<RendezvousAppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
    Json(request): Json<RelayTicketRequest>,
) -> std::result::Result<Json<RelayTicket>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ensure_authenticated_peer_identity(
        state.config.mtls.is_some(),
        &authenticated_peer,
        &request.source,
        "relay ticket source",
    )
    .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;

    let ticket = issue_runtime_relay_ticket(request, &state.config.relay_public_urls);
    ticket
        .validate()
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(Json(ticket))
}

async fn redeem_bootstrap_claim(
    State(state): State<RendezvousAppState>,
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
    state: &RendezvousAppState,
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
        &state.config.relay_public_urls,
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
            connection_name: None,
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
            .map_err(|err| {
                anyhow::anyhow!("failed writing bootstrap-claim relay request: {err}")
            })?;
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
    State(state): State<RendezvousAppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
    websocket: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    websocket.on_upgrade(move |socket| async move {
        serve_relay_tunnel_websocket(state, authenticated_peer, socket).await;
    })
}

async fn serve_relay_tunnel_websocket(
    state: RendezvousAppState,
    authenticated_peer: MaybeAuthenticatedPeer,
    mut socket: WebSocket,
) {
    let initial = match read_relay_tunnel_initial_message(&mut socket).await {
        Ok(initial) => initial,
        Err(err) => {
            let error = err.to_string();
            log_relay_tunnel_websocket_error(&error, None);
            let _ = send_relay_tunnel_control(
                &mut socket,
                &RelayTunnelControlMessage::Error { message: error },
            )
            .await;
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
    };
    let log_context = RelayTunnelLogContext::from_initial(&initial);
    if let Err(err) =
        run_relay_tunnel_websocket(&state, &authenticated_peer, &mut socket, initial).await
    {
        let error = err.to_string();
        log_relay_tunnel_websocket_error(&error, log_context.as_ref());
        let _ = send_relay_tunnel_control(
            &mut socket,
            &RelayTunnelControlMessage::Error { message: error },
        )
        .await;
    }
    let _ = socket.send(Message::Close(None)).await;
}

async fn run_relay_tunnel_websocket(
    state: &RendezvousAppState,
    authenticated_peer: &MaybeAuthenticatedPeer,
    socket: &mut WebSocket,
    initial: RelayTunnelControlMessage,
) -> anyhow::Result<()> {
    // Race the (potentially long-running, up to tens of seconds) broker wait against the
    // socket so that a peer that abandons this connection before pairing completes is
    // noticed immediately. Without this, `establish_relay_tunnel_endpoint` is a plain
    // `.await` that never observes the socket closing, so a dropped connection leaves a
    // "zombie" entry in the broker's FIFO pairing queue that a later, still-live peer can
    // falsely pair with instead of a genuine one.
    let establish = establish_relay_tunnel_endpoint(state, authenticated_peer, initial);
    tokio::pin!(establish);

    let mut endpoint = loop {
        tokio::select! {
            result = &mut establish => break result,
            message = socket.recv() => {
                match message {
                    Some(Ok(Message::Ping(payload))) => {
                        socket
                            .send(Message::Pong(payload))
                            .await
                            .context("failed sending relay tunnel pong while awaiting pairing")?;
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => {
                        anyhow::bail!("relay tunnel websocket closed before pairing completed");
                    }
                    Some(Ok(_)) => {
                        anyhow::bail!(
                            "relay tunnel peer sent unexpected data before pairing completed"
                        );
                    }
                    Some(Err(err)) => {
                        return Err(err)
                            .context("relay tunnel websocket errored before pairing completed");
                    }
                }
            }
        }
    }?;
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
                        if let Err(err) = endpoint.send(RelayTunnelFrame::Data(bytes.to_vec())).await {
                            tracing::debug!(
                                error = %err,
                                session_id = %endpoint.session().session_id,
                                "relay tunnel endpoint closed after pairing"
                            );
                            break;
                        }
                    }
                    Some(Ok(Message::Text(text))) => match parse_relay_tunnel_control(&text)? {
                        RelayTunnelControlMessage::CloseWrite => {
                            if let Err(err) = endpoint.send(RelayTunnelFrame::CloseWrite).await {
                                tracing::debug!(
                                    error = %err,
                                    session_id = %endpoint.session().session_id,
                                    "relay tunnel endpoint closed after pairing"
                                );
                                break;
                            }
                        }
                        other => {
                            anyhow::bail!(
                                "unexpected relay tunnel control message after pairing: {}",
                                serde_json::to_string(&other)
                                    .unwrap_or_else(|_| "<unserializable>".to_string())
                            );
                        }
                    },
                    Some(Ok(Message::Ping(payload))) => {
                        if let Err(err) = socket.send(Message::Pong(payload)).await {
                            tracing::debug!(
                                error = %err,
                                session_id = %endpoint.session().session_id,
                                "relay tunnel websocket closed after pairing"
                            );
                            break;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {}
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(err)) => {
                        tracing::debug!(
                            error = %err,
                            session_id = %endpoint.session().session_id,
                            "relay tunnel websocket closed after pairing"
                        );
                        break;
                    }
                }
            }
            frame = endpoint.recv() => {
                match frame {
                    Some(RelayTunnelFrame::Data(bytes)) => {
                        if let Err(err) = socket.send(Message::Binary(bytes.into())).await {
                            tracing::debug!(
                                error = %err,
                                session_id = %endpoint.session().session_id,
                                "relay tunnel websocket closed after pairing"
                            );
                            break;
                        }
                    }
                    Some(RelayTunnelFrame::CloseWrite) => {
                        if let Err(err) = send_relay_tunnel_control(
                            socket,
                            &RelayTunnelControlMessage::CloseWrite,
                        )
                        .await
                        {
                            tracing::debug!(
                                error = %err,
                                session_id = %endpoint.session().session_id,
                                "relay tunnel websocket closed after pairing"
                            );
                            break;
                        }
                    }
                    None => break,
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelayTunnelLogContext {
    Source {
        cluster_id: ClusterId,
        session_id: String,
        source_peer: PeerIdentity,
        target_peer: PeerIdentity,
        session_kind: RelayTunnelSessionKind,
    },
    Target {
        cluster_id: ClusterId,
        target_peer: PeerIdentity,
        session_kind: RelayTunnelSessionKind,
    },
}

impl RelayTunnelLogContext {
    fn from_initial(control: &RelayTunnelControlMessage) -> Option<Self> {
        match control {
            RelayTunnelControlMessage::ConnectSource { ticket } => Some(Self::Source {
                cluster_id: ticket.cluster_id,
                session_id: ticket.session_id.clone(),
                source_peer: ticket.source.clone(),
                target_peer: ticket.target.clone(),
                session_kind: ticket.session_kind,
            }),
            RelayTunnelControlMessage::AcceptTarget { request } => Some(Self::Target {
                cluster_id: request.cluster_id,
                target_peer: request.target.clone(),
                session_kind: request.session_kind,
            }),
            RelayTunnelControlMessage::Paired { .. }
            | RelayTunnelControlMessage::CloseWrite
            | RelayTunnelControlMessage::Error { .. } => None,
        }
    }
}

fn log_relay_tunnel_websocket_error(error: &str, context: Option<&RelayTunnelLogContext>) {
    let is_expected_idle = transport_sdk::is_expected_idle_relay_tunnel_accept_timeout(error);
    match context {
        Some(RelayTunnelLogContext::Source {
            cluster_id,
            session_id,
            source_peer,
            target_peer,
            session_kind,
        }) => {
            if is_expected_idle {
                tracing::debug!(
                    error,
                    websocket_role = "source",
                    cluster_id = %cluster_id,
                    session_id,
                    source_peer = %source_peer,
                    target_peer = %target_peer,
                    session_kind = ?session_kind,
                    "relay tunnel websocket closed after idle target wait"
                );
            } else {
                warn!(
                    error,
                    websocket_role = "source",
                    cluster_id = %cluster_id,
                    session_id,
                    source_peer = %source_peer,
                    target_peer = %target_peer,
                    session_kind = ?session_kind,
                    "relay tunnel websocket failed"
                );
            }
        }
        Some(RelayTunnelLogContext::Target {
            cluster_id,
            target_peer,
            session_kind,
        }) => {
            if is_expected_idle {
                tracing::debug!(
                    error,
                    websocket_role = "target",
                    cluster_id = %cluster_id,
                    target_peer = %target_peer,
                    session_kind = ?session_kind,
                    "relay tunnel websocket closed after idle target wait"
                );
            } else {
                warn!(
                    error,
                    websocket_role = "target",
                    cluster_id = %cluster_id,
                    target_peer = %target_peer,
                    session_kind = ?session_kind,
                    "relay tunnel websocket failed"
                );
            }
        }
        None => {
            if is_expected_idle {
                tracing::debug!(
                    error,
                    "relay tunnel websocket closed after idle target wait"
                );
            } else {
                warn!(error, "relay tunnel websocket failed");
            }
        }
    }
}

async fn read_relay_tunnel_initial_message(
    socket: &mut WebSocket,
) -> anyhow::Result<RelayTunnelControlMessage> {
    loop {
        let message = socket
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("relay tunnel websocket closed before pairing"))?
            .context("relay tunnel websocket read failed before pairing")?;
        match message {
            Message::Text(text) => return parse_relay_tunnel_control(&text),
            Message::Ping(payload) => {
                socket
                    .send(Message::Pong(payload))
                    .await
                    .context("failed sending relay tunnel pong")?;
            }
            Message::Pong(_) => {}
            Message::Close(_) => {
                anyhow::bail!("relay tunnel websocket closed before pairing");
            }
            Message::Binary(_) => {
                anyhow::bail!("relay tunnel websocket sent data before pairing");
            }
        }
    }
}

async fn establish_relay_tunnel_endpoint(
    state: &RendezvousAppState,
    authenticated_peer: &MaybeAuthenticatedPeer,
    control: RelayTunnelControlMessage,
) -> anyhow::Result<transport_sdk::RelayTunnelEndpoint> {
    match control {
        RelayTunnelControlMessage::ConnectSource { ticket } => {
            ensure_authenticated_peer_identity(
                state.config.mtls.is_some(),
                authenticated_peer,
                &ticket.source,
                "relay tunnel source",
            )?;
            state.relay_tunnel.connect_source(ticket).await
        }
        RelayTunnelControlMessage::AcceptTarget { request } => {
            ensure_authenticated_peer_identity(
                state.config.mtls.is_some(),
                authenticated_peer,
                &request.target,
                "relay tunnel target",
            )?;
            state.relay_tunnel.accept_target(request).await
        }
        RelayTunnelControlMessage::Paired { .. }
        | RelayTunnelControlMessage::CloseWrite
        | RelayTunnelControlMessage::Error { .. } => {
            anyhow::bail!("unexpected relay tunnel control message before pairing");
        }
    }
}

fn parse_relay_tunnel_control(text: &str) -> anyhow::Result<RelayTunnelControlMessage> {
    serde_json::from_str(text).context("failed parsing relay tunnel control message")
}

async fn send_relay_tunnel_control(
    socket: &mut WebSocket,
    control: &RelayTunnelControlMessage,
) -> anyhow::Result<()> {
    let payload =
        serde_json::to_string(control).context("failed encoding relay tunnel control message")?;
    socket
        .send(Message::Text(payload.into()))
        .await
        .context("failed sending relay tunnel control message")
}

/// How long a wake connection can sit with no inbound frame at all (not even a ping)
/// before it's treated as dead. Distinct from -- and much longer than -- the relay
/// tunnel's per-pairing wait, since this channel is meant to stay open indefinitely.
const RELAY_WAKE_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

async fn relay_wake_ws(
    State(state): State<RendezvousAppState>,
    authenticated_peer: MaybeAuthenticatedPeer,
    websocket: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    websocket.on_upgrade(move |socket| async move {
        serve_relay_wake_websocket(state, authenticated_peer, socket).await;
    })
}

async fn serve_relay_wake_websocket(
    state: RendezvousAppState,
    authenticated_peer: MaybeAuthenticatedPeer,
    mut socket: WebSocket,
) {
    let registration = match read_relay_wake_initial_message(&mut socket).await {
        Ok(registration) => registration,
        Err(err) => {
            let error = err.to_string();
            warn!(error, "relay wake websocket failed before registration");
            let _ = send_relay_wake_control(
                &mut socket,
                &RelayWakeControlMessage::Error { message: error },
            )
            .await;
            let _ = socket.send(Message::Close(None)).await;
            return;
        }
    };

    if let Err(err) = ensure_authenticated_peer_identity(
        state.config.mtls.is_some(),
        &authenticated_peer,
        &registration.target,
        "relay wake target",
    ) {
        let error = err.to_string();
        warn!(error, "relay wake websocket rejected before registration");
        let _ = send_relay_wake_control(
            &mut socket,
            &RelayWakeControlMessage::Error { message: error },
        )
        .await;
        let _ = socket.send(Message::Close(None)).await;
        return;
    }

    let handle = state
        .relay_tunnel
        .register_wake(
            registration.cluster_id,
            &registration.target,
            registration.session_kind,
        )
        .await;

    if send_relay_wake_control(&mut socket, &RelayWakeControlMessage::Registered)
        .await
        .is_err()
    {
        state.relay_tunnel.unregister_wake(&handle).await;
        return;
    }

    run_relay_wake_websocket(&mut socket, &handle).await;

    // Unconditional cleanup regardless of how the loop above ended: this registration
    // lives exactly as long as the socket does, so anything that ends the loop --
    // a clean close, a read error, or the idle timeout -- must release it, the same
    // "always clean up" property the zombie-queue fix gave the tunnel pairing wait.
    state.relay_tunnel.unregister_wake(&handle).await;
    let _ = socket.send(Message::Close(None)).await;
}

async fn run_relay_wake_websocket(socket: &mut WebSocket, handle: &WakeRegistrationHandle) {
    let mut idle_deadline = tokio::time::Instant::now() + RELAY_WAKE_IDLE_TIMEOUT;
    loop {
        tokio::select! {
            _ = handle.notify.notified() => {
                if send_relay_wake_control(socket, &RelayWakeControlMessage::Wake)
                    .await
                    .is_err()
                {
                    return;
                }
            }
            _ = tokio::time::sleep_until(idle_deadline) => {
                return;
            }
            message = socket.recv() => {
                match message {
                    Some(Ok(Message::Ping(payload))) => {
                        idle_deadline = tokio::time::Instant::now() + RELAY_WAKE_IDLE_TIMEOUT;
                        if socket.send(Message::Pong(payload)).await.is_err() {
                            return;
                        }
                    }
                    Some(Ok(Message::Pong(_))) => {
                        idle_deadline = tokio::time::Instant::now() + RELAY_WAKE_IDLE_TIMEOUT;
                    }
                    // The node never sends anything else on this channel after
                    // registering; any of these ends the connection.
                    Some(Ok(Message::Close(_))) | None | Some(Ok(_)) | Some(Err(_)) => {
                        return;
                    }
                }
            }
        }
    }
}

async fn read_relay_wake_initial_message(
    socket: &mut WebSocket,
) -> anyhow::Result<RelayWakeRegistration> {
    loop {
        let message = socket
            .recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("relay wake websocket closed before registration"))?
            .context("relay wake websocket read failed before registration")?;
        match message {
            Message::Text(text) => match parse_relay_wake_control(&text)? {
                RelayWakeControlMessage::Register { registration } => {
                    registration.validate()?;
                    return Ok(registration);
                }
                other => anyhow::bail!(
                    "unexpected relay wake control message before registration: {}",
                    serde_json::to_string(&other)
                        .unwrap_or_else(|_| "<unserializable>".to_string())
                ),
            },
            Message::Ping(payload) => {
                socket
                    .send(Message::Pong(payload))
                    .await
                    .context("failed sending relay wake pong")?;
            }
            Message::Pong(_) => {}
            Message::Close(_) => {
                anyhow::bail!("relay wake websocket closed before registration");
            }
            Message::Binary(_) => {
                anyhow::bail!("relay wake websocket sent data before registration");
            }
        }
    }
}

fn parse_relay_wake_control(text: &str) -> anyhow::Result<RelayWakeControlMessage> {
    serde_json::from_str(text).context("failed parsing relay wake control message")
}

async fn send_relay_wake_control(
    socket: &mut WebSocket,
    control: &RelayWakeControlMessage,
) -> anyhow::Result<()> {
    let payload =
        serde_json::to_string(control).context("failed encoding relay wake control message")?;
    socket
        .send(Message::Text(payload.into()))
        .await
        .context("failed sending relay wake control message")
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::NodeId;
    use transport_sdk::{
        RelayMode, RendezvousClientConfig, RendezvousControlClient, TransportCapability,
    };

    #[test]
    fn relay_tunnel_log_context_captures_source_ticket_metadata() {
        let cluster_id = ClusterId::now_v7();
        let source_peer = PeerIdentity::Device(DeviceId::now_v7());
        let target_peer = PeerIdentity::Node(common::NodeId::now_v7());
        let initial = RelayTunnelControlMessage::ConnectSource {
            ticket: RelayTicket {
                cluster_id,
                session_id: "relay-session-123".to_string(),
                source: source_peer.clone(),
                target: target_peer.clone(),
                session_kind: RelayTunnelSessionKind::MultiplexTransport,
                relay_urls: vec!["https://relay.example".to_string()],
                issued_at_unix: 1,
                expires_at_unix: 2,
            },
        };

        assert_eq!(
            RelayTunnelLogContext::from_initial(&initial),
            Some(RelayTunnelLogContext::Source {
                cluster_id,
                session_id: "relay-session-123".to_string(),
                source_peer,
                target_peer,
                session_kind: RelayTunnelSessionKind::MultiplexTransport,
            })
        );
    }

    #[test]
    fn relay_tunnel_log_context_captures_target_wait_metadata() {
        let cluster_id = ClusterId::now_v7();
        let target_peer = PeerIdentity::Node(common::NodeId::now_v7());
        let initial = RelayTunnelControlMessage::AcceptTarget {
            request: transport_sdk::RelayTunnelAcceptRequest {
                cluster_id,
                target: target_peer.clone(),
                session_kind: RelayTunnelSessionKind::MultiplexTransport,
                wait_timeout_ms: Some(15_000),
            },
        };

        assert_eq!(
            RelayTunnelLogContext::from_initial(&initial),
            Some(RelayTunnelLogContext::Target {
                cluster_id,
                target_peer,
                session_kind: RelayTunnelSessionKind::MultiplexTransport,
            })
        );
    }

    #[test]
    fn synthesize_server_reflexive_candidate_uses_observed_ip_and_peer_api_port() {
        let entry = transport_sdk::PresenceEntry {
            registration: PresenceRegistration {
                cluster_id: ClusterId::now_v7(),
                identity: PeerIdentity::Node(NodeId::now_v7()),
                public_api_url: Some("https://public.example:9443".to_string()),
                peer_api_url: Some("https://node.internal:7443".to_string()),
                direct_candidates: Vec::new(),
                labels: Default::default(),
                capacity_bytes: None,
                free_bytes: None,
                capabilities: vec![TransportCapability::DirectHttps],
                relay_mode: RelayMode::Disabled,
                connected_at_unix: 1,
            },
            updated_at_unix: 1,
            observed_source_addr: Some("203.0.113.10:51000".parse().expect("socket addr")),
        };

        let candidate = synthesize_server_reflexive_candidate(&entry)
            .expect("server reflexive candidate should be synthesized");
        assert_eq!(candidate.kind, CandidateKind::ServerReflexive);
        assert_eq!(candidate.endpoint, "https://203.0.113.10:7443");
    }

    #[test]
    fn synthesize_server_reflexive_candidate_requires_explicit_port() {
        let entry = transport_sdk::PresenceEntry {
            registration: PresenceRegistration {
                cluster_id: ClusterId::now_v7(),
                identity: PeerIdentity::Node(NodeId::now_v7()),
                public_api_url: Some("https://public.example".to_string()),
                peer_api_url: Some("https://node.internal".to_string()),
                direct_candidates: Vec::new(),
                labels: Default::default(),
                capacity_bytes: None,
                free_bytes: None,
                capabilities: vec![TransportCapability::DirectHttps],
                relay_mode: RelayMode::Disabled,
                connected_at_unix: 1,
            },
            updated_at_unix: 1,
            observed_source_addr: Some("203.0.113.10:51000".parse().expect("socket addr")),
        };

        assert!(synthesize_server_reflexive_candidate(&entry).is_none());
    }

    #[tokio::test]
    async fn plain_http_presence_registration_exposes_observed_source_and_reflexive_candidate() {
        let cluster_id = ClusterId::now_v7();
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("bind addr");
        let state = RendezvousAppState::new(RendezvousServerConfig {
            bind_addr,
            public_url: "http://rendezvous.example".to_string(),
            relay_public_urls: Vec::new(),
            peer_rendezvous_urls: Vec::new(),
            mtls: None,
        })
        .expect("rendezvous app state should build");
        let router = build_router(state);
        let listener = tokio::net::TcpListener::bind(bind_addr)
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("test rendezvous server should run");
        });

        let client = RendezvousControlClient::new(
            RendezvousClientConfig {
                cluster_id,
                rendezvous_urls: vec![format!("http://{addr}")],
                heartbeat_interval_secs: 15,
            },
            None,
            None,
        )
        .expect("rendezvous client should build");
        let registration = PresenceRegistration {
            cluster_id,
            identity: PeerIdentity::Node(NodeId::now_v7()),
            public_api_url: Some("https://public.example:9443".to_string()),
            peer_api_url: Some("https://node.internal:7443".to_string()),
            direct_candidates: Vec::new(),
            labels: Default::default(),
            capacity_bytes: None,
            free_bytes: None,
            capabilities: vec![TransportCapability::DirectHttps],
            relay_mode: RelayMode::Disabled,
            connected_at_unix: 1,
        };

        let response = client
            .register_presence(&registration)
            .await
            .expect("presence registration should succeed");
        assert_eq!(
            response.entry.observed_source_addr.map(|addr| addr.ip()),
            Some("127.0.0.1".parse().expect("loopback ip"))
        );
        assert_eq!(
            response.entry.registration.direct_candidates,
            vec![ConnectionCandidate {
                kind: CandidateKind::ServerReflexive,
                endpoint: "https://127.0.0.1:7443".to_string(),
                rtt_ms: None,
            }]
        );

        let listed = client
            .list_presence()
            .await
            .expect("presence listing should succeed");
        assert_eq!(listed.registered_endpoints, 1);
        assert_eq!(listed.entries[0], response.entry);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn mesh_status_reports_connected_peer_after_probe() {
        let peer_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("peer listener should bind");
        let peer_addr = peer_listener.local_addr().expect("peer listener addr");
        let peer_server = tokio::spawn(async move {
            axum::serve(
                peer_listener,
                Router::new().route("/health", get(|| async { StatusCode::OK })),
            )
            .await
            .expect("peer rendezvous should run");
        });

        let state = RendezvousAppState::new(RendezvousServerConfig {
            bind_addr: "127.0.0.1:0".parse().expect("bind addr"),
            public_url: "http://rendezvous.example".to_string(),
            relay_public_urls: Vec::new(),
            peer_rendezvous_urls: vec![format!("http://{peer_addr}")],
            mtls: None,
        })
        .expect("rendezvous app state should build");
        let mesh_peers = state
            .mesh_peers
            .as_ref()
            .expect("mesh peer client should exist");
        mesh_peers
            .probe_health_endpoints()
            .await
            .expect("mesh probe should succeed");

        let response = mesh_status(State(state), MaybeAuthenticatedPeer::default())
            .await
            .expect("mesh status should succeed without mTLS")
            .0;
        assert_eq!(response.active_url, None);
        assert_eq!(response.endpoint_statuses.len(), 1);
        assert_eq!(
            response.endpoint_statuses[0].url,
            format!("http://{peer_addr}")
        );
        assert_eq!(
            response.endpoint_statuses[0].status,
            transport_sdk::RendezvousEndpointConnectionState::Connected
        );

        peer_server.abort();
        let _ = peer_server.await;
    }

    #[tokio::test]
    async fn discovery_returns_mesh_status_and_node_candidates() {
        let peer_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("peer listener should bind");
        let peer_addr = peer_listener.local_addr().expect("peer listener addr");
        let peer_server = tokio::spawn(async move {
            axum::serve(
                peer_listener,
                Router::new().route("/health", get(|| async { StatusCode::OK })),
            )
            .await
            .expect("peer rendezvous should run");
        });

        let node_id = NodeId::now_v7();
        let state = RendezvousAppState::new(RendezvousServerConfig {
            bind_addr: "127.0.0.1:0".parse().expect("bind addr"),
            public_url: "http://rendezvous.example".to_string(),
            relay_public_urls: Vec::new(),
            peer_rendezvous_urls: vec![format!("http://{peer_addr}")],
            mtls: None,
        })
        .expect("rendezvous app state should build");
        state.presence.register(
            PresenceRegistration {
                cluster_id: ClusterId::now_v7(),
                identity: PeerIdentity::Node(node_id),
                public_api_url: None,
                peer_api_url: Some("https://node.internal:7443".to_string()),
                direct_candidates: Vec::new(),
                labels: Default::default(),
                capacity_bytes: None,
                free_bytes: None,
                capabilities: vec![TransportCapability::RelayTunnel],
                relay_mode: RelayMode::Fallback,
                connected_at_unix: 1,
            },
            Some("203.0.113.10:50000".parse().expect("socket addr")),
        );
        state
            .mesh_peers
            .as_ref()
            .expect("mesh peer client should exist")
            .probe_health_endpoints()
            .await
            .expect("mesh probe should succeed");

        let response = discovery(
            State(state),
            MaybeAuthenticatedPeer::default(),
            Query(DiscoveryQuery {
                node_id: Some(node_id),
            }),
        )
        .await
        .expect("discovery should succeed without mTLS")
        .0;
        assert_eq!(response.rendezvous_peers.len(), 1);
        assert_eq!(
            response.rendezvous_peers[0].status,
            transport_sdk::RendezvousEndpointConnectionState::Connected
        );
        assert_eq!(
            response.node_candidates,
            Some(vec![ConnectionCandidate {
                kind: CandidateKind::ServerReflexive,
                endpoint: "https://203.0.113.10:7443".to_string(),
                rtt_ms: None,
            }])
        );
        assert!(response.node_relay_capable);

        peer_server.abort();
        let _ = peer_server.await;
    }

    /// Regression test for a zombie-queue bug: a source that abandons its `ConnectSource`
    /// websocket before pairing completes (e.g. a caller-side timeout firing before the
    /// server's own wait elapses) must not leave a stale entry in the broker's FIFO queue
    /// for a later `AcceptTarget` to falsely pair with. The abandoned connection should be
    /// noticed and cleaned up, so the target sees a clean timeout instead.
    #[tokio::test]
    async fn abandoned_source_connection_does_not_falsely_pair_with_a_later_target() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::net::TcpStream;
        use tokio_tungstenite::client_async;
        use tokio_tungstenite::tungstenite::Message;
        use uuid::Uuid;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let bind_addr = listener.local_addr().expect("listener should have an addr");
        drop(listener);

        let state = RendezvousAppState::new(RendezvousServerConfig {
            bind_addr,
            public_url: format!("http://{bind_addr}"),
            relay_public_urls: vec![format!("http://{bind_addr}")],
            peer_rendezvous_urls: Vec::new(),
            mtls: None,
        })
        .expect("test rendezvous app state should build");
        let server_handle = tokio::spawn(async move {
            serve(state)
                .await
                .expect("test rendezvous server should run");
        });

        // Wait for the listener to actually be accepting connections.
        for _ in 0..100 {
            if TcpStream::connect(bind_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let cluster_id = Uuid::now_v7();
        let source = PeerIdentity::Device(Uuid::now_v7());
        let target = PeerIdentity::Node(Uuid::now_v7());

        let ticket = issue_runtime_relay_ticket(
            RelayTicketRequest {
                cluster_id,
                source: source.clone(),
                target: target.clone(),
                session_kind: RelayTunnelSessionKind::MultiplexTransport,
                requested_expires_in_secs: Some(60),
            },
            &[format!("http://{bind_addr}")],
        );

        let ws_url = format!("ws://{bind_addr}/relay/tunnel/ws");

        // Step 1: connect as the source, send ConnectSource, then abandon the
        // connection immediately without reading the "Paired" response -- this is
        // exactly what happens when a caller-side timeout (e.g. the client's 3s
        // latency-probe budget) fires before the server-side wait resolves.
        {
            let tcp = TcpStream::connect(bind_addr)
                .await
                .expect("source TCP connect should succeed");
            let (mut ws, _response) = client_async(ws_url.as_str(), tcp)
                .await
                .expect("source websocket handshake should succeed");
            let control = RelayTunnelControlMessage::ConnectSource {
                ticket: ticket.clone(),
            };
            ws.send(Message::Text(
                serde_json::to_string(&control).expect("control message should serialize"),
            ))
            .await
            .expect("source control message should send");
            // Abandon: drop without ever reading a response.
            drop(ws);
        }

        // Give the server a moment; if it detected the abandonment, this is enough time
        // for cleanup to have happened.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;

        // Step 2: connect as the target and try to pair against the same key.
        let tcp = TcpStream::connect(bind_addr)
            .await
            .expect("target TCP connect should succeed");
        let (mut ws, _response) = client_async(ws_url.as_str(), tcp)
            .await
            .expect("target websocket handshake should succeed");
        let accept_control = RelayTunnelControlMessage::AcceptTarget {
            request: transport_sdk::RelayTunnelAcceptRequest {
                cluster_id,
                target: target.clone(),
                session_kind: RelayTunnelSessionKind::MultiplexTransport,
                wait_timeout_ms: Some(2_000),
            },
        };
        ws.send(Message::Text(
            serde_json::to_string(&accept_control).expect("control message should serialize"),
        ))
        .await
        .expect("target control message should send");

        let response = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .expect("target should receive a response within 5s")
            .expect("target websocket should not end without a response")
            .expect("target websocket read should not error");

        server_handle.abort();

        match response {
            Message::Text(text) => {
                match serde_json::from_str::<RelayTunnelControlMessage>(&text)
                    .expect("response should parse")
                {
                    RelayTunnelControlMessage::Paired { .. } => {
                        panic!(
                            "zombie-queue bug confirmed: target paired with an already-abandoned \
                             source; the real source's socket was closed ~300ms earlier and can \
                             never receive this pairing"
                        );
                    }
                    RelayTunnelControlMessage::Error { message } => {
                        assert!(
                            message.contains("timed out"),
                            "expected a clean timeout when no live source is present, got: {message}"
                        );
                    }
                    other => panic!("unexpected control message: {other:?}"),
                }
            }
            other => panic!("unexpected websocket message: {other:?}"),
        }
    }

    async fn spawn_test_rendezvous_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio::net::TcpStream;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let bind_addr = listener.local_addr().expect("listener should have an addr");
        drop(listener);

        let state = RendezvousAppState::new(RendezvousServerConfig {
            bind_addr,
            public_url: format!("http://{bind_addr}"),
            relay_public_urls: vec![format!("http://{bind_addr}")],
            peer_rendezvous_urls: Vec::new(),
            mtls: None,
        })
        .expect("test rendezvous app state should build");
        let server_handle = tokio::spawn(async move {
            serve(state)
                .await
                .expect("test rendezvous server should run");
        });

        for _ in 0..100 {
            if TcpStream::connect(bind_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        (bind_addr, server_handle)
    }

    async fn connect_and_register_wake(
        wake_url: &str,
        bind_addr: std::net::SocketAddr,
        cluster_id: ClusterId,
        target: PeerIdentity,
    ) -> tokio_tungstenite::WebSocketStream<tokio::net::TcpStream> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::client_async;
        use tokio_tungstenite::tungstenite::Message;

        let tcp = tokio::net::TcpStream::connect(bind_addr)
            .await
            .expect("wake TCP connect should succeed");
        let (mut ws, _response) = client_async(wake_url, tcp)
            .await
            .expect("wake websocket handshake should succeed");

        let registration = RelayWakeRegistration {
            cluster_id,
            target,
            session_kind: RelayTunnelSessionKind::MultiplexTransport,
        };
        ws.send(Message::Text(
            serde_json::to_string(&RelayWakeControlMessage::Register { registration })
                .expect("register message should serialize"),
        ))
        .await
        .expect("register message should send");

        let registered = tokio::time::timeout(std::time::Duration::from_secs(5), ws.next())
            .await
            .expect("should receive a registration response within 5s")
            .expect("wake websocket should not end without a response")
            .expect("wake websocket read should not error");
        match registered {
            Message::Text(text) => {
                let parsed: RelayWakeControlMessage =
                    serde_json::from_str(&text).expect("registration response should parse");
                assert!(
                    matches!(parsed, RelayWakeControlMessage::Registered),
                    "expected Registered, got {parsed:?}"
                );
            }
            other => panic!("unexpected wake websocket message: {other:?}"),
        }

        ws
    }

    async fn assert_wake_arrives(
        ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        within: std::time::Duration,
    ) {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message;

        let message = tokio::time::timeout(within, ws.next())
            .await
            .expect("should receive a wake message in time")
            .expect("wake websocket should not end before a wake arrives")
            .expect("wake websocket read should not error");
        match message {
            Message::Text(text) => {
                let parsed: RelayWakeControlMessage =
                    serde_json::from_str(&text).expect("wake message should parse");
                assert!(
                    matches!(parsed, RelayWakeControlMessage::Wake),
                    "expected Wake, got {parsed:?}"
                );
            }
            other => panic!("unexpected wake websocket message: {other:?}"),
        }
    }

    /// Demonstrates the actual point of this feature: a source registering with the
    /// broker pushes a `Wake` to an already-connected, already-registered target almost
    /// immediately, instead of the target needing to poll on a timer.
    #[tokio::test]
    async fn relay_wake_ws_pushes_wake_message_when_source_registers() {
        use futures_util::SinkExt;
        use tokio::net::TcpStream;
        use tokio_tungstenite::client_async;
        use tokio_tungstenite::tungstenite::Message;
        use uuid::Uuid;

        let (bind_addr, _server_handle) = spawn_test_rendezvous_server().await;
        let cluster_id = Uuid::now_v7();
        let source = PeerIdentity::Device(Uuid::now_v7());
        let target = PeerIdentity::Node(Uuid::now_v7());

        let wake_url = format!("ws://{bind_addr}/relay/wake/ws");
        let mut wake_ws =
            connect_and_register_wake(&wake_url, bind_addr, cluster_id, target.clone()).await;

        let ticket = issue_runtime_relay_ticket(
            RelayTicketRequest {
                cluster_id,
                source,
                target,
                session_kind: RelayTunnelSessionKind::MultiplexTransport,
                requested_expires_in_secs: Some(60),
            },
            &[format!("http://{bind_addr}")],
        );
        let tunnel_url = format!("ws://{bind_addr}/relay/tunnel/ws");
        tokio::spawn(async move {
            let tcp = TcpStream::connect(bind_addr)
                .await
                .expect("source TCP connect should succeed");
            let (mut source_ws, _response) = client_async(tunnel_url.as_str(), tcp)
                .await
                .expect("source websocket handshake should succeed");
            let control = RelayTunnelControlMessage::ConnectSource { ticket };
            let _ = source_ws
                .send(Message::Text(
                    serde_json::to_string(&control).expect("control message should serialize"),
                ))
                .await;
            // Keep the source connection open long enough for the assertion below.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        });

        assert_wake_arrives(&mut wake_ws, std::time::Duration::from_secs(3)).await;
    }

    /// The wake-channel analogue of the zombie-queue regression test: a stale
    /// registration from an abruptly-dropped connection must not prevent (or get
    /// confused with) a fresh registration for the same target after a reconnect.
    #[tokio::test]
    async fn relay_wake_ws_registration_cleanup_survives_abrupt_reconnect() {
        use futures_util::SinkExt;
        use tokio::net::TcpStream;
        use tokio_tungstenite::client_async;
        use tokio_tungstenite::tungstenite::Message;
        use uuid::Uuid;

        let (bind_addr, _server_handle) = spawn_test_rendezvous_server().await;
        let cluster_id = Uuid::now_v7();
        let target = PeerIdentity::Node(Uuid::now_v7());
        let wake_url = format!("ws://{bind_addr}/relay/wake/ws");

        let ws1 = connect_and_register_wake(&wake_url, bind_addr, cluster_id, target.clone()).await;
        // Abrupt drop, no close handshake -- simulates a network blip or process restart.
        drop(ws1);

        let mut ws2 =
            connect_and_register_wake(&wake_url, bind_addr, cluster_id, target.clone()).await;

        let source = PeerIdentity::Device(Uuid::now_v7());
        let ticket = issue_runtime_relay_ticket(
            RelayTicketRequest {
                cluster_id,
                source,
                target,
                session_kind: RelayTunnelSessionKind::MultiplexTransport,
                requested_expires_in_secs: Some(60),
            },
            &[format!("http://{bind_addr}")],
        );
        let tunnel_url = format!("ws://{bind_addr}/relay/tunnel/ws");
        tokio::spawn(async move {
            let tcp = TcpStream::connect(bind_addr)
                .await
                .expect("source TCP connect should succeed");
            let (mut source_ws, _response) = client_async(tunnel_url.as_str(), tcp)
                .await
                .expect("source websocket handshake should succeed");
            let control = RelayTunnelControlMessage::ConnectSource { ticket };
            let _ = source_ws
                .send(Message::Text(
                    serde_json::to_string(&control).expect("control message should serialize"),
                ))
                .await;
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        });

        assert_wake_arrives(&mut ws2, std::time::Duration::from_secs(3)).await;
    }
}
