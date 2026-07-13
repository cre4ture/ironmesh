mod auth;

use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::http::Uri;
use axum::http::header::CACHE_CONTROL;
use axum::routing::{get, post};
use axum::{Json, Router};
use common::{ClusterId, DeviceId};
use serde::Serialize;
use tracing::warn;
use transport_sdk::peer::PeerIdentity;
use transport_sdk::rendezvous::{
    PresenceListResponse, PresenceRegistration, RegisterPresenceResponse,
};
use transport_sdk::{
    BufferedTransportRequest, CandidateKind, ClientBootstrapClaimRedeemRequest,
    ClientBootstrapClaimRedeemResponse, ConnectionCandidate, MultiplexConfig, MultiplexMode,
    PresenceRegistry, RelayTicket, RelayTicketRequest, RelayTunnelBroker,
    RelayTunnelControlMessage, RelayTunnelFrame, RelayTunnelSessionKind,
    TRANSPORT_PROTOCOL_VERSION, TransportHeader, TransportSessionControlMessage,
    TransportSessionRole, TransportStreamKind, issue_relay_ticket as issue_runtime_relay_ticket,
    perform_transport_client_handshake, rank_candidates, read_buffered_transport_response,
    write_buffered_transport_request,
};

use crate::auth::{
    MaybeAuthenticatedPeer, MaybeObservedPeerAddr, MtlsAuthenticatedPeerAcceptor,
    build_mtls_rustls_config, ensure_authenticated_peer_identity, require_authenticated_node,
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
    pub mtls: Option<RendezvousMtlsConfig>,
}

#[derive(Clone)]
pub struct RendezvousAppState {
    pub config: RendezvousServerConfig,
    pub presence: PresenceRegistry,
    pub relay_tunnel: RelayTunnelBroker,
}

impl RendezvousAppState {
    pub fn new(config: RendezvousServerConfig) -> Self {
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
    software_version: &'static str,
}

pub fn build_router(state: RendezvousAppState) -> Router {
    let relay_router = Router::new().route("/relay/tunnel/ws", get(relay_tunnel_ws));

    Router::new()
        .route("/health", get(health))
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
    require_authenticated_node(state.config.mtls.is_some(), &authenticated_peer)
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
            mtls: None,
        });
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
}
