mod auth;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use axum::extract::ws::{Message, WebSocket};
use axum::extract::{State, WebSocketUpgrade};
use axum::http::StatusCode;
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
    BufferedTransportRequest, ClientBootstrapClaimRedeemRequest,
    ClientBootstrapClaimRedeemResponse, MultiplexConfig, MultiplexMode, PresenceRegistry,
    RelayTicket, RelayTicketRequest, RelayTunnelBroker, RelayTunnelControlMessage,
    RelayTunnelFrame, RelayTunnelSessionKind, RelayWakeControlMessage, RelayWakeRegistration,
    TRANSPORT_PROTOCOL_VERSION, TransportHeader, TransportSessionControlMessage,
    TransportSessionRole, TransportStreamKind, WakeRegistrationHandle,
    issue_relay_ticket as issue_runtime_relay_ticket, perform_transport_client_handshake,
    read_buffered_transport_response, write_buffered_transport_request,
};

use crate::auth::{
    MaybeAuthenticatedPeer, MtlsAuthenticatedPeerAcceptor, build_mtls_rustls_config,
    ensure_authenticated_peer_identity, require_authenticated_node,
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
    let relay_router = Router::new()
        .route("/relay/tunnel/ws", get(relay_tunnel_ws))
        .route("/relay/wake/ws", get(relay_wake_ws));

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
        axum::serve(listener, app).await?;
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

    let entry = state.presence.register(request);
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
    let entries = state.presence.list();
    Ok(Json(PresenceListResponse {
        registered_endpoints: entries.len(),
        entries,
    }))
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
            mtls: None,
        });
        let server_handle = tokio::spawn(async move {
            serve(state).await.expect("test rendezvous server should run");
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
                    RelayTunnelControlMessage::Paired { session } => {
                        panic!(
                            "zombie-queue bug confirmed: target paired with an already-abandoned \
                             source (session_id={}); the real source's socket was closed ~300ms \
                             earlier and can never receive this pairing",
                            session.session_id
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
            mtls: None,
        });
        let server_handle = tokio::spawn(async move {
            serve(state).await.expect("test rendezvous server should run");
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

        let ws1 =
            connect_and_register_wake(&wake_url, bind_addr, cluster_id, target.clone()).await;
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
