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
use common::DeviceId;
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
    RelayTunnelFrame, RelayTunnelSessionKind, TRANSPORT_PROTOCOL_VERSION, TransportHeader,
    TransportSessionControlMessage, TransportSessionRole, TransportStreamKind,
    issue_relay_ticket as issue_runtime_relay_ticket, perform_transport_client_handshake,
    read_buffered_transport_response, write_buffered_transport_request,
};

use crate::auth::{
    MaybeAuthenticatedPeer, MtlsAuthenticatedPeerAcceptor, build_mtls_rustls_config,
    ensure_authenticated_peer_identity, require_authenticated_node,
};

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
    File {
        cert_path: PathBuf,
    },
    InlinePem {
        cert_pem: String,
    },
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
        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn health(State(state): State<RendezvousAppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        public_url: state.config.public_url,
        registered_endpoints: state.presence.len(),
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
    if let Err(err) = run_relay_tunnel_websocket(&state, &authenticated_peer, &mut socket).await {
        if transport_sdk::is_expected_idle_relay_tunnel_accept_timeout(&err.to_string()) {
            tracing::debug!(
                error = %err,
                "relay tunnel websocket closed after idle target wait"
            );
        } else {
            warn!(error = %err, "relay tunnel websocket failed");
        }
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
    state: &RendezvousAppState,
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
