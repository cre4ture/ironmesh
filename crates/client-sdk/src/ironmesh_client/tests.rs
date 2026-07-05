use super::*;
use axum::{
    Json, Router,
    body::Body,
    extract::{
        Path as AxumPath, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    http::{Response, header},
    response::IntoResponse,
    routing::{get, post, put},
};
use futures_util::{Sink, Stream, StreamExt};
use std::pin::Pin;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use tokio::sync::Mutex;
use transport_sdk::{
    BufferedTransportResponse as MultiplexBufferedTransportResponse, DecodedWebSocketMessage,
    MultiplexConfig, MultiplexMode, MultiplexedSession, RelayHttpHeader, RelayTicket,
    RelayTicketRequest, RelayTunnelControlMessage, RelayTunnelSession, RelayTunnelSessionKind,
    RendezvousClientConfig, RendezvousControlClient, TRANSPORT_PROTOCOL_VERSION, TransportHeader,
    TransportResponseHead, TransportSessionControlMessage, TransportSessionRole,
    TransportStreamKind, WebSocketByteStream, WebSocketMessageCodec,
    perform_transport_server_handshake, read_buffered_transport_request,
    write_buffered_transport_response, write_transport_response_head,
};

#[test]
fn object_url_builder_escapes_segments() {
    let client = IronMeshClient::from_direct_base_url("http://127.0.0.1:18080/");
    let url = client
        .store_key_url("read me.txt")
        .expect("object url should build");
    assert_eq!(
        url.as_str(),
        "http://127.0.0.1:18080/api/v1/store/read%20me.txt"
    );
}

#[test]
fn normalize_client_api_path_prefixes_known_public_routes() {
    assert_eq!(
        normalize_client_api_path("/cluster/status").as_ref(),
        "/api/v1/cluster/status"
    );
    assert_eq!(
        normalize_client_api_path("/api/v1/cluster/status").as_ref(),
        "/api/v1/cluster/status"
    );
    assert_eq!(
        normalize_client_api_path("/media/thumbnail?key=gallery%2Fcat.png").as_ref(),
        "/api/v1/media/thumbnail?key=gallery%2Fcat.png"
    );
}

#[test]
fn normalize_connection_name_preserves_readable_role_segments() {
    assert_eq!(
        normalize_connection_name(" Windows Cfapi / Upload Worker #1 ").as_deref(),
        Some("windows-cfapi-/-upload-worker-1")
    );
    assert_eq!(normalize_connection_name("   "), None);
}

#[test]
fn transport_stream_kind_classification_accepts_versioned_public_routes() {
    assert_eq!(
        transport_stream_kind_for_path("/api/v1/health"),
        TransportStreamKind::Diagnostics
    );
    assert_eq!(
        transport_stream_kind_for_path("/api/v1/diagnostics/latency"),
        TransportStreamKind::Diagnostics
    );
    assert_eq!(
        transport_stream_kind_for_path("/api/v1/cluster/status"),
        TransportStreamKind::Rpc
    );
}

#[test]
fn normalize_server_base_url_adds_scheme_and_trailing_slash() {
    let normalized = normalize_server_base_url("127.0.0.1:18080").expect("url should be valid");
    assert_eq!(normalized.as_str(), "http://127.0.0.1:18080/");
}

#[test]
fn snapshot_conversion_maps_prefix_and_keys() {
    let snapshot = snapshot_from_store_index_entries(vec![
        StoreIndexEntry {
            path: "docs/".to_string(),
            entry_type: "prefix".to_string(),
            version: None,
            content_hash: None,
            size_bytes: None,
            modified_at_unix: None,
            content_fingerprint: None,
            media: None,
        },
        StoreIndexEntry {
            path: "docs/readme.txt".to_string(),
            entry_type: "key".to_string(),
            version: None,
            content_hash: None,
            size_bytes: Some(42),
            modified_at_unix: None,
            content_fingerprint: Some("cfp-readme".to_string()),
            media: None,
        },
    ]);

    assert_eq!(snapshot.local.len(), 0);
    assert_eq!(snapshot.remote.len(), 2);
    assert_eq!(snapshot.remote[0], NamespaceEntry::directory("docs"));
    assert_eq!(snapshot.remote[1].path, "docs/readme.txt");
    assert_eq!(snapshot.remote[1].version.as_deref(), Some("server-head"));
    assert_eq!(
        snapshot.remote[1].content_hash.as_deref(),
        Some("server-head:docs/readme.txt")
    );
    assert_eq!(
        snapshot.remote[1].content_fingerprint.as_deref(),
        Some("cfp-readme")
    );
    assert_eq!(snapshot.remote[1].size_bytes, Some(42));
}

#[test]
fn ensure_missing_folder_markers_adds_nested_parents() {
    let mut entries = vec![StoreIndexEntry {
        path: "a/b/c.txt".to_string(),
        entry_type: "key".to_string(),
        version: None,
        content_hash: None,
        size_bytes: Some(7),
        modified_at_unix: None,
        content_fingerprint: None,
        media: None,
    }];

    ensure_missing_folder_markers(&mut entries);

    let paths = entries
        .into_iter()
        .map(|entry| entry.path)
        .collect::<Vec<_>>();
    assert_eq!(paths, vec!["a/", "a/b/", "a/b/c.txt"]);
}

#[test]
fn ensure_missing_folder_markers_keeps_existing_markers_unique() {
    let mut entries = vec![
        StoreIndexEntry {
            path: "docs/".to_string(),
            entry_type: "prefix".to_string(),
            version: None,
            content_hash: None,
            size_bytes: None,
            modified_at_unix: None,
            content_fingerprint: None,
            media: None,
        },
        StoreIndexEntry {
            path: "docs/guides/readme.md".to_string(),
            entry_type: "key".to_string(),
            version: None,
            content_hash: None,
            size_bytes: Some(11),
            modified_at_unix: None,
            content_fingerprint: None,
            media: None,
        },
    ];

    ensure_missing_folder_markers(&mut entries);

    let paths = entries
        .into_iter()
        .map(|entry| entry.path)
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        vec!["docs/", "docs/guides/", "docs/guides/readme.md"]
    );
}

#[test]
fn place_downloaded_file_creates_missing_target_directory() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "ironmesh-place-downloaded-file-test-{}-{}",
        std::process::id(),
        nonce
    ));
    let source_dir = root.join("source");
    let target_dir = root.join("target").join("nested");
    fs::create_dir_all(&source_dir).unwrap();
    let temp_path = source_dir.join("download.part");
    let target_path = target_dir.join("download.bin");
    fs::write(&temp_path, b"hello").unwrap();

    place_downloaded_file(&temp_path, &target_path).unwrap();

    assert_eq!(fs::read(&target_path).unwrap(), b"hello");
    assert!(!temp_path.exists());

    fs::remove_dir_all(root).unwrap();
}

#[test]
fn delete_url_builder_builds_expected_path() {
    let client = IronMeshClient::from_direct_base_url("http://127.0.0.1:18080/");
    let url = client.store_delete_url().expect("delete url should build");
    assert_eq!(url.as_str(), "http://127.0.0.1:18080/api/v1/store/delete");
}

#[test]
fn versions_url_builder_builds_expected_path() {
    let client = IronMeshClient::from_direct_base_url("http://127.0.0.1:18080/");
    let url = client.store_versions_url("docs/readme.txt").unwrap();
    assert_eq!(
        url.as_str(),
        "http://127.0.0.1:18080/api/v1/versions/docs%2Freadme.txt"
    );
}

#[tokio::test]
async fn list_versions_parses_version_graph_summary() {
    async fn versions(
        axum::extract::Path(key): axum::extract::Path<String>,
    ) -> axum::Json<VersionGraphSummary> {
        axum::Json(VersionGraphSummary {
            key,
            object_id: "obj-123".to_string(),
            preferred_head_version_id: Some("v2".to_string()),
            preferred_head_reason: Some(PreferredHeadReason::DeterministicTiebreakVersionId),
            head_version_ids: vec!["v2".to_string()],
            versions: vec![VersionRecordSummary {
                version_id: "v2".to_string(),
                logical_path: Some("docs/readme.txt".to_string()),
                parent_version_ids: vec!["v1".to_string()],
                state: VersionConsistencyState::Confirmed,
                created_at_unix: 123,
                copied_from_object_id: None,
                copied_from_version_id: None,
                copied_from_path: None,
            }],
        })
    }

    let app = axum::Router::new().route("/api/v1/versions/{key}", axum::routing::get(versions));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener should have addr");
    let server = axum::serve(listener, app.into_make_service());
    let handle = tokio::spawn(async move {
        let _ = server.await;
    });

    let client = IronMeshClient::from_direct_base_url(format!("http://{addr}"));
    let versions = client
        .list_versions("docs/readme.txt")
        .await
        .expect("versions should parse")
        .expect("versions should exist");

    assert_eq!(versions.object_id, "obj-123");
    assert_eq!(versions.preferred_head_version_id.as_deref(), Some("v2"));
    assert_eq!(versions.versions.len(), 1);
    assert_eq!(versions.versions[0].version_id, "v2");

    handle.abort();
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RelayTestCapturedRequest {
    kind: Option<TransportStreamKind>,
    method: String,
    path_and_query: String,
    headers: Vec<RelayHttpHeader>,
    body: Vec<u8>,
}

#[derive(Debug, Clone)]
struct DirectHttpRouteState {
    cluster_status_hits: Arc<AtomicUsize>,
    health_hits: Arc<AtomicUsize>,
    response_delay_ms: u64,
    name: String,
}

async fn spawn_direct_http_route_server_at(
    bind_addr: std::net::SocketAddr,
    response_delay_ms: u64,
    name: &str,
) -> (String, DirectHttpRouteState, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener should have addr");
    let state = DirectHttpRouteState {
        cluster_status_hits: Arc::new(AtomicUsize::new(0)),
        health_hits: Arc::new(AtomicUsize::new(0)),
        response_delay_ms,
        name: name.to_string(),
    };
    let router = Router::new()
        .route(
            "/api/v1/cluster/status",
            get(|State(state): State<DirectHttpRouteState>| async move {
                state.cluster_status_hits.fetch_add(1, Ordering::SeqCst);
                if state.response_delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(state.response_delay_ms)).await;
                }
                Json(serde_json::json!({
                    "status": "ok",
                    "route": state.name,
                }))
            }),
        )
        .route(
            "/api/v1/health",
            get(|State(state): State<DirectHttpRouteState>| async move {
                state.health_hits.fetch_add(1, Ordering::SeqCst);
                if state.response_delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(state.response_delay_ms)).await;
                }
                StatusCode::OK
            }),
        )
        .with_state(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("direct http route server should run");
    });
    (format!("http://{addr}"), state, server)
}

async fn spawn_direct_http_route_server(
    response_delay_ms: u64,
    name: &str,
) -> (String, DirectHttpRouteState, tokio::task::JoinHandle<()>) {
    spawn_direct_http_route_server_at(
        "127.0.0.1:0".parse().expect("bind addr should parse"),
        response_delay_ms,
        name,
    )
    .await
}

#[derive(Clone, Default)]
struct UploadSessionHttpSharedState {
    sessions: Arc<Mutex<std::collections::HashMap<String, UploadSessionView>>>,
}

#[derive(Clone)]
struct UploadSessionHttpServerState {
    shared: UploadSessionHttpSharedState,
    start_hits: Arc<AtomicUsize>,
    chunk_hits: Arc<AtomicUsize>,
    complete_hits: Arc<AtomicUsize>,
}

async fn upload_session_http_start(
    State(state): State<UploadSessionHttpServerState>,
    Json(request): Json<UploadSessionStartRequest>,
) -> impl IntoResponse {
    state.start_hits.fetch_add(1, Ordering::SeqCst);
    let chunk_size_bytes = CHUNK_UPLOAD_SIZE_BYTES;
    let chunk_count = if request.total_size_bytes == 0 {
        1
    } else {
        ((request.total_size_bytes - 1) / chunk_size_bytes as u64 + 1) as usize
    };
    let view = UploadSessionView {
        upload_id: format!("upload-{}", uuid::Uuid::now_v7()),
        key: request.key,
        total_size_bytes: request.total_size_bytes,
        chunk_size_bytes,
        chunk_count,
        received_indexes: Vec::new(),
        completed: false,
        completed_result: None,
        expires_at_unix: unix_ts().saturating_add(60),
    };
    state
        .shared
        .sessions
        .lock()
        .await
        .insert(view.upload_id.clone(), view.clone());
    (StatusCode::CREATED, Json(view)).into_response()
}

async fn upload_session_http_get(
    State(state): State<UploadSessionHttpServerState>,
    AxumPath(upload_id): AxumPath<String>,
) -> impl IntoResponse {
    let sessions = state.shared.sessions.lock().await;
    let Some(session) = sessions.get(&upload_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    Json(session.clone()).into_response()
}

async fn upload_session_http_chunk(
    State(state): State<UploadSessionHttpServerState>,
    AxumPath((upload_id, index)): AxumPath<(String, usize)>,
    _payload: Bytes,
) -> impl IntoResponse {
    let mut sessions = state.shared.sessions.lock().await;
    let Some(session) = sessions.get_mut(&upload_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    state.chunk_hits.fetch_add(1, Ordering::SeqCst);
    if !session.received_indexes.contains(&index) {
        session.received_indexes.push(index);
        session.received_indexes.sort_unstable();
    }

    (
        StatusCode::OK,
        Json(UploadSessionChunkResponse {
            stored: true,
            received_index: index,
        }),
    )
        .into_response()
}

async fn upload_session_http_complete(
    State(state): State<UploadSessionHttpServerState>,
    AxumPath(upload_id): AxumPath<String>,
) -> impl IntoResponse {
    let mut sessions = state.shared.sessions.lock().await;
    let Some(session) = sessions.get_mut(&upload_id) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    state.complete_hits.fetch_add(1, Ordering::SeqCst);
    session.completed = true;
    let response = UploadSessionCompleteResponse {
        snapshot_id: "snap-test".to_string(),
        version_id: "ver-test".to_string(),
        manifest_hash: "manifest-test".to_string(),
        state: "confirmed".to_string(),
        new_chunks: session.received_indexes.len(),
        dedup_reused_chunks: 0,
        created_new_version: true,
        total_size_bytes: session.total_size_bytes,
    };
    session.completed_result = Some(response.clone());
    (StatusCode::OK, Json(response)).into_response()
}

async fn spawn_upload_session_http_server(
    bind_addr: std::net::SocketAddr,
    shared: UploadSessionHttpSharedState,
) -> (
    String,
    UploadSessionHttpServerState,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener addr");
    let state = UploadSessionHttpServerState {
        shared,
        start_hits: Arc::new(AtomicUsize::new(0)),
        chunk_hits: Arc::new(AtomicUsize::new(0)),
        complete_hits: Arc::new(AtomicUsize::new(0)),
    };
    let router = Router::new()
        .route(
            "/api/v1/store/uploads/start",
            post(upload_session_http_start),
        )
        .route(
            "/api/v1/store/uploads/{upload_id}",
            get(upload_session_http_get),
        )
        .route(
            "/api/v1/store/uploads/{upload_id}/chunk/{index}",
            put(upload_session_http_chunk),
        )
        .route(
            "/api/v1/store/uploads/{upload_id}/complete",
            post(upload_session_http_complete),
        )
        .with_state(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("upload session http server should run");
    });
    (format!("http://{addr}"), state, server)
}

#[derive(Clone)]
struct RelayTestState {
    public_url: String,
    captured_request: Arc<Mutex<Option<RelayTestCapturedRequest>>>,
    health_hits: Arc<AtomicUsize>,
    issued_ticket_count: Arc<AtomicUsize>,
    paired_session_count: Arc<AtomicUsize>,
    object_write_failures_remaining: Arc<AtomicUsize>,
    response_delay_ms: u64,
    response_status: u16,
    response_headers: Vec<RelayHttpHeader>,
    response_body: Vec<u8>,
}

async fn issue_ticket(
    State(state): State<RelayTestState>,
    Json(request): Json<RelayTicketRequest>,
) -> Json<RelayTicket> {
    state.issued_ticket_count.fetch_add(1, Ordering::SeqCst);
    Json(RelayTicket {
        cluster_id: request.cluster_id,
        session_id: format!("relay-session-{}", uuid::Uuid::now_v7()),
        source: request.source,
        target: request.target,
        session_kind: request.session_kind,
        relay_urls: vec![state.public_url],
        issued_at_unix: 1,
        expires_at_unix: 61,
    })
}

async fn relay_tunnel_ws(
    State(state): State<RelayTestState>,
    websocket: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    websocket.on_upgrade(move |socket| async move {
        serve_relay_tunnel_test_socket(state, socket).await;
    })
}

async fn direct_transport_ws(
    State(state): State<RelayTestState>,
    websocket: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    websocket.on_upgrade(move |socket| async move {
        state.paired_session_count.fetch_add(1, Ordering::SeqCst);
        serve_test_multiplex_socket(
            state,
            socket,
            format!("direct-session-{}", uuid::Uuid::now_v7()),
        )
        .await;
    })
}

#[derive(Clone)]
struct RelayMixedWorkloadState {
    public_url: String,
    payload: Arc<Vec<u8>>,
    issued_ticket_count: Arc<AtomicUsize>,
    paired_session_count: Arc<AtomicUsize>,
}

async fn issue_mixed_workload_ticket(
    State(state): State<RelayMixedWorkloadState>,
    Json(request): Json<RelayTicketRequest>,
) -> Json<RelayTicket> {
    state.issued_ticket_count.fetch_add(1, Ordering::SeqCst);
    Json(RelayTicket {
        cluster_id: request.cluster_id,
        session_id: format!("relay-mixed-session-{}", uuid::Uuid::now_v7()),
        source: request.source,
        target: request.target,
        session_kind: request.session_kind,
        relay_urls: vec![state.public_url],
        issued_at_unix: 1,
        expires_at_unix: 61,
    })
}

async fn relay_mixed_workload_tunnel_ws(
    State(state): State<RelayMixedWorkloadState>,
    websocket: WebSocketUpgrade,
) -> impl axum::response::IntoResponse {
    websocket.on_upgrade(move |mut socket| async move {
        let initial = match socket.recv().await {
            Some(Ok(Message::Text(text))) => text,
            _ => return,
        };
        let RelayTunnelControlMessage::ConnectSource { ticket } =
            serde_json::from_str(&initial).expect("mixed workload relay control should parse")
        else {
            return;
        };

        let session = RelayTunnelSession {
            cluster_id: ticket.cluster_id,
            session_id: ticket.session_id.clone(),
            source: ticket.source.clone(),
            target: ticket.target.clone(),
            session_kind: ticket.session_kind,
        };
        socket
            .send(Message::Text(
                serde_json::to_string(&RelayTunnelControlMessage::Paired { session })
                    .expect("mixed workload paired control should serialize")
                    .into(),
            ))
            .await
            .expect("mixed workload paired response should send");

        state.paired_session_count.fetch_add(1, Ordering::SeqCst);
        assert_eq!(
            ticket.session_kind,
            RelayTunnelSessionKind::MultiplexTransport
        );
        serve_mixed_workload_transport_socket(
            socket,
            Arc::clone(&state.payload),
            ticket.session_id,
        )
        .await;
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RelayTestWsMessage {
    Binary(Vec<u8>),
    Text(String),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close,
}

impl WebSocketMessageCodec for RelayTestWsMessage {
    fn decode(self) -> std::io::Result<DecodedWebSocketMessage> {
        Ok(match self {
            Self::Binary(bytes) => DecodedWebSocketMessage::Binary(bytes),
            Self::Text(_) => DecodedWebSocketMessage::Ignore,
            Self::Ping(payload) => DecodedWebSocketMessage::Ping(payload),
            Self::Pong(_) => DecodedWebSocketMessage::Pong,
            Self::Close => DecodedWebSocketMessage::Close,
        })
    }

    fn binary(bytes: Vec<u8>) -> Self {
        Self::Binary(bytes)
    }

    fn pong(bytes: Vec<u8>) -> Self {
        Self::Pong(bytes)
    }
}

struct RelayTestSocketAdapter {
    socket: WebSocket,
}

impl Stream for RelayTestSocketAdapter {
    type Item = Result<RelayTestWsMessage, axum::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.socket).poll_next(cx) {
            Poll::Ready(Some(Ok(Message::Binary(bytes)))) => {
                Poll::Ready(Some(Ok(RelayTestWsMessage::Binary(bytes.to_vec()))))
            }
            Poll::Ready(Some(Ok(Message::Text(text)))) => {
                Poll::Ready(Some(Ok(RelayTestWsMessage::Text(text.to_string()))))
            }
            Poll::Ready(Some(Ok(Message::Ping(payload)))) => {
                Poll::Ready(Some(Ok(RelayTestWsMessage::Ping(payload.to_vec()))))
            }
            Poll::Ready(Some(Ok(Message::Pong(payload)))) => {
                Poll::Ready(Some(Ok(RelayTestWsMessage::Pong(payload.to_vec()))))
            }
            Poll::Ready(Some(Ok(Message::Close(_)))) => {
                Poll::Ready(Some(Ok(RelayTestWsMessage::Close)))
            }
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(err))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Sink<RelayTestWsMessage> for RelayTestSocketAdapter {
    type Error = axum::Error;

    fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().socket).poll_ready(cx)
    }

    fn start_send(self: Pin<&mut Self>, item: RelayTestWsMessage) -> Result<(), Self::Error> {
        let message = match item {
            RelayTestWsMessage::Binary(bytes) => Message::Binary(bytes.into()),
            RelayTestWsMessage::Text(text) => Message::Text(text.into()),
            RelayTestWsMessage::Ping(payload) => Message::Ping(payload.into()),
            RelayTestWsMessage::Pong(payload) => Message::Pong(payload.into()),
            RelayTestWsMessage::Close => Message::Close(None),
        };
        Pin::new(&mut self.get_mut().socket).start_send(message)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().socket).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.get_mut().socket).poll_close(cx)
    }
}

async fn serve_relay_tunnel_test_socket(state: RelayTestState, mut socket: WebSocket) {
    let initial = match socket.recv().await {
        Some(Ok(Message::Text(text))) => text,
        _ => return,
    };
    let RelayTunnelControlMessage::ConnectSource { ticket } =
        serde_json::from_str(&initial).expect("test relay tunnel control should parse")
    else {
        return;
    };

    let session = RelayTunnelSession {
        cluster_id: ticket.cluster_id,
        session_id: ticket.session_id.clone(),
        source: ticket.source.clone(),
        target: ticket.target.clone(),
        session_kind: ticket.session_kind,
    };
    socket
        .send(Message::Text(
            serde_json::to_string(&RelayTunnelControlMessage::Paired { session })
                .expect("paired control should serialize")
                .into(),
        ))
        .await
        .expect("paired response should send");

    state.paired_session_count.fetch_add(1, Ordering::SeqCst);
    assert_eq!(
        ticket.session_kind,
        RelayTunnelSessionKind::MultiplexTransport
    );
    serve_relay_multiplex_test_socket(state, socket, ticket).await;
}

async fn serve_test_multiplex_socket(state: RelayTestState, socket: WebSocket, session_id: String) {
    let transport = WebSocketByteStream::new(RelayTestSocketAdapter { socket });
    let mut session =
        MultiplexedSession::spawn(transport, MultiplexMode::Server, MultiplexConfig::default())
            .expect("multiplexed relay test session should spawn");

    let hello = perform_transport_server_handshake(
        &mut session,
        TransportSessionControlMessage::Ready {
            protocol_version: TRANSPORT_PROTOCOL_VERSION,
            session_id,
            max_concurrent_streams: MultiplexConfig::default().max_num_streams,
        },
    )
    .await
    .expect("multiplexed relay test handshake should succeed");
    assert!(matches!(
        hello,
        TransportSessionControlMessage::Hello {
            role: TransportSessionRole::Client,
            ..
        }
    ));

    while let Some(mut stream) = session
        .accept_stream()
        .await
        .expect("multiplexed relay test stream accept should succeed")
    {
        let request = read_buffered_transport_request(&mut stream)
            .await
            .expect("multiplexed relay test request should decode");
        if request.path == "/api/v1/health" {
            state.health_hits.fetch_add(1, Ordering::SeqCst);
        }
        *state.captured_request.lock().await = Some(RelayTestCapturedRequest {
            kind: Some(request.kind),
            method: request.method.clone(),
            path_and_query: request.path.clone(),
            headers: request
                .headers
                .iter()
                .map(|header| RelayHttpHeader {
                    name: header.name.clone(),
                    value: header.value.clone(),
                })
                .collect(),
            body: request.body.clone(),
        });

        let fail_object_write = request.kind == TransportStreamKind::ObjectWrite
            && state
                .object_write_failures_remaining
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok();
        if fail_object_write {
            return;
        }

        if state.response_delay_ms > 0 {
            tokio::time::sleep(Duration::from_millis(state.response_delay_ms)).await;
        }

        write_buffered_transport_response(
            &mut stream,
            &MultiplexBufferedTransportResponse {
                request_id: request.request_id,
                status: state.response_status,
                headers: state
                    .response_headers
                    .iter()
                    .map(|header| TransportHeader {
                        name: header.name.clone(),
                        value: header.value.clone(),
                    })
                    .collect(),
                body: state.response_body.clone(),
            },
        )
        .await
        .expect("multiplexed relay test response should write");
    }
}

async fn serve_relay_multiplex_test_socket(
    state: RelayTestState,
    socket: WebSocket,
    ticket: RelayTicket,
) {
    serve_test_multiplex_socket(state, socket, ticket.session_id).await;
}

async fn spawn_relay_test_server(
    response_status: u16,
    response_headers: Vec<RelayHttpHeader>,
    response_body: Vec<u8>,
) -> (RelayTestState, tokio::task::JoinHandle<()>) {
    spawn_relay_test_server_with_object_write_failures(
        response_status,
        response_headers,
        response_body,
        0,
    )
    .await
}

async fn spawn_relay_test_server_with_object_write_failures(
    response_status: u16,
    response_headers: Vec<RelayHttpHeader>,
    response_body: Vec<u8>,
    object_write_failures_remaining: usize,
) -> (RelayTestState, tokio::task::JoinHandle<()>) {
    spawn_relay_test_server_with_delay_and_object_write_failures(
        response_status,
        response_headers,
        response_body,
        0,
        object_write_failures_remaining,
    )
    .await
}

async fn spawn_relay_test_server_with_delay(
    response_status: u16,
    response_headers: Vec<RelayHttpHeader>,
    response_body: Vec<u8>,
    response_delay_ms: u64,
) -> (RelayTestState, tokio::task::JoinHandle<()>) {
    spawn_relay_test_server_with_delay_and_object_write_failures(
        response_status,
        response_headers,
        response_body,
        response_delay_ms,
        0,
    )
    .await
}

async fn spawn_relay_test_server_with_delay_and_object_write_failures(
    response_status: u16,
    response_headers: Vec<RelayHttpHeader>,
    response_body: Vec<u8>,
    response_delay_ms: u64,
    object_write_failures_remaining: usize,
) -> (RelayTestState, tokio::task::JoinHandle<()>) {
    spawn_relay_test_server_at(
        "127.0.0.1:0".parse().expect("bind addr should parse"),
        response_status,
        response_headers,
        response_body,
        response_delay_ms,
        object_write_failures_remaining,
    )
    .await
}

async fn spawn_relay_test_server_at(
    bind_addr: std::net::SocketAddr,
    response_status: u16,
    response_headers: Vec<RelayHttpHeader>,
    response_body: Vec<u8>,
    response_delay_ms: u64,
    object_write_failures_remaining: usize,
) -> (RelayTestState, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener addr");
    let state = RelayTestState {
        public_url: format!("http://{addr}"),
        captured_request: Arc::new(Mutex::new(None)),
        health_hits: Arc::new(AtomicUsize::new(0)),
        issued_ticket_count: Arc::new(AtomicUsize::new(0)),
        paired_session_count: Arc::new(AtomicUsize::new(0)),
        object_write_failures_remaining: Arc::new(AtomicUsize::new(
            object_write_failures_remaining,
        )),
        response_delay_ms,
        response_status,
        response_headers,
        response_body,
    };
    let router = Router::new()
        .route("/control/relay/ticket", post(issue_ticket))
        .route("/relay/tunnel/ws", get(relay_tunnel_ws))
        .with_state(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("relay test server should run");
    });
    (state, server)
}

async fn spawn_direct_transport_test_server(
    response_status: u16,
    response_headers: Vec<RelayHttpHeader>,
    response_body: Vec<u8>,
) -> (RelayTestState, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener addr");
    let state = RelayTestState {
        public_url: format!("http://{addr}"),
        captured_request: Arc::new(Mutex::new(None)),
        health_hits: Arc::new(AtomicUsize::new(0)),
        issued_ticket_count: Arc::new(AtomicUsize::new(0)),
        paired_session_count: Arc::new(AtomicUsize::new(0)),
        object_write_failures_remaining: Arc::new(AtomicUsize::new(0)),
        response_delay_ms: 0,
        response_status,
        response_headers,
        response_body,
    };
    let router = Router::new()
        .route("/transport/ws", get(direct_transport_ws))
        .with_state(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("direct transport test server should run");
    });
    (state, server)
}

async fn serve_mixed_workload_transport_socket(
    socket: WebSocket,
    payload: Arc<Vec<u8>>,
    session_id: String,
) {
    let transport = WebSocketByteStream::new(RelayTestSocketAdapter { socket });
    let mut session =
        MultiplexedSession::spawn(transport, MultiplexMode::Server, MultiplexConfig::default())
            .expect("mixed workload session should spawn");
    let hello = perform_transport_server_handshake(
        &mut session,
        TransportSessionControlMessage::Ready {
            protocol_version: TRANSPORT_PROTOCOL_VERSION,
            session_id,
            max_concurrent_streams: MultiplexConfig::default().max_num_streams,
        },
    )
    .await
    .expect("mixed workload handshake should succeed");
    assert!(matches!(
        hello,
        TransportSessionControlMessage::Hello {
            role: TransportSessionRole::Client,
            ..
        }
    ));

    while let Some(mut stream) = session
        .accept_stream()
        .await
        .expect("mixed workload stream accept should succeed")
    {
        let payload = Arc::clone(&payload);
        tokio::spawn(async move {
            let request = read_buffered_transport_request(&mut stream)
                .await
                .expect("mixed workload request should decode");

            match (request.kind, request.method.as_str(), request.path.as_str()) {
                (TransportStreamKind::Rpc, "HEAD", "/api/v1/store/large.bin") => {
                    write_buffered_transport_response(
                        &mut stream,
                        &MultiplexBufferedTransportResponse {
                            request_id: request.request_id,
                            status: StatusCode::OK.as_u16(),
                            headers: vec![
                                TransportHeader {
                                    name: ACCEPT_RANGES.as_str().to_string(),
                                    value: "bytes".to_string(),
                                },
                                TransportHeader {
                                    name: CONTENT_LENGTH.as_str().to_string(),
                                    value: payload.len().to_string(),
                                },
                                TransportHeader {
                                    name: ETAG.as_str().to_string(),
                                    value: "\"mixed-etag\"".to_string(),
                                },
                                TransportHeader {
                                    name: "x-ironmesh-object-size".to_string(),
                                    value: payload.len().to_string(),
                                },
                            ],
                            body: Vec::new(),
                        },
                    )
                    .await
                    .expect("mixed workload HEAD response should write");
                }
                (TransportStreamKind::ObjectRead, "GET", "/api/v1/store/large.bin") => {
                    let range = request
                        .headers
                        .iter()
                        .find(|header| header.name.eq_ignore_ascii_case("range"))
                        .map(|header| header.value.clone())
                        .expect("range header should be present");
                    let (start, end_inclusive) = parse_range_header(&range, payload.len());
                    let selected = &payload[start..=end_inclusive];
                    write_transport_response_head(
                        &mut stream,
                        &TransportResponseHead {
                            request_id: request.request_id,
                            status: StatusCode::PARTIAL_CONTENT.as_u16(),
                            headers: vec![
                                TransportHeader {
                                    name: ACCEPT_RANGES.as_str().to_string(),
                                    value: "bytes".to_string(),
                                },
                                TransportHeader {
                                    name: CONTENT_LENGTH.as_str().to_string(),
                                    value: selected.len().to_string(),
                                },
                                TransportHeader {
                                    name: CONTENT_RANGE.as_str().to_string(),
                                    value: format!(
                                        "bytes {start}-{end_inclusive}/{}",
                                        payload.len()
                                    ),
                                },
                                TransportHeader {
                                    name: ETAG.as_str().to_string(),
                                    value: "\"mixed-etag\"".to_string(),
                                },
                                TransportHeader {
                                    name: "x-ironmesh-object-size".to_string(),
                                    value: payload.len().to_string(),
                                },
                            ],
                        },
                    )
                    .await
                    .expect("mixed workload object-read head should write");

                    for chunk in selected.chunks(16 * 1024) {
                        stream
                            .write_all(chunk)
                            .await
                            .expect("mixed workload object-read body should write");
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    stream
                        .close()
                        .await
                        .expect("mixed workload object-read stream should close");
                }
                (
                    TransportStreamKind::ObjectRead,
                    "GET",
                    "/s3/photos.example/docs/streamed.txt",
                ) => {
                    write_transport_response_head(
                        &mut stream,
                        &TransportResponseHead {
                            request_id: request.request_id,
                            status: StatusCode::OK.as_u16(),
                            headers: vec![
                                TransportHeader {
                                    name: CONTENT_LENGTH.as_str().to_string(),
                                    value: payload.len().to_string(),
                                },
                                TransportHeader {
                                    name: ETAG.as_str().to_string(),
                                    value: "\"s3-streamed-etag\"".to_string(),
                                },
                                TransportHeader {
                                    name: "content-type".to_string(),
                                    value: "application/octet-stream".to_string(),
                                },
                            ],
                        },
                    )
                    .await
                    .expect("mixed workload S3 object-read head should write");

                    for chunk in payload.chunks(16 * 1024) {
                        stream
                            .write_all(chunk)
                            .await
                            .expect("mixed workload S3 object-read body should write");
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                    stream
                        .close()
                        .await
                        .expect("mixed workload S3 object-read stream should close");
                }
                (TransportStreamKind::Rpc, "GET", "/api/v1/cluster/status") => {
                    write_buffered_transport_response(
                        &mut stream,
                        &MultiplexBufferedTransportResponse {
                            request_id: request.request_id,
                            status: StatusCode::OK.as_u16(),
                            headers: vec![
                                TransportHeader {
                                    name: "content-type".to_string(),
                                    value: "application/json".to_string(),
                                },
                                TransportHeader {
                                    name: "content-length".to_string(),
                                    value: br#"{"status":"ok"}"#.len().to_string(),
                                },
                            ],
                            body: br#"{"status":"ok"}"#.to_vec(),
                        },
                    )
                    .await
                    .expect("mixed workload RPC response should write");
                }
                _ => {
                    write_buffered_transport_response(
                        &mut stream,
                        &MultiplexBufferedTransportResponse {
                            request_id: request.request_id,
                            status: StatusCode::BAD_REQUEST.as_u16(),
                            headers: vec![
                                TransportHeader {
                                    name: "content-type".to_string(),
                                    value: "text/plain; charset=utf-8".to_string(),
                                },
                                TransportHeader {
                                    name: "content-length".to_string(),
                                    value: b"unsupported".len().to_string(),
                                },
                            ],
                            body: b"unsupported".to_vec(),
                        },
                    )
                    .await
                    .expect("mixed workload error response should write");
                }
            }
        });
    }
}

async fn direct_mixed_workload_ws(
    websocket: WebSocketUpgrade,
    State(payload): State<Arc<Vec<u8>>>,
) -> impl IntoResponse {
    websocket.on_upgrade(move |socket| async move {
        serve_mixed_workload_transport_socket(
            socket,
            payload,
            format!("mixed-session-{}", uuid::Uuid::now_v7()),
        )
        .await;
    })
}

async fn spawn_direct_mixed_workload_test_server(
    payload: Arc<Vec<u8>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener addr");
    let router = Router::new()
        .route("/transport/ws", get(direct_mixed_workload_ws))
        .with_state(payload);
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("mixed workload server should run");
    });
    (format!("http://{addr}"), server)
}

async fn spawn_relay_mixed_workload_test_server(
    payload: Arc<Vec<u8>>,
) -> (
    String,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let addr = listener.local_addr().expect("listener addr");
    let state = RelayMixedWorkloadState {
        public_url: format!("http://{addr}"),
        payload,
        issued_ticket_count: Arc::new(AtomicUsize::new(0)),
        paired_session_count: Arc::new(AtomicUsize::new(0)),
    };
    let issued_ticket_count = Arc::clone(&state.issued_ticket_count);
    let paired_session_count = Arc::clone(&state.paired_session_count);
    let router = Router::new()
        .route("/control/relay/ticket", post(issue_mixed_workload_ticket))
        .route("/relay/tunnel/ws", get(relay_mixed_workload_tunnel_ws))
        .with_state(state.clone());
    let server = tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("relay mixed workload server should run");
    });
    (
        state.public_url,
        issued_ticket_count,
        paired_session_count,
        server,
    )
}

fn relay_test_client_for_public_url(
    public_url: impl Into<String>,
    identity: ClientIdentityMaterial,
    target_node_id: NodeId,
) -> IronMeshClient {
    let rendezvous = RendezvousControlClient::new(
        RendezvousClientConfig {
            cluster_id: identity.cluster_id,
            rendezvous_urls: vec![public_url.into()],
            heartbeat_interval_secs: 15,
        },
        None,
        None,
    )
    .expect("rendezvous client should build");
    IronMeshClient::with_relay_transport("https://relay.invalid/", rendezvous, target_node_id)
        .with_client_identity(identity)
}

fn direct_transport_test_client(
    state: &RelayTestState,
    identity: ClientIdentityMaterial,
) -> IronMeshClient {
    IronMeshClient::from_direct_base_url(state.public_url.clone()).with_client_identity(identity)
}

fn relay_test_client(
    state: &RelayTestState,
    identity: ClientIdentityMaterial,
    target_node_id: NodeId,
) -> IronMeshClient {
    relay_test_client_for_public_url(state.public_url.clone(), identity, target_node_id)
}

fn parse_range_header(range: &str, total_len: usize) -> (usize, usize) {
    let trimmed = range
        .strip_prefix("bytes=")
        .expect("range header should have bytes= prefix");
    let (start, end) = trimmed
        .split_once('-')
        .expect("range header should contain dash");
    let start = start.parse::<usize>().expect("range start should parse");
    let end = end.parse::<usize>().expect("range end should parse");
    assert!(start <= end, "range start must not exceed end");
    assert!(end < total_len, "range end must stay within payload");
    (start, end)
}

#[tokio::test]
async fn relay_transport_executes_store_index_request_with_signed_device_identity() {
    let (relay_state, server) = spawn_relay_test_server(
        200,
        vec![
            RelayHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
            RelayHttpHeader {
                name: "content-length".to_string(),
                value: serde_json::to_vec(&StoreIndexResponse {
                    prefix: String::new(),
                    depth: 1,
                    entry_count: 1,
                    total_entry_count: 1,
                    offset: 0,
                    limit: None,
                    has_more: false,
                    next_cursor: None,
                    media_summary: StoreIndexMediaSummary::default(),
                    entries: vec![StoreIndexEntry {
                        path: "docs/readme.txt".to_string(),
                        entry_type: "key".to_string(),
                        version: Some("v1".to_string()),
                        content_hash: Some("hash-1".to_string()),
                        size_bytes: Some(42),
                        modified_at_unix: None,
                        content_fingerprint: None,
                        media: None,
                    }],
                })
                .expect("store index response should serialize")
                .len()
                .to_string(),
            },
        ],
        serde_json::to_vec(&StoreIndexResponse {
            prefix: String::new(),
            depth: 1,
            entry_count: 1,
            total_entry_count: 1,
            offset: 0,
            limit: None,
            has_more: false,
            next_cursor: None,
            media_summary: StoreIndexMediaSummary::default(),
            entries: vec![StoreIndexEntry {
                path: "docs/readme.txt".to_string(),
                entry_type: "key".to_string(),
                version: Some("v1".to_string()),
                content_hash: Some("hash-1".to_string()),
                size_bytes: Some(42),
                modified_at_unix: None,
                content_fingerprint: None,
                media: None,
            }],
        })
        .expect("store index response should serialize"),
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("relay-test-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let target_node_id = NodeId::new_v4();
    let client = relay_test_client(&relay_state, identity.clone(), target_node_id);

    let response = client
        .store_index(None, 1, None)
        .await
        .expect("store index over relay should succeed");

    assert_eq!(response.entry_count, 2);
    assert_eq!(response.entries[0].path, "docs/");
    assert_eq!(response.entries[1].path, "docs/readme.txt");

    let captured = relay_state
        .captured_request
        .lock()
        .await
        .clone()
        .expect("relay request should be captured");
    assert_eq!(captured.method, "GET");
    assert_eq!(captured.path_and_query, "/api/v1/store/index?depth=1");
    assert!(
        captured
            .headers
            .iter()
            .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                && header.value == identity.device_id.to_string())
    );

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn relay_transport_executes_generic_json_get_request() {
    let (relay_state, server) = spawn_relay_test_server(
        200,
        vec![
            RelayHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
            RelayHttpHeader {
                name: "content-length".to_string(),
                value: br#"{"status":"ok"}"#.len().to_string(),
            },
        ],
        br#"{"status":"ok"}"#.to_vec(),
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("relay-test-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let target_node_id = NodeId::new_v4();
    let client = relay_test_client(&relay_state, identity.clone(), target_node_id);

    let response = client
        .get_json_path("/cluster/status")
        .await
        .expect("generic JSON GET over relay should succeed");

    assert_eq!(response["status"], "ok");

    let captured = relay_state
        .captured_request
        .lock()
        .await
        .clone()
        .expect("relay request should be captured");
    assert_eq!(captured.path_and_query, "/api/v1/cluster/status");
    assert!(
        captured
            .headers
            .iter()
            .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                && header.value == identity.device_id.to_string())
    );

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn relay_transport_executes_relative_path_get_request() {
    let (relay_state, server) = spawn_relay_test_server(
        200,
        vec![
            RelayHttpHeader {
                name: "content-type".to_string(),
                value: "image/jpeg".to_string(),
            },
            RelayHttpHeader {
                name: "content-length".to_string(),
                value: b"thumb-jpeg-bytes".len().to_string(),
            },
        ],
        b"thumb-jpeg-bytes".to_vec(),
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("relay-test-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let target_node_id = NodeId::new_v4();
    let client = relay_test_client(&relay_state, identity.clone(), target_node_id);

    let response = client
        .get_relative_path("/media/thumbnail?key=gallery%2Fcat.png")
        .await
        .expect("relative GET over relay should succeed");

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body.as_ref(), b"thumb-jpeg-bytes");

    let captured = relay_state
        .captured_request
        .lock()
        .await
        .clone()
        .expect("relay request should be captured");
    assert_eq!(
        captured.path_and_query,
        "/api/v1/media/thumbnail?key=gallery%2Fcat.png"
    );
    assert!(
        captured
            .headers
            .iter()
            .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                && header.value == identity.device_id.to_string())
    );

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn relay_transport_preserves_head_response_headers() {
    let payload = b"head-only-payload";
    let (relay_state, server) = spawn_relay_test_server(
        200,
        vec![
            RelayHttpHeader {
                name: ACCEPT_RANGES.as_str().to_string(),
                value: "bytes".to_string(),
            },
            RelayHttpHeader {
                name: CONTENT_LENGTH.as_str().to_string(),
                value: payload.len().to_string(),
            },
            RelayHttpHeader {
                name: ETAG.as_str().to_string(),
                value: "\"relay-head-etag\"".to_string(),
            },
        ],
        Vec::new(),
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("relay-test-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let target_node_id = NodeId::new_v4();
    let client = relay_test_client(&relay_state, identity.clone(), target_node_id);

    let response = client
        .head_object("gallery/cat.png", None, None)
        .await
        .expect("HEAD over relay should succeed");

    assert_eq!(response.total_size_bytes, payload.len() as u64);
    assert!(response.accept_ranges);
    assert_eq!(response.etag.as_deref(), Some("\"relay-head-etag\""));

    let captured = relay_state
        .captured_request
        .lock()
        .await
        .clone()
        .expect("relay request should be captured");
    assert_eq!(captured.method, "HEAD");
    assert_eq!(captured.path_and_query, "/api/v1/store/gallery%2Fcat.png");

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn relay_transport_reuses_multiplexed_session_for_multiple_requests() {
    let (relay_state, server) = spawn_relay_test_server(
        200,
        vec![
            RelayHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
            RelayHttpHeader {
                name: "content-length".to_string(),
                value: br#"{"status":"ok"}"#.len().to_string(),
            },
        ],
        br#"{"status":"ok"}"#.to_vec(),
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("relay-test-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let target_node_id = NodeId::new_v4();
    let client = relay_test_client(&relay_state, identity, target_node_id);

    let first = client
        .get_json_path("/cluster/status")
        .await
        .expect("first multiplex relay request should succeed");
    let second = client
        .get_json_path("/cluster/status")
        .await
        .expect("second multiplex relay request should succeed");

    assert_eq!(first["status"], "ok");
    assert_eq!(second["status"], "ok");
    assert_eq!(relay_state.issued_ticket_count.load(Ordering::SeqCst), 1);
    assert_eq!(relay_state.paired_session_count.load(Ordering::SeqCst), 1);

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn relay_transport_streams_upload_session_chunks_over_object_write() {
    let response_body = serde_json::to_vec(&UploadSessionChunkResponse {
        stored: true,
        received_index: 2,
    })
    .expect("upload chunk response should serialize");
    let (relay_state, server) = spawn_relay_test_server(
        200,
        vec![
            RelayHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
            RelayHttpHeader {
                name: "content-length".to_string(),
                value: response_body.len().to_string(),
            },
        ],
        response_body,
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("relay-upload-test-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let target_node_id = NodeId::new_v4();
    let client = relay_test_client(&relay_state, identity, target_node_id);

    let response = client
        .upload_session_chunk_bytes("upload-123", 2, b"chunk-body".to_vec())
        .await
        .expect("relay upload chunk should succeed");

    assert!(response.stored);
    assert_eq!(response.received_index, 2);

    let captured = relay_state
        .captured_request
        .lock()
        .await
        .clone()
        .expect("relay request should be captured");
    assert_eq!(captured.kind, Some(TransportStreamKind::ObjectWrite));
    assert_eq!(captured.method, "PUT");
    assert_eq!(
        captured.path_and_query,
        "/api/v1/store/uploads/upload-123/chunk/2"
    );
    assert_eq!(captured.body, b"chunk-body".to_vec());

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn relay_transport_retries_streamed_upload_chunk_after_partial_session_failure() {
    let response_body = serde_json::to_vec(&UploadSessionChunkResponse {
        stored: true,
        received_index: 4,
    })
    .expect("upload chunk response should serialize");
    let (relay_state, server) = spawn_relay_test_server_with_object_write_failures(
        200,
        vec![
            RelayHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
            RelayHttpHeader {
                name: "content-length".to_string(),
                value: response_body.len().to_string(),
            },
        ],
        response_body,
        1,
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("relay-upload-retry-test-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let target_node_id = NodeId::new_v4();
    let client = relay_test_client(&relay_state, identity, target_node_id);

    let response = client
        .upload_session_chunk_bytes("upload-retry", 4, b"retry-body".to_vec())
        .await
        .expect("relay upload chunk retry should succeed");

    assert!(response.stored);
    assert_eq!(response.received_index, 4);
    assert_eq!(relay_state.issued_ticket_count.load(Ordering::SeqCst), 2);
    assert_eq!(relay_state.paired_session_count.load(Ordering::SeqCst), 2);

    let captured = relay_state
        .captured_request
        .lock()
        .await
        .clone()
        .expect("relay request should be captured");
    assert_eq!(captured.kind, Some(TransportStreamKind::ObjectWrite));
    assert_eq!(
        captured.path_and_query,
        "/api/v1/store/uploads/upload-retry/chunk/4"
    );
    assert_eq!(captured.body, b"retry-body".to_vec());

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn upload_session_affinity_uses_same_node_after_path_change() {
    let shared_node_a = UploadSessionHttpSharedState::default();
    let node_a = NodeId::new_v4();
    let node_b = NodeId::new_v4();

    let (node_a_primary_url, node_a_primary_state, node_a_primary_server) =
        spawn_upload_session_http_server(
            "127.0.0.1:0".parse().expect("bind addr should parse"),
            shared_node_a.clone(),
        )
        .await;
    let (node_b_url, node_b_state, node_b_server) = spawn_upload_session_http_server(
        "127.0.0.1:0".parse().expect("bind addr should parse"),
        UploadSessionHttpSharedState::default(),
    )
    .await;
    let (node_a_secondary_url, node_a_secondary_state, node_a_secondary_server) =
        spawn_upload_session_http_server(
            "127.0.0.1:0".parse().expect("bind addr should parse"),
            shared_node_a,
        )
        .await;

    let client = IronMeshClient::combine(vec![
        IronMeshClient::from_direct_http_client_with_target_node_id_and_ca_pem(
            node_a_primary_url,
            HttpClient::new(),
            Some(node_a),
            None,
        ),
        IronMeshClient::from_direct_http_client_with_target_node_id_and_ca_pem(
            node_b_url,
            HttpClient::new(),
            Some(node_b),
            None,
        ),
        IronMeshClient::from_direct_http_client_with_target_node_id_and_ca_pem(
            node_a_secondary_url,
            HttpClient::new(),
            Some(node_a),
            None,
        ),
    ])
    .expect("combined direct client should build");

    let session = client
        .begin_upload_session("photos/path-change.bin", 5)
        .await
        .expect("upload session should start");
    assert_eq!(node_a_primary_state.start_hits.load(Ordering::SeqCst), 1);
    assert_eq!(node_b_state.start_hits.load(Ordering::SeqCst), 0);
    assert_eq!(node_a_secondary_state.start_hits.load(Ordering::SeqCst), 0);

    node_a_primary_server.abort();
    let _ = node_a_primary_server.await;

    let chunk = client
        .upload_session_chunk_bytes(&session.upload_id, 0, b"hello".to_vec())
        .await
        .expect("chunk upload should switch to the second path on the same node");
    assert_eq!(chunk.received_index, 0);

    let completed = client
        .finalize_upload_session(&session.upload_id)
        .await
        .expect("upload session completion should use the same-node fallback path");
    assert_eq!(completed.total_size_bytes, 5);

    assert_eq!(node_b_state.chunk_hits.load(Ordering::SeqCst), 0);
    assert_eq!(node_b_state.complete_hits.load(Ordering::SeqCst), 0);
    assert_eq!(node_a_secondary_state.chunk_hits.load(Ordering::SeqCst), 1);
    assert_eq!(
        node_a_secondary_state.complete_hits.load(Ordering::SeqCst),
        1
    );

    node_b_server.abort();
    let _ = node_b_server.await;
    node_a_secondary_server.abort();
    let _ = node_a_secondary_server.await;
}

#[tokio::test]
async fn direct_transport_executes_and_reuses_multiplexed_session() {
    let (direct_state, server) = spawn_direct_transport_test_server(
        200,
        vec![
            RelayHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
            RelayHttpHeader {
                name: "content-length".to_string(),
                value: br#"{"status":"ok"}"#.len().to_string(),
            },
        ],
        br#"{"status":"ok"}"#.to_vec(),
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("direct-test-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let client = direct_transport_test_client(&direct_state, identity.clone());

    let first = client
        .get_json_path("/cluster/status")
        .await
        .expect("first direct multiplex request should succeed");
    let second = client
        .get_json_path("/cluster/status")
        .await
        .expect("second direct multiplex request should succeed");

    assert_eq!(first["status"], "ok");
    assert_eq!(second["status"], "ok");
    assert_eq!(direct_state.paired_session_count.load(Ordering::SeqCst), 1);

    let captured = direct_state
        .captured_request
        .lock()
        .await
        .clone()
        .expect("direct request should be captured");
    assert_eq!(captured.path_and_query, "/api/v1/cluster/status");
    assert!(
        captured
            .headers
            .iter()
            .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                && header.value == identity.device_id.to_string())
    );

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn direct_transport_executes_store_index_request_with_signed_device_identity() {
    let (direct_state, server) = spawn_direct_transport_test_server(
        200,
        vec![
            RelayHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
            RelayHttpHeader {
                name: "content-length".to_string(),
                value: serde_json::to_vec(&StoreIndexResponse {
                    prefix: String::new(),
                    depth: 1,
                    entry_count: 1,
                    total_entry_count: 1,
                    offset: 0,
                    limit: None,
                    has_more: false,
                    next_cursor: None,
                    media_summary: StoreIndexMediaSummary::default(),
                    entries: vec![StoreIndexEntry {
                        path: "docs/readme.txt".to_string(),
                        entry_type: "key".to_string(),
                        version: Some("v1".to_string()),
                        content_hash: Some("hash-1".to_string()),
                        size_bytes: Some(42),
                        modified_at_unix: None,
                        content_fingerprint: None,
                        media: None,
                    }],
                })
                .expect("store index response should serialize")
                .len()
                .to_string(),
            },
        ],
        serde_json::to_vec(&StoreIndexResponse {
            prefix: String::new(),
            depth: 1,
            entry_count: 1,
            total_entry_count: 1,
            offset: 0,
            limit: None,
            has_more: false,
            next_cursor: None,
            media_summary: StoreIndexMediaSummary::default(),
            entries: vec![StoreIndexEntry {
                path: "docs/readme.txt".to_string(),
                entry_type: "key".to_string(),
                version: Some("v1".to_string()),
                content_hash: Some("hash-1".to_string()),
                size_bytes: Some(42),
                modified_at_unix: None,
                content_fingerprint: None,
                media: None,
            }],
        })
        .expect("store index response should serialize"),
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("direct-store-index-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let client = direct_transport_test_client(&direct_state, identity.clone());

    let response = client
        .store_index(None, 1, None)
        .await
        .expect("store index over direct transport should succeed");

    assert_eq!(response.entry_count, 2);
    assert_eq!(response.entries[0].path, "docs/");
    assert_eq!(response.entries[1].path, "docs/readme.txt");

    let captured = direct_state
        .captured_request
        .lock()
        .await
        .clone()
        .expect("direct request should be captured");
    assert_eq!(captured.method, "GET");
    assert_eq!(captured.path_and_query, "/api/v1/store/index?depth=1");
    assert!(
        captured
            .headers
            .iter()
            .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                && header.value == identity.device_id.to_string())
    );

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn combined_direct_transports_fail_over_to_second_endpoint() {
    let (direct_state, server) = spawn_direct_transport_test_server(
        200,
        vec![
            RelayHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
            RelayHttpHeader {
                name: "content-length".to_string(),
                value: br#"{"status":"ok"}"#.len().to_string(),
            },
        ],
        br#"{"status":"ok"}"#.to_vec(),
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("direct-failover-test-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());

    let failing = IronMeshClient::from_direct_base_url("http://127.0.0.1:9")
        .with_client_identity(identity.clone());
    let healthy = direct_transport_test_client(&direct_state, identity);
    let client = IronMeshClient::combine(vec![failing, healthy])
        .expect("combined direct client should build");

    let first = client
        .get_json_path("/cluster/status")
        .await
        .expect("first combined direct request should succeed via fallback");
    let second = client
        .get_json_path("/cluster/status")
        .await
        .expect("second combined direct request should keep using the healthy route");

    assert_eq!(first["status"], "ok");
    assert_eq!(second["status"], "ok");
    assert_eq!(
        client.direct_server_base_url(),
        Some(direct_state.public_url.as_str())
    );
    assert_eq!(direct_state.paired_session_count.load(Ordering::SeqCst), 1);

    server.abort();
    let _ = server.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_probe_reprioritizes_recovered_direct_endpoint() {
    let reserved_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let primary_addr = reserved_listener
        .local_addr()
        .expect("listener should have addr");
    drop(reserved_listener);

    let primary_url = format!("http://{primary_addr}");
    let (fallback_url, fallback_state, fallback_server) =
        spawn_direct_http_route_server(125, "fallback").await;

    let primary = IronMeshClient::from_direct_base_url(primary_url.clone());
    let fallback = IronMeshClient::from_direct_base_url(fallback_url.clone());
    let client = IronMeshClient::combine(vec![primary, fallback])
        .expect("combined direct client should build");

    let first = client
        .get_json_path("/cluster/status")
        .await
        .expect("first request should fall back to the healthy route");
    assert_eq!(first["route"], "fallback");
    assert_eq!(client.direct_server_base_url(), Some(fallback_url.as_str()));

    let (_primary_url, primary_state, primary_server) =
        spawn_direct_http_route_server_at(primary_addr, 0, "primary").await;

    tokio::time::sleep(Duration::from_millis(
        CLIENT_ROUTE_CIRCUIT_BASE_BACKOFF_MS + 100,
    ))
    .await;

    let second = client
        .get_json_path("/cluster/status")
        .await
        .expect("second request should still use the current fallback route");
    assert_eq!(second["route"], "fallback");

    tokio::time::sleep(Duration::from_millis(200)).await;

    let third = client
        .get_json_path("/cluster/status")
        .await
        .expect("third request should use the reprobed primary route");
    assert_eq!(third["route"], "primary");
    assert_eq!(client.direct_server_base_url(), Some(primary_url.as_str()));
    assert!(primary_state.health_hits.load(Ordering::SeqCst) >= 1);
    assert_eq!(primary_state.cluster_status_hits.load(Ordering::SeqCst), 1);
    assert_eq!(fallback_state.cluster_status_hits.load(Ordering::SeqCst), 2);

    primary_server.abort();
    let _ = primary_server.await;
    fallback_server.abort();
    let _ = fallback_server.await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn background_probe_reprioritizes_recovered_relay_endpoint() {
    let reserved_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener should bind");
    let primary_addr = reserved_listener
        .local_addr()
        .expect("listener should have addr");
    drop(reserved_listener);

    let primary_url = format!("http://{primary_addr}");
    let fallback_body = serde_json::to_vec(&serde_json::json!({
        "status": "ok",
        "route": "fallback",
    }))
    .expect("fallback relay body should serialize");
    let (fallback_state, fallback_server) = spawn_relay_test_server_with_delay(
        200,
        vec![
            RelayHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
            RelayHttpHeader {
                name: "content-length".to_string(),
                value: fallback_body.len().to_string(),
            },
        ],
        fallback_body,
        125,
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("relay-background-refresh-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let primary_target_node_id = NodeId::new_v4();
    let fallback_target_node_id = NodeId::new_v4();
    let primary = relay_test_client_for_public_url(
        primary_url.clone(),
        identity.clone(),
        primary_target_node_id,
    );
    let fallback = relay_test_client(&fallback_state, identity.clone(), fallback_target_node_id);
    let client = IronMeshClient::combine(vec![primary, fallback])
        .expect("combined relay client should build");

    let first = client
        .get_json_path("/cluster/status")
        .await
        .expect("first request should fall back to the healthy relay route");
    assert_eq!(first["route"], "fallback");
    assert_eq!(client.relay_target_node_id(), Some(fallback_target_node_id));
    assert!(client.uses_relay_transport());

    let primary_body = serde_json::to_vec(&serde_json::json!({
        "status": "ok",
        "route": "primary",
    }))
    .expect("primary relay body should serialize");
    let (primary_state, primary_server) = spawn_relay_test_server_at(
        primary_addr,
        200,
        vec![
            RelayHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
            RelayHttpHeader {
                name: "content-length".to_string(),
                value: primary_body.len().to_string(),
            },
        ],
        primary_body,
        0,
        0,
    )
    .await;

    tokio::time::sleep(Duration::from_millis(
        CLIENT_ROUTE_CIRCUIT_BASE_BACKOFF_MS + 100,
    ))
    .await;

    let second = client
        .get_json_path("/cluster/status")
        .await
        .expect("second request after backoff should succeed");
    assert!(matches!(
        second["route"].as_str(),
        Some("fallback" | "primary")
    ));

    // Allow up to 10s: the probe fires immediately on success, but if it fails
    // transiently the min-interval (5000ms) gates the retry, leaving only a
    // narrow window before the test would time out at 5s.
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if primary_state.health_hits.load(Ordering::SeqCst) >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("background probe should hit the recovered relay route");

    let third = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let response = client
                .get_json_path("/cluster/status")
                .await
                .expect("request after background probe should succeed");
            if response["route"] == "primary" {
                break response;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("client should eventually prefer the recovered relay route");
    assert_eq!(third["route"], "primary");
    assert_eq!(client.relay_target_node_id(), Some(primary_target_node_id));
    assert!(primary_state.health_hits.load(Ordering::SeqCst) >= 1);
    assert!(primary_state.issued_ticket_count.load(Ordering::SeqCst) >= 1);
    assert!(primary_state.paired_session_count.load(Ordering::SeqCst) >= 1);
    assert_eq!(fallback_state.issued_ticket_count.load(Ordering::SeqCst), 1);
    assert_eq!(
        fallback_state.paired_session_count.load(Ordering::SeqCst),
        1
    );

    primary_server.abort();
    let _ = primary_server.await;
    fallback_server.abort();
    let _ = fallback_server.await;
}

#[tokio::test]
async fn direct_transport_executes_relative_path_get_request() {
    let (direct_state, server) = spawn_direct_transport_test_server(
        200,
        vec![
            RelayHttpHeader {
                name: "content-type".to_string(),
                value: "image/jpeg".to_string(),
            },
            RelayHttpHeader {
                name: "content-length".to_string(),
                value: b"thumb-jpeg-bytes".len().to_string(),
            },
        ],
        b"thumb-jpeg-bytes".to_vec(),
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("direct-relative-path-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let client = direct_transport_test_client(&direct_state, identity.clone());

    let response = client
        .get_relative_path("/media/thumbnail?key=gallery%2Fcat.png")
        .await
        .expect("relative GET over direct transport should succeed");

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.body.as_ref(), b"thumb-jpeg-bytes");

    let captured = direct_state
        .captured_request
        .lock()
        .await
        .clone()
        .expect("direct request should be captured");
    assert_eq!(
        captured.path_and_query,
        "/api/v1/media/thumbnail?key=gallery%2Fcat.png"
    );
    assert!(
        captured
            .headers
            .iter()
            .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                && header.value == identity.device_id.to_string())
    );

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn direct_transport_preserves_head_response_headers() {
    let payload = b"head-only-payload";
    let (direct_state, server) = spawn_direct_transport_test_server(
        200,
        vec![
            RelayHttpHeader {
                name: ACCEPT_RANGES.as_str().to_string(),
                value: "bytes".to_string(),
            },
            RelayHttpHeader {
                name: CONTENT_LENGTH.as_str().to_string(),
                value: payload.len().to_string(),
            },
            RelayHttpHeader {
                name: ETAG.as_str().to_string(),
                value: "\"direct-head-etag\"".to_string(),
            },
        ],
        Vec::new(),
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("direct-head-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let client = direct_transport_test_client(&direct_state, identity);

    let response = client
        .head_object("gallery/cat.png", None, None)
        .await
        .expect("HEAD over direct transport should succeed");

    assert_eq!(response.total_size_bytes, payload.len() as u64);
    assert!(response.accept_ranges);
    assert_eq!(response.etag.as_deref(), Some("\"direct-head-etag\""));

    let captured = direct_state
        .captured_request
        .lock()
        .await
        .clone()
        .expect("direct request should be captured");
    assert_eq!(captured.method, "HEAD");
    assert_eq!(captured.path_and_query, "/api/v1/store/gallery%2Fcat.png");

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn direct_transport_streams_upload_session_chunks_over_object_write() {
    let response_body = serde_json::to_vec(&UploadSessionChunkResponse {
        stored: true,
        received_index: 3,
    })
    .expect("upload chunk response should serialize");
    let (direct_state, server) = spawn_direct_transport_test_server(
        200,
        vec![
            RelayHttpHeader {
                name: "content-type".to_string(),
                value: "application/json".to_string(),
            },
            RelayHttpHeader {
                name: "content-length".to_string(),
                value: response_body.len().to_string(),
            },
        ],
        response_body,
    )
    .await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("direct-upload-test-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let client = direct_transport_test_client(&direct_state, identity);

    let response = client
        .upload_session_chunk_bytes("upload-abc", 3, b"direct-chunk".to_vec())
        .await
        .expect("direct upload chunk should succeed");

    assert!(response.stored);
    assert_eq!(response.received_index, 3);

    let captured = direct_state
        .captured_request
        .lock()
        .await
        .clone()
        .expect("direct request should be captured");
    assert_eq!(captured.kind, Some(TransportStreamKind::ObjectWrite));
    assert_eq!(captured.method, "PUT");
    assert_eq!(
        captured.path_and_query,
        "/api/v1/store/uploads/upload-abc/chunk/3"
    );
    assert_eq!(captured.body, b"direct-chunk".to_vec());

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn direct_transport_keeps_small_rpcs_responsive_during_streamed_downloads() {
    let payload = Arc::new(vec![0x5A; 1024 * 1024]);
    let payload_len = payload.len();
    let (base_url, server) = spawn_direct_mixed_workload_test_server(Arc::clone(&payload)).await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("direct-mixed-workload-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let client = IronMeshClient::from_direct_base_url(base_url).with_client_identity(identity);

    let download_client = client.clone();
    let download_future = async move {
        let mut output = Vec::new();
        let mut progress = Vec::new();
        let mut on_progress = |update: DownloadProgress| {
            progress.push(update);
        };
        let result = download_client
            .download_range_to_writer_with_progress(
                DownloadRangeRequest {
                    key: "large.bin",
                    snapshot: None,
                    version: None,
                    range: RequestedRange {
                        offset: 0,
                        length: payload_len as u64,
                    },
                },
                &mut output,
                &mut on_progress,
                &|| false,
            )
            .await
            .expect("streamed download should succeed");
        (output, progress, result)
    };
    let rpc_future = async {
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        tokio::time::timeout(
            std::time::Duration::from_millis(250),
            client.get_json_path("/cluster/status"),
        )
        .await
        .expect("small RPC should not be blocked behind streamed download")
        .expect("small RPC should succeed")
    };
    let ((output, progress, result), rpc_response) = tokio::join!(download_future, rpc_future);

    assert_eq!(rpc_response["status"], "ok");
    assert_eq!(output.len(), payload_len);
    assert_eq!(result.bytes_downloaded, payload_len as u64);
    assert!(
        progress
            .last()
            .is_some_and(|entry| entry.bytes_downloaded == payload_len as u64)
    );
    let snapshot = client.transport_session_pool_snapshot();
    assert_eq!(snapshot.connect_count, 1);
    assert!(snapshot.reuse_count >= 2);

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn direct_transport_streams_relative_s3_reads_without_blocking_small_rpcs() {
    let payload = Arc::new(vec![0x7B; 1024 * 1024]);
    let payload_len = payload.len();
    let (base_url, server) = spawn_direct_mixed_workload_test_server(Arc::clone(&payload)).await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("direct-stream-relative-s3-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let client = IronMeshClient::from_direct_base_url(base_url).with_client_identity(identity);

    let download_client = client.clone();
    let download_future = async move {
        let mut response = download_client
            .request_relative_path_streaming_response(
                Method::GET,
                "/s3/photos.example/docs/streamed.txt",
                Vec::new(),
            )
            .await
            .expect("streamed relative S3 read should succeed");
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response
                .headers
                .get(ETAG)
                .and_then(|value| value.to_str().ok()),
            Some("\"s3-streamed-etag\"")
        );

        let mut output = Vec::new();
        while let Some(chunk) = response.body.next().await {
            let chunk = chunk.expect("streamed relative S3 body chunk should succeed");
            output.extend_from_slice(chunk.as_ref());
        }
        output
    };
    let rpc_future = async {
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        tokio::time::timeout(
            std::time::Duration::from_millis(250),
            client.get_json_path("/cluster/status"),
        )
        .await
        .expect("small RPC should not be blocked behind streamed relative S3 read")
        .expect("small RPC should succeed")
    };
    let (output, rpc_response) = tokio::join!(download_future, rpc_future);

    assert_eq!(rpc_response["status"], "ok");
    assert_eq!(output.len(), payload_len);
    assert_eq!(output, payload.as_ref().to_vec());
    let snapshot = client.transport_session_pool_snapshot();
    assert_eq!(snapshot.connect_count, 1);
    assert!(snapshot.reuse_count >= 1);

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn relay_transport_streams_relative_s3_reads_without_blocking_small_rpcs() {
    let payload = Arc::new(vec![0x7B; 1024 * 1024]);
    let payload_len = payload.len();
    let (public_url, issued_ticket_count, paired_session_count, server) =
        spawn_relay_mixed_workload_test_server(Arc::clone(&payload)).await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("relay-stream-relative-s3-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let client = relay_test_client_for_public_url(public_url, identity, NodeId::new_v4());

    let download_client = client.clone();
    let download_future = async move {
        let mut response = download_client
            .request_relative_path_streaming_response(
                Method::GET,
                "/s3/photos.example/docs/streamed.txt",
                Vec::new(),
            )
            .await
            .expect("relay streamed relative S3 read should succeed");
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            response
                .headers
                .get(ETAG)
                .and_then(|value| value.to_str().ok()),
            Some("\"s3-streamed-etag\"")
        );

        let mut output = Vec::new();
        while let Some(chunk) = response.body.next().await {
            let chunk = chunk.expect("relay streamed relative S3 body chunk should succeed");
            output.extend_from_slice(chunk.as_ref());
        }
        output
    };
    let rpc_future = async {
        tokio::time::sleep(std::time::Duration::from_millis(40)).await;
        tokio::time::timeout(
            std::time::Duration::from_millis(250),
            client.get_json_path("/cluster/status"),
        )
        .await
        .expect("small RPC should not be blocked behind relay streamed relative S3 read")
        .expect("small RPC should succeed")
    };
    let (output, rpc_response) = tokio::join!(download_future, rpc_future);

    assert_eq!(rpc_response["status"], "ok");
    assert_eq!(output.len(), payload_len);
    assert_eq!(output, payload.as_ref().to_vec());
    assert_eq!(issued_ticket_count.load(Ordering::SeqCst), 1);
    assert_eq!(paired_session_count.load(Ordering::SeqCst), 1);

    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn direct_transport_cancels_streamed_download_promptly() {
    let payload = Arc::new(vec![0x3C; 1024 * 1024]);
    let payload_len = payload.len();
    let (base_url, server) = spawn_direct_mixed_workload_test_server(Arc::clone(&payload)).await;

    let mut identity = ClientIdentityMaterial::generate(
        uuid::Uuid::now_v7(),
        None,
        Some("direct-cancel-download-device".to_string()),
    )
    .expect("identity should generate");
    identity.credential_pem = Some("issued-credential".to_string());
    let client = IronMeshClient::from_direct_base_url(base_url).with_client_identity(identity);

    let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancel_for_task = Arc::clone(&cancel);
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(15)).await;
        cancel_for_task.store(true, Ordering::SeqCst);
    });

    let mut output = Vec::new();
    let result = client
        .download_range_to_writer_with_progress(
            DownloadRangeRequest {
                key: "large.bin",
                snapshot: None,
                version: None,
                range: RequestedRange {
                    offset: 0,
                    length: payload_len as u64,
                },
            },
            &mut output,
            &mut |_| {},
            &|| cancel.load(Ordering::SeqCst),
        )
        .await;

    let error = result.expect_err("streamed download should cancel");
    assert!(error.to_string().contains("download canceled"));
    assert!(output.len() < payload_len);

    server.abort();
    let _ = server.await;
}

#[test]
fn blocking_range_download_handles_concurrent_overlapping_requests() {
    fn build_range_response(
        payload: &[u8],
        status: StatusCode,
        start: usize,
        end_inclusive: usize,
    ) -> Response<Body> {
        Response::builder()
            .status(status)
            .header("x-ironmesh-object-size", payload.len().to_string())
            .header(ETAG.as_str(), "\"test-etag\"")
            .header(ACCEPT_RANGES.as_str(), "bytes")
            .header(
                CONTENT_LENGTH.as_str(),
                (end_inclusive - start + 1).to_string(),
            )
            .header(
                CONTENT_RANGE.as_str(),
                format!("bytes {start}-{end_inclusive}/{}", payload.len()),
            )
            .body(Body::from(payload[start..=end_inclusive].to_vec()))
            .expect("range response should build")
    }

    fn parse_range_header(range: &str, total_len: usize) -> (usize, usize) {
        let trimmed = range
            .strip_prefix("bytes=")
            .expect("range header should have bytes= prefix");
        let (start, end) = trimmed
            .split_once('-')
            .expect("range header should contain dash");
        let start = start.parse::<usize>().expect("range start should parse");
        let end = end.parse::<usize>().expect("range end should parse");
        assert!(start <= end, "range start must not exceed end");
        assert!(end < total_len, "range end must stay within payload");
        (start, end)
    }

    async fn head_store(
        State(payload): State<Arc<Vec<u8>>>,
        AxumPath(_key): AxumPath<String>,
    ) -> Response<Body> {
        Response::builder()
            .status(StatusCode::OK)
            .header("x-ironmesh-object-size", payload.len().to_string())
            .header(ETAG.as_str(), "\"test-etag\"")
            .header(ACCEPT_RANGES.as_str(), "bytes")
            .header(CONTENT_LENGTH.as_str(), payload.len().to_string())
            .body(Body::empty())
            .expect("head response should build")
    }

    async fn get_store(
        State(payload): State<Arc<Vec<u8>>>,
        AxumPath(_key): AxumPath<String>,
        headers: HeaderMap,
    ) -> Response<Body> {
        tokio::time::sleep(Duration::from_millis(20)).await;

        match headers.get(RANGE).and_then(|value| value.to_str().ok()) {
            Some(range) => {
                let (start, end_inclusive) = parse_range_header(range, payload.len());
                build_range_response(&payload, StatusCode::PARTIAL_CONTENT, start, end_inclusive)
            }
            None => Response::builder()
                .status(StatusCode::OK)
                .header("x-ironmesh-object-size", payload.len().to_string())
                .header(ETAG.as_str(), "\"test-etag\"")
                .header(ACCEPT_RANGES.as_str(), "bytes")
                .header(header::CONTENT_LENGTH, payload.len().to_string())
                .body(Body::from(payload.as_ref().clone()))
                .expect("full response should build"),
        }
    }

    let payload = Arc::new(
        (0..200_000)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>(),
    );

    let app = Router::new()
        .route("/api/v1/store/{*key}", get(get_store).head(head_store))
        .with_state(payload.clone());
    let (addr_tx, addr_rx) = std::sync::mpsc::sync_channel(1);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let server_thread = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("server runtime should build");
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("listener should bind");
            addr_tx
                .send(listener.local_addr().expect("listener should have addr"))
                .expect("server addr should send");
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("range server should run");
        });
    });

    let addr = addr_rx.recv().expect("server addr should arrive");
    let client = IronMeshClient::from_direct_base_url(format!("http://{addr}"));
    let requests = [
        (0_u64, 65_536_u64),
        (65_536_u64, 4_096_u64),
        (69_632_u64, 61_440_u64),
        (131_072_u64, payload.len() as u64 - 131_072_u64),
    ];

    for _round in 0..8 {
        let barrier = Arc::new(Barrier::new(requests.len()));
        let mut handles = Vec::new();
        for (start, length) in requests {
            let client = client.clone();
            let barrier = barrier.clone();
            let expected = payload[start as usize..(start + length) as usize].to_vec();
            handles.push(std::thread::spawn(move || {
                let mut writer = Vec::new();
                let mut progress_updates = Vec::new();
                barrier.wait();
                let result = client
                    .download_range_to_writer_with_progress_blocking(
                        DownloadRangeRequest {
                            key: "photos/test.jpg",
                            snapshot: None,
                            version: None,
                            range: RequestedRange {
                                offset: start,
                                length,
                            },
                        },
                        &mut writer,
                        &mut |progress| progress_updates.push(progress),
                        &|| false,
                    )
                    .expect("blocking ranged download should succeed");
                assert_eq!(writer, expected);
                assert_eq!(result.range.offset, start);
                assert_eq!(result.range.length, length);
                assert_eq!(result.bytes_downloaded, length);
                assert!(
                    progress_updates
                        .last()
                        .is_some_and(|progress| progress.bytes_downloaded == length),
                    "final progress update should report the completed byte count",
                );
            }));
        }

        for handle in handles {
            handle.join().expect("download worker should complete");
        }
    }

    let _ = shutdown_tx.send(());
    server_thread.join().expect("server thread should stop");
}
