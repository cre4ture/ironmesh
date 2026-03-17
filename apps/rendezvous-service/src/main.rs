mod auth;
mod config;
mod control;
mod presence;
mod relay;
mod state;

use anyhow::Result;
use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use tracing::info;
use tracing_subscriber::EnvFilter;
use transport_sdk::relay::{
    RelayHttpPollRequest, RelayHttpPollResponse, RelayHttpRequest, RelayHttpResponse, RelayTicket,
    RelayTicketRequest,
};
use transport_sdk::rendezvous::PresenceRegistration;

use crate::auth::{
    MaybeAuthenticatedNode, MtlsAuthenticatedNodeAcceptor, ensure_authenticated_peer_identity,
    require_authenticated_node,
};
use crate::config::RendezvousServiceConfig;
use crate::control::{PresenceListResponse, RegisterPresenceResponse};
use crate::state::AppState;

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    public_url: String,
    registered_endpoints: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let config = RendezvousServiceConfig::from_env()?;
    let state = AppState::new(config);
    run_with_state(state).await
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/control/presence", get(list_presence))
        .route("/control/presence/register", post(register_presence))
        .route("/control/relay/ticket", post(issue_relay_ticket))
        .route("/relay/http/request", post(submit_relay_http_request))
        .route("/relay/http/poll", post(poll_relay_http_request))
        .route("/relay/http/respond", post(complete_relay_http_request))
        .with_state(state)
}

async fn run_with_state(state: AppState) -> Result<()> {
    let bind_addr = state.config.bind_addr;
    let app = build_router(state.clone());

    info!(
        bind_addr = %bind_addr,
        public_url = %state.config.public_url,
        mtls_enabled = state.config.mtls.is_some(),
        "rendezvous service listening"
    );

    if let Some(mtls) = state.config.mtls.as_ref() {
        let tls_config = auth::build_mtls_rustls_config(
            &mtls.client_ca_cert_path,
            &mtls.cert_path,
            &mtls.key_path,
        )?;
        axum_server::bind(bind_addr)
            .acceptor(MtlsAuthenticatedNodeAcceptor::new(tls_config))
            .serve(app.into_make_service())
            .await?;
        Ok(())
    } else {
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        axum::serve(listener, app).await?;
        Ok(())
    }
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
    authenticated_node: MaybeAuthenticatedNode,
    Json(request): Json<PresenceRegistration>,
) -> std::result::Result<Json<RegisterPresenceResponse>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ensure_authenticated_peer_identity(
        state.config.mtls.is_some(),
        &authenticated_node,
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
    authenticated_node: MaybeAuthenticatedNode,
) -> std::result::Result<Json<PresenceListResponse>, (StatusCode, String)> {
    require_authenticated_node(state.config.mtls.is_some(), &authenticated_node)
        .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;
    let entries = state.presence.list();
    Ok(Json(PresenceListResponse {
        registered_endpoints: entries.len(),
        entries,
    }))
}

async fn issue_relay_ticket(
    State(state): State<AppState>,
    authenticated_node: MaybeAuthenticatedNode,
    Json(request): Json<RelayTicketRequest>,
) -> std::result::Result<Json<RelayTicket>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ensure_authenticated_peer_identity(
        state.config.mtls.is_some(),
        &authenticated_node,
        &request.source,
        "relay ticket source",
    )
    .map_err(|err| (StatusCode::UNAUTHORIZED, err.to_string()))?;

    let ticket = relay::issue_relay_ticket(request, &state.config.relay_public_urls);
    ticket
        .validate()
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(Json(ticket))
}

async fn submit_relay_http_request(
    State(state): State<AppState>,
    authenticated_node: MaybeAuthenticatedNode,
    Json(request): Json<RelayHttpRequest>,
) -> std::result::Result<Json<RelayHttpResponse>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ensure_authenticated_peer_identity(
        state.config.mtls.is_some(),
        &authenticated_node,
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
    authenticated_node: MaybeAuthenticatedNode,
    Json(request): Json<RelayHttpPollRequest>,
) -> std::result::Result<Json<RelayHttpPollResponse>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ensure_authenticated_peer_identity(
        state.config.mtls.is_some(),
        &authenticated_node,
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
    authenticated_node: MaybeAuthenticatedNode,
    Json(response): Json<RelayHttpResponse>,
) -> std::result::Result<Json<serde_json::Value>, (StatusCode, String)> {
    response
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    ensure_authenticated_peer_identity(
        state.config.mtls.is_some(),
        &authenticated_node,
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

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;
    use axum::http::StatusCode;
    use server_node_sdk::{InternalTlsConfig, ServerNodeConfig, ServerNodeMode, run};
    use std::net::IpAddr;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use transport_sdk::RelayMode;
    use uuid::Uuid;

    #[tokio::test]
    async fn relay_required_replication_flows_through_rendezvous() {
        let rendezvous_bind_addr = free_bind_addr();
        let rendezvous_public_url = format!("http://{rendezvous_bind_addr}");
        let rendezvous_state = AppState::new(RendezvousServiceConfig {
            bind_addr: rendezvous_bind_addr,
            public_url: rendezvous_public_url.clone(),
            relay_public_urls: vec![rendezvous_public_url.clone()],
            mtls: None,
        });
        let rendezvous_state_for_server = rendezvous_state.clone();
        let rendezvous_handle = tokio::spawn(async move {
            run_with_state(rendezvous_state_for_server)
                .await
                .expect("rendezvous service should run");
        });

        let http = reqwest::Client::new();
        wait_for_http_status(
            &http,
            &format!("{rendezvous_public_url}/health"),
            StatusCode::OK,
            Duration::from_secs(5),
        )
        .await;

        let cluster_id = Uuid::now_v7();
        let source_dir = fresh_test_dir("relay-required-source");
        let source_bind_addr = free_bind_addr();
        let source_public_url = format!("http://{source_bind_addr}");
        let mut source_config = ServerNodeConfig::local_edge(&source_dir, source_bind_addr);
        source_config.mode = ServerNodeMode::Cluster;
        source_config.cluster_id = cluster_id;
        source_config.public_url = Some(source_public_url.clone());
        source_config.public_peer_api_enabled = true;
        source_config.rendezvous_urls = vec![rendezvous_public_url.clone()];
        source_config.rendezvous_registration_enabled = true;
        source_config.relay_mode = RelayMode::Required;
        source_config.replica_view_sync_interval_secs = 1;
        source_config.peer_heartbeat_enabled = true;
        source_config.peer_heartbeat_interval_secs = 1;
        source_config.replication_factor = 2;
        source_config.replication_repair_enabled = true;
        source_config.replication_repair_backoff_secs = 1;
        source_config.startup_repair_enabled = false;

        let target_dir = fresh_test_dir("relay-required-target");
        let target_bind_addr = free_bind_addr();
        let target_public_url = format!("http://{target_bind_addr}");
        let mut target_config = ServerNodeConfig::local_edge(&target_dir, target_bind_addr);
        target_config.mode = ServerNodeMode::Cluster;
        target_config.cluster_id = cluster_id;
        target_config.public_url = Some(target_public_url.clone());
        target_config.public_peer_api_enabled = true;
        target_config.rendezvous_urls = vec![rendezvous_public_url.clone()];
        target_config.rendezvous_registration_enabled = true;
        target_config.relay_mode = RelayMode::Required;
        target_config.replica_view_sync_interval_secs = 1;
        target_config.peer_heartbeat_enabled = true;
        target_config.peer_heartbeat_interval_secs = 1;
        target_config.replication_factor = 2;
        target_config.replication_repair_enabled = true;
        target_config.replication_repair_backoff_secs = 1;
        target_config.startup_repair_enabled = false;

        let source_handle = tokio::spawn(async move {
            run(source_config)
                .await
                .expect("source node should start cleanly");
        });
        let target_handle = tokio::spawn(async move {
            run(target_config)
                .await
                .expect("target node should start cleanly");
        });

        wait_for_http_status(
            &http,
            &format!("{source_public_url}/health"),
            StatusCode::OK,
            Duration::from_secs(5),
        )
        .await;
        wait_for_http_status(
            &http,
            &format!("{target_public_url}/health"),
            StatusCode::OK,
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            "nodes discover each other through rendezvous",
            Duration::from_secs(10),
            || {
                let http = http.clone();
                let source_public_url = source_public_url.clone();
                let target_public_url = target_public_url.clone();
                async move {
                    let source_nodes = match http
                        .get(format!("{source_public_url}/cluster/nodes"))
                        .send()
                        .await
                    {
                        Ok(response) => match response.json::<Vec<serde_json::Value>>().await {
                            Ok(nodes) => nodes,
                            Err(_) => return false,
                        },
                        Err(_) => return false,
                    };
                    let target_nodes = match http
                        .get(format!("{target_public_url}/cluster/nodes"))
                        .send()
                        .await
                    {
                        Ok(response) => match response.json::<Vec<serde_json::Value>>().await {
                            Ok(nodes) => nodes,
                            Err(_) => return false,
                        },
                        Err(_) => return false,
                    };

                    source_nodes.len() >= 2 && target_nodes.len() >= 2
                }
            },
        )
        .await;

        let replication_key = "relay-required-replication.txt";
        let replication_payload = "replicated-through-rendezvous-relay";
        let put_response = http
            .put(format!("{source_public_url}/store/{replication_key}"))
            .body(replication_payload.to_string())
            .send()
            .await
            .expect("source PUT should succeed");
        assert_eq!(put_response.status(), StatusCode::CREATED);

        wait_for_condition(
            "target receives replicated object through relay",
            Duration::from_secs(20),
            || {
                let http = http.clone();
                let target_public_url = target_public_url.clone();
                let replication_key = replication_key.to_string();
                let replication_payload = replication_payload.to_string();
                async move {
                    let _ = http
                        .post(format!("{target_public_url}/cluster/replication/repair"))
                        .send()
                        .await;

                    match http
                        .get(format!("{target_public_url}/store/{replication_key}"))
                        .send()
                        .await
                    {
                        Ok(response) if response.status() == StatusCode::OK => {
                            match response.text().await {
                                Ok(body) => body == replication_payload,
                                Err(_) => false,
                            }
                        }
                        _ => false,
                    }
                }
            },
        )
        .await;

        let relay_stats = rendezvous_state.relay.stats().await;
        assert!(
            relay_stats.submitted_requests > 0,
            "expected relay broker to observe submitted requests"
        );
        assert!(
            relay_stats.delivered_requests > 0,
            "expected relay broker to deliver at least one request"
        );
        assert!(
            relay_stats.completed_responses > 0,
            "expected relay broker to observe completed responses"
        );

        source_handle.abort();
        let _ = source_handle.await;
        target_handle.abort();
        let _ = target_handle.await;
        rendezvous_handle.abort();
        let _ = rendezvous_handle.await;
        let _ = std::fs::remove_dir_all(&source_dir);
        let _ = std::fs::remove_dir_all(&target_dir);
    }

    #[tokio::test]
    async fn relay_required_replication_flows_through_mtls_authenticated_rendezvous() {
        let ca = issue_test_ca().expect("test CA should generate");

        let rendezvous_dir = fresh_test_dir("relay-required-rendezvous-mtls");
        let rendezvous_bind_addr = free_bind_addr();
        let rendezvous_public_url = format!("https://{rendezvous_bind_addr}");
        let (rendezvous_ca_path, rendezvous_cert_path, rendezvous_key_path) = write_tls_material(
            &rendezvous_dir,
            &ca.ca_pem,
            &issue_server_cert(&ca).expect("rendezvous server cert should issue"),
        )
        .expect("rendezvous TLS material should write");
        let rendezvous_state = AppState::new(RendezvousServiceConfig {
            bind_addr: rendezvous_bind_addr,
            public_url: rendezvous_public_url.clone(),
            relay_public_urls: vec![rendezvous_public_url.clone()],
            mtls: Some(config::RendezvousMtlsConfig {
                client_ca_cert_path: rendezvous_ca_path.clone(),
                cert_path: rendezvous_cert_path,
                key_path: rendezvous_key_path,
            }),
        });

        let source_dir = fresh_test_dir("relay-required-source-mtls");
        let source_node_id = Uuid::now_v7();
        let source_tls = write_tls_material(
            &source_dir,
            &ca.ca_pem,
            &issue_node_cert(&ca, source_node_id).expect("source node cert should issue"),
        )
        .expect("source TLS material should write");
        let rendezvous_health_client =
            build_https_client_with_identity(&rendezvous_ca_path, &source_tls.1, &source_tls.2)
                .expect("rendezvous mTLS client should build");

        let rendezvous_handle = tokio::spawn(async move {
            run_with_state(rendezvous_state)
                .await
                .expect("mTLS rendezvous service should run");
        });

        wait_for_http_status(
            &rendezvous_health_client,
            &format!("{rendezvous_public_url}/health"),
            StatusCode::OK,
            Duration::from_secs(5),
        )
        .await;

        let cluster_id = Uuid::now_v7();
        let source_bind_addr = free_bind_addr();
        let source_public_url = format!("http://{source_bind_addr}");
        let source_internal_bind_addr = free_bind_addr();
        let source_internal_url = format!("https://{source_internal_bind_addr}");
        let mut source_config = ServerNodeConfig::local_edge(&source_dir, source_bind_addr);
        source_config.mode = ServerNodeMode::Cluster;
        source_config.cluster_id = cluster_id;
        source_config.node_id = source_node_id;
        source_config.public_url = Some(source_public_url.clone());
        source_config.public_peer_api_enabled = false;
        source_config.internal_tls = Some(InternalTlsConfig {
            bind_addr: source_internal_bind_addr,
            internal_url: Some(source_internal_url),
            ca_cert_path: source_tls.0.clone(),
            cert_path: source_tls.1.clone(),
            key_path: source_tls.2.clone(),
            metadata_path: None,
        });
        source_config.rendezvous_urls = vec![rendezvous_public_url.clone()];
        source_config.rendezvous_registration_enabled = true;
        source_config.relay_mode = RelayMode::Required;
        source_config.replica_view_sync_interval_secs = 1;
        source_config.peer_heartbeat_enabled = true;
        source_config.peer_heartbeat_interval_secs = 1;
        source_config.replication_factor = 2;
        source_config.replication_repair_enabled = true;
        source_config.replication_repair_backoff_secs = 1;
        source_config.startup_repair_enabled = false;

        let target_dir = fresh_test_dir("relay-required-target-mtls");
        let target_node_id = Uuid::now_v7();
        let target_tls = write_tls_material(
            &target_dir,
            &ca.ca_pem,
            &issue_node_cert(&ca, target_node_id).expect("target node cert should issue"),
        )
        .expect("target TLS material should write");
        let target_bind_addr = free_bind_addr();
        let target_public_url = format!("http://{target_bind_addr}");
        let target_internal_bind_addr = free_bind_addr();
        let target_internal_url = format!("https://{target_internal_bind_addr}");
        let mut target_config = ServerNodeConfig::local_edge(&target_dir, target_bind_addr);
        target_config.mode = ServerNodeMode::Cluster;
        target_config.cluster_id = cluster_id;
        target_config.node_id = target_node_id;
        target_config.public_url = Some(target_public_url.clone());
        target_config.public_peer_api_enabled = false;
        target_config.internal_tls = Some(InternalTlsConfig {
            bind_addr: target_internal_bind_addr,
            internal_url: Some(target_internal_url),
            ca_cert_path: target_tls.0.clone(),
            cert_path: target_tls.1.clone(),
            key_path: target_tls.2.clone(),
            metadata_path: None,
        });
        target_config.rendezvous_urls = vec![rendezvous_public_url.clone()];
        target_config.rendezvous_registration_enabled = true;
        target_config.relay_mode = RelayMode::Required;
        target_config.replica_view_sync_interval_secs = 1;
        target_config.peer_heartbeat_enabled = true;
        target_config.peer_heartbeat_interval_secs = 1;
        target_config.replication_factor = 2;
        target_config.replication_repair_enabled = true;
        target_config.replication_repair_backoff_secs = 1;
        target_config.startup_repair_enabled = false;

        let source_handle = tokio::spawn(async move {
            run(source_config)
                .await
                .expect("source node with mTLS rendezvous should start cleanly");
        });
        let target_handle = tokio::spawn(async move {
            run(target_config)
                .await
                .expect("target node with mTLS rendezvous should start cleanly");
        });

        let http = reqwest::Client::new();
        wait_for_http_status(
            &http,
            &format!("{source_public_url}/health"),
            StatusCode::OK,
            Duration::from_secs(5),
        )
        .await;
        wait_for_http_status(
            &http,
            &format!("{target_public_url}/health"),
            StatusCode::OK,
            Duration::from_secs(5),
        )
        .await;

        wait_for_condition(
            "mTLS rendezvous nodes discover each other",
            Duration::from_secs(10),
            || {
                let http = http.clone();
                let source_public_url = source_public_url.clone();
                let target_public_url = target_public_url.clone();
                async move {
                    let source_nodes = match http
                        .get(format!("{source_public_url}/cluster/nodes"))
                        .send()
                        .await
                    {
                        Ok(response) => match response.json::<Vec<serde_json::Value>>().await {
                            Ok(nodes) => nodes,
                            Err(_) => return false,
                        },
                        Err(_) => return false,
                    };
                    let target_nodes = match http
                        .get(format!("{target_public_url}/cluster/nodes"))
                        .send()
                        .await
                    {
                        Ok(response) => match response.json::<Vec<serde_json::Value>>().await {
                            Ok(nodes) => nodes,
                            Err(_) => return false,
                        },
                        Err(_) => return false,
                    };

                    source_nodes.len() >= 2 && target_nodes.len() >= 2
                }
            },
        )
        .await;

        let replication_key = "relay-required-mtls-replication.txt";
        let replication_payload = "replicated-through-authenticated-rendezvous-relay";
        let put_response = http
            .put(format!("{source_public_url}/store/{replication_key}"))
            .body(replication_payload.to_string())
            .send()
            .await
            .expect("source PUT should succeed");
        assert_eq!(put_response.status(), StatusCode::CREATED);

        wait_for_condition(
            "target receives replicated object through authenticated relay",
            Duration::from_secs(20),
            || {
                let http = http.clone();
                let target_public_url = target_public_url.clone();
                let replication_key = replication_key.to_string();
                let replication_payload = replication_payload.to_string();
                async move {
                    let _ = http
                        .post(format!("{target_public_url}/cluster/replication/repair"))
                        .send()
                        .await;

                    match http
                        .get(format!("{target_public_url}/store/{replication_key}"))
                        .send()
                        .await
                    {
                        Ok(response) if response.status() == StatusCode::OK => {
                            match response.text().await {
                                Ok(body) => body == replication_payload,
                                Err(_) => false,
                            }
                        }
                        _ => false,
                    }
                }
            },
        )
        .await;

        let relay_stats = rendezvous_health_client
            .get(format!("{rendezvous_public_url}/control/presence"))
            .send()
            .await
            .expect("authenticated rendezvous client should reach control plane");
        assert_eq!(relay_stats.status(), StatusCode::OK);

        let relay_stats =
            build_https_client_with_identity(&rendezvous_ca_path, &target_tls.1, &target_tls.2)
                .expect("target rendezvous mTLS client should build");
        let presence = relay_stats
            .get(format!("{rendezvous_public_url}/control/presence"))
            .send()
            .await
            .expect("authenticated target should list presence")
            .error_for_status()
            .expect("presence listing should succeed")
            .json::<PresenceListResponse>()
            .await
            .expect("presence response should decode");
        assert!(presence.registered_endpoints >= 2);

        source_handle.abort();
        let _ = source_handle.await;
        target_handle.abort();
        let _ = target_handle.await;
        rendezvous_handle.abort();
        let _ = rendezvous_handle.await;
        let _ = std::fs::remove_dir_all(&rendezvous_dir);
        let _ = std::fs::remove_dir_all(&source_dir);
        let _ = std::fs::remove_dir_all(&target_dir);
    }

    fn free_bind_addr() -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("listener should bind");
        let addr = listener
            .local_addr()
            .expect("listener should report local addr");
        drop(listener);
        addr
    }

    fn fresh_test_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("ironmesh-{name}-{unique}"));
        let _ = std::fs::remove_dir_all(&path);
        let _ = std::fs::create_dir_all(&path);
        path
    }

    struct TestCa {
        ca_pem: String,
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    }

    fn issue_test_ca() -> anyhow::Result<TestCa> {
        let ca_key = rcgen::KeyPair::generate().context("failed generating test CA key")?;
        let mut params = rcgen::CertificateParams::default();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ironmesh-rendezvous-test-ca");
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
            rcgen::KeyUsagePurpose::DigitalSignature,
        ];

        let ca_cert = params
            .self_signed(&ca_key)
            .context("failed creating test CA certificate")?;
        Ok(TestCa {
            ca_pem: ca_cert.pem(),
            issuer: rcgen::Issuer::new(params, ca_key),
        })
    }

    fn issue_node_cert(ca: &TestCa, node_id: Uuid) -> anyhow::Result<(String, String)> {
        let node_key = rcgen::KeyPair::generate().context("failed generating node key")?;
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            format!("ironmesh-node-{node_id}"),
        );
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        params.subject_alt_names.push(rcgen::SanType::URI(
            rcgen::string::Ia5String::try_from(format!("urn:ironmesh:node:{node_id}"))
                .context("invalid node SAN URI")?,
        ));
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];

        let cert = params
            .signed_by(&node_key, &ca.issuer)
            .context("failed signing node certificate")?;
        Ok((cert.pem(), node_key.serialize_pem()))
    }

    fn issue_server_cert(ca: &TestCa) -> anyhow::Result<(String, String)> {
        let server_key = rcgen::KeyPair::generate().context("failed generating server key")?;
        let mut params = rcgen::CertificateParams::default();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "ironmesh-rendezvous-service");
        params
            .subject_alt_names
            .push(rcgen::SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];

        let cert = params
            .signed_by(&server_key, &ca.issuer)
            .context("failed signing rendezvous server certificate")?;
        Ok((cert.pem(), server_key.serialize_pem()))
    }

    fn write_tls_material(
        root: &Path,
        ca_pem: &str,
        cert_and_key: &(String, String),
    ) -> anyhow::Result<(PathBuf, PathBuf, PathBuf)> {
        let tls_dir = root.join("tls");
        std::fs::create_dir_all(&tls_dir).context("failed creating tls dir")?;

        let ca_path = tls_dir.join("ca.pem");
        let cert_path = tls_dir.join("node.pem");
        let key_path = tls_dir.join("node.key");
        std::fs::write(&ca_path, ca_pem).context("failed writing CA pem")?;
        std::fs::write(&cert_path, &cert_and_key.0).context("failed writing cert pem")?;
        std::fs::write(&key_path, &cert_and_key.1).context("failed writing key pem")?;
        Ok((ca_path, cert_path, key_path))
    }

    fn build_https_client_with_identity(
        ca_path: &Path,
        cert_path: &Path,
        key_path: &Path,
    ) -> anyhow::Result<reqwest::Client> {
        let ca_pem = std::fs::read(ca_path).context("failed reading CA pem")?;
        let cert_pem = std::fs::read(cert_path).context("failed reading cert pem")?;
        let key_pem = std::fs::read(key_path).context("failed reading key pem")?;

        let ca_cert =
            reqwest::Certificate::from_pem(&ca_pem).context("failed parsing CA certificate PEM")?;
        let mut identity_pem = Vec::new();
        identity_pem.extend_from_slice(&cert_pem);
        identity_pem.extend_from_slice(b"\n");
        identity_pem.extend_from_slice(&key_pem);
        let identity =
            reqwest::Identity::from_pem(&identity_pem).context("failed parsing identity PEM")?;

        reqwest::Client::builder()
            .add_root_certificate(ca_cert)
            .identity(identity)
            .build()
            .context("failed building mTLS reqwest client")
    }

    async fn wait_for_condition<F, Fut>(label: &str, timeout: Duration, mut condition: F)
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            if condition().await {
                return;
            }

            assert!(
                tokio::time::Instant::now() < deadline,
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
}
