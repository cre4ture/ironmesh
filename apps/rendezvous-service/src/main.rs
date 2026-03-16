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
    let bind_addr = config.bind_addr;
    let state = AppState::new(config);
    let app = build_router(state.clone());

    info!(
        bind_addr = %bind_addr,
        public_url = %state.config.public_url,
        "rendezvous service listening"
    );

    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
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

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        public_url: state.config.public_url,
        registered_endpoints: state.presence.len(),
    })
}

async fn register_presence(
    State(state): State<AppState>,
    Json(request): Json<PresenceRegistration>,
) -> std::result::Result<Json<RegisterPresenceResponse>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let entry = state.presence.register(request);
    Ok(Json(RegisterPresenceResponse {
        accepted: true,
        updated_at_unix: entry.updated_at_unix,
        entry,
    }))
}

async fn list_presence(State(state): State<AppState>) -> Json<PresenceListResponse> {
    let entries = state.presence.list();
    Json(PresenceListResponse {
        registered_endpoints: entries.len(),
        entries,
    })
}

async fn issue_relay_ticket(
    State(state): State<AppState>,
    Json(request): Json<RelayTicketRequest>,
) -> std::result::Result<Json<RelayTicket>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let ticket = relay::issue_relay_ticket(request, &state.config.relay_public_urls);
    ticket
        .validate()
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    Ok(Json(ticket))
}

async fn submit_relay_http_request(
    State(state): State<AppState>,
    Json(request): Json<RelayHttpRequest>,
) -> std::result::Result<Json<RelayHttpResponse>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;

    let response = state
        .relay
        .submit_and_await(request)
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
    Ok(Json(response))
}

async fn poll_relay_http_request(
    State(state): State<AppState>,
    Json(request): Json<RelayHttpPollRequest>,
) -> std::result::Result<Json<RelayHttpPollResponse>, (StatusCode, String)> {
    request
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
    let response = state
        .relay
        .poll(request)
        .await
        .map_err(|err| (StatusCode::BAD_GATEWAY, err.to_string()))?;
    Ok(Json(response))
}

async fn complete_relay_http_request(
    State(state): State<AppState>,
    Json(response): Json<RelayHttpResponse>,
) -> std::result::Result<Json<serde_json::Value>, (StatusCode, String)> {
    response
        .validate()
        .map_err(|err| (StatusCode::BAD_REQUEST, err.to_string()))?;
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
    use axum::http::StatusCode;
    use server_node_sdk::{ServerNodeConfig, ServerNodeMode, run};
    use std::net::{Ipv4Addr, SocketAddr, TcpListener};
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
        });
        let rendezvous_listener = tokio::net::TcpListener::bind(rendezvous_bind_addr)
            .await
            .expect("rendezvous listener should bind");
        let rendezvous_app = build_router(rendezvous_state.clone());
        let rendezvous_handle = tokio::spawn(async move {
            axum::serve(rendezvous_listener, rendezvous_app)
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
