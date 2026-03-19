use anyhow::{Context, Result, anyhow, bail};
use common::ClusterId;
use reqwest::{Certificate, Client, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::bootstrap::RelayMode;
use crate::candidates::ConnectionCandidate;
use crate::peer::PeerIdentity;
use crate::relay::{
    RelayHttpPollRequest, RelayHttpPollResponse, RelayHttpRequest, RelayHttpResponse, RelayTicket,
    RelayTicketRequest,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportCapability {
    DirectHttps,
    DirectQuic,
    RelayTunnel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RendezvousClientConfig {
    pub cluster_id: ClusterId,
    pub rendezvous_urls: Vec<String>,
    #[serde(default = "default_heartbeat_interval_secs")]
    pub heartbeat_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceRegistration {
    pub cluster_id: ClusterId,
    pub identity: PeerIdentity,
    #[serde(default)]
    pub public_api_url: Option<String>,
    #[serde(default)]
    pub peer_api_url: Option<String>,
    #[serde(default)]
    pub direct_candidates: Vec<ConnectionCandidate>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub capacity_bytes: Option<u64>,
    #[serde(default)]
    pub free_bytes: Option<u64>,
    #[serde(default)]
    pub capabilities: Vec<TransportCapability>,
    #[serde(default)]
    pub relay_mode: RelayMode,
    pub connected_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceEntry {
    pub registration: PresenceRegistration,
    pub updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegisterPresenceResponse {
    pub accepted: bool,
    pub updated_at_unix: u64,
    pub entry: PresenceEntry,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PresenceListResponse {
    pub registered_endpoints: usize,
    pub entries: Vec<PresenceEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RendezvousEndpointConnectionState {
    Unknown,
    Connected,
    Disconnected,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RendezvousEndpointStatus {
    pub url: String,
    pub status: RendezvousEndpointConnectionState,
    #[serde(default)]
    pub last_attempt_unix: Option<u64>,
    #[serde(default)]
    pub last_success_unix: Option<u64>,
    #[serde(default)]
    pub consecutive_failures: u64,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RendezvousRuntimeState {
    #[serde(default)]
    pub active_url: Option<String>,
    #[serde(default)]
    pub endpoint_statuses: Vec<RendezvousEndpointStatus>,
}

#[derive(Debug, Clone)]
pub struct RendezvousControlClient {
    config: RendezvousClientConfig,
    http: Client,
    runtime_state: Arc<Mutex<TrackedRendezvousRuntimeState>>,
}

#[derive(Debug, Default)]
struct TrackedRendezvousRuntimeState {
    active_url: Option<String>,
    endpoints: HashMap<String, RendezvousEndpointStatus>,
}

impl RendezvousClientConfig {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("rendezvous client config must include a non-nil cluster_id");
        }
        if self.rendezvous_urls.is_empty() {
            bail!("rendezvous client config must include at least one rendezvous URL");
        }
        for url in &self.rendezvous_urls {
            if url.trim().is_empty() {
                bail!("rendezvous URLs must not contain empty values");
            }
            Url::parse(url.trim())?;
        }
        Ok(())
    }
}

impl PresenceRegistration {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("presence registration must include a non-nil cluster_id");
        }
        validate_optional_url("public_api_url", self.public_api_url.as_deref())?;
        validate_optional_url("peer_api_url", self.peer_api_url.as_deref())?;
        for candidate in &self.direct_candidates {
            candidate.validate()?;
        }
        Ok(())
    }
}

impl RendezvousControlClient {
    pub fn new(
        config: RendezvousClientConfig,
        server_ca_pem: Option<&str>,
        client_identity_pem: Option<&[u8]>,
    ) -> Result<Self> {
        config.validate()?;

        let builder = Client::builder();
        let builder = if let Some(server_ca_pem) = server_ca_pem {
            builder.add_root_certificate(
                Certificate::from_pem(server_ca_pem.as_bytes())
                    .context("failed to parse rendezvous server CA certificate")?,
            )
        } else {
            builder
        };
        let builder = if let Some(client_identity_pem) = client_identity_pem {
            builder.identity(
                reqwest::Identity::from_pem(client_identity_pem)
                    .context("failed to parse rendezvous client identity PEM")?,
            )
        } else {
            builder
        };

        let http = builder
            .build()
            .context("failed building rendezvous control HTTP client")?;
        Ok(Self {
            runtime_state: Arc::new(Mutex::new(TrackedRendezvousRuntimeState::new(
                &config.rendezvous_urls,
            ))),
            config,
            http,
        })
    }

    pub fn config(&self) -> &RendezvousClientConfig {
        &self.config
    }

    pub fn runtime_state(&self) -> RendezvousRuntimeState {
        self.runtime_state
            .lock()
            .expect("rendezvous runtime state lock poisoned")
            .snapshot(&self.config.rendezvous_urls)
    }

    pub async fn probe_endpoints(&self) -> Result<RendezvousRuntimeState> {
        self.probe_endpoints_with_path("/control/presence").await
    }

    pub async fn probe_health_endpoints(&self) -> Result<RendezvousRuntimeState> {
        self.probe_endpoints_with_path("/health").await
    }

    async fn probe_endpoints_with_path(&self, path: &str) -> Result<RendezvousRuntimeState> {
        for base_url in &self.config.rendezvous_urls {
            let url = control_url(base_url, path)?;
            let result = match self.http.get(url.clone()).send().await {
                Ok(response) => match response.error_for_status() {
                    Ok(_) => Ok(()),
                    Err(err) => Err(format!("rendezvous endpoint {url} returned error: {err}")),
                },
                Err(err) => Err(format!(
                    "failed contacting rendezvous endpoint {url}: {err}"
                )),
            };
            self.record_endpoint_result(base_url, result, false);
        }

        Ok(self.runtime_state())
    }

    pub async fn register_presence(
        &self,
        registration: &PresenceRegistration,
    ) -> Result<RegisterPresenceResponse> {
        registration.validate()?;
        if registration.cluster_id != self.config.cluster_id {
            bail!(
                "presence registration cluster_id {} does not match rendezvous client cluster_id {}",
                registration.cluster_id,
                self.config.cluster_id
            );
        }
        self.post_json("/control/presence/register", registration)
            .await
    }

    pub async fn list_presence(&self) -> Result<PresenceListResponse> {
        self.get_json("/control/presence").await
    }

    pub async fn issue_relay_ticket(&self, request: &RelayTicketRequest) -> Result<RelayTicket> {
        request.validate()?;
        if request.cluster_id != self.config.cluster_id {
            bail!(
                "relay ticket request cluster_id {} does not match rendezvous client cluster_id {}",
                request.cluster_id,
                self.config.cluster_id
            );
        }
        self.post_json("/control/relay/ticket", request).await
    }

    pub async fn submit_relay_http_request(
        &self,
        request: &RelayHttpRequest,
    ) -> Result<RelayHttpResponse> {
        request.validate()?;
        if request.ticket.cluster_id != self.config.cluster_id {
            bail!(
                "relay HTTP request cluster_id {} does not match rendezvous client cluster_id {}",
                request.ticket.cluster_id,
                self.config.cluster_id
            );
        }
        self.post_json("/relay/http/request", request).await
    }

    pub async fn poll_relay_http_request(
        &self,
        request: &RelayHttpPollRequest,
    ) -> Result<RelayHttpPollResponse> {
        request.validate()?;
        if request.cluster_id != self.config.cluster_id {
            bail!(
                "relay HTTP poll request cluster_id {} does not match rendezvous client cluster_id {}",
                request.cluster_id,
                self.config.cluster_id
            );
        }
        self.post_json("/relay/http/poll", request).await
    }

    pub async fn respond_relay_http_request(&self, response: &RelayHttpResponse) -> Result<()> {
        response.validate()?;
        let _: serde_json::Value = self.post_json("/relay/http/respond", response).await?;
        Ok(())
    }

    async fn get_json<T>(&self, path: &str) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let mut last_error = None;
        for base_url in &self.config.rendezvous_urls {
            let url = control_url(base_url, path)?;
            match self.http.get(url.clone()).send().await {
                Ok(response) => match response.error_for_status() {
                    Ok(ok_response) => match ok_response.json::<T>().await {
                        Ok(payload) => {
                            self.record_endpoint_result(base_url, Ok(()), true);
                            return Ok(payload);
                        }
                        Err(err) => {
                            let message =
                                format!("failed decoding rendezvous response from {url}: {err}");
                            self.record_endpoint_result(base_url, Err(message.clone()), true);
                            return Err(anyhow!(message));
                        }
                    },
                    Err(err) => {
                        let message = format!("rendezvous endpoint {url} returned error: {err}");
                        self.record_endpoint_result(base_url, Err(message.clone()), true);
                        last_error = Some(anyhow!(message));
                    }
                },
                Err(err) => {
                    let message = format!("failed contacting rendezvous endpoint {url}: {err}");
                    self.record_endpoint_result(base_url, Err(message.clone()), true);
                    last_error = Some(anyhow!(message));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("rendezvous client has no configured URLs")))
    }

    async fn post_json<Body, T>(&self, path: &str, body: &Body) -> Result<T>
    where
        Body: Serialize + ?Sized,
        T: DeserializeOwned,
    {
        let mut last_error = None;
        for base_url in &self.config.rendezvous_urls {
            let url = control_url(base_url, path)?;
            match self.http.post(url.clone()).json(body).send().await {
                Ok(response) => match response.error_for_status() {
                    Ok(ok_response) => match ok_response.json::<T>().await {
                        Ok(payload) => {
                            self.record_endpoint_result(base_url, Ok(()), true);
                            return Ok(payload);
                        }
                        Err(err) => {
                            let message =
                                format!("failed decoding rendezvous response from {url}: {err}");
                            self.record_endpoint_result(base_url, Err(message.clone()), true);
                            return Err(anyhow!(message));
                        }
                    },
                    Err(err) => {
                        let message = format!("rendezvous endpoint {url} returned error: {err}");
                        self.record_endpoint_result(base_url, Err(message.clone()), true);
                        last_error = Some(anyhow!(message));
                    }
                },
                Err(err) => {
                    let message = format!("failed contacting rendezvous endpoint {url}: {err}");
                    self.record_endpoint_result(base_url, Err(message.clone()), true);
                    last_error = Some(anyhow!(message));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("rendezvous client has no configured URLs")))
    }

    fn record_endpoint_result(
        &self,
        base_url: &str,
        result: std::result::Result<(), String>,
        mark_active: bool,
    ) {
        self.runtime_state
            .lock()
            .expect("rendezvous runtime state lock poisoned")
            .record_result(base_url, result, mark_active);
    }
}

impl TrackedRendezvousRuntimeState {
    fn new(urls: &[String]) -> Self {
        let mut state = Self::default();
        state.ensure_urls(urls);
        state
    }

    fn ensure_urls(&mut self, urls: &[String]) {
        for url in urls {
            let normalized = normalized_endpoint_url(url);
            self.endpoints
                .entry(normalized.clone())
                .or_insert_with(|| RendezvousEndpointStatus {
                    url: normalized,
                    status: RendezvousEndpointConnectionState::Unknown,
                    last_attempt_unix: None,
                    last_success_unix: None,
                    consecutive_failures: 0,
                    last_error: None,
                    active: false,
                });
        }
    }

    fn record_result(
        &mut self,
        base_url: &str,
        result: std::result::Result<(), String>,
        mark_active: bool,
    ) {
        let now = unix_timestamp();
        let normalized = normalized_endpoint_url(base_url);
        let endpoint =
            self.endpoints
                .entry(normalized.clone())
                .or_insert_with(|| RendezvousEndpointStatus {
                    url: normalized.clone(),
                    status: RendezvousEndpointConnectionState::Unknown,
                    last_attempt_unix: None,
                    last_success_unix: None,
                    consecutive_failures: 0,
                    last_error: None,
                    active: false,
                });
        endpoint.last_attempt_unix = Some(now);

        match result {
            Ok(()) => {
                endpoint.status = RendezvousEndpointConnectionState::Connected;
                endpoint.last_success_unix = Some(now);
                endpoint.consecutive_failures = 0;
                endpoint.last_error = None;
                if mark_active {
                    self.active_url = Some(endpoint.url.clone());
                }
            }
            Err(error) => {
                endpoint.status = RendezvousEndpointConnectionState::Disconnected;
                endpoint.consecutive_failures = endpoint.consecutive_failures.saturating_add(1);
                endpoint.last_error = Some(error);
                if mark_active && self.active_url.as_deref() == Some(endpoint.url.as_str()) {
                    self.active_url = None;
                }
            }
        }
    }

    fn snapshot(&self, urls: &[String]) -> RendezvousRuntimeState {
        let mut endpoint_statuses = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for url in urls {
            let normalized = normalized_endpoint_url(url);
            if !seen.insert(normalized.clone()) {
                continue;
            }
            if let Some(endpoint) = self.endpoints.get(&normalized) {
                let mut endpoint = endpoint.clone();
                endpoint.active = self.active_url.as_deref() == Some(endpoint.url.as_str());
                endpoint_statuses.push(endpoint);
            } else {
                endpoint_statuses.push(RendezvousEndpointStatus {
                    url: normalized.clone(),
                    status: RendezvousEndpointConnectionState::Unknown,
                    last_attempt_unix: None,
                    last_success_unix: None,
                    consecutive_failures: 0,
                    last_error: None,
                    active: self.active_url.as_deref() == Some(normalized.as_str()),
                });
            }
        }

        RendezvousRuntimeState {
            active_url: self.active_url.clone(),
            endpoint_statuses,
        }
    }
}

fn default_heartbeat_interval_secs() -> u64 {
    15
}

fn normalized_endpoint_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_string()
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|value| value.as_secs())
        .unwrap_or(0)
}

fn control_url(base_url: &str, path: &str) -> Result<Url> {
    Url::parse(base_url.trim())
        .with_context(|| format!("invalid rendezvous base URL {}", base_url))?
        .join(path.trim_start_matches('/'))
        .with_context(|| {
            format!("failed to build rendezvous control URL from {base_url} and {path}")
        })
}

fn validate_optional_url(field_name: &str, value: Option<&str>) -> Result<()> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    Url::parse(value).with_context(|| format!("invalid {field_name} URL {value}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::{Json, Router, routing::get};
    use uuid::Uuid;

    #[tokio::test]
    async fn runtime_state_tracks_failed_and_active_rendezvous_endpoints() {
        let cluster_id = Uuid::now_v7();
        let unused_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("unused listener should bind");
        let unused_addr = unused_listener
            .local_addr()
            .expect("unused listener should expose addr");
        drop(unused_listener);

        let router = Router::new().route(
            "/control/presence",
            get(|| async {
                Json(PresenceListResponse {
                    registered_endpoints: 0,
                    entries: Vec::new(),
                })
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("test rendezvous server should run");
        });

        let healthy_url = format!("http://{addr}");
        let client = RendezvousControlClient::new(
            RendezvousClientConfig {
                cluster_id,
                rendezvous_urls: vec![format!("http://{unused_addr}"), healthy_url.clone()],
                heartbeat_interval_secs: 15,
            },
            None,
            None,
        )
        .expect("rendezvous client should build");

        client
            .list_presence()
            .await
            .expect("list presence should succeed");

        let runtime_state = client.runtime_state();
        assert_eq!(
            runtime_state.active_url.as_deref(),
            Some(healthy_url.as_str())
        );
        assert_eq!(runtime_state.endpoint_statuses.len(), 2);
        assert_eq!(
            runtime_state.endpoint_statuses[0].status,
            RendezvousEndpointConnectionState::Disconnected
        );
        assert_eq!(
            runtime_state.endpoint_statuses[1].status,
            RendezvousEndpointConnectionState::Connected
        );
        assert!(runtime_state.endpoint_statuses[1].active);

        let probed_state = client
            .probe_endpoints()
            .await
            .expect("probing endpoints should succeed");
        assert_eq!(
            probed_state.active_url.as_deref(),
            Some(healthy_url.as_str())
        );
        assert!(probed_state.endpoint_statuses[1].active);

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn health_probe_succeeds_when_presence_endpoint_is_unauthorized() {
        let cluster_id = Uuid::now_v7();
        let router = Router::new()
            .route(
                "/health",
                get(|| async { Json(serde_json::json!({ "status": "ok" })) }),
            )
            .route(
                "/control/presence",
                get(|| async { (StatusCode::UNAUTHORIZED, "node certificate required") }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("test rendezvous server should run");
        });

        let healthy_url = format!("http://{addr}");
        let client = RendezvousControlClient::new(
            RendezvousClientConfig {
                cluster_id,
                rendezvous_urls: vec![healthy_url.clone()],
                heartbeat_interval_secs: 15,
            },
            None,
            None,
        )
        .expect("rendezvous client should build");

        let presence_probe = client
            .probe_endpoints()
            .await
            .expect("probe should complete");
        assert_eq!(
            presence_probe.endpoint_statuses[0].status,
            RendezvousEndpointConnectionState::Disconnected
        );
        assert!(
            presence_probe.endpoint_statuses[0]
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("401"))
        );

        let health_probe = client
            .probe_health_endpoints()
            .await
            .expect("health probe should succeed");
        assert_eq!(health_probe.active_url, None);
        assert_eq!(
            health_probe.endpoint_statuses[0].status,
            RendezvousEndpointConnectionState::Connected
        );
        assert!(!health_probe.endpoint_statuses[0].active);
        assert_eq!(health_probe.endpoint_statuses[0].url, healthy_url);

        server.abort();
        let _ = server.await;
    }
}
