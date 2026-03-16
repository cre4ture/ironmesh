use anyhow::{Context, Result, anyhow, bail};
use common::ClusterId;
use reqwest::{Certificate, Client, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashMap;

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

#[derive(Debug, Clone)]
pub struct RendezvousControlClient {
    config: RendezvousClientConfig,
    http: Client,
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
    pub fn new(config: RendezvousClientConfig, server_ca_pem: Option<&str>) -> Result<Self> {
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

        let http = builder
            .build()
            .context("failed building rendezvous control HTTP client")?;
        Ok(Self { config, http })
    }

    pub fn config(&self) -> &RendezvousClientConfig {
        &self.config
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
                    Ok(ok_response) => {
                        return ok_response.json::<T>().await.with_context(|| {
                            format!("failed decoding rendezvous response from {url}")
                        });
                    }
                    Err(err) => {
                        last_error =
                            Some(anyhow!("rendezvous endpoint {url} returned error: {err}"));
                    }
                },
                Err(err) => {
                    last_error = Some(anyhow!(
                        "failed contacting rendezvous endpoint {url}: {err}"
                    ));
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
                    Ok(ok_response) => {
                        return ok_response.json::<T>().await.with_context(|| {
                            format!("failed decoding rendezvous response from {url}")
                        });
                    }
                    Err(err) => {
                        last_error =
                            Some(anyhow!("rendezvous endpoint {url} returned error: {err}"));
                    }
                },
                Err(err) => {
                    last_error = Some(anyhow!(
                        "failed contacting rendezvous endpoint {url}: {err}"
                    ));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow!("rendezvous client has no configured URLs")))
    }
}

fn default_heartbeat_interval_secs() -> u64 {
    15
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
