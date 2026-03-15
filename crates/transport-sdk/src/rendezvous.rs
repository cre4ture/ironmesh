use anyhow::{Result, bail};
use common::ClusterId;
use reqwest::Url;
use serde::{Deserialize, Serialize};

use crate::bootstrap::RelayMode;
use crate::candidates::ConnectionCandidate;
use crate::peer::PeerIdentity;

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
    pub direct_candidates: Vec<ConnectionCandidate>,
    #[serde(default)]
    pub capabilities: Vec<TransportCapability>,
    #[serde(default)]
    pub relay_mode: RelayMode,
    pub connected_at_unix: u64,
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
        for candidate in &self.direct_candidates {
            candidate.validate()?;
        }
        Ok(())
    }
}

fn default_heartbeat_interval_secs() -> u64 {
    15
}
