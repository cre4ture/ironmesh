use anyhow::{Result, bail};
use common::ClusterId;
use serde::{Deserialize, Serialize};

use crate::peer::PeerIdentity;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RelayTunnelSessionKind {
    #[default]
    MultiplexTransport,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayTicketRequest {
    pub cluster_id: ClusterId,
    pub source: PeerIdentity,
    pub target: PeerIdentity,
    #[serde(default)]
    pub session_kind: RelayTunnelSessionKind,
    #[serde(default)]
    pub requested_expires_in_secs: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayTicket {
    pub cluster_id: ClusterId,
    pub session_id: String,
    pub source: PeerIdentity,
    pub target: PeerIdentity,
    #[serde(default)]
    pub session_kind: RelayTunnelSessionKind,
    pub relay_urls: Vec<String>,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayHttpHeader {
    pub name: String,
    pub value: String,
}

impl RelayTicketRequest {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("relay ticket request must include a non-nil cluster_id");
        }
        Ok(())
    }
}

impl RelayTicket {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("relay ticket must include a non-nil cluster_id");
        }
        if self.session_id.trim().is_empty() {
            bail!("relay ticket must include a session_id");
        }
        if self.relay_urls.is_empty() {
            bail!("relay ticket must include at least one relay URL");
        }
        if self.expires_at_unix <= self.issued_at_unix {
            bail!("relay ticket expires_at_unix must be greater than issued_at_unix");
        }
        Ok(())
    }
}
