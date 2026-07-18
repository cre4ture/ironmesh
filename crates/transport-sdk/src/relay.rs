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

/// Security protocol negotiated inside a paired relay tunnel.
///
/// `LegacyPlaintext` remains the serde default so older tickets and peers keep their existing
/// behavior during a staged rollout. Callers must opt into `InnerMtls`; conversion APIs reject a
/// session whose declared mode does not match the selected transport.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RelayTunnelSecurityMode {
    #[default]
    LegacyPlaintext,
    InnerMtls,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayTicketRequest {
    pub cluster_id: ClusterId,
    pub source: PeerIdentity,
    pub target: PeerIdentity,
    #[serde(default)]
    pub session_kind: RelayTunnelSessionKind,
    #[serde(default)]
    pub security_mode: RelayTunnelSecurityMode,
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
    #[serde(default)]
    pub security_mode: RelayTunnelSecurityMode,
    pub relay_urls: Vec<String>,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_ticket_request_defaults_missing_security_mode_to_legacy_plaintext() {
        let cluster_id = uuid::Uuid::now_v7();
        let source = PeerIdentity::Device(uuid::Uuid::now_v7());
        let target = PeerIdentity::Node(uuid::Uuid::now_v7());
        let request: RelayTicketRequest = serde_json::from_value(serde_json::json!({
            "cluster_id": cluster_id,
            "source": source,
            "target": target,
        }))
        .expect("legacy relay ticket request should deserialize");

        assert_eq!(
            request.security_mode,
            RelayTunnelSecurityMode::LegacyPlaintext
        );
    }

    #[test]
    fn relay_ticket_defaults_missing_security_mode_to_legacy_plaintext() {
        let cluster_id = uuid::Uuid::now_v7();
        let source = PeerIdentity::Device(uuid::Uuid::now_v7());
        let target = PeerIdentity::Node(uuid::Uuid::now_v7());
        let ticket: RelayTicket = serde_json::from_value(serde_json::json!({
            "cluster_id": cluster_id,
            "session_id": "legacy-session",
            "source": source,
            "target": target,
            "relay_urls": ["https://relay.example"],
            "issued_at_unix": 1,
            "expires_at_unix": 2,
        }))
        .expect("legacy relay ticket should deserialize");

        assert_eq!(
            ticket.security_mode,
            RelayTunnelSecurityMode::LegacyPlaintext
        );
    }
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
