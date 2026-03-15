use std::fmt;

use anyhow::{Result, bail};
use common::{ClusterId, DeviceId, NodeId};
use serde::{Deserialize, Serialize};

use crate::candidates::ConnectionCandidate;
use crate::session::{
    SessionPreference, TransportSessionPlan, TransportSessionRequest, select_session_plan,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum PeerIdentity {
    Node(NodeId),
    Device(DeviceId),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PeerTransportClientConfig {
    pub cluster_id: ClusterId,
    #[serde(default = "default_true")]
    pub prefer_direct: bool,
    #[serde(default = "default_true")]
    pub allow_relay: bool,
}

#[derive(Debug, Clone)]
pub struct PeerTransportClient {
    config: PeerTransportClientConfig,
}

impl PeerTransportClient {
    pub fn new(config: PeerTransportClientConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &PeerTransportClientConfig {
        &self.config
    }

    pub fn session_request(&self, target: PeerIdentity) -> TransportSessionRequest {
        TransportSessionRequest {
            cluster_id: self.config.cluster_id,
            target,
            preference: SessionPreference {
                prefer_direct: self.config.prefer_direct,
                allow_relay: self.config.allow_relay,
            },
        }
    }

    pub fn plan_session(
        &self,
        target: PeerIdentity,
        candidates: &[ConnectionCandidate],
    ) -> Option<TransportSessionPlan> {
        let request = self.session_request(target);
        select_session_plan(&request, candidates)
    }
}

impl PeerTransportClientConfig {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("peer transport client config must include a non-nil cluster_id");
        }
        if !self.prefer_direct && !self.allow_relay {
            bail!("peer transport config cannot disable both direct and relay connectivity");
        }
        Ok(())
    }
}

impl fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Node(node_id) => write!(f, "node:{node_id}"),
            Self::Device(device_id) => write!(f, "device:{device_id}"),
        }
    }
}

fn default_true() -> bool {
    true
}
