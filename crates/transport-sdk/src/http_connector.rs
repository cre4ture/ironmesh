use common::ClusterId;
use serde::{Deserialize, Serialize};

use crate::peer::PeerIdentity;
use crate::session::TransportPathKind;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpRouteKind {
    PublicApi,
    PeerApi,
    RendezvousControl,
    RelayControl,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportHttpRequestTarget {
    pub cluster_id: ClusterId,
    pub route_kind: HttpRouteKind,
    #[serde(default)]
    pub peer: Option<PeerIdentity>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportHttpClientConfig {
    #[serde(default = "default_true")]
    pub prefer_http2: bool,
    #[serde(default)]
    pub expected_path_kind: Option<TransportPathKind>,
}

impl Default for TransportHttpClientConfig {
    fn default() -> Self {
        Self {
            prefer_http2: true,
            expected_path_kind: None,
        }
    }
}

fn default_true() -> bool {
    true
}
