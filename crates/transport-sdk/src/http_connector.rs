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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::TransportPathKind;
    use uuid::Uuid;

    #[test]
    fn transport_http_client_config_defaults_to_http2_without_path_kind() {
        let config = TransportHttpClientConfig::default();
        assert!(config.prefer_http2);
        assert_eq!(config.expected_path_kind, None);
    }

    #[test]
    fn transport_http_request_target_roundtrips_via_json() {
        let target = TransportHttpRequestTarget {
            cluster_id: Uuid::now_v7(),
            route_kind: HttpRouteKind::RendezvousControl,
            peer: None,
        };
        let encoded = serde_json::to_string(&target).expect("target should serialize");
        let decoded: TransportHttpRequestTarget =
            serde_json::from_str(&encoded).expect("target should deserialize");
        assert_eq!(decoded, target);
    }

    #[test]
    fn transport_http_client_config_roundtrips_expected_path_kind() {
        let config = TransportHttpClientConfig {
            prefer_http2: false,
            expected_path_kind: Some(TransportPathKind::RelayTunnel),
        };
        let encoded = serde_json::to_string(&config).expect("config should serialize");
        let decoded: TransportHttpClientConfig =
            serde_json::from_str(&encoded).expect("config should deserialize");
        assert_eq!(decoded, config);
    }
}
