use common::ClusterId;
use serde::{Deserialize, Serialize};

use crate::candidates::{CandidateKind, ConnectionCandidate, rank_candidates};
use crate::peer::PeerIdentity;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportPathKind {
    DirectHttps,
    DirectQuic,
    RelayTunnel,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionPreference {
    pub prefer_direct: bool,
    pub allow_relay: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportSessionRequest {
    pub cluster_id: ClusterId,
    pub target: PeerIdentity,
    pub preference: SessionPreference,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportSessionPlan {
    pub cluster_id: ClusterId,
    pub target: PeerIdentity,
    pub path_kind: TransportPathKind,
    #[serde(default)]
    pub candidate: Option<ConnectionCandidate>,
}

impl Default for SessionPreference {
    fn default() -> Self {
        Self {
            prefer_direct: true,
            allow_relay: true,
        }
    }
}

pub fn select_session_plan(
    request: &TransportSessionRequest,
    candidates: &[ConnectionCandidate],
) -> Option<TransportSessionPlan> {
    let mut ranked = rank_candidates(candidates);
    if !request.preference.prefer_direct {
        ranked.sort_by_key(|candidate| match candidate.kind {
            CandidateKind::Relay => 0,
            _ => 1,
        });
    }

    for candidate in ranked {
        if candidate.kind == CandidateKind::Relay && !request.preference.allow_relay {
            continue;
        }

        return Some(TransportSessionPlan {
            cluster_id: request.cluster_id,
            target: request.target.clone(),
            path_kind: candidate_path_kind(candidate.kind),
            candidate: Some(candidate),
        });
    }

    None
}

fn candidate_path_kind(kind: CandidateKind) -> TransportPathKind {
    match kind {
        CandidateKind::DirectHttps => TransportPathKind::DirectHttps,
        CandidateKind::DirectQuic | CandidateKind::ServerReflexiveQuic => {
            TransportPathKind::DirectQuic
        }
        CandidateKind::Relay => TransportPathKind::RelayTunnel,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn request(prefer_direct: bool, allow_relay: bool) -> TransportSessionRequest {
        TransportSessionRequest {
            cluster_id: Uuid::now_v7(),
            target: PeerIdentity::Node(Uuid::now_v7()),
            preference: SessionPreference {
                prefer_direct,
                allow_relay,
            },
        }
    }

    #[test]
    fn session_preference_defaults_to_direct_with_relay_allowed() {
        let preference = SessionPreference::default();
        assert!(preference.prefer_direct);
        assert!(preference.allow_relay);
    }

    #[test]
    fn select_session_plan_prefers_direct_candidates_by_default() {
        let request = request(true, true);
        let plan = select_session_plan(
            &request,
            &[
                ConnectionCandidate {
                    kind: CandidateKind::Relay,
                    endpoint: "https://relay.example".to_string(),
                    rtt_ms: Some(30),
                },
                ConnectionCandidate {
                    kind: CandidateKind::DirectHttps,
                    endpoint: "https://node.example".to_string(),
                    rtt_ms: Some(10),
                },
            ],
        )
        .expect("a direct session plan should be selected");

        assert_eq!(plan.path_kind, TransportPathKind::DirectHttps);
        assert_eq!(
            plan.candidate.expect("candidate should be present").kind,
            CandidateKind::DirectHttps
        );
    }

    #[test]
    fn select_session_plan_prefers_relay_when_direct_is_disabled() {
        let request = request(false, true);
        let plan = select_session_plan(
            &request,
            &[
                ConnectionCandidate {
                    kind: CandidateKind::DirectQuic,
                    endpoint: "https://node.example:4433".to_string(),
                    rtt_ms: Some(10),
                },
                ConnectionCandidate {
                    kind: CandidateKind::Relay,
                    endpoint: "https://relay.example".to_string(),
                    rtt_ms: Some(20),
                },
            ],
        )
        .expect("a relay session plan should be selected");

        assert_eq!(plan.path_kind, TransportPathKind::RelayTunnel);
        assert_eq!(
            plan.candidate.expect("candidate should be present").kind,
            CandidateKind::Relay
        );
    }

    #[test]
    fn select_session_plan_skips_relay_candidates_when_relay_is_disabled() {
        let request = request(true, false);
        let plan = select_session_plan(
            &request,
            &[ConnectionCandidate {
                kind: CandidateKind::Relay,
                endpoint: "https://relay.example".to_string(),
                rtt_ms: Some(10),
            }],
        );

        assert!(plan.is_none());
    }

    #[test]
    fn select_session_plan_maps_quic_candidates_to_direct_quic_path() {
        let request = request(true, true);
        let plan = select_session_plan(
            &request,
            &[ConnectionCandidate {
                kind: CandidateKind::ServerReflexiveQuic,
                endpoint: "https://reflexive.example:4433".to_string(),
                rtt_ms: Some(10),
            }],
        )
        .expect("a quic session plan should be selected");

        assert_eq!(plan.path_kind, TransportPathKind::DirectQuic);
    }
}
