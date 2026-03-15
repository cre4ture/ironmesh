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
