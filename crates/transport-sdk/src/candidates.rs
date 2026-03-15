use std::cmp::Ordering;

use anyhow::{Context, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    DirectHttps,
    DirectQuic,
    ServerReflexiveQuic,
    Relay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionCandidate {
    pub kind: CandidateKind,
    pub endpoint: String,
    #[serde(default)]
    pub rtt_ms: Option<u32>,
}

impl ConnectionCandidate {
    pub fn validate(&self) -> Result<()> {
        if self.endpoint.trim().is_empty() {
            anyhow::bail!("candidate endpoint must not be empty");
        }
        Url::parse(self.endpoint.trim())
            .with_context(|| format!("invalid candidate endpoint {}", self.endpoint))?;
        Ok(())
    }
}

pub fn rank_candidates(candidates: &[ConnectionCandidate]) -> Vec<ConnectionCandidate> {
    let mut ranked = candidates.to_vec();
    ranked.sort_by(compare_candidates);
    ranked
}

fn compare_candidates(left: &ConnectionCandidate, right: &ConnectionCandidate) -> Ordering {
    candidate_priority(left.kind)
        .cmp(&candidate_priority(right.kind))
        .then_with(|| compare_rtt(left.rtt_ms, right.rtt_ms))
        .then_with(|| left.endpoint.cmp(&right.endpoint))
}

fn candidate_priority(kind: CandidateKind) -> u8 {
    match kind {
        CandidateKind::DirectQuic => 0,
        CandidateKind::DirectHttps => 1,
        CandidateKind::ServerReflexiveQuic => 2,
        CandidateKind::Relay => 3,
    }
}

fn compare_rtt(left: Option<u32>, right: Option<u32>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => left.cmp(&right),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranks_direct_candidates_before_relay() {
        let ranked = rank_candidates(&[
            ConnectionCandidate {
                kind: CandidateKind::Relay,
                endpoint: "https://relay.example/session/1".to_string(),
                rtt_ms: Some(10),
            },
            ConnectionCandidate {
                kind: CandidateKind::DirectHttps,
                endpoint: "https://node.example".to_string(),
                rtt_ms: Some(30),
            },
            ConnectionCandidate {
                kind: CandidateKind::DirectQuic,
                endpoint: "https://node.example:4433".to_string(),
                rtt_ms: Some(50),
            },
        ]);

        assert_eq!(ranked[0].kind, CandidateKind::DirectQuic);
        assert_eq!(ranked[1].kind, CandidateKind::DirectHttps);
        assert_eq!(ranked[2].kind, CandidateKind::Relay);
    }
}
