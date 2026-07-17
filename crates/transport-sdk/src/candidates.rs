use std::cmp::Ordering;

use anyhow::{Context, Result};
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    DirectHttps,
    DirectQuic,
    #[serde(rename = "server_reflexive", alias = "server_reflexive_quic")]
    ServerReflexive,
    Relay,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ConnectionCandidateTransportHints {
    #[serde(default)]
    pub transport_id: Option<String>,
    #[serde(default)]
    pub relay_url: Option<String>,
    #[serde(default)]
    pub alpn: Option<String>,
    #[serde(default)]
    pub direct_socket_addrs: Vec<String>,
    #[serde(default)]
    pub observed_socket_addrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConnectionCandidate {
    pub kind: CandidateKind,
    pub endpoint: String,
    #[serde(default)]
    pub rtt_ms: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport_hints: Option<ConnectionCandidateTransportHints>,
}

impl ConnectionCandidate {
    pub fn validate(&self) -> Result<()> {
        if self.endpoint.trim().is_empty() {
            anyhow::bail!("candidate endpoint must not be empty");
        }
        Url::parse(self.endpoint.trim())
            .with_context(|| format!("invalid candidate endpoint {}", self.endpoint))?;
        if let Some(transport_hints) = &self.transport_hints {
            transport_hints.validate()?;
        }
        Ok(())
    }
}

impl ConnectionCandidateTransportHints {
    pub fn validate(&self) -> Result<()> {
        if self
            .transport_id
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            anyhow::bail!("candidate transport_id must not be blank when present");
        }
        if self
            .alpn
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            anyhow::bail!("candidate alpn must not be blank when present");
        }
        if let Some(relay_url) = self.relay_url.as_deref() {
            if relay_url.trim().is_empty() {
                anyhow::bail!("candidate relay_url must not be blank when present");
            }
            Url::parse(relay_url.trim())
                .with_context(|| format!("invalid candidate relay_url {relay_url}"))?;
        }
        validate_socket_addr_list("direct_socket_addrs", &self.direct_socket_addrs)?;
        validate_socket_addr_list("observed_socket_addrs", &self.observed_socket_addrs)?;
        Ok(())
    }
}

fn validate_socket_addr_list(field_name: &str, values: &[String]) -> Result<()> {
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            anyhow::bail!("candidate {field_name} entries must not be blank");
        }
        trimmed
            .parse::<std::net::SocketAddr>()
            .with_context(|| format!("invalid candidate {field_name} entry {value}"))?;
    }
    Ok(())
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
        CandidateKind::ServerReflexive => 2,
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
                transport_hints: None,
            },
            ConnectionCandidate {
                kind: CandidateKind::DirectHttps,
                endpoint: "https://node.example".to_string(),
                rtt_ms: Some(30),
                transport_hints: None,
            },
            ConnectionCandidate {
                kind: CandidateKind::DirectQuic,
                endpoint: "https://node.example:4433".to_string(),
                rtt_ms: Some(50),
                transport_hints: None,
            },
        ]);

        assert_eq!(ranked[0].kind, CandidateKind::DirectQuic);
        assert_eq!(ranked[1].kind, CandidateKind::DirectHttps);
        assert_eq!(ranked[2].kind, CandidateKind::Relay);
    }

    #[test]
    fn ranks_server_reflexive_between_direct_and_relay() {
        let ranked = rank_candidates(&[
            ConnectionCandidate {
                kind: CandidateKind::Relay,
                endpoint: "https://relay.example/session/1".to_string(),
                rtt_ms: Some(10),
                transport_hints: None,
            },
            ConnectionCandidate {
                kind: CandidateKind::ServerReflexive,
                endpoint: "https://203.0.113.10:7443".to_string(),
                rtt_ms: Some(20),
                transport_hints: None,
            },
            ConnectionCandidate {
                kind: CandidateKind::DirectHttps,
                endpoint: "https://node.example".to_string(),
                rtt_ms: Some(30),
                transport_hints: None,
            },
        ]);

        assert_eq!(ranked[0].kind, CandidateKind::DirectHttps);
        assert_eq!(ranked[1].kind, CandidateKind::ServerReflexive);
        assert_eq!(ranked[2].kind, CandidateKind::Relay);
    }

    #[test]
    fn candidate_validation_rejects_blank_transport_hint_fields() {
        let error = ConnectionCandidate {
            kind: CandidateKind::DirectQuic,
            endpoint: "https://node.example:4433".to_string(),
            rtt_ms: None,
            transport_hints: Some(ConnectionCandidateTransportHints {
                transport_id: Some(" ".to_string()),
                relay_url: None,
                alpn: None,
                direct_socket_addrs: Vec::new(),
                observed_socket_addrs: Vec::new(),
            }),
        }
        .validate()
        .expect_err("blank transport id should fail");

        assert!(error.to_string().contains("transport_id"));
    }

    #[test]
    fn candidate_validation_rejects_invalid_relay_url_hint() {
        let error = ConnectionCandidate {
            kind: CandidateKind::DirectQuic,
            endpoint: "https://node.example:4433".to_string(),
            rtt_ms: None,
            transport_hints: Some(ConnectionCandidateTransportHints {
                transport_id: Some("peer-key-1".to_string()),
                relay_url: Some("not-a-url".to_string()),
                alpn: Some("iroh/0".to_string()),
                direct_socket_addrs: Vec::new(),
                observed_socket_addrs: Vec::new(),
            }),
        }
        .validate()
        .expect_err("invalid relay url should fail");

        assert!(error.to_string().contains("relay_url"));
    }

    #[test]
    fn candidate_validation_accepts_transport_hints() {
        ConnectionCandidate {
            kind: CandidateKind::DirectQuic,
            endpoint: "https://node.example:4433".to_string(),
            rtt_ms: Some(15),
            transport_hints: Some(ConnectionCandidateTransportHints {
                transport_id: Some("peer-key-1".to_string()),
                relay_url: Some("https://relay.example".to_string()),
                alpn: Some("iroh/0".to_string()),
                direct_socket_addrs: vec!["192.0.2.10:4242".to_string()],
                observed_socket_addrs: vec!["203.0.113.10:55000".to_string()],
            }),
        }
        .validate()
        .expect("valid transport hints should pass");
    }

    #[test]
    fn candidate_validation_rejects_invalid_direct_socket_addr_hint() {
        let error = ConnectionCandidate {
            kind: CandidateKind::DirectQuic,
            endpoint: "iroh://peer-key-1".to_string(),
            rtt_ms: None,
            transport_hints: Some(ConnectionCandidateTransportHints {
                transport_id: Some("peer-key-1".to_string()),
                relay_url: Some("https://relay.example".to_string()),
                alpn: Some("iroh/0".to_string()),
                direct_socket_addrs: vec!["not-a-socket-addr".to_string()],
                observed_socket_addrs: Vec::new(),
            }),
        }
        .validate()
        .expect_err("invalid direct socket addr should fail");

        assert!(error.to_string().contains("direct_socket_addrs"));
    }

    #[test]
    fn candidate_validation_rejects_blank_observed_socket_addr_hint() {
        let error = ConnectionCandidate {
            kind: CandidateKind::DirectQuic,
            endpoint: "iroh://peer-key-1".to_string(),
            rtt_ms: None,
            transport_hints: Some(ConnectionCandidateTransportHints {
                transport_id: Some("peer-key-1".to_string()),
                relay_url: Some("https://relay.example".to_string()),
                alpn: Some("iroh/0".to_string()),
                direct_socket_addrs: Vec::new(),
                observed_socket_addrs: vec![" ".to_string()],
            }),
        }
        .validate()
        .expect_err("blank observed socket addr should fail");

        assert!(error.to_string().contains("observed_socket_addrs"));
    }
}
