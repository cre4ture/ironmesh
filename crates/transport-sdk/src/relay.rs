use anyhow::{Context, Result, bail};
use base64::Engine;
use common::ClusterId;
use serde::{Deserialize, Serialize};

use crate::peer::PeerIdentity;

pub const RELAY_HTTP_JSON_BODY_LIMIT_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RelayTunnelSessionKind {
    #[default]
    LegacyHttpTunnel,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayHttpRequest {
    pub ticket: RelayTicket,
    pub request_id: String,
    pub method: String,
    pub path_and_query: String,
    #[serde(default)]
    pub headers: Vec<RelayHttpHeader>,
    #[serde(default)]
    pub body_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingRelayHttpRequest {
    pub cluster_id: ClusterId,
    pub session_id: String,
    pub request_id: String,
    pub source: PeerIdentity,
    pub target: PeerIdentity,
    pub method: String,
    pub path_and_query: String,
    #[serde(default)]
    pub headers: Vec<RelayHttpHeader>,
    #[serde(default)]
    pub body_base64: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayHttpPollRequest {
    pub cluster_id: ClusterId,
    pub target: PeerIdentity,
    #[serde(default)]
    pub wait_timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayHttpPollResponse {
    #[serde(default)]
    pub request: Option<PendingRelayHttpRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayHttpResponse {
    pub cluster_id: ClusterId,
    pub session_id: String,
    pub request_id: String,
    pub responder: PeerIdentity,
    pub status: u16,
    #[serde(default)]
    pub headers: Vec<RelayHttpHeader>,
    #[serde(default)]
    pub body_base64: Option<String>,
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

impl RelayHttpRequest {
    pub fn validate(&self) -> Result<()> {
        self.ticket.validate()?;
        if self.request_id.trim().is_empty() {
            bail!("relay HTTP request must include a request_id");
        }
        if self.method.trim().is_empty() {
            bail!("relay HTTP request must include a method");
        }
        validate_path_and_query(&self.path_and_query)?;
        validate_headers(&self.headers)?;
        validate_body_base64(self.body_base64.as_deref())?;
        Ok(())
    }

    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        decode_optional_body_base64(self.body_base64.as_deref())
    }
}

impl PendingRelayHttpRequest {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("pending relay HTTP request must include a non-nil cluster_id");
        }
        if self.session_id.trim().is_empty() {
            bail!("pending relay HTTP request must include a session_id");
        }
        if self.request_id.trim().is_empty() {
            bail!("pending relay HTTP request must include a request_id");
        }
        if self.method.trim().is_empty() {
            bail!("pending relay HTTP request must include a method");
        }
        validate_path_and_query(&self.path_and_query)?;
        validate_headers(&self.headers)?;
        validate_body_base64(self.body_base64.as_deref())?;
        Ok(())
    }

    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        decode_optional_body_base64(self.body_base64.as_deref())
    }
}

impl RelayHttpPollRequest {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("relay HTTP poll request must include a non-nil cluster_id");
        }
        Ok(())
    }
}

impl RelayHttpResponse {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("relay HTTP response must include a non-nil cluster_id");
        }
        if self.session_id.trim().is_empty() {
            bail!("relay HTTP response must include a session_id");
        }
        if self.request_id.trim().is_empty() {
            bail!("relay HTTP response must include a request_id");
        }
        if !(100..=599).contains(&self.status) {
            bail!("relay HTTP response status must be a valid HTTP status code");
        }
        validate_headers(&self.headers)?;
        validate_body_base64(self.body_base64.as_deref())?;
        Ok(())
    }

    pub fn body_bytes(&self) -> Result<Vec<u8>> {
        decode_optional_body_base64(self.body_base64.as_deref())
    }

    pub fn from_body_bytes(mut self, bytes: &[u8]) -> Self {
        self.body_base64 = encode_optional_body_base64(bytes);
        self
    }
}

pub fn encode_optional_body_base64(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() {
        None
    } else {
        Some(base64::engine::general_purpose::STANDARD.encode(bytes))
    }
}

fn decode_optional_body_base64(value: Option<&str>) -> Result<Vec<u8>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };
    base64::engine::general_purpose::STANDARD
        .decode(value)
        .context("failed to decode relay HTTP body base64")
}

fn validate_headers(headers: &[RelayHttpHeader]) -> Result<()> {
    for header in headers {
        if header.name.trim().is_empty() {
            bail!("relay HTTP header name must not be empty");
        }
    }
    Ok(())
}

fn validate_path_and_query(value: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() {
        bail!("relay HTTP path_and_query must not be empty");
    }
    if !value.starts_with('/') {
        bail!("relay HTTP path_and_query must start with '/'");
    }
    Ok(())
}

fn validate_body_base64(value: Option<&str>) -> Result<()> {
    let _ = decode_optional_body_base64(value)?;
    Ok(())
}
