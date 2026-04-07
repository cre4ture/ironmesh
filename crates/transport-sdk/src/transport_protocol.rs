use anyhow::{Result, bail};
use common::ClusterId;
use serde::{Deserialize, Serialize};

use crate::peer::PeerIdentity;

pub const TRANSPORT_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransportHeader {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportSessionRole {
    Client,
    Node,
    RelayBridge,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TransportStreamKind {
    Rpc,
    ObjectRead,
    ObjectWrite,
    Subscription,
    Diagnostics,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransportSessionControlMessage {
    Hello {
        protocol_version: u16,
        cluster_id: ClusterId,
        role: TransportSessionRole,
        peer: PeerIdentity,
        #[serde(default)]
        target: Option<PeerIdentity>,
    },
    Ready {
        protocol_version: u16,
        session_id: String,
        max_concurrent_streams: usize,
    },
    Ping {
        sent_at_unix_ms: u64,
    },
    Pong {
        sent_at_unix_ms: u64,
    },
    GoAway {
        #[serde(default)]
        reason: Option<String>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransportStreamControlMessage {
    RequestHead {
        request_id: String,
        kind: TransportStreamKind,
        method: String,
        path: String,
        #[serde(default)]
        headers: Vec<TransportHeader>,
        #[serde(default)]
        end_of_stream: bool,
    },
    ResponseHead {
        request_id: String,
        status: u16,
        #[serde(default)]
        headers: Vec<TransportHeader>,
    },
    Finish,
    Cancel {
        #[serde(default)]
        reason: Option<String>,
    },
    Error {
        message: String,
    },
}

impl TransportHeader {
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            bail!("transport header name must not be empty");
        }
        Ok(())
    }
}

impl TransportSessionControlMessage {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Hello {
                protocol_version,
                cluster_id,
                ..
            } => {
                if *protocol_version != TRANSPORT_PROTOCOL_VERSION {
                    bail!("transport hello uses unsupported protocol_version");
                }
                if cluster_id.is_nil() {
                    bail!("transport hello must include a non-nil cluster_id");
                }
            }
            Self::Ready {
                protocol_version,
                session_id,
                max_concurrent_streams,
            } => {
                if *protocol_version != TRANSPORT_PROTOCOL_VERSION {
                    bail!("transport ready uses unsupported protocol_version");
                }
                if session_id.trim().is_empty() {
                    bail!("transport ready must include a session_id");
                }
                if *max_concurrent_streams == 0 {
                    bail!("transport ready max_concurrent_streams must be greater than zero");
                }
            }
            Self::Ping { .. } | Self::Pong { .. } | Self::GoAway { .. } => {}
            Self::Error { message } => {
                if message.trim().is_empty() {
                    bail!("transport session error message must not be empty");
                }
            }
        }
        Ok(())
    }
}

impl TransportStreamControlMessage {
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::RequestHead {
                request_id,
                method,
                path,
                headers,
                ..
            } => {
                if request_id.trim().is_empty() {
                    bail!("transport request head must include a request_id");
                }
                if method.trim().is_empty() {
                    bail!("transport request head must include a method");
                }
                if !path.starts_with('/') {
                    bail!("transport request head path must start with '/'");
                }
                for header in headers {
                    header.validate()?;
                }
            }
            Self::ResponseHead {
                request_id,
                status,
                headers,
            } => {
                if request_id.trim().is_empty() {
                    bail!("transport response head must include a request_id");
                }
                if !(100..=599).contains(status) {
                    bail!("transport response head must include a valid HTTP status");
                }
                for header in headers {
                    header.validate()?;
                }
            }
            Self::Finish => {}
            Self::Cancel { .. } => {}
            Self::Error { message } => {
                if message.trim().is_empty() {
                    bail!("transport stream error message must not be empty");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn session_control_message_round_trips_through_json() {
        let message = TransportSessionControlMessage::Hello {
            protocol_version: TRANSPORT_PROTOCOL_VERSION,
            cluster_id: Uuid::now_v7(),
            role: TransportSessionRole::Client,
            peer: PeerIdentity::Device(Uuid::now_v7()),
            target: Some(PeerIdentity::Node(Uuid::now_v7())),
        };

        let json =
            serde_json::to_string(&message).expect("session control message should serialize");
        let decoded: TransportSessionControlMessage =
            serde_json::from_str(&json).expect("session control message should deserialize");

        assert_eq!(decoded, message);
        decoded
            .validate()
            .expect("decoded session control message should validate");
    }

    #[test]
    fn stream_control_message_round_trips_through_json() {
        let message = TransportStreamControlMessage::RequestHead {
            request_id: "req-1".to_string(),
            kind: TransportStreamKind::Diagnostics,
            method: "GET".to_string(),
            path: "/diagnostics/latency".to_string(),
            headers: vec![TransportHeader {
                name: "accept".to_string(),
                value: "application/json".to_string(),
            }],
            end_of_stream: true,
        };

        let json =
            serde_json::to_string(&message).expect("stream control message should serialize");
        let decoded: TransportStreamControlMessage =
            serde_json::from_str(&json).expect("stream control message should deserialize");

        assert_eq!(decoded, message);
        decoded
            .validate()
            .expect("decoded stream control message should validate");
    }
}
