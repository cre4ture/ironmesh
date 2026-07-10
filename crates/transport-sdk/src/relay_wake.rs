use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;

use crate::peer::PeerIdentity;
use crate::relay::RelayTunnelSessionKind;
use crate::websocket_client::{AsyncIo, connect_websocket, websocket_url};
use common::ClusterId;

/// A node's registration for the long-lived relay "wake" channel: instead of
/// repeatedly reopening a short-lived `AcceptTarget` connection to poll for a peer,
/// a node registers once on this channel and is pushed a `Wake` the instant a peer
/// is waiting for it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RelayWakeRegistration {
    pub cluster_id: ClusterId,
    pub target: PeerIdentity,
    #[serde(default)]
    pub session_kind: RelayTunnelSessionKind,
}

impl RelayWakeRegistration {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("relay wake registration must include a non-nil cluster_id");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RelayWakeControlMessage {
    Register { registration: RelayWakeRegistration },
    Registered,
    Wake,
    Error { message: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayWakeEvent {
    Wake,
    Closed,
}

pub struct RelayWakeClient {
    websocket: WebSocketStream<Box<dyn AsyncIo>>,
}

impl RelayWakeClient {
    pub async fn connect(
        base_url: &str,
        server_ca_pem: Option<&str>,
        client_identity_pem: Option<&[u8]>,
        registration: RelayWakeRegistration,
    ) -> Result<Self> {
        registration.validate()?;
        let url = websocket_url(base_url, "relay/wake/ws")
            .with_context(|| format!("failed building relay wake URL from {base_url}"))?;
        let mut websocket = connect_websocket(&url, server_ca_pem, client_identity_pem, &[])
            .await
            .context("relay wake websocket handshake failed")?;

        send_wake_control(
            &mut websocket,
            &RelayWakeControlMessage::Register { registration },
        )
        .await?;

        loop {
            let next = websocket
                .next()
                .await
                .ok_or_else(|| anyhow!("relay wake websocket closed before registration"))?;
            match next.context("failed reading relay wake registration response")? {
                Message::Text(text) => {
                    match serde_json::from_str::<RelayWakeControlMessage>(&text)
                        .context("failed parsing relay wake registration response")?
                    {
                        RelayWakeControlMessage::Registered => break,
                        RelayWakeControlMessage::Error { message } => {
                            bail!("relay wake registration failed: {message}");
                        }
                        other => bail!(
                            "unexpected relay wake message before registration: {}",
                            serde_json::to_string(&other)
                                .unwrap_or_else(|_| "<unserializable>".to_string())
                        ),
                    }
                }
                Message::Ping(payload) => {
                    websocket
                        .send(Message::Pong(payload))
                        .await
                        .context("failed sending relay wake pong")?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => {
                    bail!("relay wake websocket closed before registration");
                }
                Message::Binary(_) | Message::Frame(_) => {
                    bail!("relay wake websocket sent data before registration");
                }
            }
        }

        Ok(Self { websocket })
    }

    /// Reads the next event from the wake channel, transparently answering pings.
    pub async fn next_event(&mut self) -> Result<RelayWakeEvent> {
        loop {
            let next = match self.websocket.next().await {
                Some(next) => next,
                None => return Ok(RelayWakeEvent::Closed),
            };
            match next.context("relay wake websocket read failed")? {
                Message::Text(text) => {
                    match serde_json::from_str::<RelayWakeControlMessage>(&text)
                        .context("failed parsing relay wake control message")?
                    {
                        RelayWakeControlMessage::Wake => return Ok(RelayWakeEvent::Wake),
                        RelayWakeControlMessage::Error { message } => {
                            bail!("relay wake peer reported error: {message}");
                        }
                        other => bail!(
                            "unexpected relay wake control message: {}",
                            serde_json::to_string(&other)
                                .unwrap_or_else(|_| "<unserializable>".to_string())
                        ),
                    }
                }
                Message::Ping(payload) => {
                    self.websocket
                        .send(Message::Pong(payload))
                        .await
                        .context("failed sending relay wake pong")?;
                }
                Message::Pong(_) => {}
                Message::Close(_) => return Ok(RelayWakeEvent::Closed),
                Message::Binary(_) | Message::Frame(_) => {
                    bail!("relay wake websocket sent unexpected binary data");
                }
            }
        }
    }

    pub async fn send_ping(&mut self) -> Result<()> {
        self.websocket
            .send(Message::Ping(Vec::new()))
            .await
            .context("failed sending relay wake ping")
    }

    pub async fn close(mut self) -> Result<()> {
        self.websocket
            .close(None)
            .await
            .context("failed closing relay wake websocket")
    }
}

async fn send_wake_control(
    websocket: &mut WebSocketStream<Box<dyn AsyncIo>>,
    control: &RelayWakeControlMessage,
) -> Result<()> {
    let payload = serde_json::to_string(control).context("failed encoding relay wake control")?;
    websocket
        .send(Message::Text(payload))
        .await
        .context("failed sending relay wake control")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};
    use uuid::Uuid;

    #[tokio::test]
    async fn relay_wake_client_connect_times_out_when_handshake_stalls() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener
            .local_addr()
            .expect("test listener should have a local address");
        let server_task = tokio::spawn(async move {
            let (_socket, _peer) = listener
                .accept()
                .await
                .expect("test server should accept the client TCP connection");
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let registration = RelayWakeRegistration {
            cluster_id: Uuid::now_v7(),
            target: PeerIdentity::Node(Uuid::now_v7()),
            session_kind: RelayTunnelSessionKind::MultiplexTransport,
        };

        let started_at = Instant::now();
        let error =
            match RelayWakeClient::connect(&format!("ws://{addr}"), None, None, registration).await
            {
                Ok(_) => panic!("stalled websocket handshake should fail"),
                Err(error) => error,
            };

        server_task.abort();

        assert!(
            started_at.elapsed() < Duration::from_secs(7),
            "relay wake handshake should fail within the timeout window"
        );
        assert!(
            error.to_string().contains("handshake"),
            "unexpected relay wake error: {error:#}"
        );
    }
}
