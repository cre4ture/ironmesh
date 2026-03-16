use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use tokio::sync::{Mutex, Notify, oneshot};
use transport_sdk::relay::{
    PendingRelayHttpRequest, RelayHttpPollRequest, RelayHttpPollResponse, RelayHttpRequest,
    RelayHttpResponse, RelayTicket, RelayTicketRequest,
};
use uuid::Uuid;

use crate::auth::peer_identity_key;

pub fn issue_relay_ticket(
    request: RelayTicketRequest,
    relay_public_urls: &[String],
) -> RelayTicket {
    let now = unix_ts();
    let expires_at_unix = now
        + request
            .requested_expires_in_secs
            .unwrap_or(300)
            .clamp(60, 60 * 60);

    RelayTicket {
        cluster_id: request.cluster_id,
        session_id: Uuid::now_v7().to_string(),
        source: request.source,
        target: request.target,
        relay_urls: relay_public_urls.to_vec(),
        issued_at_unix: now,
        expires_at_unix,
    }
}

#[derive(Clone, Default)]
pub struct RelayBroker {
    inner: Arc<RelayBrokerInner>,
}

#[derive(Default)]
struct RelayBrokerInner {
    state: Mutex<RelayBrokerState>,
    notify: Notify,
}

#[derive(Default)]
struct RelayBrokerState {
    pending_by_target: HashMap<String, VecDeque<PendingRelayHttpRequest>>,
    inflight: HashMap<String, oneshot::Sender<RelayHttpResponse>>,
}

impl RelayBroker {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn submit_and_await(&self, request: RelayHttpRequest) -> Result<RelayHttpResponse> {
        request.validate()?;
        request.ticket.validate()?;
        if request.ticket.expires_at_unix <= unix_ts() {
            bail!("relay ticket has expired");
        }

        let target_key = relay_target_key(request.ticket.cluster_id, &request.ticket.target);
        let request_id = request.request_id.clone();
        let pending = PendingRelayHttpRequest {
            cluster_id: request.ticket.cluster_id,
            session_id: request.ticket.session_id.clone(),
            request_id: request.request_id.clone(),
            source: request.ticket.source.clone(),
            target: request.ticket.target.clone(),
            method: request.method,
            path_and_query: request.path_and_query,
            headers: request.headers,
            body_base64: request.body_base64,
        };
        pending.validate()?;

        let wait_timeout = request
            .ticket
            .expires_at_unix
            .saturating_sub(unix_ts())
            .clamp(5, 60);
        let (tx, rx) = oneshot::channel();

        {
            let mut state = self.inner.state.lock().await;
            state
                .pending_by_target
                .entry(target_key)
                .or_default()
                .push_back(pending);
            state.inflight.insert(request_id.clone(), tx);
        }
        self.inner.notify.notify_waiters();

        match tokio::time::timeout(Duration::from_secs(wait_timeout), rx).await {
            Ok(Ok(response)) => {
                response.validate()?;
                Ok(response)
            }
            Ok(Err(_)) => Err(anyhow!("relay response channel closed before completion")),
            Err(_) => {
                let mut state = self.inner.state.lock().await;
                state.inflight.remove(&request_id);
                remove_pending_request(&mut state.pending_by_target, &request_id);
                bail!("timed out waiting for relayed HTTP response")
            }
        }
    }

    pub async fn poll(&self, request: RelayHttpPollRequest) -> Result<RelayHttpPollResponse> {
        request.validate()?;
        let target_key = relay_target_key(request.cluster_id, &request.target);
        let timeout =
            Duration::from_millis(request.wait_timeout_ms.unwrap_or(15_000).clamp(100, 30_000));

        if let Some(pending) = self.try_pop_pending(&target_key).await? {
            return Ok(RelayHttpPollResponse {
                request: Some(pending),
            });
        }

        let notified = self.inner.notify.notified();
        let _ = tokio::time::timeout(timeout, notified).await;

        Ok(RelayHttpPollResponse {
            request: self.try_pop_pending(&target_key).await?,
        })
    }

    pub async fn respond(&self, response: RelayHttpResponse) -> Result<bool> {
        response.validate()?;
        let sender = {
            let mut state = self.inner.state.lock().await;
            state.inflight.remove(&response.request_id)
        };
        match sender {
            Some(sender) => {
                let _ = sender.send(response);
                Ok(true)
            }
            None => Ok(false),
        }
    }

    async fn try_pop_pending(&self, target_key: &str) -> Result<Option<PendingRelayHttpRequest>> {
        let mut state = self.inner.state.lock().await;
        let pending = state
            .pending_by_target
            .get_mut(target_key)
            .and_then(|queue| queue.pop_front());
        if state
            .pending_by_target
            .get(target_key)
            .map(|queue| queue.is_empty())
            .unwrap_or(false)
        {
            state.pending_by_target.remove(target_key);
        }
        if let Some(pending) = pending.as_ref() {
            pending.validate()?;
        }
        Ok(pending)
    }
}

fn remove_pending_request(
    pending_by_target: &mut HashMap<String, VecDeque<PendingRelayHttpRequest>>,
    request_id: &str,
) {
    let keys = pending_by_target.keys().cloned().collect::<Vec<_>>();
    for key in keys {
        if let Some(queue) = pending_by_target.get_mut(&key) {
            queue.retain(|request| request.request_id != request_id);
            if queue.is_empty() {
                pending_by_target.remove(&key);
            }
        }
    }
}

fn relay_target_key(cluster_id: uuid::Uuid, target: &transport_sdk::PeerIdentity) -> String {
    format!("{cluster_id}:{}", peer_identity_key(target))
}

fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport_sdk::encode_optional_body_base64;
    use transport_sdk::peer::PeerIdentity;

    #[tokio::test]
    async fn relay_broker_round_trips_http_request() {
        let broker = RelayBroker::new();
        let cluster_id = uuid::Uuid::now_v7();
        let source = PeerIdentity::Node(uuid::Uuid::now_v7());
        let target = PeerIdentity::Node(uuid::Uuid::now_v7());
        let ticket = issue_relay_ticket(
            RelayTicketRequest {
                cluster_id,
                source: source.clone(),
                target: target.clone(),
                requested_expires_in_secs: Some(60),
            },
            &["https://relay.example".to_string()],
        );

        let broker_for_submit = broker.clone();
        let submit = tokio::spawn(async move {
            broker_for_submit
                .submit_and_await(RelayHttpRequest {
                    ticket,
                    request_id: "req-1".to_string(),
                    method: "GET".to_string(),
                    path_and_query: "/health".to_string(),
                    headers: Vec::new(),
                    body_base64: None,
                })
                .await
                .expect("relay request should complete")
        });

        let pending = broker
            .poll(RelayHttpPollRequest {
                cluster_id,
                target,
                wait_timeout_ms: Some(100),
            })
            .await
            .expect("relay poll should succeed")
            .request
            .expect("poll should return a pending request");
        assert_eq!(pending.request_id, "req-1");
        assert_eq!(pending.path_and_query, "/health");

        let accepted = broker
            .respond(RelayHttpResponse {
                request_id: pending.request_id,
                status: 200,
                headers: Vec::new(),
                body_base64: encode_optional_body_base64(br#"{"ok":true}"#),
            })
            .await
            .expect("relay response should be accepted");
        assert!(accepted);

        let response = submit.await.expect("submit task should join");
        assert_eq!(response.status, 200);
        assert_eq!(
            response.body_bytes().expect("body should decode"),
            br#"{"ok":true}"#
        );
    }
}
