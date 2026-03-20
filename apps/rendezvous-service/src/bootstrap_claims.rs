use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, bail};
use common::NodeId;
use tokio::sync::Mutex;
use transport_sdk::{
    ClientBootstrap, ClientBootstrapClaimPublishRequest, ClientBootstrapClaimPublishResponse,
    PeerIdentity,
};

#[derive(Clone, Default)]
pub struct BootstrapClaimBroker {
    inner: Arc<Mutex<HashMap<String, BootstrapClaimRecord>>>,
}

#[derive(Debug, Clone)]
pub struct BootstrapClaimRecord {
    pub issuer: PeerIdentity,
    pub target_node_id: NodeId,
    pub expires_at_unix: u64,
    pub bootstrap: ClientBootstrap,
}

impl BootstrapClaimBroker {
    pub fn new() -> Self {
        Self::default()
    }

    pub async fn publish(
        &self,
        request: ClientBootstrapClaimPublishRequest,
    ) -> Result<ClientBootstrapClaimPublishResponse> {
        request.validate()?;
        let mut state = self.inner.lock().await;
        retain_active_claims(&mut state);
        state.insert(
            request.claim_secret_hash.clone(),
            BootstrapClaimRecord {
                issuer: request.issuer,
                target_node_id: request.target_node_id,
                expires_at_unix: request.expires_at_unix,
                bootstrap: request.bootstrap,
            },
        );
        Ok(ClientBootstrapClaimPublishResponse {
            accepted: true,
            expires_at_unix: request.expires_at_unix,
        })
    }

    pub async fn take_for_redeem(&self, claim_token: &str) -> Result<BootstrapClaimRecord> {
        let claim_token = claim_token.trim();
        if claim_token.is_empty() {
            bail!("bootstrap claim token must not be empty");
        }

        let claim_secret_hash = hash_token(claim_token);
        let mut state = self.inner.lock().await;
        retain_active_claims(&mut state);
        state
            .remove(&claim_secret_hash)
            .ok_or_else(|| anyhow::anyhow!("bootstrap claim was not found or has expired"))
    }

    pub async fn restore(&self, claim_token: &str, record: BootstrapClaimRecord) {
        let mut state = self.inner.lock().await;
        if record.expires_at_unix > unix_ts() {
            state.insert(hash_token(claim_token), record);
        }
    }
}

fn retain_active_claims(state: &mut HashMap<String, BootstrapClaimRecord>) {
    let now = unix_ts();
    state.retain(|_, record| record.expires_at_unix > now);
}

fn hash_token(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

fn unix_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
