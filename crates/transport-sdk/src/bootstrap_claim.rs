use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use common::{ClusterId, NodeId};
use serde::{Deserialize, Serialize};

use crate::{ClientBootstrap, IssuedClientIdentity, PeerIdentity};

pub const CLIENT_BOOTSTRAP_CLAIM_VERSION: u32 = 1;
pub const CLIENT_BOOTSTRAP_CLAIM_KIND: &str = "client_bootstrap_claim";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClientBootstrapClaimTrustMode {
    RendezvousCaDerB64u,
    RendezvousCaPem,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientBootstrapClaimTrust {
    pub mode: ClientBootstrapClaimTrustMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_der_b64u: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientBootstrapClaim {
    pub version: u32,
    pub kind: String,
    pub cluster_id: ClusterId,
    pub rendezvous_url: String,
    pub trust: ClientBootstrapClaimTrust,
    pub claim_token: String,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientBootstrapClaimIssueResponse {
    pub bootstrap_bundle: ClientBootstrap,
    pub bootstrap_claim: ClientBootstrapClaim,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientBootstrapClaimPublishRequest {
    pub cluster_id: ClusterId,
    pub issuer: PeerIdentity,
    pub target_node_id: NodeId,
    pub claim_secret_hash: String,
    pub expires_at_unix: u64,
    pub bootstrap: ClientBootstrap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientBootstrapClaimPublishResponse {
    pub accepted: bool,
    pub expires_at_unix: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientBootstrapClaimRedeemRequest {
    pub claim_token: String,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    pub public_key_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientBootstrapClaimRedeemResponse {
    pub bootstrap: ClientBootstrap,
    pub cluster_id: ClusterId,
    pub device_id: String,
    #[serde(default)]
    pub label: Option<String>,
    pub public_key_pem: String,
    pub credential_pem: String,
    #[serde(default)]
    pub rendezvous_client_identity_pem: Option<String>,
    #[serde(default)]
    pub created_at_unix: Option<u64>,
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
}

impl ClientBootstrapClaimTrust {
    pub fn validate(&self) -> Result<()> {
        match self.mode {
            ClientBootstrapClaimTrustMode::RendezvousCaDerB64u => {
                let value = self
                    .ca_der_b64u
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("claim trust requires ca_der_b64u"))?;
                let _ = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(value)
                    .context("failed to decode claim rendezvous CA DER base64url")?;
            }
            ClientBootstrapClaimTrustMode::RendezvousCaPem => {
                let value = self
                    .ca_pem
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| anyhow::anyhow!("claim trust requires ca_pem"))?;
                if !value.contains("BEGIN CERTIFICATE") {
                    bail!("claim rendezvous CA PEM must include a certificate block");
                }
            }
        }
        Ok(())
    }
}

impl ClientBootstrapClaim {
    pub fn from_json_str(raw: &str) -> Result<Self> {
        let claim =
            serde_json::from_str::<Self>(raw).context("failed to parse bootstrap claim JSON")?;
        claim.validate()?;
        Ok(claim)
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read bootstrap claim {}", path.display()))?;
        Self::from_json_str(&raw)
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string_pretty(self).context("failed to serialize bootstrap claim JSON")
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != CLIENT_BOOTSTRAP_CLAIM_VERSION {
            bail!("unsupported bootstrap claim version {}", self.version);
        }
        if self.kind.trim() != CLIENT_BOOTSTRAP_CLAIM_KIND {
            bail!("unsupported bootstrap claim kind {}", self.kind);
        }
        if self.cluster_id.is_nil() {
            bail!("bootstrap claim must include a non-nil cluster_id");
        }
        reqwest::Url::parse(self.rendezvous_url.trim()).with_context(|| {
            format!(
                "invalid bootstrap claim rendezvous_url {}",
                self.rendezvous_url
            )
        })?;
        self.trust.validate()?;
        if self.claim_token.trim().is_empty() {
            bail!("bootstrap claim must include a claim_token");
        }
        if self.expires_at_unix == 0 {
            bail!("bootstrap claim must include a non-zero expires_at_unix");
        }
        Ok(())
    }
}

impl ClientBootstrapClaimIssueResponse {
    pub fn validate(&self) -> Result<()> {
        self.bootstrap_bundle.validate()?;
        self.bootstrap_claim.validate()?;
        if self.bootstrap_bundle.cluster_id != self.bootstrap_claim.cluster_id {
            bail!("bootstrap bundle and claim cluster_id must match");
        }
        Ok(())
    }
}

impl ClientBootstrapClaimPublishRequest {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("bootstrap claim publish request must include a non-nil cluster_id");
        }
        if !matches!(self.issuer, PeerIdentity::Node(_)) {
            bail!("bootstrap claim publish issuer must be a node identity");
        }
        if self.target_node_id.is_nil() {
            bail!("bootstrap claim publish request must include a non-nil target_node_id");
        }
        if self.claim_secret_hash.trim().is_empty() {
            bail!("bootstrap claim publish request must include a claim_secret_hash");
        }
        if self.expires_at_unix == 0 {
            bail!("bootstrap claim publish request must include a non-zero expires_at_unix");
        }
        self.bootstrap.validate()?;
        if self.bootstrap.cluster_id != self.cluster_id {
            bail!("bootstrap claim publish request cluster_id does not match bootstrap cluster_id");
        }
        Ok(())
    }
}

impl ClientBootstrapClaimRedeemRequest {
    pub fn validate(&self) -> Result<()> {
        if self.claim_token.trim().is_empty() {
            bail!("bootstrap claim redeem request must include a claim_token");
        }
        if self.public_key_pem.trim().is_empty() {
            bail!("bootstrap claim redeem request must include a public_key_pem");
        }
        if let Some(device_id) = self.device_id.as_deref()
            && device_id.trim().is_empty()
        {
            bail!("bootstrap claim redeem request device_id must not be empty when provided");
        }
        if let Some(label) = self.label.as_deref()
            && label.trim().is_empty()
        {
            bail!("bootstrap claim redeem request label must not be empty when provided");
        }
        Ok(())
    }
}

impl ClientBootstrapClaimRedeemResponse {
    pub fn validate(&self) -> Result<()> {
        self.bootstrap.validate()?;
        if self.cluster_id.is_nil() {
            bail!("bootstrap claim redeem response must include a non-nil cluster_id");
        }
        if self.cluster_id != self.bootstrap.cluster_id {
            bail!("bootstrap claim redeem response cluster_id does not match bootstrap cluster_id");
        }
        if self.device_id.trim().is_empty() {
            bail!("bootstrap claim redeem response must include a device_id");
        }
        if self.public_key_pem.trim().is_empty() {
            bail!("bootstrap claim redeem response must include a public_key_pem");
        }
        if self.credential_pem.trim().is_empty() {
            bail!("bootstrap claim redeem response must include a credential_pem");
        }
        if self
            .rendezvous_client_identity_pem
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
        {
            bail!(
                "bootstrap claim redeem response rendezvous_client_identity_pem must not be empty when provided"
            );
        }
        Ok(())
    }

    pub fn issued_identity(&self) -> Result<IssuedClientIdentity> {
        let issued = IssuedClientIdentity {
            cluster_id: self.cluster_id,
            device_id: self
                .device_id
                .parse()
                .with_context(|| format!("invalid device_id {}", self.device_id))?,
            label: self.label.clone(),
            public_key_pem: self.public_key_pem.clone(),
            credential_pem: self.credential_pem.clone(),
            issued_at_unix: self.created_at_unix.unwrap_or_default(),
            expires_at_unix: self.expires_at_unix,
        };
        issued.validate()?;
        Ok(issued)
    }
}
