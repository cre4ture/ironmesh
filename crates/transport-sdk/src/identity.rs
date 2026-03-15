use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use common::{ClusterId, DeviceId};
use ed25519_dalek::SigningKey;
use pkcs8::{EncodePrivateKey, EncodePublicKey, LineEnding};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::request_auth::credential_fingerprint;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientEnrollmentRequest {
    pub cluster_id: ClusterId,
    pub pairing_token: String,
    #[serde(default)]
    pub device_id: Option<DeviceId>,
    #[serde(default)]
    pub label: Option<String>,
    pub public_key_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedClientIdentity {
    pub cluster_id: ClusterId,
    pub device_id: DeviceId,
    #[serde(default)]
    pub label: Option<String>,
    pub public_key_pem: String,
    pub credential_pem: String,
    pub issued_at_unix: u64,
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientIdentityMaterial {
    pub cluster_id: ClusterId,
    pub device_id: DeviceId,
    #[serde(default)]
    pub label: Option<String>,
    pub private_key_pem: String,
    pub public_key_pem: String,
    #[serde(default)]
    pub credential_pem: Option<String>,
    #[serde(default)]
    pub issued_at_unix: Option<u64>,
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
}

pub fn next_device_id() -> DeviceId {
    Uuid::now_v7()
}

impl ClientIdentityMaterial {
    pub fn generate(
        cluster_id: ClusterId,
        device_id: Option<DeviceId>,
        label: Option<String>,
    ) -> Result<Self> {
        if cluster_id.is_nil() {
            bail!("client identity generation requires a non-nil cluster_id");
        }

        let device_id = device_id.unwrap_or_else(next_device_id);
        let signing_key = SigningKey::generate(&mut OsRng);
        let private_key_pem = signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .context("failed encoding client private key PEM")?
            .to_string();
        let public_key_pem = signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .context("failed encoding client public key PEM")?;

        Ok(Self {
            cluster_id,
            device_id,
            label,
            private_key_pem,
            public_key_pem,
            credential_pem: None,
            issued_at_unix: None,
            expires_at_unix: None,
        })
    }

    pub fn apply_issued_identity(&mut self, issued: &IssuedClientIdentity) -> Result<()> {
        issued.validate()?;
        if self.cluster_id != issued.cluster_id {
            bail!("issued identity cluster_id does not match local client identity");
        }
        if self.device_id != issued.device_id {
            bail!("issued identity device_id does not match local client identity");
        }
        if self.public_key_pem != issued.public_key_pem {
            bail!("issued identity public_key_pem does not match local client identity");
        }

        self.label = issued.label.clone();
        self.credential_pem = Some(issued.credential_pem.clone());
        self.issued_at_unix = Some(issued.issued_at_unix);
        self.expires_at_unix = issued.expires_at_unix;
        Ok(())
    }
}

impl ClientEnrollmentRequest {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("client enrollment request must include a non-nil cluster_id");
        }
        if self.pairing_token.trim().is_empty() {
            bail!("client enrollment request must include a pairing_token");
        }
        if self.public_key_pem.trim().is_empty() {
            bail!("client enrollment request must include a public_key_pem");
        }
        if let Some(label) = self.label.as_deref()
            && label.trim().is_empty()
        {
            bail!("client enrollment request label must not be empty when provided");
        }
        Ok(())
    }
}

impl IssuedClientIdentity {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("issued client identity must include a non-nil cluster_id");
        }
        if self.device_id.is_nil() {
            bail!("issued client identity must include a non-nil device_id");
        }
        if self.public_key_pem.trim().is_empty() {
            bail!("issued client identity must include a public_key_pem");
        }
        if self.credential_pem.trim().is_empty() {
            bail!("issued client identity must include a credential_pem");
        }
        Ok(())
    }
}

impl ClientIdentityMaterial {
    pub fn from_json_str(raw: &str) -> Result<Self> {
        let material = serde_json::from_str::<Self>(raw)
            .context("failed to parse client identity material JSON")?;
        material.validate()?;
        Ok(material)
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read client identity {}", path.display()))?;
        Self::from_json_str(&raw)
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string_pretty(self).context("failed to serialize client identity JSON")
    }

    pub fn write_to_path(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
        fs::write(path, self.to_json_pretty()?)
            .with_context(|| format!("failed to write client identity {}", path.display()))
    }

    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("client identity must include a non-nil cluster_id");
        }
        if self.device_id.is_nil() {
            bail!("client identity must include a non-nil device_id");
        }
        if self.private_key_pem.trim().is_empty() {
            bail!("client identity must include a private_key_pem");
        }
        if self.public_key_pem.trim().is_empty() {
            bail!("client identity must include a public_key_pem");
        }
        if let Some(credential_pem) = self.credential_pem.as_deref()
            && credential_pem.trim().is_empty()
        {
            bail!("client identity credential_pem must not be empty when provided");
        }
        if let Some(label) = self.label.as_deref()
            && label.trim().is_empty()
        {
            bail!("client identity label must not be empty when provided");
        }
        Ok(())
    }

    pub fn credential_fingerprint(&self) -> Result<Option<String>> {
        self.credential_pem
            .as_deref()
            .map(credential_fingerprint)
            .transpose()
    }
}
