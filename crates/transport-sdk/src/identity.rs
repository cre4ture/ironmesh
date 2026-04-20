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
    #[serde(default, rename = "device_label", alias = "label")]
    pub label: Option<String>,
    pub public_key_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IssuedClientIdentity {
    pub cluster_id: ClusterId,
    pub device_id: DeviceId,
    #[serde(default, rename = "device_label", alias = "label")]
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
    pub rendezvous_client_identity_pem: Option<String>,
    #[serde(default)]
    pub issued_at_unix: Option<u64>,
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
}

pub fn next_device_id() -> DeviceId {
    Uuid::now_v7()
}

fn normalize_pem_text(value: &str) -> String {
    value.replace("\r\n", "\n").trim().to_string()
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
            rendezvous_client_identity_pem: None,
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
        if normalize_pem_text(&self.public_key_pem) != normalize_pem_text(&issued.public_key_pem) {
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
            bail!("client enrollment request device_label must not be empty when provided");
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
        if let Some(rendezvous_client_identity_pem) = self.rendezvous_client_identity_pem.as_deref()
            && rendezvous_client_identity_pem.trim().is_empty()
        {
            bail!("client identity rendezvous_client_identity_pem must not be empty when provided");
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn client_enrollment_request_serializes_device_label_and_accepts_legacy_label() {
        let request = ClientEnrollmentRequest {
            cluster_id: "019d02eb-ab39-7220-911a-c0eafcb38249".parse().unwrap(),
            pairing_token: "pairing-token".to_string(),
            device_id: Some("019d04a8-3099-75bc-8ff5-f5bd9a78bb83".parse().unwrap()),
            label: Some("Tablet".to_string()),
            public_key_pem: "public-key".to_string(),
        };

        let json = serde_json::to_value(&request).expect("request should serialize");
        let object = json
            .as_object()
            .expect("request should serialize as an object");
        assert_eq!(
            object
                .get("device_label")
                .and_then(serde_json::Value::as_str),
            Some("Tablet")
        );
        assert!(!object.contains_key("label"));

        let legacy: ClientEnrollmentRequest = serde_json::from_value(json!({
            "cluster_id": "019d02eb-ab39-7220-911a-c0eafcb38249",
            "pairing_token": "pairing-token",
            "device_id": "019d04a8-3099-75bc-8ff5-f5bd9a78bb83",
            "label": "Phone",
            "public_key_pem": "public-key"
        }))
        .expect("legacy request should deserialize");

        assert_eq!(legacy.label.as_deref(), Some("Phone"));
    }

    #[test]
    fn issued_client_identity_serializes_device_label_and_accepts_legacy_label() {
        let identity = IssuedClientIdentity {
            cluster_id: "019d02eb-ab39-7220-911a-c0eafcb38249".parse().unwrap(),
            device_id: "019d04a8-3099-75bc-8ff5-f5bd9a78bb83".parse().unwrap(),
            label: Some("Laptop".to_string()),
            public_key_pem: "public-key".to_string(),
            credential_pem: "credential".to_string(),
            issued_at_unix: 10,
            expires_at_unix: Some(20),
        };

        let json = serde_json::to_value(&identity).expect("identity should serialize");
        let object = json
            .as_object()
            .expect("identity should serialize as an object");
        assert_eq!(
            object
                .get("device_label")
                .and_then(serde_json::Value::as_str),
            Some("Laptop")
        );
        assert!(!object.contains_key("label"));

        let legacy: IssuedClientIdentity = serde_json::from_value(json!({
            "cluster_id": "019d02eb-ab39-7220-911a-c0eafcb38249",
            "device_id": "019d04a8-3099-75bc-8ff5-f5bd9a78bb83",
            "label": "Desktop",
            "public_key_pem": "public-key",
            "credential_pem": "credential",
            "issued_at_unix": 10,
            "expires_at_unix": 20
        }))
        .expect("legacy issued identity should deserialize");

        assert_eq!(legacy.label.as_deref(), Some("Desktop"));
    }
}
