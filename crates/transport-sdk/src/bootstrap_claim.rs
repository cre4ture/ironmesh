use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use base64::Engine;
use common::{ClusterId, NodeId};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{ClientBootstrap, IssuedClientIdentity, PeerIdentity};

pub const CLIENT_BOOTSTRAP_CLAIM_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientBootstrapClaimTrust {
    pub ca_der_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientBootstrapClaim {
    pub version: u32,
    pub cluster_id: ClusterId,
    pub target_node_id: NodeId,
    pub rendezvous_urls: Vec<String>,
    pub trust: ClientBootstrapClaimTrust,
    pub claim_token: String,
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
    pub target_node_id: NodeId,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default, rename = "device_label", alias = "label")]
    pub label: Option<String>,
    pub public_key_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientBootstrapClaimRedeemResponse {
    pub bootstrap: ClientBootstrap,
    pub cluster_id: ClusterId,
    pub device_id: String,
    #[serde(default, rename = "device_label", alias = "label")]
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
        let value = self.ca_der_b64u.trim();
        if value.is_empty() {
            bail!("claim trust requires ca_der_b64u");
        }
        let _ = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .context("failed to decode claim rendezvous CA DER base64url")?;
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
        if self.cluster_id.is_nil() {
            bail!("bootstrap claim must include a non-nil cluster_id");
        }
        if self.target_node_id.is_nil() {
            bail!("bootstrap claim must include a non-nil target_node_id");
        }
        if self.rendezvous_urls.is_empty() {
            bail!("bootstrap claim must include at least one rendezvous URL");
        }
        for (index, rendezvous_url) in self.rendezvous_urls.iter().enumerate() {
            normalize_claim_rendezvous_url(rendezvous_url, &format!("rendezvous_urls[{index}]"))?;
        }
        self.trust.validate()?;
        if self.claim_token.trim().is_empty() {
            bail!("bootstrap claim must include a claim_token");
        }
        Ok(())
    }

    pub fn ordered_rendezvous_urls(&self) -> Result<Vec<String>> {
        let mut urls = Vec::new();
        let mut seen = HashSet::new();
        for rendezvous_url in self.rendezvous_urls.iter().map(String::as_str) {
            let normalized = normalize_claim_rendezvous_url(rendezvous_url, "rendezvous_url")?;
            if seen.insert(normalized.clone()) {
                urls.push(normalized);
            }
        }
        Ok(urls)
    }
}

fn normalize_claim_rendezvous_url(value: &str, field_name: &str) -> Result<String> {
    reqwest::Url::parse(value.trim())
        .with_context(|| format!("invalid bootstrap claim {field_name} {value}"))
        .map(|url| url.to_string())
}

#[derive(Serialize)]
struct ClientBootstrapClaimWire<'a> {
    #[serde(rename = "v")]
    version: u32,
    #[serde(rename = "c")]
    cluster_id: &'a ClusterId,
    #[serde(rename = "n")]
    target_node_id: &'a NodeId,
    #[serde(rename = "r")]
    rendezvous_urls: &'a [String],
    #[serde(rename = "t")]
    ca_der_b64u: &'a str,
    #[serde(rename = "k")]
    claim_token: &'a str,
}

#[derive(Deserialize)]
struct ClientBootstrapClaimWireOwned {
    #[serde(rename = "v", alias = "version")]
    version: u32,
    #[serde(rename = "c", alias = "cluster_id")]
    cluster_id: ClusterId,
    #[serde(rename = "n", alias = "target_node_id")]
    target_node_id: NodeId,
    #[serde(rename = "r", alias = "rendezvous_urls", default)]
    rendezvous_urls: Vec<String>,
    #[serde(rename = "u", alias = "rendezvous_url", default)]
    rendezvous_url: Option<String>,
    #[serde(rename = "t", alias = "trust")]
    trust: ClientBootstrapClaimWireTrust,
    #[serde(rename = "k", alias = "claim_token")]
    claim_token: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum ClientBootstrapClaimWireTrust {
    Compact(String),
    Legacy(ClientBootstrapClaimLegacyTrust),
}

#[derive(Deserialize)]
struct ClientBootstrapClaimLegacyTrust {
    #[serde(default)]
    ca_der_b64u: Option<String>,
    #[serde(default)]
    ca_pem: Option<String>,
}

impl Serialize for ClientBootstrapClaim {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let wire = ClientBootstrapClaimWire {
            version: self.version,
            cluster_id: &self.cluster_id,
            target_node_id: &self.target_node_id,
            rendezvous_urls: &self.rendezvous_urls,
            ca_der_b64u: self.trust.ca_der_b64u.as_str(),
            claim_token: self.claim_token.as_str(),
        };
        wire.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ClientBootstrapClaim {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = ClientBootstrapClaimWireOwned::deserialize(deserializer)?;
        ClientBootstrapClaim::try_from(wire).map_err(serde::de::Error::custom)
    }
}

impl TryFrom<ClientBootstrapClaimWireOwned> for ClientBootstrapClaim {
    type Error = anyhow::Error;

    fn try_from(wire: ClientBootstrapClaimWireOwned) -> Result<Self> {
        let mut rendezvous_urls = wire.rendezvous_urls;
        if let Some(primary_rendezvous_url) = wire
            .rendezvous_url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            && !rendezvous_urls
                .iter()
                .any(|candidate| candidate.trim() == primary_rendezvous_url)
        {
            rendezvous_urls.insert(0, primary_rendezvous_url);
        }
        Ok(Self {
            version: wire.version,
            cluster_id: wire.cluster_id,
            target_node_id: wire.target_node_id,
            rendezvous_urls,
            trust: match wire.trust {
                ClientBootstrapClaimWireTrust::Compact(ca_der_b64u) => {
                    ClientBootstrapClaimTrust { ca_der_b64u }
                }
                ClientBootstrapClaimWireTrust::Legacy(legacy) => {
                    ClientBootstrapClaimTrust::try_from(legacy)?
                }
            },
            claim_token: wire.claim_token,
        })
    }
}

impl TryFrom<ClientBootstrapClaimLegacyTrust> for ClientBootstrapClaimTrust {
    type Error = anyhow::Error;

    fn try_from(legacy: ClientBootstrapClaimLegacyTrust) -> Result<Self> {
        if let Some(ca_der_b64u) = legacy
            .ca_der_b64u
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
        {
            return Ok(Self { ca_der_b64u });
        }

        let ca_pem = legacy
            .ca_pem
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("claim trust requires ca_der_b64u"))?;
        let der = der_from_pem_certificate(ca_pem)?;
        Ok(Self {
            ca_der_b64u: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(der),
        })
    }
}

fn der_from_pem_certificate(pem: &str) -> Result<Vec<u8>> {
    let body = pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("-----BEGIN ") && !line.starts_with("-----END "))
        .collect::<String>();
    if body.is_empty() {
        bail!("claim rendezvous CA PEM must include a certificate block");
    }
    base64::engine::general_purpose::STANDARD
        .decode(body)
        .context("failed to decode claim rendezvous CA PEM")
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
        if self.target_node_id.is_nil() {
            bail!("bootstrap claim redeem request must include a non-nil target_node_id");
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
            bail!("bootstrap claim redeem request device_label must not be empty when provided");
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

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bootstrap_bundle() -> ClientBootstrap {
        ClientBootstrap {
            version: crate::CLIENT_BOOTSTRAP_VERSION,
            cluster_id: "019d02eb-ab39-7220-911a-c0eafcb38249".parse().unwrap(),
            rendezvous_urls: vec!["https://rendezvous-a.example:9443/".to_string()],
            rendezvous_mtls_required: true,
            direct_endpoints: vec![],
            relay_mode: crate::RelayMode::Fallback,
            trust_roots: crate::BootstrapTrustRoots {
                cluster_ca_pem: Some("cluster-ca".to_string()),
                public_api_ca_pem: Some("public-ca".to_string()),
                rendezvous_ca_pem: Some("rendezvous-ca".to_string()),
            },
            pairing_token: None,
            device_id: Some("019d04a8-3099-75bc-8ff5-f5bd9a78bb83".parse().unwrap()),
            device_label: Some("Tablet".to_string()),
        }
    }

    fn sample_claim() -> ClientBootstrapClaim {
        ClientBootstrapClaim {
            version: CLIENT_BOOTSTRAP_CLAIM_VERSION,
            cluster_id: "019d02eb-ab39-7220-911a-c0eafcb38249".parse().unwrap(),
            target_node_id: "9f068697-bd16-431a-8311-8ae985025bcf".parse().unwrap(),
            rendezvous_urls: vec![
                "https://rendezvous-a.example:9443".to_string(),
                "https://rendezvous-b.example:9443/".to_string(),
            ],
            trust: ClientBootstrapClaimTrust {
                ca_der_b64u: "Y2xhaW0tdGVzdA".to_string(),
            },
            claim_token: "im-claim-test-token".to_string(),
        }
    }

    #[test]
    fn bootstrap_claim_serializes_to_compact_shape() {
        let json = serde_json::to_value(sample_claim()).expect("claim should serialize");
        let object = json
            .as_object()
            .expect("bootstrap claim should serialize as an object");

        assert_eq!(object.get("v").and_then(serde_json::Value::as_u64), Some(1));
        assert_eq!(
            object.get("c").and_then(serde_json::Value::as_str),
            Some("019d02eb-ab39-7220-911a-c0eafcb38249")
        );
        assert_eq!(
            object.get("n").and_then(serde_json::Value::as_str),
            Some("9f068697-bd16-431a-8311-8ae985025bcf")
        );
        assert_eq!(
            object
                .get("r")
                .and_then(serde_json::Value::as_array)
                .map(Vec::len),
            Some(2)
        );
        assert_eq!(
            object.get("t").and_then(serde_json::Value::as_str),
            Some("Y2xhaW0tdGVzdA")
        );
        assert_eq!(
            object.get("k").and_then(serde_json::Value::as_str),
            Some("im-claim-test-token")
        );
        assert!(!object.contains_key("kind"));
        assert!(!object.contains_key("rendezvous_url"));
        assert!(!object.contains_key("expires_at_unix"));
    }

    #[test]
    fn bootstrap_claim_deserializes_legacy_shape() {
        let claim = ClientBootstrapClaim::from_json_str(
            r#"{
                "version": 1,
                "kind": "client_bootstrap_claim",
                "cluster_id": "019d02eb-ab39-7220-911a-c0eafcb38249",
                "target_node_id": "9f068697-bd16-431a-8311-8ae985025bcf",
                "rendezvous_url": "https://rendezvous-a.example:9443",
                "rendezvous_urls": ["https://rendezvous-b.example:9443/"],
                "trust": {
                    "mode": "rendezvous_ca_pem",
                    "ca_pem": "-----BEGIN CERTIFICATE-----\nY2xhaW0tdGVzdA==\n-----END CERTIFICATE-----\n"
                },
                "claim_token": "im-claim-test-token",
                "expires_at_unix": 42
            }"#,
        )
        .expect("legacy claim should deserialize");
        assert_eq!(
            claim.rendezvous_urls,
            vec![
                "https://rendezvous-a.example:9443".to_string(),
                "https://rendezvous-b.example:9443/".to_string(),
            ]
        );
        assert_eq!(claim.trust.ca_der_b64u, "Y2xhaW0tdGVzdA");
    }

    #[test]
    fn bootstrap_claim_redeem_request_serializes_device_label_and_accepts_legacy_label() {
        let request = ClientBootstrapClaimRedeemRequest {
            claim_token: "im-claim-test-token".to_string(),
            target_node_id: "9f068697-bd16-431a-8311-8ae985025bcf".parse().unwrap(),
            device_id: Some("019d04a8-3099-75bc-8ff5-f5bd9a78bb83".to_string()),
            label: Some("Tablet".to_string()),
            public_key_pem: "public-key".to_string(),
        };

        let json = serde_json::to_value(&request).expect("redeem request should serialize");
        let object = json
            .as_object()
            .expect("redeem request should serialize as an object");
        assert_eq!(
            object
                .get("device_label")
                .and_then(serde_json::Value::as_str),
            Some("Tablet")
        );
        assert!(!object.contains_key("label"));

        let legacy = serde_json::json!({
            "claim_token": "im-claim-test-token",
            "target_node_id": "9f068697-bd16-431a-8311-8ae985025bcf",
            "device_id": "019d04a8-3099-75bc-8ff5-f5bd9a78bb83",
            "label": "Phone",
            "public_key_pem": "public-key"
        });
        let parsed: ClientBootstrapClaimRedeemRequest =
            serde_json::from_value(legacy).expect("legacy redeem request should deserialize");

        assert_eq!(parsed.label.as_deref(), Some("Phone"));
    }

    #[test]
    fn bootstrap_claim_redeem_response_serializes_device_label_and_accepts_legacy_label() {
        let response = ClientBootstrapClaimRedeemResponse {
            bootstrap: sample_bootstrap_bundle(),
            cluster_id: "019d02eb-ab39-7220-911a-c0eafcb38249".parse().unwrap(),
            device_id: "019d04a8-3099-75bc-8ff5-f5bd9a78bb83".to_string(),
            label: Some("Tablet".to_string()),
            public_key_pem: "public-key".to_string(),
            credential_pem: "credential".to_string(),
            rendezvous_client_identity_pem: Some("rendezvous-identity".to_string()),
            created_at_unix: Some(10),
            expires_at_unix: Some(20),
        };

        let json = serde_json::to_value(&response).expect("redeem response should serialize");
        let object = json
            .as_object()
            .expect("redeem response should serialize as an object");
        assert_eq!(
            object
                .get("device_label")
                .and_then(serde_json::Value::as_str),
            Some("Tablet")
        );
        assert!(!object.contains_key("label"));

        let mut legacy = serde_json::to_value(&response).expect("response should serialize");
        let legacy_object = legacy
            .as_object_mut()
            .expect("response should serialize as an object");
        legacy_object.remove("device_label");
        legacy_object.insert(
            "label".to_string(),
            serde_json::Value::String("Phone".to_string()),
        );

        let parsed: ClientBootstrapClaimRedeemResponse =
            serde_json::from_value(legacy).expect("legacy redeem response should deserialize");

        assert_eq!(parsed.label.as_deref(), Some("Phone"));
    }
}
