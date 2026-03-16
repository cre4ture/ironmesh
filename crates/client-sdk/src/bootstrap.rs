use anyhow::{Context, Result, anyhow, bail};
use common::ClusterId;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Duration;
use transport_sdk::{
    BootstrapEndpoint, BootstrapEndpointUse, BootstrapTrustRoots,
    ClientBootstrap as TransportClientBootstrap, ClientIdentityMaterial, RelayMode,
};

use crate::connection::build_blocking_reqwest_client_from_pem;
use crate::device_auth::{
    DeviceEnrollmentRequest, DeviceEnrollmentResponse, enroll_device_blocking_from_pem,
};
use crate::ironmesh_client::normalize_server_base_url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionBootstrap {
    pub version: u32,
    pub cluster_id: ClusterId,
    pub rendezvous_urls: Vec<String>,
    #[serde(default)]
    pub rendezvous_mtls_required: bool,
    #[serde(default)]
    pub direct_endpoints: Vec<BootstrapEndpoint>,
    #[serde(default)]
    pub relay_mode: RelayMode,
    pub trust_roots: BootstrapTrustRoots,
    #[serde(default)]
    pub pairing_token: Option<String>,
    #[serde(default)]
    pub device_label: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedConnectionBootstrap {
    pub cluster_id: ClusterId,
    pub rendezvous_urls: Vec<String>,
    #[serde(default)]
    pub rendezvous_mtls_required: bool,
    pub relay_mode: RelayMode,
    pub server_base_url: String,
    #[serde(default)]
    pub server_ca_pem: Option<String>,
    #[serde(default)]
    pub cluster_ca_pem: Option<String>,
    #[serde(default)]
    pub rendezvous_ca_pem: Option<String>,
    #[serde(default)]
    pub pairing_token: Option<String>,
    #[serde(default)]
    pub device_label: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapEnrollmentResult {
    pub cluster_id: ClusterId,
    pub server_base_url: String,
    #[serde(default)]
    pub server_ca_pem: Option<String>,
    pub device_id: String,
    pub device_token: String,
    #[serde(default)]
    pub label: Option<String>,
    pub public_key_pem: String,
    pub private_key_pem: String,
    pub credential_pem: String,
    #[serde(default)]
    pub created_at_unix: Option<u64>,
    #[serde(default)]
    pub expires_at_unix: Option<u64>,
}

impl BootstrapEnrollmentResult {
    pub fn client_identity_material(&self) -> Result<ClientIdentityMaterial> {
        let identity = ClientIdentityMaterial {
            cluster_id: self.cluster_id,
            device_id: self
                .device_id
                .parse()
                .with_context(|| format!("invalid enrolled device_id {}", self.device_id))?,
            label: self.label.clone(),
            private_key_pem: self.private_key_pem.clone(),
            public_key_pem: self.public_key_pem.clone(),
            credential_pem: Some(self.credential_pem.clone()),
            issued_at_unix: self.created_at_unix,
            expires_at_unix: self.expires_at_unix,
        };
        identity.validate()?;
        Ok(identity)
    }
}

impl ConnectionBootstrap {
    pub fn from_json_str(raw: &str) -> Result<Self> {
        let bundle = serde_json::from_str::<Self>(raw).context("failed to parse bootstrap JSON")?;
        bundle.validate()?;
        Ok(bundle)
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read bootstrap file {}", path.display()))?;
        Self::from_json_str(&raw)
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string_pretty(self).context("failed to serialize bootstrap JSON")
    }

    pub fn write_to_path(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create bootstrap dir {}", parent.display()))?;
        }
        fs::write(path, self.to_json_pretty()?)
            .with_context(|| format!("failed to write bootstrap file {}", path.display()))
    }

    pub fn validate(&self) -> Result<()> {
        self.to_transport_bootstrap()?.validate()
    }

    pub fn candidate_endpoints(&self) -> Result<Vec<Url>> {
        let mut seen = BTreeSet::new();
        let mut endpoints = Vec::new();

        for endpoint in &self.direct_endpoints {
            if matches!(endpoint.usage, Some(BootstrapEndpointUse::Rendezvous)) {
                continue;
            }
            let url = normalize_server_base_url(&endpoint.url)?;
            if seen.insert(url.as_str().to_string()) {
                endpoints.push(url);
            }
        }

        Ok(endpoints)
    }

    pub fn resolve_blocking(&self) -> Result<ResolvedConnectionBootstrap> {
        self.validate()?;
        if self.candidate_endpoints()?.is_empty() {
            bail!("bootstrap does not contain any direct public API endpoints to probe");
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .context("failed building bootstrap probe client")?;
        let server_ca_pem = self
            .trust_roots
            .public_api_ca_pem
            .as_deref()
            .or(self.trust_roots.cluster_ca_pem.as_deref());
        let trusted = build_blocking_reqwest_client_from_pem(server_ca_pem)
            .context("failed building bootstrap trusted client")?;

        for endpoint in self.candidate_endpoints()? {
            let health_url = endpoint
                .join("health")
                .with_context(|| format!("failed to build health URL from {endpoint}"))?;
            let probe_client = if endpoint.scheme() == "https" {
                &trusted
            } else {
                &client
            };
            if let Ok(response) = probe_client.get(health_url).send()
                && response.status().is_success()
            {
                return Ok(ResolvedConnectionBootstrap {
                    cluster_id: self.cluster_id,
                    rendezvous_urls: self.rendezvous_urls.clone(),
                    rendezvous_mtls_required: self.rendezvous_mtls_required,
                    relay_mode: self.relay_mode,
                    server_base_url: endpoint.to_string(),
                    server_ca_pem: self.trust_roots.public_api_ca_pem.clone(),
                    cluster_ca_pem: self.trust_roots.cluster_ca_pem.clone(),
                    rendezvous_ca_pem: self.trust_roots.rendezvous_ca_pem.clone(),
                    pairing_token: self.pairing_token.clone(),
                    device_label: self.device_label.clone(),
                    device_id: self.device_id.clone(),
                });
            }
        }

        bail!("failed to resolve any bootstrap endpoint");
    }

    pub fn enroll_blocking(
        &self,
        device_id_override: Option<&str>,
        device_label_override: Option<&str>,
    ) -> Result<BootstrapEnrollmentResult> {
        let resolved = self.resolve_blocking()?;
        let pairing_token = resolved
            .pairing_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("bootstrap is missing pairing_token"))?;
        let device_id = normalize_optional(device_id_override)
            .or_else(|| normalize_optional(resolved.device_id.as_deref()))
            .map(|value| {
                value
                    .parse()
                    .with_context(|| format!("invalid bootstrap device_id {}", value))
            })
            .transpose()?;
        let label = normalize_optional(device_label_override)
            .or_else(|| normalize_optional(resolved.device_label.as_deref()));
        let mut identity =
            ClientIdentityMaterial::generate(self.cluster_id, device_id, label.clone())?;

        let enrollment = enroll_device_blocking_from_pem(
            &Url::parse(&resolved.server_base_url).with_context(|| {
                format!("invalid resolved server URL {}", resolved.server_base_url)
            })?,
            resolved.server_ca_pem.as_deref(),
            &DeviceEnrollmentRequest {
                cluster_id: self.cluster_id,
                pairing_token: pairing_token.to_string(),
                device_id: Some(identity.device_id.to_string()),
                label,
                public_key_pem: identity.public_key_pem.clone(),
            },
        )?;
        identity.apply_issued_identity(&enrollment.issued_identity()?)?;

        Ok(BootstrapEnrollmentResult {
            cluster_id: resolved.cluster_id,
            server_base_url: resolved.server_base_url,
            server_ca_pem: resolved.server_ca_pem,
            device_id: enrollment.device_id,
            device_token: enrollment.device_token,
            label: enrollment.label,
            public_key_pem: identity.public_key_pem,
            private_key_pem: identity.private_key_pem,
            credential_pem: enrollment.credential_pem,
            created_at_unix: enrollment.created_at_unix,
            expires_at_unix: enrollment.expires_at_unix,
        })
    }

    fn to_transport_bootstrap(&self) -> Result<TransportClientBootstrap> {
        Ok(TransportClientBootstrap {
            version: self.version,
            cluster_id: self.cluster_id,
            rendezvous_urls: self.rendezvous_urls.clone(),
            rendezvous_mtls_required: self.rendezvous_mtls_required,
            direct_endpoints: self.direct_endpoints.clone(),
            relay_mode: self.relay_mode,
            trust_roots: self.trust_roots.clone(),
            pairing_token: self.pairing_token.clone(),
            device_id: self
                .device_id
                .as_deref()
                .map(|value| {
                    value
                        .parse()
                        .with_context(|| format!("invalid bootstrap device_id {}", value))
                })
                .transpose()?,
            device_label: self.device_label.clone(),
        })
    }
}

fn normalize_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

impl From<&BootstrapEnrollmentResult> for DeviceEnrollmentResponse {
    fn from(value: &BootstrapEnrollmentResult) -> Self {
        Self {
            cluster_id: value.cluster_id,
            device_id: value.device_id.clone(),
            device_token: value.device_token.clone(),
            label: value.label.clone(),
            public_key_pem: value.public_key_pem.clone(),
            credential_pem: value.credential_pem.clone(),
            created_at_unix: value.created_at_unix,
            expires_at_unix: value.expires_at_unix,
        }
    }
}
