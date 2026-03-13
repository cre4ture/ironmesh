use anyhow::{Context, Result, bail};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Duration;

use crate::connection::build_blocking_reqwest_client_from_pem;
use crate::device_auth::{
    DeviceEnrollmentRequest, DeviceEnrollmentResponse, enroll_device_blocking_from_pem,
};
use crate::ironmesh_client::normalize_server_base_url;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionBootstrap {
    pub version: u32,
    pub endpoints: Vec<String>,
    #[serde(default)]
    pub resolved_endpoint: Option<String>,
    #[serde(default)]
    pub server_ca_pem: Option<String>,
    #[serde(default)]
    pub pairing_token: Option<String>,
    #[serde(default)]
    pub device_label: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedConnectionBootstrap {
    pub server_base_url: String,
    #[serde(default)]
    pub server_ca_pem: Option<String>,
    #[serde(default)]
    pub pairing_token: Option<String>,
    #[serde(default)]
    pub device_label: Option<String>,
    #[serde(default)]
    pub device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapEnrollmentResult {
    pub server_base_url: String,
    #[serde(default)]
    pub server_ca_pem: Option<String>,
    pub device_id: String,
    pub device_token: String,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub created_at_unix: Option<u64>,
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
        if self.version != 1 {
            bail!("unsupported bootstrap version {}", self.version);
        }
        if self.endpoints.is_empty() && self.resolved_endpoint.is_none() {
            bail!("bootstrap must include at least one endpoint");
        }
        Ok(())
    }

    pub fn candidate_endpoints(&self) -> Result<Vec<Url>> {
        let mut seen = BTreeSet::new();
        let mut endpoints = Vec::new();

        if let Some(endpoint) = self.resolved_endpoint.as_deref() {
            let url = normalize_server_base_url(endpoint)?;
            if seen.insert(url.as_str().to_string()) {
                endpoints.push(url);
            }
        }

        for endpoint in &self.endpoints {
            let url = normalize_server_base_url(endpoint)?;
            if seen.insert(url.as_str().to_string()) {
                endpoints.push(url);
            }
        }

        Ok(endpoints)
    }

    pub fn resolve_blocking(&self) -> Result<ResolvedConnectionBootstrap> {
        self.validate()?;
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .context("failed building bootstrap probe client")?;
        let trusted = build_blocking_reqwest_client_from_pem(self.server_ca_pem.as_deref())
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
                    server_base_url: endpoint.to_string(),
                    server_ca_pem: self.server_ca_pem.clone(),
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
        let pairing_token = self
            .pairing_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow::anyhow!("bootstrap is missing pairing_token"))?;

        let enrollment = enroll_device_blocking_from_pem(
            &Url::parse(&resolved.server_base_url).with_context(|| {
                format!("invalid resolved server URL {}", resolved.server_base_url)
            })?,
            resolved.server_ca_pem.as_deref(),
            &DeviceEnrollmentRequest {
                pairing_token: pairing_token.to_string(),
                device_id: normalize_optional(device_id_override)
                    .or_else(|| normalize_optional(resolved.device_id.as_deref())),
                label: normalize_optional(device_label_override)
                    .or_else(|| normalize_optional(resolved.device_label.as_deref())),
            },
        )?;

        Ok(BootstrapEnrollmentResult {
            server_base_url: resolved.server_base_url,
            server_ca_pem: resolved.server_ca_pem,
            device_id: enrollment.device_id,
            device_token: enrollment.device_token,
            label: enrollment.label,
            created_at_unix: enrollment.created_at_unix,
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
            device_id: value.device_id.clone(),
            device_token: value.device_token.clone(),
            label: value.label.clone(),
            created_at_unix: value.created_at_unix,
        }
    }
}
