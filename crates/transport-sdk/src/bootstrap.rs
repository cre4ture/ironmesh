use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};
use common::{ClusterId, DeviceId, NodeId};
use reqwest::Url;
use serde::{Deserialize, Serialize};

pub const CLIENT_BOOTSTRAP_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RelayMode {
    Disabled,
    #[default]
    Fallback,
    Preferred,
    Required,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapEndpointUse {
    PublicApi,
    PeerApi,
    Rendezvous,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapEndpoint {
    pub url: String,
    #[serde(default)]
    pub usage: Option<BootstrapEndpointUse>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapTrustRoots {
    #[serde(default)]
    pub cluster_ca_pem: Option<String>,
    #[serde(default)]
    pub public_api_ca_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientBootstrap {
    pub version: u32,
    pub cluster_id: ClusterId,
    pub rendezvous_urls: Vec<String>,
    #[serde(default)]
    pub direct_endpoints: Vec<BootstrapEndpoint>,
    #[serde(default)]
    pub relay_mode: RelayMode,
    pub trust_roots: BootstrapTrustRoots,
    #[serde(default)]
    pub pairing_token: Option<String>,
    #[serde(default)]
    pub device_id: Option<DeviceId>,
    #[serde(default)]
    pub device_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeBootstrap {
    pub version: u32,
    pub cluster_id: ClusterId,
    pub node_id: NodeId,
    pub rendezvous_urls: Vec<String>,
    #[serde(default)]
    pub direct_endpoints: Vec<BootstrapEndpoint>,
    #[serde(default)]
    pub relay_mode: RelayMode,
    pub trust_roots: BootstrapTrustRoots,
}

impl ClientBootstrap {
    pub fn from_json_str(raw: &str) -> Result<Self> {
        let bootstrap =
            serde_json::from_str::<Self>(raw).context("failed to parse client bootstrap JSON")?;
        bootstrap.validate()?;
        Ok(bootstrap)
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read client bootstrap {}", path.display()))?;
        Self::from_json_str(&raw)
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string_pretty(self).context("failed to serialize client bootstrap JSON")
    }

    pub fn write_to_path(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
        fs::write(path, self.to_json_pretty()?)
            .with_context(|| format!("failed to write client bootstrap {}", path.display()))
    }

    pub fn validate(&self) -> Result<()> {
        validate_version(self.version)?;
        validate_cluster_id(self.cluster_id)?;
        validate_url_list("rendezvous_urls", &self.rendezvous_urls)?;
        validate_endpoint_list(&self.direct_endpoints)?;
        validate_trust_roots(&self.trust_roots)?;
        validate_optional_non_empty("pairing_token", self.pairing_token.as_deref())?;
        validate_optional_non_empty("device_label", self.device_label.as_deref())?;
        Ok(())
    }

    pub fn preferred_direct_urls(&self) -> Result<Vec<Url>> {
        dedup_urls(
            self.direct_endpoints
                .iter()
                .map(|endpoint| endpoint.url.as_str()),
        )
    }
}

impl NodeBootstrap {
    pub fn from_json_str(raw: &str) -> Result<Self> {
        let bootstrap =
            serde_json::from_str::<Self>(raw).context("failed to parse node bootstrap JSON")?;
        bootstrap.validate()?;
        Ok(bootstrap)
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read node bootstrap {}", path.display()))?;
        Self::from_json_str(&raw)
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string_pretty(self).context("failed to serialize node bootstrap JSON")
    }

    pub fn write_to_path(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
        fs::write(path, self.to_json_pretty()?)
            .with_context(|| format!("failed to write node bootstrap {}", path.display()))
    }

    pub fn validate(&self) -> Result<()> {
        validate_version(self.version)?;
        validate_cluster_id(self.cluster_id)?;
        if self.node_id.is_nil() {
            bail!("node bootstrap must include a non-nil node_id");
        }
        validate_url_list("rendezvous_urls", &self.rendezvous_urls)?;
        validate_endpoint_list(&self.direct_endpoints)?;
        validate_trust_roots(&self.trust_roots)?;
        Ok(())
    }
}

fn validate_version(version: u32) -> Result<()> {
    if version != CLIENT_BOOTSTRAP_VERSION {
        bail!("unsupported bootstrap version {version}");
    }
    Ok(())
}

fn validate_cluster_id(cluster_id: ClusterId) -> Result<()> {
    if cluster_id.is_nil() {
        bail!("bootstrap must include a non-nil cluster_id");
    }
    Ok(())
}

fn validate_endpoint_list(endpoints: &[BootstrapEndpoint]) -> Result<()> {
    for endpoint in endpoints {
        if endpoint.url.trim().is_empty() {
            bail!("bootstrap direct_endpoints must not contain empty URLs");
        }
        Url::parse(endpoint.url.trim())
            .with_context(|| format!("invalid bootstrap endpoint URL {}", endpoint.url))?;
    }
    Ok(())
}

fn validate_trust_roots(trust_roots: &BootstrapTrustRoots) -> Result<()> {
    validate_optional_non_empty(
        "trust_roots.cluster_ca_pem",
        trust_roots.cluster_ca_pem.as_deref(),
    )?;
    validate_optional_non_empty(
        "trust_roots.public_api_ca_pem",
        trust_roots.public_api_ca_pem.as_deref(),
    )
}

fn validate_url_list(field_name: &str, values: &[String]) -> Result<()> {
    if values.is_empty() {
        bail!("bootstrap must include at least one {field_name}");
    }

    let mut seen = HashSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            bail!("{field_name} must not contain empty URLs");
        }
        let parsed = Url::parse(trimmed)
            .with_context(|| format!("invalid URL in {field_name}: {trimmed}"))?;
        if !seen.insert(parsed.as_str().to_string()) {
            bail!("{field_name} must not contain duplicate URLs");
        }
    }

    Ok(())
}

fn validate_optional_non_empty(field_name: &str, value: Option<&str>) -> Result<()> {
    if let Some(value) = value
        && value.trim().is_empty()
    {
        bail!("{field_name} must not be empty when provided");
    }
    Ok(())
}

fn dedup_urls<'a>(values: impl IntoIterator<Item = &'a str>) -> Result<Vec<Url>> {
    let mut seen = HashSet::new();
    let mut urls = Vec::new();

    for value in values {
        let parsed = Url::parse(value.trim())
            .with_context(|| format!("invalid URL in bootstrap endpoint list: {value}"))?;
        if seen.insert(parsed.as_str().to_string()) {
            urls.push(parsed);
        }
    }

    Ok(urls)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn client_bootstrap_validates_rendezvous_and_cluster() {
        let bootstrap = ClientBootstrap {
            version: CLIENT_BOOTSTRAP_VERSION,
            cluster_id: Uuid::now_v7(),
            rendezvous_urls: vec!["https://rendezvous.example".to_string()],
            direct_endpoints: vec![BootstrapEndpoint {
                url: "https://node-a.example".to_string(),
                usage: Some(BootstrapEndpointUse::PublicApi),
            }],
            relay_mode: RelayMode::Fallback,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: Some("cluster-ca".to_string()),
                public_api_ca_pem: Some("public-ca".to_string()),
            },
            pairing_token: Some("pair-secret".to_string()),
            device_id: Some(Uuid::now_v7()),
            device_label: Some("laptop".to_string()),
        };

        bootstrap.validate().expect("bootstrap should validate");
    }

    #[test]
    fn client_bootstrap_rejects_empty_rendezvous_urls() {
        let bootstrap = ClientBootstrap {
            version: CLIENT_BOOTSTRAP_VERSION,
            cluster_id: Uuid::now_v7(),
            rendezvous_urls: Vec::new(),
            direct_endpoints: Vec::new(),
            relay_mode: RelayMode::Fallback,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: Some("cluster-ca".to_string()),
                public_api_ca_pem: None,
            },
            pairing_token: None,
            device_id: None,
            device_label: None,
        };

        assert!(bootstrap.validate().is_err());
    }
}
