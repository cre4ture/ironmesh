use std::collections::{HashMap, HashSet};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<NodeId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapTrustRoots {
    #[serde(default)]
    pub cluster_ca_pem: Option<String>,
    #[serde(default)]
    pub public_api_ca_pem: Option<String>,
    #[serde(default)]
    pub rendezvous_ca_pem: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum NodeBootstrapMode {
    #[default]
    Cluster,
    LocalEdge,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapTlsFiles {
    pub ca_cert_path: String,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapServerTlsFiles {
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapMutualTlsMaterial {
    pub ca_cert_pem: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub metadata: BootstrapTlsMaterialMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapTlsMaterialMetadata {
    pub issued_at_unix: u64,
    pub not_before_unix: u64,
    pub not_after_unix: u64,
    pub renew_after_unix: u64,
    pub certificate_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientBootstrap {
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
    pub device_id: Option<DeviceId>,
    #[serde(default)]
    pub device_label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeBootstrap {
    pub version: u32,
    pub cluster_id: ClusterId,
    pub node_id: NodeId,
    #[serde(default)]
    pub mode: NodeBootstrapMode,
    pub data_dir: String,
    pub bind_addr: String,
    #[serde(default)]
    pub public_url: Option<String>,
    #[serde(default)]
    pub labels: HashMap<String, String>,
    #[serde(default)]
    pub public_tls: Option<BootstrapServerTlsFiles>,
    #[serde(default)]
    pub public_ca_cert_path: Option<String>,
    #[serde(default)]
    pub public_peer_api_enabled: bool,
    #[serde(default)]
    pub internal_bind_addr: Option<String>,
    #[serde(default)]
    pub internal_url: Option<String>,
    #[serde(default)]
    pub internal_tls: Option<BootstrapTlsFiles>,
    pub rendezvous_urls: Vec<String>,
    #[serde(default)]
    pub rendezvous_mtls_required: bool,
    #[serde(default)]
    pub direct_endpoints: Vec<BootstrapEndpoint>,
    #[serde(default)]
    pub relay_mode: RelayMode,
    pub trust_roots: BootstrapTrustRoots,
    #[serde(default)]
    pub upstream_public_url: Option<String>,
    #[serde(default)]
    pub enrollment_issuer_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeEnrollmentPackage {
    pub bootstrap: NodeBootstrap,
    #[serde(default)]
    pub public_tls_material: Option<BootstrapMutualTlsMaterial>,
    #[serde(default)]
    pub internal_tls_material: Option<BootstrapMutualTlsMaterial>,
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
        validate_required_non_empty("data_dir", &self.data_dir)?;
        validate_socket_addr("bind_addr", &self.bind_addr)?;
        validate_optional_url("public_url", self.public_url.as_deref())?;
        validate_optional_non_empty("public_ca_cert_path", self.public_ca_cert_path.as_deref())?;
        validate_optional_socket_addr("internal_bind_addr", self.internal_bind_addr.as_deref())?;
        validate_optional_url("internal_url", self.internal_url.as_deref())?;
        validate_optional_url("upstream_public_url", self.upstream_public_url.as_deref())?;
        validate_optional_url(
            "enrollment_issuer_url",
            self.enrollment_issuer_url.as_deref(),
        )?;
        validate_optional_server_tls_files("public_tls", self.public_tls.as_ref())?;
        validate_optional_tls_files("internal_tls", self.internal_tls.as_ref())?;
        if self.mode == NodeBootstrapMode::Cluster && self.internal_tls.is_none() {
            bail!("cluster node bootstrap must include internal_tls");
        }
        if self.internal_tls.is_some() && self.internal_bind_addr.is_none() {
            bail!("node bootstrap internal_tls requires internal_bind_addr");
        }
        validate_url_list("rendezvous_urls", &self.rendezvous_urls)?;
        validate_endpoint_list(&self.direct_endpoints)?;
        validate_trust_roots(&self.trust_roots)?;
        Ok(())
    }
}

impl NodeEnrollmentPackage {
    pub fn from_json_str(raw: &str) -> Result<Self> {
        let package =
            serde_json::from_str::<Self>(raw).context("failed to parse node enrollment JSON")?;
        package.validate()?;
        Ok(package)
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let raw = fs::read_to_string(path)
            .with_context(|| format!("failed to read node enrollment {}", path.display()))?;
        Self::from_json_str(&raw)
    }

    pub fn to_json_pretty(&self) -> Result<String> {
        self.validate()?;
        serde_json::to_string_pretty(self).context("failed to serialize node enrollment JSON")
    }

    pub fn write_to_path(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
        fs::write(path, self.to_json_pretty()?)
            .with_context(|| format!("failed to write node enrollment {}", path.display()))
    }

    pub fn validate(&self) -> Result<()> {
        self.bootstrap.validate()?;
        match (
            self.bootstrap.public_tls.as_ref(),
            self.public_tls_material.as_ref(),
        ) {
            (Some(_), Some(material)) => validate_tls_material("public_tls_material", material)?,
            (Some(_), None) => bail!("node enrollment package must include public_tls_material"),
            (None, Some(_)) => {
                bail!("node enrollment package public_tls_material requires bootstrap.public_tls")
            }
            (None, None) => {}
        }
        match (
            self.bootstrap.internal_tls.as_ref(),
            self.internal_tls_material.as_ref(),
        ) {
            (Some(_), Some(material)) => validate_tls_material("internal_tls_material", material),
            (Some(_), None) => bail!("node enrollment package must include internal_tls_material"),
            (None, Some(_)) => {
                bail!(
                    "node enrollment package internal_tls_material requires bootstrap.internal_tls"
                )
            }
            (None, None) => Ok(()),
        }
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
        if let Some(node_id) = endpoint.node_id
            && node_id.is_nil()
        {
            bail!("bootstrap endpoint node_id must not be nil");
        }
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
    )?;
    validate_optional_non_empty(
        "trust_roots.rendezvous_ca_pem",
        trust_roots.rendezvous_ca_pem.as_deref(),
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

fn validate_required_non_empty(field_name: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        bail!("{field_name} must not be empty");
    }
    Ok(())
}

fn validate_optional_url(field_name: &str, value: Option<&str>) -> Result<()> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    Url::parse(value).with_context(|| format!("invalid URL in {field_name}: {value}"))?;
    Ok(())
}

fn validate_socket_addr(field_name: &str, value: &str) -> Result<()> {
    value
        .trim()
        .parse::<std::net::SocketAddr>()
        .with_context(|| format!("invalid socket address in {field_name}: {value}"))?;
    Ok(())
}

fn validate_optional_socket_addr(field_name: &str, value: Option<&str>) -> Result<()> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };
    validate_socket_addr(field_name, value)
}

fn validate_optional_tls_files(field_name: &str, value: Option<&BootstrapTlsFiles>) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    validate_required_non_empty(&format!("{field_name}.ca_cert_path"), &value.ca_cert_path)?;
    validate_required_non_empty(&format!("{field_name}.cert_path"), &value.cert_path)?;
    validate_required_non_empty(&format!("{field_name}.key_path"), &value.key_path)?;
    Ok(())
}

fn validate_optional_server_tls_files(
    field_name: &str,
    value: Option<&BootstrapServerTlsFiles>,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    validate_required_non_empty(&format!("{field_name}.cert_path"), &value.cert_path)?;
    validate_required_non_empty(&format!("{field_name}.key_path"), &value.key_path)?;
    Ok(())
}

fn validate_tls_material(field_name: &str, value: &BootstrapMutualTlsMaterial) -> Result<()> {
    validate_required_non_empty(&format!("{field_name}.ca_cert_pem"), &value.ca_cert_pem)?;
    validate_required_non_empty(&format!("{field_name}.cert_pem"), &value.cert_pem)?;
    validate_required_non_empty(&format!("{field_name}.key_pem"), &value.key_pem)?;
    validate_required_non_empty(
        &format!("{field_name}.metadata.certificate_fingerprint"),
        &value.metadata.certificate_fingerprint,
    )?;
    if value.metadata.not_before_unix > value.metadata.not_after_unix {
        bail!("{field_name}.metadata not_before_unix must be <= not_after_unix");
    }
    if value.metadata.issued_at_unix < value.metadata.not_before_unix
        || value.metadata.issued_at_unix > value.metadata.not_after_unix
    {
        bail!("{field_name}.metadata issued_at_unix must fall within cert validity");
    }
    if value.metadata.renew_after_unix < value.metadata.not_before_unix
        || value.metadata.renew_after_unix > value.metadata.not_after_unix
    {
        bail!("{field_name}.metadata renew_after_unix must fall within cert validity");
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

    fn sample_tls_material() -> BootstrapMutualTlsMaterial {
        BootstrapMutualTlsMaterial {
            ca_cert_pem: "ca".to_string(),
            cert_pem: "cert".to_string(),
            key_pem: "key".to_string(),
            metadata: BootstrapTlsMaterialMetadata {
                issued_at_unix: 200,
                not_before_unix: 100,
                not_after_unix: 300,
                renew_after_unix: 250,
                certificate_fingerprint: "fingerprint".to_string(),
            },
        }
    }

    #[test]
    fn client_bootstrap_validates_rendezvous_and_cluster() {
        let bootstrap = ClientBootstrap {
            version: CLIENT_BOOTSTRAP_VERSION,
            cluster_id: Uuid::now_v7(),
            rendezvous_urls: vec!["https://rendezvous.example".to_string()],
            rendezvous_mtls_required: true,
            direct_endpoints: vec![BootstrapEndpoint {
                url: "https://node-a.example".to_string(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: Some(Uuid::now_v7()),
            }],
            relay_mode: RelayMode::Fallback,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: Some("cluster-ca".to_string()),
                public_api_ca_pem: Some("public-ca".to_string()),
                rendezvous_ca_pem: Some("rendezvous-ca".to_string()),
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
            rendezvous_mtls_required: false,
            direct_endpoints: Vec::new(),
            relay_mode: RelayMode::Fallback,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: Some("cluster-ca".to_string()),
                public_api_ca_pem: None,
                rendezvous_ca_pem: None,
            },
            pairing_token: None,
            device_id: None,
            device_label: None,
        };

        assert!(bootstrap.validate().is_err());
    }

    #[test]
    fn node_bootstrap_validates_cluster_runtime_shape() {
        let bootstrap = NodeBootstrap {
            version: CLIENT_BOOTSTRAP_VERSION,
            cluster_id: Uuid::now_v7(),
            node_id: Uuid::now_v7(),
            mode: NodeBootstrapMode::Cluster,
            data_dir: "./data/node-a".to_string(),
            bind_addr: "127.0.0.1:8080".to_string(),
            public_url: Some("https://node-a.example".to_string()),
            labels: HashMap::from([("dc".to_string(), "edge-a".to_string())]),
            public_tls: None,
            public_ca_cert_path: None,
            public_peer_api_enabled: false,
            internal_bind_addr: Some("127.0.0.1:18080".to_string()),
            internal_url: Some("https://127.0.0.1:18080".to_string()),
            internal_tls: Some(BootstrapTlsFiles {
                ca_cert_path: "tls/ca.pem".to_string(),
                cert_path: "tls/node.pem".to_string(),
                key_path: "tls/node.key".to_string(),
            }),
            rendezvous_urls: vec!["https://rendezvous.example".to_string()],
            rendezvous_mtls_required: true,
            direct_endpoints: vec![BootstrapEndpoint {
                url: "https://node-a.example".to_string(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: Some(Uuid::now_v7()),
            }],
            relay_mode: RelayMode::Required,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: Some("cluster-ca".to_string()),
                public_api_ca_pem: Some("public-ca".to_string()),
                rendezvous_ca_pem: Some("rendezvous-ca".to_string()),
            },
            upstream_public_url: None,
            enrollment_issuer_url: Some("https://issuer.example".to_string()),
        };

        bootstrap
            .validate()
            .expect("node bootstrap should validate");
    }

    #[test]
    fn node_enrollment_package_requires_internal_tls_material_for_cluster_bootstrap() {
        let package = NodeEnrollmentPackage {
            bootstrap: NodeBootstrap {
                version: CLIENT_BOOTSTRAP_VERSION,
                cluster_id: Uuid::now_v7(),
                node_id: Uuid::now_v7(),
                mode: NodeBootstrapMode::Cluster,
                data_dir: "./data/node-a".to_string(),
                bind_addr: "127.0.0.1:8080".to_string(),
                public_url: Some("https://node-a.example".to_string()),
                labels: HashMap::new(),
                public_tls: None,
                public_ca_cert_path: None,
                public_peer_api_enabled: false,
                internal_bind_addr: Some("127.0.0.1:18080".to_string()),
                internal_url: Some("https://127.0.0.1:18080".to_string()),
                internal_tls: Some(BootstrapTlsFiles {
                    ca_cert_path: "tls/ca.pem".to_string(),
                    cert_path: "tls/node.pem".to_string(),
                    key_path: "tls/node.key".to_string(),
                }),
                rendezvous_urls: vec!["https://rendezvous.example".to_string()],
                rendezvous_mtls_required: false,
                direct_endpoints: Vec::new(),
                relay_mode: RelayMode::Fallback,
                trust_roots: BootstrapTrustRoots {
                    cluster_ca_pem: Some("cluster-ca".to_string()),
                    public_api_ca_pem: None,
                    rendezvous_ca_pem: None,
                },
                upstream_public_url: None,
                enrollment_issuer_url: None,
            },
            public_tls_material: None,
            internal_tls_material: None,
        };

        assert!(package.validate().is_err());
    }

    #[test]
    fn node_enrollment_package_requires_public_tls_material_when_public_tls_is_present() {
        let package = NodeEnrollmentPackage {
            bootstrap: NodeBootstrap {
                version: CLIENT_BOOTSTRAP_VERSION,
                cluster_id: Uuid::now_v7(),
                node_id: Uuid::now_v7(),
                mode: NodeBootstrapMode::LocalEdge,
                data_dir: "./data/node-a".to_string(),
                bind_addr: "127.0.0.1:8080".to_string(),
                public_url: Some("https://node-a.example".to_string()),
                labels: HashMap::new(),
                public_tls: Some(BootstrapServerTlsFiles {
                    cert_path: "tls/public.pem".to_string(),
                    key_path: "tls/public.key".to_string(),
                }),
                public_ca_cert_path: Some("tls/public-ca.pem".to_string()),
                public_peer_api_enabled: false,
                internal_bind_addr: None,
                internal_url: None,
                internal_tls: None,
                rendezvous_urls: vec!["https://rendezvous.example".to_string()],
                rendezvous_mtls_required: false,
                direct_endpoints: Vec::new(),
                relay_mode: RelayMode::Fallback,
                trust_roots: BootstrapTrustRoots {
                    cluster_ca_pem: None,
                    public_api_ca_pem: Some("public-ca".to_string()),
                    rendezvous_ca_pem: None,
                },
                upstream_public_url: None,
                enrollment_issuer_url: None,
            },
            public_tls_material: None,
            internal_tls_material: None,
        };

        assert!(package.validate().is_err());
    }

    #[test]
    fn node_enrollment_package_accepts_tls_material_with_metadata() {
        let package = NodeEnrollmentPackage {
            bootstrap: NodeBootstrap {
                version: CLIENT_BOOTSTRAP_VERSION,
                cluster_id: Uuid::now_v7(),
                node_id: Uuid::now_v7(),
                mode: NodeBootstrapMode::Cluster,
                data_dir: "./data/node-a".to_string(),
                bind_addr: "127.0.0.1:8080".to_string(),
                public_url: Some("https://node-a.example".to_string()),
                labels: HashMap::new(),
                public_tls: Some(BootstrapServerTlsFiles {
                    cert_path: "tls/public.pem".to_string(),
                    key_path: "tls/public.key".to_string(),
                }),
                public_ca_cert_path: Some("tls/public-ca.pem".to_string()),
                public_peer_api_enabled: false,
                internal_bind_addr: Some("127.0.0.1:18080".to_string()),
                internal_url: Some("https://127.0.0.1:18080".to_string()),
                internal_tls: Some(BootstrapTlsFiles {
                    ca_cert_path: "tls/ca.pem".to_string(),
                    cert_path: "tls/node.pem".to_string(),
                    key_path: "tls/node.key".to_string(),
                }),
                rendezvous_urls: vec!["https://rendezvous.example".to_string()],
                rendezvous_mtls_required: false,
                direct_endpoints: Vec::new(),
                relay_mode: RelayMode::Fallback,
                trust_roots: BootstrapTrustRoots {
                    cluster_ca_pem: Some("cluster-ca".to_string()),
                    public_api_ca_pem: Some("public-ca".to_string()),
                    rendezvous_ca_pem: None,
                },
                upstream_public_url: None,
                enrollment_issuer_url: Some("https://issuer.example".to_string()),
            },
            public_tls_material: Some(sample_tls_material()),
            internal_tls_material: Some(sample_tls_material()),
        };

        package.validate().unwrap();
    }

    #[test]
    fn node_enrollment_package_rejects_invalid_tls_metadata_window() {
        let mut invalid = sample_tls_material();
        invalid.metadata.renew_after_unix = 99;
        let package = NodeEnrollmentPackage {
            bootstrap: NodeBootstrap {
                version: CLIENT_BOOTSTRAP_VERSION,
                cluster_id: Uuid::now_v7(),
                node_id: Uuid::now_v7(),
                mode: NodeBootstrapMode::LocalEdge,
                data_dir: "./data/node-a".to_string(),
                bind_addr: "127.0.0.1:8080".to_string(),
                public_url: Some("https://node-a.example".to_string()),
                labels: HashMap::new(),
                public_tls: Some(BootstrapServerTlsFiles {
                    cert_path: "tls/public.pem".to_string(),
                    key_path: "tls/public.key".to_string(),
                }),
                public_ca_cert_path: Some("tls/public-ca.pem".to_string()),
                public_peer_api_enabled: false,
                internal_bind_addr: None,
                internal_url: None,
                internal_tls: None,
                rendezvous_urls: vec!["https://rendezvous.example".to_string()],
                rendezvous_mtls_required: false,
                direct_endpoints: Vec::new(),
                relay_mode: RelayMode::Fallback,
                trust_roots: BootstrapTrustRoots {
                    cluster_ca_pem: None,
                    public_api_ca_pem: Some("public-ca".to_string()),
                    rendezvous_ca_pem: None,
                },
                upstream_public_url: None,
                enrollment_issuer_url: Some("https://issuer.example".to_string()),
            },
            public_tls_material: Some(invalid),
            internal_tls_material: None,
        };

        assert!(package.validate().is_err());
    }

    #[test]
    fn bootstrap_endpoint_rejects_nil_node_id() {
        let bootstrap = ClientBootstrap {
            version: CLIENT_BOOTSTRAP_VERSION,
            cluster_id: Uuid::now_v7(),
            rendezvous_urls: vec!["https://rendezvous.example".to_string()],
            rendezvous_mtls_required: true,
            direct_endpoints: vec![BootstrapEndpoint {
                url: "https://node-a.example".to_string(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: Some(Uuid::nil()),
            }],
            relay_mode: RelayMode::Fallback,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: Some("cluster-ca".to_string()),
                public_api_ca_pem: Some("public-ca".to_string()),
                rendezvous_ca_pem: Some("rendezvous-ca".to_string()),
            },
            pairing_token: None,
            device_id: None,
            device_label: None,
        };

        assert!(bootstrap.validate().is_err());
    }
}
