use anyhow::{Context, Result, anyhow, bail};
use common::{ClusterId, NodeId};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Duration;
use transport_sdk::{
    BootstrapEndpoint, BootstrapEndpointUse, BootstrapTrustRoots,
    ClientBootstrap as TransportClientBootstrap, ClientIdentityMaterial, RelayMode,
    TransportPathKind,
};

use crate::connection::{
    build_blocking_reqwest_client_from_pem, build_http_client_from_pem,
    build_http_client_with_identity_from_planned_target,
};
use crate::device_auth::{
    DeviceEnrollmentRequest, DeviceEnrollmentResponse, enroll_device_blocking_from_pem,
};
use crate::ironmesh_client::{IronMeshClient, normalize_server_base_url};

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
    pub target_node_id: Option<NodeId>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PlannedConnectionBootstrapTarget {
    pub cluster_id: ClusterId,
    pub rendezvous_urls: Vec<String>,
    #[serde(default)]
    pub rendezvous_mtls_required: bool,
    pub relay_mode: RelayMode,
    pub path_kind: TransportPathKind,
    #[serde(default)]
    pub server_base_url: Option<String>,
    #[serde(default)]
    pub target_node_id: Option<NodeId>,
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

impl PlannedConnectionBootstrapTarget {
    pub fn requires_custom_transport(&self) -> bool {
        self.server_base_url.is_none()
    }
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
    pub rendezvous_client_identity_pem: Option<String>,
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
            rendezvous_client_identity_pem: self.rendezvous_client_identity_pem.clone(),
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
        self.normalized_candidate_direct_endpoints()?
            .into_iter()
            .map(|endpoint| {
                Url::parse(&endpoint.url).with_context(|| {
                    format!("invalid normalized bootstrap endpoint {}", endpoint.url)
                })
            })
            .collect()
    }

    fn normalized_candidate_direct_endpoints(&self) -> Result<Vec<BootstrapEndpoint>> {
        let mut seen = BTreeSet::new();
        let mut endpoints = Vec::new();

        for endpoint in &self.direct_endpoints {
            if matches!(
                endpoint.usage,
                Some(BootstrapEndpointUse::Rendezvous | BootstrapEndpointUse::PeerApi)
            ) {
                continue;
            }
            let url = normalize_server_base_url(&endpoint.url)?;
            let seen_key = format!(
                "{}#{}",
                url.as_str(),
                endpoint
                    .node_id
                    .map(|node_id| node_id.to_string())
                    .unwrap_or_default()
            );
            if seen.insert(seen_key) {
                endpoints.push(BootstrapEndpoint {
                    url: url.to_string(),
                    usage: endpoint.usage,
                    node_id: endpoint.node_id,
                });
            }
        }

        Ok(endpoints)
    }

    pub fn planned_targets(&self) -> Result<Vec<PlannedConnectionBootstrapTarget>> {
        self.validate()?;

        let direct_targets = self
            .normalized_candidate_direct_endpoints()?
            .into_iter()
            .map(|endpoint| PlannedConnectionBootstrapTarget {
                cluster_id: self.cluster_id,
                rendezvous_urls: self.rendezvous_urls.clone(),
                rendezvous_mtls_required: self.rendezvous_mtls_required,
                relay_mode: self.relay_mode,
                path_kind: TransportPathKind::DirectHttps,
                server_base_url: Some(endpoint.url),
                target_node_id: endpoint.node_id,
                server_ca_pem: self.trust_roots.public_api_ca_pem.clone(),
                cluster_ca_pem: self.trust_roots.cluster_ca_pem.clone(),
                rendezvous_ca_pem: self.trust_roots.rendezvous_ca_pem.clone(),
                pairing_token: self.pairing_token.clone(),
                device_label: self.device_label.clone(),
                device_id: self.device_id.clone(),
            })
            .collect::<Vec<_>>();

        let relay_targets = if self.relay_mode != RelayMode::Disabled {
            if self.rendezvous_urls.is_empty() {
                if self.relay_mode == RelayMode::Required {
                    bail!(
                        "bootstrap requires relay connectivity but does not include rendezvous_urls"
                    );
                }
                Vec::new()
            } else {
                let mut relay_targets = Vec::new();
                let mut seen_node_ids = BTreeSet::new();
                for target in &direct_targets {
                    let Some(target_node_id) = target.target_node_id else {
                        continue;
                    };
                    if !seen_node_ids.insert(target_node_id.to_string()) {
                        continue;
                    }
                    relay_targets.push(PlannedConnectionBootstrapTarget {
                        cluster_id: self.cluster_id,
                        rendezvous_urls: self.rendezvous_urls.clone(),
                        rendezvous_mtls_required: self.rendezvous_mtls_required,
                        relay_mode: self.relay_mode,
                        path_kind: TransportPathKind::RelayTunnel,
                        server_base_url: None,
                        target_node_id: Some(target_node_id),
                        server_ca_pem: self.trust_roots.public_api_ca_pem.clone(),
                        cluster_ca_pem: self.trust_roots.cluster_ca_pem.clone(),
                        rendezvous_ca_pem: self.trust_roots.rendezvous_ca_pem.clone(),
                        pairing_token: self.pairing_token.clone(),
                        device_label: self.device_label.clone(),
                        device_id: self.device_id.clone(),
                    });
                }
                if relay_targets.is_empty() && self.relay_mode == RelayMode::Required {
                    bail!(
                        "bootstrap requires relay connectivity but does not identify any target node_id for public API endpoints"
                    );
                }
                relay_targets
            }
        } else {
            Vec::new()
        };

        let planned = match self.relay_mode {
            RelayMode::Disabled => direct_targets,
            RelayMode::Fallback => {
                let mut planned = direct_targets;
                planned.extend(relay_targets);
                planned
            }
            RelayMode::Preferred => {
                let mut planned = relay_targets;
                planned.extend(direct_targets);
                planned
            }
            RelayMode::Required => relay_targets,
        };

        if planned.is_empty() {
            bail!("bootstrap does not contain any usable client transport targets");
        }

        Ok(planned)
    }

    pub fn build_client_with_identity(
        &self,
        identity: &ClientIdentityMaterial,
    ) -> Result<IronMeshClient> {
        self.validate()?;
        identity.validate()?;
        if identity.cluster_id != self.cluster_id {
            bail!(
                "client identity cluster_id {} does not match bootstrap cluster_id {}",
                identity.cluster_id,
                self.cluster_id
            );
        }

        let mut last_error = None;
        for target in self.planned_targets()? {
            if target.server_base_url.is_some() {
                match probe_direct_http_target_blocking(&target) {
                    Ok(true) => {
                        return build_http_client_with_identity_from_planned_target(
                            &target, identity,
                        );
                    }
                    Ok(false) => continue,
                    Err(err) => {
                        last_error = Some(err);
                        continue;
                    }
                }
            }

            match build_http_client_with_identity_from_planned_target(&target, identity) {
                Ok(client) => return Ok(client),
                Err(err) if target.relay_mode != RelayMode::Required => {
                    last_error = Some(err);
                }
                Err(err) => return Err(err),
            }
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow!("bootstrap does not contain a reachable client transport target")
        }))
    }

    pub fn build_client(&self) -> Result<IronMeshClient> {
        self.validate()?;

        let mut last_error = None;
        let mut saw_relay_target = false;
        for target in self.planned_targets()? {
            let Some(server_base_url) = target.server_base_url.as_deref() else {
                saw_relay_target = true;
                continue;
            };

            match probe_direct_http_target_blocking(&target) {
                Ok(true) => {
                    return build_http_client_from_pem(
                        target
                            .server_ca_pem
                            .as_deref()
                            .or(target.cluster_ca_pem.as_deref()),
                        server_base_url,
                        &None,
                    );
                }
                Ok(false) => continue,
                Err(err) => {
                    last_error = Some(err);
                    continue;
                }
            }
        }

        if saw_relay_target {
            bail!(
                "bootstrap selected or permits a relay-backed client route via rendezvous, but building a relay-backed client requires enrolled client identity material"
            );
        }

        Err(last_error.unwrap_or_else(|| {
            anyhow!("bootstrap does not contain a reachable direct client transport target")
        }))
    }

    pub fn connection_target_label(&self) -> Result<String> {
        self.validate()?;

        if self.relay_mode != RelayMode::Required
            && let Some(endpoint) = self
                .normalized_candidate_direct_endpoints()?
                .into_iter()
                .next()
        {
            return Ok(endpoint.url);
        }

        let relay_target = self
            .planned_targets()?
            .into_iter()
            .find(|target| target.path_kind == TransportPathKind::RelayTunnel)
            .ok_or_else(|| {
                anyhow!("bootstrap does not contain any usable client transport targets")
            })?;
        let target_node_id = relay_target
            .target_node_id
            .ok_or_else(|| anyhow!("relay-backed bootstrap target is missing target_node_id"))?;
        let rendezvous_hint = relay_target
            .rendezvous_urls
            .first()
            .map(|url| match Url::parse(url) {
                Ok(parsed) => parsed
                    .host_str()
                    .map(|host| match parsed.port() {
                        Some(port) => format!("{host}:{port}"),
                        None => host.to_string(),
                    })
                    .unwrap_or_else(|| url.trim().trim_end_matches('/').to_string()),
                Err(_) => url.trim().trim_end_matches('/').to_string(),
            })
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "rendezvous".to_string());

        Ok(format!(
            "relay://{target_node_id}@{rendezvous_hint}?cluster_id={}",
            relay_target.cluster_id
        ))
    }

    pub fn resolve_direct_http_target_blocking(&self) -> Result<ResolvedConnectionBootstrap> {
        let planned_targets = self.planned_targets()?;
        let mut saw_relay_target = false;

        for target in planned_targets {
            let Some(server_base_url) = target.server_base_url.as_deref() else {
                saw_relay_target = true;
                continue;
            };
            if probe_direct_http_target_blocking(&target)? {
                let endpoint = Url::parse(server_base_url)
                    .with_context(|| format!("invalid planned bootstrap URL {server_base_url}"))?;
                return Ok(ResolvedConnectionBootstrap {
                    cluster_id: target.cluster_id,
                    rendezvous_urls: target.rendezvous_urls,
                    rendezvous_mtls_required: target.rendezvous_mtls_required,
                    relay_mode: target.relay_mode,
                    server_base_url: endpoint.to_string(),
                    target_node_id: target.target_node_id,
                    server_ca_pem: target.server_ca_pem,
                    cluster_ca_pem: target.cluster_ca_pem,
                    rendezvous_ca_pem: target.rendezvous_ca_pem,
                    pairing_token: target.pairing_token,
                    device_label: target.device_label,
                    device_id: target.device_id,
                });
            }
        }

        if saw_relay_target {
            bail!(
                "bootstrap selected or permits a relay-backed client route via rendezvous, but direct HTTP target resolution was requested; use a relay-capable client construction path instead"
            );
        }

        bail!("failed to resolve any bootstrap endpoint");
    }

    pub fn resolve_blocking(&self) -> Result<ResolvedConnectionBootstrap> {
        self.resolve_direct_http_target_blocking()
    }

    pub fn enroll_blocking(
        &self,
        device_id_override: Option<&str>,
        device_label_override: Option<&str>,
    ) -> Result<BootstrapEnrollmentResult> {
        let resolved = self.resolve_direct_http_target_blocking()?;
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
            rendezvous_client_identity_pem: enrollment.rendezvous_client_identity_pem,
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

fn probe_direct_http_target_blocking(target: &PlannedConnectionBootstrapTarget) -> Result<bool> {
    let server_base_url = target
        .server_base_url
        .as_deref()
        .ok_or_else(|| anyhow!("direct bootstrap target is missing server_base_url"))?;
    let endpoint = Url::parse(server_base_url)
        .with_context(|| format!("invalid planned bootstrap URL {server_base_url}"))?;
    let health_url = endpoint
        .join("health")
        .with_context(|| format!("failed to build health URL from {endpoint}"))?;

    let probe_client = if endpoint.scheme() == "https" {
        build_blocking_reqwest_client_from_pem(
            target
                .server_ca_pem
                .as_deref()
                .or(target.cluster_ca_pem.as_deref()),
        )
        .context("failed building bootstrap trusted client")?
    } else {
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(3))
            .build()
            .context("failed building bootstrap probe client")?
    };

    match probe_client.get(health_url).send() {
        Ok(response) => Ok(response.status().is_success()),
        Err(_) => Ok(false),
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
            rendezvous_client_identity_pem: value.rendezvous_client_identity_pem.clone(),
            created_at_unix: value.created_at_unix,
            expires_at_unix: value.expires_at_unix,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_bootstrap() -> ConnectionBootstrap {
        ConnectionBootstrap {
            version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
            cluster_id: ClusterId::now_v7(),
            rendezvous_urls: vec!["https://rendezvous.example".to_string()],
            rendezvous_mtls_required: true,
            direct_endpoints: vec![
                BootstrapEndpoint {
                    url: "https://peer.example".to_string(),
                    usage: Some(BootstrapEndpointUse::PeerApi),
                    node_id: Some(NodeId::new_v4()),
                },
                BootstrapEndpoint {
                    url: "https://public.example".to_string(),
                    usage: Some(BootstrapEndpointUse::PublicApi),
                    node_id: Some(NodeId::new_v4()),
                },
                BootstrapEndpoint {
                    url: "https://rendezvous.example".to_string(),
                    usage: Some(BootstrapEndpointUse::Rendezvous),
                    node_id: None,
                },
            ],
            relay_mode: RelayMode::Fallback,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: Some("cluster-ca".to_string()),
                public_api_ca_pem: Some("public-ca".to_string()),
                rendezvous_ca_pem: Some("rendezvous-ca".to_string()),
            },
            pairing_token: Some("pairing".to_string()),
            device_label: Some("desktop".to_string()),
            device_id: Some("019cf235-6922-7902-9221-0df1a3192c62".to_string()),
        }
    }

    #[test]
    fn candidate_endpoints_ignore_peer_and_rendezvous_entries() {
        let endpoints = sample_bootstrap()
            .candidate_endpoints()
            .expect("candidate endpoints should build");

        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].as_str(), "https://public.example/");
    }

    #[test]
    fn planned_targets_include_relay_after_direct_for_fallback_mode() {
        let planned = sample_bootstrap()
            .planned_targets()
            .expect("planned targets should build");

        assert_eq!(planned.len(), 2);
        assert_eq!(planned[0].path_kind, TransportPathKind::DirectHttps);
        assert_eq!(
            planned[0].server_base_url.as_deref(),
            Some("https://public.example/")
        );
        assert!(planned[0].target_node_id.is_some());
        assert_eq!(planned[1].path_kind, TransportPathKind::RelayTunnel);
        assert!(planned[1].requires_custom_transport());
        assert_eq!(planned[1].target_node_id, planned[0].target_node_id);
    }

    #[test]
    fn planned_targets_prioritize_relay_when_preferred() {
        let mut bootstrap = sample_bootstrap();
        bootstrap.relay_mode = RelayMode::Preferred;

        let planned = bootstrap
            .planned_targets()
            .expect("planned targets should build");

        assert_eq!(planned[0].path_kind, TransportPathKind::RelayTunnel);
        assert!(planned[0].target_node_id.is_some());
        assert_eq!(planned[1].path_kind, TransportPathKind::DirectHttps);
    }

    #[test]
    fn relay_required_without_rendezvous_urls_is_rejected() {
        let mut bootstrap = sample_bootstrap();
        bootstrap.relay_mode = RelayMode::Required;
        bootstrap.rendezvous_urls.clear();

        let error = bootstrap
            .planned_targets()
            .expect_err("relay-required bootstrap without rendezvous should fail");

        assert!(error.to_string().contains("rendezvous_urls"));
    }

    #[test]
    fn resolve_direct_http_target_reports_relay_gap_when_only_relay_is_planned() {
        let mut bootstrap = sample_bootstrap();
        bootstrap.relay_mode = RelayMode::Required;

        let error = bootstrap
            .resolve_direct_http_target_blocking()
            .expect_err("relay-only client path should report the missing transport support");

        assert!(
            error
                .to_string()
                .contains("relay-capable client construction path")
        );
    }

    #[test]
    fn relay_required_without_endpoint_node_ids_is_rejected() {
        let mut bootstrap = sample_bootstrap();
        bootstrap.relay_mode = RelayMode::Required;
        for endpoint in &mut bootstrap.direct_endpoints {
            endpoint.node_id = None;
        }

        let error = bootstrap
            .planned_targets()
            .expect_err("relay-only bootstrap without endpoint node ids should fail");

        assert!(error.to_string().contains("target node_id"));
    }

    #[test]
    fn build_client_with_identity_rejects_mtls_only_rendezvous_relay() {
        let mut bootstrap = sample_bootstrap();
        bootstrap.relay_mode = RelayMode::Required;
        bootstrap.rendezvous_mtls_required = true;

        let mut identity = ClientIdentityMaterial::generate(
            bootstrap.cluster_id,
            None,
            Some("desktop".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());

        let error = bootstrap
            .build_client_with_identity(&identity)
            .err()
            .expect("mTLS-only rendezvous relay should be rejected for client devices");

        assert!(error.to_string().contains("rendezvous_client_identity_pem"));
    }

    #[test]
    fn build_client_without_identity_rejects_relay_only_bootstrap() {
        let mut bootstrap = sample_bootstrap();
        bootstrap.relay_mode = RelayMode::Required;

        let error = match bootstrap.build_client() {
            Ok(_) => panic!("relay-only bootstrap without client identity should fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("requires enrolled client identity material")
        );
    }

    #[test]
    fn connection_target_label_falls_back_to_relay_descriptor() {
        let mut bootstrap = sample_bootstrap();
        bootstrap.relay_mode = RelayMode::Required;
        bootstrap.direct_endpoints = vec![BootstrapEndpoint {
            url: "https://public.example".to_string(),
            usage: Some(BootstrapEndpointUse::PublicApi),
            node_id: Some(NodeId::new_v4()),
        }];

        let label = bootstrap
            .connection_target_label()
            .expect("relay label should build");

        assert!(label.starts_with("relay://"));
        assert!(label.contains("@rendezvous.example"));
    }
}
