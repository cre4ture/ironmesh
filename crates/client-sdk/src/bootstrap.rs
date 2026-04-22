use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use common::{ClusterId, NodeId};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Duration;
use transport_sdk::{
    BootstrapEndpoint, BootstrapEndpointUse, BootstrapTrustRoots,
    ClientBootstrap as TransportClientBootstrap, ClientBootstrapClaim,
    ClientBootstrapClaimRedeemRequest, ClientBootstrapClaimRedeemResponse,
    ClientBootstrapClaimTrust, ClientIdentityMaterial, RelayMode, TransportPathKind,
};

use crate::connection::{
    build_blocking_reqwest_client_from_pem_for_url, build_http_client_from_pem,
    build_http_client_with_identity_from_planned_target,
};
use crate::device_auth::{
    DeviceEnrollmentRequest, DeviceEnrollmentResponse, enroll_device_blocking_from_pem,
};
use crate::ironmesh_client::{CLIENT_API_V1_PREFIX, IronMeshClient, normalize_server_base_url};

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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionBootstrapDiagnosticTargets {
    #[serde(default)]
    pub direct: Option<PlannedConnectionBootstrapTarget>,
    #[serde(default)]
    pub relay: Vec<PlannedConnectionBootstrapTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapEnrollmentResult {
    pub cluster_id: ClusterId,
    #[serde(default)]
    pub server_base_url: Option<String>,
    #[serde(default)]
    pub server_ca_pem: Option<String>,
    #[serde(default)]
    pub connection_bootstrap_json: Option<String>,
    pub device_id: String,
    #[serde(default, rename = "device_label", alias = "label")]
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

        let direct_targets = self.direct_https_targets()?.into_iter().collect::<Vec<_>>();

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

    fn direct_https_targets(&self) -> Result<Vec<PlannedConnectionBootstrapTarget>> {
        Ok(self
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
            .collect::<Vec<_>>())
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

    pub fn build_client_with_optional_identity(
        &self,
        identity: Option<&ClientIdentityMaterial>,
    ) -> Result<IronMeshClient> {
        match identity {
            Some(identity) => self.build_client_with_identity(identity),
            None => self.build_client(),
        }
    }

    pub fn diagnostic_targets(&self) -> Result<ConnectionBootstrapDiagnosticTargets> {
        self.validate()?;

        let direct_targets = self.direct_https_targets()?;
        let direct = direct_targets.first().cloned();
        let relay = if self.relay_mode == RelayMode::Disabled || self.rendezvous_urls.is_empty() {
            Vec::new()
        } else {
            let Some(target_node_id) = direct_targets
                .iter()
                .find_map(|target| target.target_node_id)
            else {
                return Ok(ConnectionBootstrapDiagnosticTargets {
                    direct,
                    relay: Vec::new(),
                });
            };

            let mut seen_urls = BTreeSet::new();
            self.rendezvous_urls
                .iter()
                .filter_map(|url| {
                    let normalized = url.trim().trim_end_matches('/').to_string();
                    if normalized.is_empty() || !seen_urls.insert(normalized.clone()) {
                        return None;
                    }
                    Some(PlannedConnectionBootstrapTarget {
                        cluster_id: self.cluster_id,
                        rendezvous_urls: vec![normalized],
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
                    })
                })
                .collect()
        };

        Ok(ConnectionBootstrapDiagnosticTargets { direct, relay })
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

    fn resolve_direct_enrollment_target_blocking(&self) -> Result<ResolvedConnectionBootstrap> {
        for target in self.direct_https_targets()? {
            let Some(server_base_url) = target.server_base_url.as_deref() else {
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

        bail!("failed to resolve any direct bootstrap endpoint for enrollment");
    }

    pub fn enroll_blocking(
        &self,
        device_id_override: Option<&str>,
        device_label_override: Option<&str>,
    ) -> Result<BootstrapEnrollmentResult> {
        let resolved = self.resolve_direct_enrollment_target_blocking()?;
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
            server_base_url: Some(resolved.server_base_url.clone()),
            server_ca_pem: resolved.server_ca_pem,
            connection_bootstrap_json: Some(persistable_bootstrap_json(
                self,
                &enrollment.device_id,
                enrollment.label.as_deref(),
            )?),
            device_id: enrollment.device_id,
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

pub fn enroll_connection_input_blocking(
    raw_input: &str,
    device_id_override: Option<&str>,
    device_label_override: Option<&str>,
) -> Result<BootstrapEnrollmentResult> {
    let trimmed = raw_input.trim();
    if trimmed.is_empty() {
        bail!("bootstrap claim or bundle is required");
    }

    if let Ok(claim) = ClientBootstrapClaim::from_json_str(trimmed) {
        return enroll_bootstrap_claim_blocking(&claim, device_id_override, device_label_override);
    }

    ConnectionBootstrap::from_json_str(trimmed)?
        .enroll_blocking(device_id_override, device_label_override)
}

pub fn enroll_bootstrap_claim_blocking(
    claim: &ClientBootstrapClaim,
    device_id_override: Option<&str>,
    device_label_override: Option<&str>,
) -> Result<BootstrapEnrollmentResult> {
    claim.validate()?;

    let device_id = normalize_optional(device_id_override)
        .map(|value| {
            value
                .parse()
                .with_context(|| format!("invalid bootstrap claim device_id {}", value))
        })
        .transpose()?;
    let label = normalize_optional(device_label_override);
    let mut identity =
        ClientIdentityMaterial::generate(claim.cluster_id, device_id, label.clone())?;
    let rendezvous_ca_pem = claim_rendezvous_ca_pem(&claim.trust)?;
    let redeem_request = ClientBootstrapClaimRedeemRequest {
        claim_token: claim.claim_token.clone(),
        target_node_id: claim.target_node_id,
        device_id: Some(identity.device_id.to_string()),
        label,
        public_key_pem: identity.public_key_pem.clone(),
    };
    let mut retryable_errors = Vec::new();
    let mut redeemed = None;
    for redeem_url in claim_redeem_urls(claim)? {
        let response = match build_blocking_reqwest_client_from_pem_for_url(
            Some(&rendezvous_ca_pem),
            &redeem_url,
        )?
        .post(redeem_url.clone())
        .json(&redeem_request)
        .send()
        {
            Ok(response) => response,
            Err(err) => {
                retryable_errors.push(format!(
                    "failed to call /bootstrap-claims/redeem via {redeem_url}: {err}"
                ));
                continue;
            }
        };
        let status = response.status();
        let body = response
            .text()
            .unwrap_or_else(|_| "<failed to read response body>".to_string());
        if status.is_success() {
            redeemed = Some(parse_bootstrap_claim_redeem_response(status, body)?);
            break;
        }
        if status.is_server_error() {
            retryable_errors.push(format!(
                "bootstrap claim redeem failed via {redeem_url} with HTTP {status}: {body}"
            ));
            continue;
        }
        bail!("bootstrap claim redeem failed via {redeem_url} with HTTP {status}: {body}");
    }
    let redeemed = redeemed.ok_or_else(|| {
        anyhow!(
            "bootstrap claim redeem failed across all rendezvous endpoints: {}",
            retryable_errors.join(" | ")
        )
    })?;
    identity.apply_issued_identity(&redeemed.issued_identity()?)?;

    let bootstrap = connection_bootstrap_from_transport(&redeemed.bootstrap);
    let server_base_url = preferred_direct_server_base_url(&bootstrap)?;
    let server_ca_pem = bootstrap.trust_roots.public_api_ca_pem.clone();
    let connection_bootstrap_json = Some(persistable_bootstrap_json(
        &bootstrap,
        &redeemed.device_id,
        redeemed.label.as_deref(),
    )?);

    Ok(BootstrapEnrollmentResult {
        cluster_id: redeemed.cluster_id,
        server_base_url,
        server_ca_pem,
        connection_bootstrap_json,
        device_id: redeemed.device_id,
        label: redeemed.label,
        public_key_pem: identity.public_key_pem,
        private_key_pem: identity.private_key_pem,
        credential_pem: redeemed.credential_pem,
        rendezvous_client_identity_pem: redeemed.rendezvous_client_identity_pem,
        created_at_unix: redeemed.created_at_unix,
        expires_at_unix: redeemed.expires_at_unix,
    })
}

fn parse_bootstrap_claim_redeem_response(
    status: reqwest::StatusCode,
    body: String,
) -> Result<ClientBootstrapClaimRedeemResponse> {
    if !status.is_success() {
        bail!("bootstrap claim redeem failed with HTTP {status}: {body}");
    }
    let redeemed = serde_json::from_str::<ClientBootstrapClaimRedeemResponse>(&body)
        .context("failed to parse /bootstrap-claims/redeem response")?;
    redeemed.validate()?;
    Ok(redeemed)
}

fn claim_redeem_urls(claim: &ClientBootstrapClaim) -> Result<Vec<Url>> {
    claim
        .ordered_rendezvous_urls()?
        .into_iter()
        .map(|rendezvous_url| {
            Url::parse(&rendezvous_url)
                .with_context(|| format!("invalid claim rendezvous URL {rendezvous_url}"))?
                .join("bootstrap-claims/redeem")
                .with_context(|| {
                    format!("failed to build bootstrap claim redeem URL from {rendezvous_url}")
                })
        })
        .collect()
}

fn probe_direct_http_target_blocking(target: &PlannedConnectionBootstrapTarget) -> Result<bool> {
    let server_base_url = target
        .server_base_url
        .as_deref()
        .ok_or_else(|| anyhow!("direct bootstrap target is missing server_base_url"))?;
    let endpoint = Url::parse(server_base_url)
        .with_context(|| format!("invalid planned bootstrap URL {server_base_url}"))?;
    let health_url = endpoint
        .join(&format!(
            "{}/health",
            CLIENT_API_V1_PREFIX.trim_start_matches('/')
        ))
        .with_context(|| format!("failed to build health URL from {endpoint}"))?;

    let probe_client = if endpoint.scheme() == "https" {
        build_blocking_reqwest_client_from_pem_for_url(
            target
                .server_ca_pem
                .as_deref()
                .or(target.cluster_ca_pem.as_deref()),
            &health_url,
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

fn persistable_bootstrap_json(
    bootstrap: &ConnectionBootstrap,
    device_id: &str,
    label: Option<&str>,
) -> Result<String> {
    let mut bootstrap = bootstrap.clone();
    bootstrap.pairing_token = None;
    bootstrap.device_id = Some(device_id.trim().to_string());
    if let Some(label) = normalize_optional(label) {
        bootstrap.device_label = Some(label);
    }
    bootstrap.to_json_pretty()
}

fn connection_bootstrap_from_transport(
    bootstrap: &TransportClientBootstrap,
) -> ConnectionBootstrap {
    ConnectionBootstrap {
        version: bootstrap.version,
        cluster_id: bootstrap.cluster_id,
        rendezvous_urls: bootstrap.rendezvous_urls.clone(),
        rendezvous_mtls_required: bootstrap.rendezvous_mtls_required,
        direct_endpoints: bootstrap.direct_endpoints.clone(),
        relay_mode: bootstrap.relay_mode,
        trust_roots: bootstrap.trust_roots.clone(),
        pairing_token: bootstrap.pairing_token.clone(),
        device_label: bootstrap.device_label.clone(),
        device_id: bootstrap.device_id.map(|value| value.to_string()),
    }
}

fn preferred_direct_server_base_url(bootstrap: &ConnectionBootstrap) -> Result<Option<String>> {
    Ok(bootstrap
        .normalized_candidate_direct_endpoints()?
        .into_iter()
        .next()
        .map(|endpoint| endpoint.url))
}

fn claim_rendezvous_ca_pem(trust: &ClientBootstrapClaimTrust) -> Result<String> {
    trust.validate()?;
    let encoded = trust.ca_der_b64u.trim();
    if encoded.is_empty() {
        bail!("bootstrap claim trust is missing ca_der_b64u");
    }
    let der = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .context("failed to decode bootstrap claim rendezvous CA DER")?;
    Ok(pem_from_der_certificate(&der))
}

fn pem_from_der_certificate(der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let body = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
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
    use transport_sdk::{
        CLIENT_BOOTSTRAP_CLAIM_VERSION, ClientBootstrapClaim, ClientBootstrapClaimTrust,
    };

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

    fn sample_claim() -> ClientBootstrapClaim {
        ClientBootstrapClaim {
            version: CLIENT_BOOTSTRAP_CLAIM_VERSION,
            cluster_id: ClusterId::now_v7(),
            target_node_id: NodeId::new_v4(),
            rendezvous_urls: vec![
                "https://rendezvous-a.example:9443/".to_string(),
                "https://rendezvous-b.example:9443".to_string(),
            ],
            trust: ClientBootstrapClaimTrust {
                ca_der_b64u: "Y2xhaW0tdGVzdA".to_string(),
            },
            claim_token: "im-claim-test-token".to_string(),
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
    fn claim_redeem_urls_prefer_primary_and_deduplicate_variants() {
        let claim = sample_claim();

        let redeem_urls = claim_redeem_urls(&claim).expect("claim redeem URLs should build");

        assert_eq!(redeem_urls.len(), 2);
        assert_eq!(
            redeem_urls[0].as_str(),
            "https://rendezvous-a.example:9443/bootstrap-claims/redeem"
        );
        assert_eq!(
            redeem_urls[1].as_str(),
            "https://rendezvous-b.example:9443/bootstrap-claims/redeem"
        );
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

    #[test]
    fn bootstrap_enrollment_result_serializes_device_label_and_accepts_legacy_label() {
        let response = BootstrapEnrollmentResult {
            cluster_id: ClusterId::now_v7(),
            server_base_url: Some("https://public.example/".to_string()),
            server_ca_pem: Some("public-ca".to_string()),
            connection_bootstrap_json: Some("{\"version\":1}".to_string()),
            device_id: "019d04a8-3099-75bc-8ff5-f5bd9a78bb83".to_string(),
            label: Some("Tablet".to_string()),
            public_key_pem: "public-key".to_string(),
            private_key_pem: "private-key".to_string(),
            credential_pem: "credential".to_string(),
            rendezvous_client_identity_pem: Some("rendezvous-identity".to_string()),
            created_at_unix: Some(10),
            expires_at_unix: Some(20),
        };

        let json = serde_json::to_value(&response).expect("response should serialize");
        let object = json
            .as_object()
            .expect("response should serialize as an object");
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

        let parsed: BootstrapEnrollmentResult =
            serde_json::from_value(legacy).expect("legacy response should deserialize");

        assert_eq!(parsed.label.as_deref(), Some("Phone"));
    }
}
