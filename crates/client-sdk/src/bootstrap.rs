use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use common::{ClusterId, NodeId};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::Duration;
use transport_sdk::{
    BootstrapEndpoint, BootstrapEndpointUse, BootstrapTrustRoots, CandidateKind,
    ClientBootstrap as TransportClientBootstrap, ClientBootstrapClaim,
    ClientBootstrapClaimRedeemRequest, ClientBootstrapClaimRedeemResponse,
    ClientBootstrapClaimTrust, ClientIdentityMaterial, ConnectionCandidate, DiscoveryResponse,
    RelayMode, RendezvousControlClient, RendezvousEndpointConnectionState,
    RendezvousEndpointStatus, TransportPathKind,
};

use crate::connection::{
    build_blocking_reqwest_client_from_pem_for_url,
    build_blocking_reqwest_client_from_pem_for_url_with_expected_server_identity,
    build_http_client_from_planned_targets, build_http_client_with_identity_from_planned_targets,
};
use crate::device_auth::{
    DeviceEnrollmentRequest, DeviceEnrollmentResponse, enroll_device_blocking_from_pem,
    renew_rendezvous_identity,
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
    pub direct_candidate: Option<ConnectionCandidate>,
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
        !matches!(self.path_kind, TransportPathKind::DirectHttps)
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

/// The complete, normalized connection state produced by a successful client enrollment.
///
/// Platform applications must persist `connection_input`, `server_ca_pem`, and the device
/// metadata together, while placing `client_identity_json` in their platform secure store. This
/// prevents each native shell from independently choosing between a bootstrap claim, a completed
/// bootstrap bundle, and a direct server URL.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EnrolledClientConnection {
    pub connection_input: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_ca_pem: Option<String>,
    pub client_identity_json: String,
    pub cluster_id: ClusterId,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_label: Option<String>,
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

    /// Converts an enrollment response into the single state contract consumed by mobile apps.
    ///
    /// The connection bundle is parsed and re-serialized here, before it reaches platform
    /// storage. Consequently, a bootstrap claim can never be mistaken for a reconnectable client
    /// bootstrap after a successful enrollment.
    pub fn enrolled_client_connection(&self) -> Result<EnrolledClientConnection> {
        let client_identity = self.client_identity_material()?;
        let connection_input = match self
            .connection_bootstrap_json
            .as_deref()
            .and_then(|value| normalize_optional(Some(value)))
        {
            Some(raw_bootstrap) => ConnectionBootstrap::from_json_str(&raw_bootstrap)
                .context("enrollment returned an invalid persisted connection bootstrap")?
                .to_json_pretty()
                .context("failed to normalize persisted connection bootstrap")?,
            None => {
                let server_base_url = self
                    .server_base_url
                    .as_deref()
                    .and_then(|value| normalize_optional(Some(value)))
                    .ok_or_else(|| {
                        anyhow!("enrollment returned no reconnectable connection target")
                    })?;
                normalize_server_base_url(&server_base_url)
                    .context("enrollment returned an invalid direct server URL")?
                    .to_string()
            }
        };

        Ok(EnrolledClientConnection {
            connection_input,
            server_ca_pem: self
                .server_ca_pem
                .as_deref()
                .and_then(|value| normalize_optional(Some(value))),
            client_identity_json: client_identity.to_json_pretty()?,
            cluster_id: client_identity.cluster_id,
            device_id: client_identity.device_id.to_string(),
            device_label: client_identity.label,
        })
    }
}

fn known_direct_target_node_ids(direct_targets: &[PlannedConnectionBootstrapTarget]) -> String {
    let ids = direct_targets
        .iter()
        .filter_map(|target| target.target_node_id)
        .map(|id| id.to_string())
        .collect::<Vec<_>>();
    if ids.is_empty() {
        "<none>".to_string()
    } else {
        ids.join(", ")
    }
}

fn known_rendezvous_urls(rendezvous_urls: &[String]) -> String {
    if rendezvous_urls.is_empty() {
        "<none>".to_string()
    } else {
        rendezvous_urls.join(", ")
    }
}

fn normalized_unique_rendezvous_urls(rendezvous_urls: &[String]) -> Result<Vec<String>> {
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();

    for rendezvous_url in rendezvous_urls {
        let normalized_url = normalize_rendezvous_base_url(rendezvous_url)?;
        if seen.insert(normalized_url.clone()) {
            normalized.push(normalized_url);
        }
    }

    Ok(normalized)
}

fn relay_targets_for_node_ids(
    bootstrap: &ConnectionBootstrap,
    rendezvous_urls: &[String],
    target_node_ids: impl IntoIterator<Item = NodeId>,
) -> Result<Vec<PlannedConnectionBootstrapTarget>> {
    let rendezvous_urls = normalized_unique_rendezvous_urls(rendezvous_urls)?;
    let mut relay_targets = Vec::new();
    let mut seen_node_ids = BTreeSet::new();

    for target_node_id in target_node_ids {
        if !seen_node_ids.insert(target_node_id.to_string()) {
            continue;
        }

        for rendezvous_url in &rendezvous_urls {
            relay_targets.push(PlannedConnectionBootstrapTarget {
                cluster_id: bootstrap.cluster_id,
                rendezvous_urls: vec![rendezvous_url.clone()],
                rendezvous_mtls_required: bootstrap.rendezvous_mtls_required,
                relay_mode: bootstrap.relay_mode,
                path_kind: TransportPathKind::RelayTunnel,
                direct_candidate: None,
                server_base_url: None,
                target_node_id: Some(target_node_id),
                server_ca_pem: bootstrap.trust_roots.public_api_ca_pem.clone(),
                cluster_ca_pem: bootstrap.trust_roots.cluster_ca_pem.clone(),
                rendezvous_ca_pem: bootstrap.trust_roots.rendezvous_ca_pem.clone(),
                pairing_token: bootstrap.pairing_token.clone(),
                device_label: bootstrap.device_label.clone(),
                device_id: bootstrap.device_id.clone(),
            });
        }
    }

    Ok(relay_targets)
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
                let relay_targets = relay_targets_for_node_ids(
                    self,
                    &self.rendezvous_urls,
                    direct_targets
                        .iter()
                        .filter_map(|target| target.target_node_id),
                )?;
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

    /// All configured direct HTTPS bootstrap targets, each carrying whichever `target_node_id`
    /// the bootstrap file recorded for it. Used by diagnostic tooling to enumerate the nodes a
    /// bootstrap file can address directly (see `diagnostic_targets_selecting`).
    pub fn direct_https_targets(&self) -> Result<Vec<PlannedConnectionBootstrapTarget>> {
        Ok(self
            .normalized_candidate_direct_endpoints()?
            .into_iter()
            .map(|endpoint| PlannedConnectionBootstrapTarget {
                cluster_id: self.cluster_id,
                rendezvous_urls: self.rendezvous_urls.clone(),
                rendezvous_mtls_required: self.rendezvous_mtls_required,
                relay_mode: self.relay_mode,
                path_kind: TransportPathKind::DirectHttps,
                direct_candidate: None,
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

        let planned_targets = self.planned_targets()?;
        build_http_client_with_identity_from_planned_targets(&planned_targets, identity)
    }

    /// Renews an expired, expiring, or legacy rendezvous client certificate when a direct target
    /// is available.
    ///
    /// Legacy certificates that do not contain this bootstrap's cluster URI SAN cannot complete
    /// rendezvous mTLS.  Their renewal request is therefore deliberately restricted to direct
    /// client targets; it is authenticated with the durable client credential rather than the
    /// rendezvous certificate.  Renewal failures are logged and leave the current identity
    /// untouched so normal direct connectivity can continue.
    ///
    /// Returns `true` only when a freshly-issued certificate was written into
    /// `identity.rendezvous_client_identity_pem`. The caller is responsible for persisting that
    /// change.
    pub fn renew_rendezvous_identity_if_needed(
        &self,
        identity: &mut ClientIdentityMaterial,
    ) -> Result<bool> {
        self.validate()?;
        identity.validate()?;
        if identity.cluster_id != self.cluster_id {
            bail!(
                "client identity cluster_id {} does not match bootstrap cluster_id {}",
                identity.cluster_id,
                self.cluster_id
            );
        }

        let planned_targets = self.planned_targets()?;

        let Some(rendezvous_client_identity_pem) =
            identity.rendezvous_client_identity_pem.as_deref()
        else {
            return Ok(false);
        };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let requires_cluster_san_migration =
            match transport_sdk::rendezvous_client_identity_has_expected_cluster_uri_san(
                rendezvous_client_identity_pem.as_bytes(),
                self.cluster_id,
            ) {
                Ok(has_expected_cluster_san) => !has_expected_cluster_san,
                Err(error) => {
                    // A malformed local identity cannot authenticate to rendezvous either. The
                    // direct renewal endpoint authenticates via the regular client credential, so it
                    // is safe and preferable to replace it when a direct route is available.
                    tracing::warn!(
                        error = %error,
                        "could not inspect rendezvous identity cluster SAN; attempting direct renewal"
                    );
                    true
                }
            };
        let needs_time_based_renewal = transport_sdk::rendezvous_client_identity_needs_renewal_at(
            rendezvous_client_identity_pem.as_bytes(),
            now,
        );
        let needs_renewal = requires_cluster_san_migration || needs_time_based_renewal;

        if needs_renewal {
            // A certificate that is expired or lacks the expected cluster URI SAN cannot
            // authenticate to modern rendezvous endpoints. In both cases renewal must go through
            // a direct target and must never try a relay route first.
            let requires_direct_renewal = requires_cluster_san_migration
                || transport_sdk::rendezvous_client_identity_is_expired_at(
                    rendezvous_client_identity_pem.as_bytes(),
                    now,
                );
            let renewal_targets: Vec<_> = if requires_direct_renewal {
                planned_targets
                    .iter()
                    .filter(|target| target.path_kind != TransportPathKind::RelayTunnel)
                    .cloned()
                    .collect()
            } else {
                planned_targets.clone()
            };

            if renewal_targets.is_empty() {
                tracing::warn!(
                    requires_cluster_san_migration,
                    "rendezvous identity needs renewal but no direct target is available"
                );
            } else {
                match try_renew_rendezvous_identity(&renewal_targets, identity) {
                    Ok(new_pem) => {
                        identity.rendezvous_client_identity_pem = Some(new_pem);
                        return Ok(true);
                    }
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "rendezvous identity renewal failed, continuing with existing certificate"
                        );
                    }
                }
            }
        }

        Ok(false)
    }

    /// Like [`build_client_with_identity`] but automatically renews the rendezvous client
    /// certificate when it is expired, expiring soon, or missing the expected cluster URI SAN.
    /// If renewal succeeds the updated PEM is written back into
    /// `identity.rendezvous_client_identity_pem`; the caller is responsible for persisting the
    /// change. Renewal failures are logged as warnings and do not prevent the client from being
    /// built.
    pub fn build_client_with_identity_renewing(
        &self,
        identity: &mut ClientIdentityMaterial,
    ) -> Result<IronMeshClient> {
        self.renew_rendezvous_identity_if_needed(identity)?;
        self.build_client_with_identity(identity)
    }

    pub fn build_client(&self) -> Result<IronMeshClient> {
        self.validate()?;

        let planned_targets = self.planned_targets()?;
        let direct_targets = planned_targets
            .iter()
            .filter(|target| target.path_kind == TransportPathKind::DirectHttps)
            .cloned()
            .collect::<Vec<_>>();
        if direct_targets.is_empty()
            && planned_targets
                .iter()
                .any(|target| target.path_kind != TransportPathKind::DirectHttps)
        {
            bail!(
                "bootstrap selected or permits a custom client transport route (relay-backed or direct QUIC), but building that route requires enrolled client identity material"
            );
        }

        if direct_targets.is_empty() {
            bail!("bootstrap does not contain a reachable direct client transport target");
        }

        build_http_client_from_planned_targets(&direct_targets)
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
        self.diagnostic_targets_selecting(None, None)
    }

    /// Like [`diagnostic_targets`](Self::diagnostic_targets), but lets a caller pin the probe to
    /// one specific cluster node and/or one specific rendezvous URL instead of the first
    /// configured direct endpoint and every configured rendezvous URL. Used by diagnostic tooling
    /// (e.g. the CLI's `latency-test --node-id`/`--relay-url`) so an operator can explicitly
    /// choose which connection to exercise.
    pub fn diagnostic_targets_selecting(
        &self,
        node_id: Option<NodeId>,
        rendezvous_url: Option<&str>,
    ) -> Result<ConnectionBootstrapDiagnosticTargets> {
        self.validate()?;

        let direct_targets = self.direct_https_targets()?;
        let direct = match node_id {
            Some(node_id) => {
                let selected = direct_targets
                    .iter()
                    .find(|target| target.target_node_id == Some(node_id))
                    .cloned();
                if selected.is_none() {
                    bail!(
                        "bootstrap does not contain a direct endpoint for node_id {node_id}; known direct target node ids: {}",
                        known_direct_target_node_ids(&direct_targets)
                    );
                }
                selected
            }
            None => direct_targets.first().cloned(),
        };

        let relay = if self.relay_mode == RelayMode::Disabled || self.rendezvous_urls.is_empty() {
            Vec::new()
        } else {
            let resolved_target_node_id = match node_id {
                Some(node_id) => Some(node_id),
                None => direct_targets
                    .iter()
                    .find_map(|target| target.target_node_id),
            };
            let Some(resolved_target_node_id) = resolved_target_node_id else {
                return Ok(ConnectionBootstrapDiagnosticTargets {
                    direct,
                    relay: Vec::new(),
                });
            };

            let normalized_selected_url = rendezvous_url
                .map(|url| url.trim().trim_end_matches('/').to_string())
                .filter(|url| !url.is_empty());
            if let Some(selected_url) = normalized_selected_url.as_deref()
                && !self
                    .rendezvous_urls
                    .iter()
                    .any(|url| url.trim().trim_end_matches('/') == selected_url)
            {
                bail!(
                    "bootstrap does not contain rendezvous URL {selected_url}; known rendezvous URLs: {}",
                    known_rendezvous_urls(&self.rendezvous_urls)
                );
            }

            let mut seen_urls = BTreeSet::new();
            self.rendezvous_urls
                .iter()
                .filter_map(|url| {
                    let normalized = url.trim().trim_end_matches('/').to_string();
                    if normalized.is_empty() || !seen_urls.insert(normalized.clone()) {
                        return None;
                    }
                    if let Some(selected_url) = normalized_selected_url.as_deref()
                        && normalized != selected_url
                    {
                        return None;
                    }
                    Some(PlannedConnectionBootstrapTarget {
                        cluster_id: self.cluster_id,
                        rendezvous_urls: vec![normalized],
                        rendezvous_mtls_required: self.rendezvous_mtls_required,
                        relay_mode: self.relay_mode,
                        path_kind: TransportPathKind::RelayTunnel,
                        direct_candidate: None,
                        server_base_url: None,
                        target_node_id: Some(resolved_target_node_id),
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

    pub fn refresh_dynamic_targets_blocking(
        &self,
        identity: Option<&ClientIdentityMaterial>,
    ) -> Result<Vec<PlannedConnectionBootstrapTarget>> {
        self.validate()?;
        if let Some(identity) = identity {
            identity.validate()?;
            if identity.cluster_id != self.cluster_id {
                bail!(
                    "client identity cluster_id {} does not match bootstrap cluster_id {}",
                    identity.cluster_id,
                    self.cluster_id
                );
            }
        }

        if self.rendezvous_urls.is_empty() {
            return self.planned_targets();
        }

        let discovery = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to build rendezvous discovery runtime")?
            .block_on(self.fetch_dynamic_discovery(identity))?;
        self.build_refreshed_targets(&discovery)
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

    fn build_rendezvous_discovery_client(
        &self,
        identity: Option<&ClientIdentityMaterial>,
    ) -> Result<RendezvousControlClient> {
        self.build_rendezvous_discovery_client_for_urls(&self.rendezvous_urls, identity)
    }

    fn build_rendezvous_discovery_client_for_urls(
        &self,
        rendezvous_urls: &[String],
        identity: Option<&ClientIdentityMaterial>,
    ) -> Result<RendezvousControlClient> {
        let rendezvous_client_identity_pem =
            identity.and_then(|identity| identity.rendezvous_client_identity_pem.as_deref());
        if self.rendezvous_mtls_required && rendezvous_client_identity_pem.is_none() {
            bail!(
                "dynamic rendezvous discovery requires rendezvous_client_identity_pem when rendezvous_mtls_required is true"
            );
        }

        RendezvousControlClient::new(
            transport_sdk::RendezvousClientConfig {
                cluster_id: self.cluster_id,
                rendezvous_urls: rendezvous_urls.to_vec(),
                heartbeat_interval_secs: 15,
            },
            self.trust_roots
                .rendezvous_ca_pem
                .as_deref()
                .or(self.trust_roots.cluster_ca_pem.as_deref()),
            rendezvous_client_identity_pem.map(str::as_bytes),
        )
    }

    async fn fetch_dynamic_discovery(
        &self,
        identity: Option<&ClientIdentityMaterial>,
    ) -> Result<DynamicDiscoveryState> {
        let rendezvous_client = self.build_rendezvous_discovery_client(identity)?;
        let mesh_discovery: DiscoveryResponse = rendezvous_client.fetch_discovery(None).await?;
        let mut discovery = DynamicDiscoveryState {
            rendezvous_urls: merge_connected_rendezvous_urls(
                &self.rendezvous_urls,
                &mesh_discovery.rendezvous_peers,
            )?,
            direct_candidates_by_node: BTreeMap::new(),
            relay_capable_nodes: BTreeSet::new(),
        };

        for node_id in self.discovery_target_node_ids()? {
            let node_discovery = self
                .fetch_node_discovery_across_rendezvous_urls(
                    identity,
                    &discovery.rendezvous_urls,
                    node_id,
                )
                .await?;
            discovery.rendezvous_urls = node_discovery.rendezvous_urls;
            if !node_discovery.candidates.is_empty() {
                discovery
                    .direct_candidates_by_node
                    .insert(node_id, node_discovery.candidates);
            }
            if node_discovery.relay_capable {
                discovery.relay_capable_nodes.insert(node_id);
            }
        }

        Ok(discovery)
    }

    async fn fetch_node_discovery_across_rendezvous_urls(
        &self,
        identity: Option<&ClientIdentityMaterial>,
        seed_rendezvous_urls: &[String],
        node_id: NodeId,
    ) -> Result<NodeDynamicDiscoveryState> {
        let mut rendezvous_urls = seed_rendezvous_urls.to_vec();
        let mut next_index = 0usize;
        let mut saw_success = false;
        let mut last_error = None;
        let mut candidates = Vec::new();
        let mut relay_capable = false;
        let mut seen_candidates = BTreeSet::new();

        while next_index < rendezvous_urls.len() {
            let current_url = rendezvous_urls[next_index].clone();
            next_index += 1;

            let rendezvous_client = self.build_rendezvous_discovery_client_for_urls(
                std::slice::from_ref(&current_url),
                identity,
            )?;
            match rendezvous_client.fetch_discovery(Some(node_id)).await {
                Ok(response) => {
                    saw_success = true;
                    rendezvous_urls = merge_connected_rendezvous_urls(
                        &rendezvous_urls,
                        &response.rendezvous_peers,
                    )?;
                    if let Some(node_candidates) = response.node_candidates {
                        for candidate in node_candidates {
                            let seen_key = discovery_candidate_seen_key(&candidate)?;
                            if seen_candidates.insert(seen_key) {
                                candidates.push(candidate);
                            }
                        }
                    }
                    relay_capable |= response.node_relay_capable;
                }
                Err(error) => last_error = Some(error),
            }
        }

        if !saw_success {
            return Err(last_error.unwrap_or_else(|| {
                anyhow!("rendezvous client has no configured URLs for node discovery")
            }));
        }

        Ok(NodeDynamicDiscoveryState {
            rendezvous_urls,
            candidates: transport_sdk::rank_candidates(&candidates),
            relay_capable,
        })
    }

    fn discovery_target_node_ids(&self) -> Result<Vec<NodeId>> {
        let mut seen = BTreeSet::new();
        let mut node_ids = Vec::new();
        for target in self.direct_https_targets()? {
            let Some(node_id) = target.target_node_id else {
                continue;
            };
            if seen.insert(node_id.to_string()) {
                node_ids.push(node_id);
            }
        }
        Ok(node_ids)
    }

    fn build_refreshed_targets(
        &self,
        discovery: &DynamicDiscoveryState,
    ) -> Result<Vec<PlannedConnectionBootstrapTarget>> {
        let static_direct_targets = self.direct_https_targets()?;
        let mut direct_targets = static_direct_targets.clone();
        let mut seen_direct_targets = BTreeSet::new();

        for target in &direct_targets {
            if let Some(seen_key) = planned_direct_target_seen_key(target)? {
                seen_direct_targets.insert(seen_key);
            }
        }

        for (node_id, candidates) in &discovery.direct_candidates_by_node {
            for candidate in candidates {
                let Some(path_kind) = planned_path_kind_for_candidate(candidate) else {
                    continue;
                };
                let seen_key = direct_candidate_seen_key(candidate, Some(*node_id))?;
                if !seen_direct_targets.insert(seen_key) {
                    continue;
                }

                direct_targets.push(PlannedConnectionBootstrapTarget {
                    cluster_id: self.cluster_id,
                    rendezvous_urls: discovery.rendezvous_urls.clone(),
                    rendezvous_mtls_required: self.rendezvous_mtls_required,
                    relay_mode: self.relay_mode,
                    path_kind,
                    direct_candidate: Some(candidate.clone()),
                    server_base_url: planned_target_server_base_url_for_candidate(candidate)?,
                    target_node_id: Some(*node_id),
                    server_ca_pem: self.trust_roots.public_api_ca_pem.clone(),
                    cluster_ca_pem: self.trust_roots.cluster_ca_pem.clone(),
                    rendezvous_ca_pem: self.trust_roots.rendezvous_ca_pem.clone(),
                    pairing_token: self.pairing_token.clone(),
                    device_label: self.device_label.clone(),
                    device_id: self.device_id.clone(),
                });
            }
        }

        let relay_targets = refreshed_relay_targets(
            self,
            &static_direct_targets,
            &discovery.rendezvous_urls,
            &discovery.relay_capable_nodes,
        )?;

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
}

#[derive(Debug, Clone)]
struct DynamicDiscoveryState {
    rendezvous_urls: Vec<String>,
    direct_candidates_by_node: BTreeMap<NodeId, Vec<ConnectionCandidate>>,
    relay_capable_nodes: BTreeSet<NodeId>,
}

#[derive(Debug, Clone)]
struct NodeDynamicDiscoveryState {
    rendezvous_urls: Vec<String>,
    candidates: Vec<ConnectionCandidate>,
    relay_capable: bool,
}

fn merge_connected_rendezvous_urls(
    seed_urls: &[String],
    peers: &[RendezvousEndpointStatus],
) -> Result<Vec<String>> {
    let mut merged = Vec::new();
    let mut seen = BTreeSet::new();

    for url in seed_urls {
        let normalized = normalize_rendezvous_base_url(url)?;
        if seen.insert(normalized.clone()) {
            merged.push(normalized);
        }
    }

    for peer in peers {
        if peer.status != RendezvousEndpointConnectionState::Connected {
            continue;
        }
        let normalized = normalize_rendezvous_base_url(&peer.url)?;
        if seen.insert(normalized.clone()) {
            merged.push(normalized);
        }
    }

    Ok(merged)
}

fn normalize_rendezvous_base_url(url: &str) -> Result<String> {
    let normalized = Url::parse(url.trim())
        .with_context(|| format!("invalid rendezvous base URL {url}"))?
        .to_string();
    Ok(normalized)
}

fn direct_target_seen_key(server_base_url: &str, target_node_id: Option<NodeId>) -> Result<String> {
    Ok(format!(
        "{:?}#{}#{}",
        TransportPathKind::DirectHttps,
        normalize_server_base_url(server_base_url)?.as_str(),
        target_node_id
            .map(|node_id| node_id.to_string())
            .unwrap_or_default()
    ))
}

fn discovery_candidate_seen_key(candidate: &ConnectionCandidate) -> Result<String> {
    match planned_path_kind_for_candidate(candidate) {
        Some(_) => direct_candidate_seen_key(candidate, None),
        None => Ok(format!(
            "{:?}#{}",
            candidate.kind,
            candidate.endpoint.trim()
        )),
    }
}

fn direct_candidate_seen_key(
    candidate: &ConnectionCandidate,
    target_node_id: Option<NodeId>,
) -> Result<String> {
    let Some(path_kind) = planned_path_kind_for_candidate(candidate) else {
        bail!("relay candidates do not produce direct bootstrap targets");
    };
    let locator = match path_kind {
        TransportPathKind::DirectHttps => {
            normalize_server_base_url(&candidate.endpoint)?.to_string()
        }
        TransportPathKind::DirectQuic => transport_sdk::endpoint_id_from_candidate(candidate)?,
        TransportPathKind::RelayTunnel => bail!("relay candidates do not produce direct targets"),
    };
    Ok(format!(
        "{:?}#{}#{}",
        path_kind,
        locator,
        target_node_id
            .map(|node_id| node_id.to_string())
            .unwrap_or_default()
    ))
}

fn planned_direct_target_seen_key(
    target: &PlannedConnectionBootstrapTarget,
) -> Result<Option<String>> {
    match target.path_kind {
        TransportPathKind::DirectHttps => target
            .server_base_url
            .as_deref()
            .map(|server_base_url| direct_target_seen_key(server_base_url, target.target_node_id))
            .transpose(),
        TransportPathKind::DirectQuic => target
            .direct_candidate
            .as_ref()
            .map(|candidate| direct_candidate_seen_key(candidate, target.target_node_id))
            .transpose(),
        TransportPathKind::RelayTunnel => Ok(None),
    }
}

fn planned_target_server_base_url_for_candidate(
    candidate: &ConnectionCandidate,
) -> Result<Option<String>> {
    match planned_path_kind_for_candidate(candidate) {
        Some(TransportPathKind::DirectHttps) => Ok(Some(
            normalize_server_base_url(&candidate.endpoint)?.to_string(),
        )),
        Some(TransportPathKind::DirectQuic) | None => Ok(None),
        Some(TransportPathKind::RelayTunnel) => Ok(None),
    }
}

fn planned_path_kind_for_candidate(candidate: &ConnectionCandidate) -> Option<TransportPathKind> {
    match candidate.kind {
        CandidateKind::DirectHttps | CandidateKind::ServerReflexive => {
            Some(TransportPathKind::DirectHttps)
        }
        CandidateKind::DirectQuic => Some(TransportPathKind::DirectQuic),
        CandidateKind::Relay => None,
    }
}

fn refreshed_relay_targets(
    bootstrap: &ConnectionBootstrap,
    static_direct_targets: &[PlannedConnectionBootstrapTarget],
    rendezvous_urls: &[String],
    relay_capable_nodes: &BTreeSet<NodeId>,
) -> Result<Vec<PlannedConnectionBootstrapTarget>> {
    if bootstrap.relay_mode == RelayMode::Disabled {
        return Ok(Vec::new());
    }

    let relay_targets = relay_targets_for_node_ids(
        bootstrap,
        rendezvous_urls,
        static_direct_targets.iter().filter_map(|target| {
            let target_node_id = target.target_node_id?;
            relay_capable_nodes
                .contains(&target_node_id)
                .then_some(target_node_id)
        }),
    )?;

    if relay_targets.is_empty() && bootstrap.relay_mode == RelayMode::Required {
        bail!(
            "bootstrap requires relay connectivity but rendezvous discovery did not report any relay-capable target node_id"
        );
    }

    Ok(relay_targets)
}

fn try_renew_rendezvous_identity(
    targets: &[PlannedConnectionBootstrapTarget],
    identity: &ClientIdentityMaterial,
) -> Result<String> {
    let renewal_client = build_http_client_with_identity_from_planned_targets(targets, identity)
        .context("failed to build client for rendezvous identity renewal")?;
    let worker = std::thread::Builder::new()
        .name("ironmesh-rendezvous-renewal".to_string())
        .spawn(move || -> Result<String> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("failed to build renewal runtime")?;
            runtime.block_on(renew_rendezvous_identity(&renewal_client))
        })
        .context("failed to spawn rendezvous renewal worker")?;
    worker
        .join()
        .map_err(|_| anyhow!("rendezvous renewal worker panicked"))?
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

/// Enrolls a device and returns the platform persistence contract in one operation.
///
/// Mobile bridges should use this instead of exposing `BootstrapEnrollmentResult`, which contains
/// protocol-level fields that native code could otherwise recombine inconsistently.
pub fn enroll_client_connection_blocking(
    raw_input: &str,
    device_id_override: Option<&str>,
    device_label_override: Option<&str>,
) -> Result<EnrolledClientConnection> {
    enroll_connection_input_blocking(raw_input, device_id_override, device_label_override)?
        .enrolled_client_connection()
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
        cluster_id: Some(claim.cluster_id),
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
        build_blocking_reqwest_client_from_pem_for_url_with_expected_server_identity(
            target
                .server_ca_pem
                .as_deref()
                .or(target.cluster_ca_pem.as_deref()),
            &health_url,
            target
                .target_node_id
                .map(|node_id| transport_sdk::ExpectedNodeServerIdentity {
                    node_id,
                    cluster_id: target.cluster_id,
                }),
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
    use axum::{
        Json, Router,
        extract::Query,
        routing::{get, post},
    };
    use serde::Deserialize;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use transport_sdk::candidates::ConnectionCandidateTransportHints;
    use transport_sdk::{
        CLIENT_BOOTSTRAP_CLAIM_VERSION, ClientBootstrapClaim, ClientBootstrapClaimTrust,
        DEFAULT_DIRECT_QUIC_ALPN,
    };

    // cert+key for an already-expired rendezvous identity (not_after = 2026-04-20)
    const EXPIRED_RENDEZVOUS_CLIENT_IDENTITY_PEM: &str = concat!(
        "-----BEGIN CERTIFICATE-----\n",
        "MIIB3DCCAYKgAwIBAgITK3r0r5jwkdN+susWXewPKMOgPDAKBggqhkjOPQQDAjBA\n",
        "MT4wPAYDVQQDDDVpcm9ubWVzaC1jbHVzdGVyLTAxOWQwMmViLWFiMzktNzIyMC05\n",
        "MTFhLWMwZWFmY2IzODI0OTAeFw0yNjAzMjExMzA5MzRaFw0yNjA0MjAxMzA5MzRa\n",
        "MD8xPTA7BgNVBAMMNGlyb25tZXNoLWRldmljZS0wMTlkMTA4My1lYTIzLTdiZjEt\n",
        "YjVjYi0xZDVmY2ViNTBlOGEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASeG/Cl\n",
        "E3s04e07hBjVXH8/IMPXIiGewwOLPXEcJM4pU0ELoDcfpgZ0evvEiOKFC+R19CI3\n",
        "/dbbU02U0VnXMMXxo1wwWjBDBgNVHREEPDA6hjh1cm46aXJvbm1lc2g6ZGV2aWNl\n",
        "OjAxOWQxMDgzLWVhMjMtN2JmMS1iNWNiLTFkNWZjZWI1MGU4YTATBgNVHSUEDDAK\n",
        "BggrBgEFBQcDAjAKBggqhkjOPQQDAgNIADBFAiBPOa5XZSZLs8CqhQO9PscDS2Il\n",
        "jkjn2HXRB0g2pB2aeAIhALe+yYYMAqULo8WmhjcudAgQm/1vYSjowEWtUcMCY2J3\n",
        "-----END CERTIFICATE-----\n",
        "-----BEGIN PRIVATE KEY-----\n",
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgaxQmF3EgQxM8/nYg\n",
        "C4fi+hVjqma6xwFK4pwamjmotA+hRANCAASeG/ClE3s04e07hBjVXH8/IMPXIiGe\n",
        "wwOLPXEcJM4pU0ELoDcfpgZ0evvEiOKFC+R19CI3/dbbU02U0VnXMMXx\n",
        "-----END PRIVATE KEY-----\n"
    );

    fn direct_bootstrap_for_url(cluster_id: ClusterId, url: &str) -> ConnectionBootstrap {
        ConnectionBootstrap {
            version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
            cluster_id,
            rendezvous_urls: vec![],
            rendezvous_mtls_required: false,
            direct_endpoints: vec![BootstrapEndpoint {
                url: url.to_string(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: None,
            }],
            relay_mode: RelayMode::Disabled,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: None,
                public_api_ca_pem: None,
                rendezvous_ca_pem: None,
            },
            pairing_token: None,
            device_label: None,
            device_id: None,
        }
    }

    fn identity_for_bootstrap(cluster_id: ClusterId) -> ClientIdentityMaterial {
        ClientIdentityMaterial::generate(cluster_id, None, None).expect("identity should generate")
    }

    async fn spawn_health_server(delay_ms: u64) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should have addr");
        let app = Router::new().route(
            "/api/v1/health",
            get(move || async move {
                if delay_ms > 0 {
                    tokio::time::sleep(Duration::from_millis(delay_ms)).await;
                }
                axum::http::StatusCode::OK
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (format!("http://{addr}"), server)
    }

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

    fn refreshable_bootstrap(
        cluster_id: ClusterId,
        rendezvous_url: String,
        target_node_id: NodeId,
    ) -> ConnectionBootstrap {
        ConnectionBootstrap {
            version: transport_sdk::CLIENT_BOOTSTRAP_VERSION,
            cluster_id,
            rendezvous_urls: vec![rendezvous_url],
            rendezvous_mtls_required: false,
            direct_endpoints: vec![BootstrapEndpoint {
                url: "https://public.example".to_string(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: Some(target_node_id),
            }],
            relay_mode: RelayMode::Fallback,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: None,
                public_api_ca_pem: None,
                rendezvous_ca_pem: None,
            },
            pairing_token: None,
            device_label: None,
            device_id: None,
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
    fn planned_targets_expand_each_rendezvous_url_into_a_distinct_relay_route() {
        let mut bootstrap = sample_bootstrap();
        bootstrap.rendezvous_urls = vec![
            "https://rendezvous-a.example".to_string(),
            "https://rendezvous-b.example".to_string(),
        ];

        let planned = bootstrap
            .planned_targets()
            .expect("planned targets should build");

        assert_eq!(planned.len(), 3);
        assert_eq!(planned[0].path_kind, TransportPathKind::DirectHttps);
        assert_eq!(planned[1].path_kind, TransportPathKind::RelayTunnel);
        assert_eq!(planned[2].path_kind, TransportPathKind::RelayTunnel);
        assert_eq!(
            planned[1].rendezvous_urls,
            vec!["https://rendezvous-a.example/".to_string()]
        );
        assert_eq!(
            planned[2].rendezvous_urls,
            vec!["https://rendezvous-b.example/".to_string()]
        );
        assert_eq!(planned[1].target_node_id, planned[0].target_node_id);
        assert_eq!(planned[2].target_node_id, planned[0].target_node_id);
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

    fn multi_node_bootstrap() -> ConnectionBootstrap {
        let mut bootstrap = sample_bootstrap();
        bootstrap.rendezvous_urls = vec![
            "https://rendezvous-a.example".to_string(),
            "https://rendezvous-b.example".to_string(),
        ];
        bootstrap.direct_endpoints = vec![
            BootstrapEndpoint {
                url: "https://node-a.example".to_string(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: Some(NodeId::new_v4()),
            },
            BootstrapEndpoint {
                url: "https://node-b.example".to_string(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: Some(NodeId::new_v4()),
            },
        ];
        bootstrap
    }

    #[test]
    fn diagnostic_targets_selecting_defaults_to_first_direct_and_all_rendezvous_urls() {
        let bootstrap = multi_node_bootstrap();
        let first_node_id = bootstrap.direct_endpoints[0].node_id;

        let targets = bootstrap
            .diagnostic_targets_selecting(None, None)
            .expect("default diagnostic targets should build");

        assert_eq!(
            targets
                .direct
                .as_ref()
                .and_then(|t| t.server_base_url.clone()),
            Some("https://node-a.example/".to_string())
        );
        assert_eq!(targets.relay.len(), 2);
        assert!(
            targets
                .relay
                .iter()
                .all(|target| target.target_node_id == first_node_id)
        );
    }

    #[test]
    fn diagnostic_targets_selecting_pins_to_requested_node() {
        let bootstrap = multi_node_bootstrap();
        let second_node_id = bootstrap.direct_endpoints[1]
            .node_id
            .expect("fixture endpoint should have a node id");

        let targets = bootstrap
            .diagnostic_targets_selecting(Some(second_node_id), None)
            .expect("diagnostic targets for a known node id should build");

        assert_eq!(
            targets
                .direct
                .as_ref()
                .and_then(|t| t.server_base_url.clone()),
            Some("https://node-b.example/".to_string())
        );
        assert_eq!(targets.relay.len(), 2);
        assert!(
            targets
                .relay
                .iter()
                .all(|target| target.target_node_id == Some(second_node_id))
        );
    }

    #[test]
    fn diagnostic_targets_selecting_rejects_unknown_node_id() {
        let bootstrap = multi_node_bootstrap();
        let unknown_node_id = NodeId::new_v4();

        let error = bootstrap
            .diagnostic_targets_selecting(Some(unknown_node_id), None)
            .expect_err("unknown node id should be rejected");

        assert!(error.to_string().contains(&unknown_node_id.to_string()));
    }

    #[test]
    fn diagnostic_targets_selecting_pins_to_requested_rendezvous_url() {
        let bootstrap = multi_node_bootstrap();

        let targets = bootstrap
            .diagnostic_targets_selecting(None, Some("https://rendezvous-b.example"))
            .expect("diagnostic targets for a known rendezvous url should build");

        assert_eq!(targets.relay.len(), 1);
        assert_eq!(
            targets.relay[0].rendezvous_urls,
            vec!["https://rendezvous-b.example".to_string()]
        );
    }

    #[test]
    fn diagnostic_targets_selecting_rejects_unknown_rendezvous_url() {
        let bootstrap = multi_node_bootstrap();

        let error = bootstrap
            .diagnostic_targets_selecting(None, Some("https://unknown-rendezvous.example"))
            .expect_err("unknown rendezvous url should be rejected");

        assert!(error.to_string().contains("unknown-rendezvous.example"));
    }

    #[test]
    fn refresh_dynamic_targets_requires_rendezvous_identity_when_mtls_required() {
        let error = sample_bootstrap()
            .refresh_dynamic_targets_blocking(None)
            .expect_err("mTLS discovery without client identity should fail");

        assert!(error.to_string().contains("rendezvous_client_identity_pem"));
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

    #[test]
    fn enrollment_result_produces_a_valid_persisted_mobile_connection() {
        let mut bootstrap = sample_bootstrap();
        bootstrap.pairing_token = None;
        let device_id = "019d04a8-3099-75bc-8ff5-f5bd9a78bb83".to_string();
        bootstrap.device_id = Some(device_id.clone());
        bootstrap.device_label = Some("Tablet".to_string());
        let response = BootstrapEnrollmentResult {
            cluster_id: bootstrap.cluster_id,
            server_base_url: Some("https://public.example/".to_string()),
            server_ca_pem: Some("public-ca".to_string()),
            connection_bootstrap_json: Some(
                bootstrap
                    .to_json_pretty()
                    .expect("bootstrap should serialize"),
            ),
            device_id: device_id.clone(),
            label: Some("Tablet".to_string()),
            public_key_pem: "public-key".to_string(),
            private_key_pem: "private-key".to_string(),
            credential_pem: "credential".to_string(),
            rendezvous_client_identity_pem: None,
            created_at_unix: Some(10),
            expires_at_unix: Some(20),
        };

        let connection = response
            .enrolled_client_connection()
            .expect("enrollment should produce a normalized connection");

        let persisted_bootstrap = ConnectionBootstrap::from_json_str(&connection.connection_input)
            .expect("normalized connection input should be a reconnectable bootstrap");
        let persisted_identity =
            ClientIdentityMaterial::from_json_str(&connection.client_identity_json)
                .expect("normalized client identity should be valid");
        assert_eq!(persisted_bootstrap.cluster_id, response.cluster_id);
        assert_eq!(connection.device_id, device_id);
        assert_eq!(connection.device_label.as_deref(), Some("Tablet"));
        assert_eq!(
            persisted_identity.device_id.to_string(),
            connection.device_id
        );
    }

    #[derive(Debug, Deserialize)]
    struct TestDiscoveryQuery {
        node_id: Option<String>,
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_dynamic_targets_adds_discovered_candidates_and_mesh_peers() {
        let cluster_id = ClusterId::now_v7();
        let target_node_id = NodeId::new_v4();
        let expected_node_id = target_node_id.to_string();
        let seed_calls = Arc::new(Mutex::new(Vec::new()));
        let peer_calls = Arc::new(Mutex::new(Vec::new()));

        let peer_route_calls = Arc::clone(&peer_calls);
        let peer_route_expected_node_id = expected_node_id.clone();
        let peer_router = Router::new().route(
            "/control/discovery",
            get(move |Query(query): Query<TestDiscoveryQuery>| {
                let peer_route_calls = Arc::clone(&peer_route_calls);
                let peer_route_expected_node_id = peer_route_expected_node_id.clone();
                async move {
                    peer_route_calls
                        .lock()
                        .expect("query record lock should not be poisoned")
                        .push(query.node_id.clone());

                    let response = if query.node_id.as_deref()
                        == Some(peer_route_expected_node_id.as_str())
                    {
                        DiscoveryResponse {
                            rendezvous_peers: Vec::new(),
                            node_candidates: Some(vec![
                                ConnectionCandidate {
                                    kind: CandidateKind::DirectQuic,
                                    endpoint: "iroh://peer-key-1".to_string(),
                                    rtt_ms: Some(5),
                                    transport_hints: Some(ConnectionCandidateTransportHints {
                                        transport_id: Some("peer-key-1".to_string()),
                                        relay_url: Some("https://relay-quic.example".to_string()),
                                        alpn: Some(DEFAULT_DIRECT_QUIC_ALPN.to_string()),
                                        direct_socket_addrs: vec!["127.0.0.1:7000".to_string()],
                                        observed_socket_addrs: vec![
                                            "203.0.113.10:40000".to_string(),
                                        ],
                                    }),
                                },
                                ConnectionCandidate {
                                    kind: CandidateKind::DirectHttps,
                                    endpoint: "https://public.example".to_string(),
                                    rtt_ms: Some(8),
                                    transport_hints: None,
                                },
                                ConnectionCandidate {
                                    kind: CandidateKind::ServerReflexive,
                                    endpoint: "https://203.0.113.10:7443".to_string(),
                                    rtt_ms: Some(12),
                                    transport_hints: None,
                                },
                                ConnectionCandidate {
                                    kind: CandidateKind::Relay,
                                    endpoint: "https://relay.example/session/123".to_string(),
                                    rtt_ms: Some(20),
                                    transport_hints: None,
                                },
                            ]),
                            node_relay_capable: true,
                        }
                    } else {
                        DiscoveryResponse {
                            rendezvous_peers: Vec::new(),
                            node_candidates: None,
                            node_relay_capable: false,
                        }
                    };

                    Json(response)
                }
            }),
        );
        let peer_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("peer listener should bind");
        let peer_addr = peer_listener.local_addr().expect("peer listener addr");
        let peer_server = tokio::spawn(async move {
            axum::serve(peer_listener, peer_router)
                .await
                .expect("peer discovery test server should run");
        });

        let peer_rendezvous_url = format!("http://{peer_addr}");
        let seed_route_calls = Arc::clone(&seed_calls);
        let seed_router = Router::new().route(
            "/control/discovery",
            get(move |Query(query): Query<TestDiscoveryQuery>| {
                let seed_route_calls = Arc::clone(&seed_route_calls);
                let peer_rendezvous_url = peer_rendezvous_url.clone();
                async move {
                    seed_route_calls
                        .lock()
                        .expect("query record lock should not be poisoned")
                        .push(query.node_id.clone());

                    let response = if query.node_id.is_none() {
                        DiscoveryResponse {
                            rendezvous_peers: vec![RendezvousEndpointStatus {
                                url: peer_rendezvous_url,
                                status: RendezvousEndpointConnectionState::Connected,
                                last_attempt_unix: Some(10),
                                last_success_unix: Some(10),
                                consecutive_failures: 0,
                                last_error: None,
                                active: false,
                            }],
                            node_candidates: None,
                            node_relay_capable: false,
                        }
                    } else {
                        DiscoveryResponse {
                            rendezvous_peers: Vec::new(),
                            node_candidates: None,
                            node_relay_capable: false,
                        }
                    };

                    Json(response)
                }
            }),
        );
        let seed_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("seed listener should bind");
        let seed_addr = seed_listener.local_addr().expect("seed listener addr");
        let seed_server = tokio::spawn(async move {
            axum::serve(seed_listener, seed_router)
                .await
                .expect("seed discovery test server should run");
        });

        let bootstrap =
            refreshable_bootstrap(cluster_id, format!("http://{seed_addr}"), target_node_id);
        let targets =
            tokio::task::spawn_blocking(move || bootstrap.refresh_dynamic_targets_blocking(None))
                .await
                .expect("refresh task should not panic")
                .expect("dynamic target refresh should succeed");

        assert_eq!(
            seed_calls
                .lock()
                .expect("query record lock should not be poisoned")
                .clone(),
            vec![None, Some(expected_node_id.clone())]
        );
        assert_eq!(
            peer_calls
                .lock()
                .expect("query record lock should not be poisoned")
                .clone(),
            vec![Some(expected_node_id.clone())]
        );
        assert_eq!(targets[0].path_kind, TransportPathKind::DirectHttps);
        assert_eq!(
            targets[0].server_base_url.as_deref(),
            Some("https://public.example/")
        );
        assert_eq!(targets[0].target_node_id, Some(target_node_id));

        assert_eq!(targets[1].path_kind, TransportPathKind::DirectQuic);
        assert!(targets[1].server_base_url.is_none());
        assert_eq!(
            targets[1]
                .direct_candidate
                .as_ref()
                .map(|candidate| candidate.endpoint.as_str()),
            Some("iroh://peer-key-1")
        );
        assert_eq!(
            targets[1]
                .direct_candidate
                .as_ref()
                .and_then(|candidate| candidate.transport_hints.as_ref())
                .and_then(|hints| hints.transport_id.as_deref()),
            Some("peer-key-1")
        );
        assert_eq!(
            targets[1]
                .direct_candidate
                .as_ref()
                .and_then(|candidate| candidate.transport_hints.as_ref())
                .and_then(|hints| hints.relay_url.as_deref()),
            Some("https://relay-quic.example")
        );
        assert_eq!(targets[1].target_node_id, Some(target_node_id));

        assert_eq!(targets.len(), 5);

        assert_eq!(targets[2].path_kind, TransportPathKind::DirectHttps);
        assert_eq!(
            targets[2].server_base_url.as_deref(),
            Some("https://203.0.113.10:7443/")
        );
        assert_eq!(targets[2].target_node_id, Some(target_node_id));

        assert_eq!(targets[3].path_kind, TransportPathKind::RelayTunnel);
        assert_eq!(targets[3].target_node_id, Some(target_node_id));
        assert_eq!(
            targets[3].rendezvous_urls,
            vec![format!("http://{seed_addr}/")]
        );

        assert_eq!(targets[4].path_kind, TransportPathKind::RelayTunnel);
        assert_eq!(targets[4].target_node_id, Some(target_node_id));
        assert_eq!(
            targets[4].rendezvous_urls,
            vec![format!("http://{peer_addr}/")]
        );

        seed_server.abort();
        let _ = seed_server.await;
        peer_server.abort();
        let _ = peer_server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn build_client_with_identity_renewing_skips_renewal_when_no_cert() {
        let cluster_id = ClusterId::now_v7();
        // Port 9 is the discard port — connection will be refused, but no connection
        // is attempted here because there's no cert to renew and a single direct target
        // skips the startup probe.
        let bootstrap = direct_bootstrap_for_url(cluster_id, "http://127.0.0.1:9");
        let mut identity = identity_for_bootstrap(cluster_id);

        let result = tokio::task::spawn_blocking(move || {
            bootstrap.build_client_with_identity_renewing(&mut identity)
        })
        .await
        .expect("task should not panic");

        assert!(
            result.is_ok(),
            "renewal should be skipped and client built when no cert is present: {:?}",
            result.err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn build_client_with_identity_renewing_continues_when_renewal_endpoint_is_absent() {
        let cluster_id = ClusterId::now_v7();
        // The mock server serves only /api/v1/health — no renewal endpoint.
        let (url, server) = spawn_health_server(0).await;
        let bootstrap = direct_bootstrap_for_url(cluster_id, &url);
        let mut identity = identity_for_bootstrap(cluster_id);
        identity.rendezvous_client_identity_pem =
            Some(EXPIRED_RENDEZVOUS_CLIENT_IDENTITY_PEM.to_string());

        let result = tokio::task::spawn_blocking(move || {
            bootstrap.build_client_with_identity_renewing(&mut identity)
        })
        .await
        .expect("task should not panic");

        assert!(
            result.is_ok(),
            "renewal failure should be non-fatal and client should still build: {:?}",
            result.err()
        );

        server.abort();
        let _ = server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn legacy_cluster_san_identity_never_uses_relay_for_renewal() {
        let cluster_id = ClusterId::now_v7();
        let relay_requests = Arc::new(AtomicUsize::new(0));
        let relay_requests_for_handler = Arc::clone(&relay_requests);
        let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("relay listener should bind");
        let relay_addr = relay_listener
            .local_addr()
            .expect("relay listener should have an address");
        let relay_app = Router::new().route(
            "/control/relay/ticket",
            post(move || {
                let relay_requests = Arc::clone(&relay_requests_for_handler);
                async move {
                    relay_requests.fetch_add(1, Ordering::SeqCst);
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        );
        let relay_server = tokio::spawn(async move {
            let _ = axum::serve(relay_listener, relay_app).await;
        });

        let mut bootstrap = direct_bootstrap_for_url(cluster_id, "http://127.0.0.1:9");
        bootstrap.relay_mode = RelayMode::Required;
        bootstrap.rendezvous_mtls_required = true;
        bootstrap.rendezvous_urls = vec![format!("http://{relay_addr}")];
        bootstrap.direct_endpoints[0].node_id = Some(NodeId::new_v4());

        let mut identity = identity_for_bootstrap(cluster_id);
        identity.credential_pem = Some("issued-credential".to_string());
        identity.rendezvous_client_identity_pem =
            Some(EXPIRED_RENDEZVOUS_CLIENT_IDENTITY_PEM.to_string());

        let renewed = tokio::task::spawn_blocking(move || {
            bootstrap.renew_rendezvous_identity_if_needed(&mut identity)
        })
        .await
        .expect("renewal task should not panic")
        .expect("relay-only migration attempt should be handled");

        assert!(!renewed, "legacy SAN migration requires a direct target");
        assert_eq!(
            relay_requests.load(Ordering::SeqCst),
            0,
            "legacy SAN migration must not send a renewal request through relay"
        );

        relay_server.abort();
        let _ = relay_server.await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn build_client_prefers_fastest_direct_endpoint_after_startup_probe() {
        let (slow_url, slow_server) = spawn_health_server(120).await;
        let (fast_url, fast_server) = spawn_health_server(0).await;

        let mut bootstrap = sample_bootstrap();
        bootstrap.relay_mode = RelayMode::Disabled;
        bootstrap.rendezvous_urls.clear();
        bootstrap.direct_endpoints = vec![
            BootstrapEndpoint {
                url: slow_url.clone(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: Some(NodeId::new_v4()),
            },
            BootstrapEndpoint {
                url: fast_url.clone(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: Some(NodeId::new_v4()),
            },
        ];

        let client = bootstrap
            .build_client()
            .expect("direct bootstrap client should build inside an async context");
        let uses_relay = client.uses_relay_transport();
        let direct_url = client.direct_server_base_url().map(str::to_string);

        assert!(!uses_relay);
        assert_eq!(direct_url.as_deref(), Some(fast_url.as_str()));

        slow_server.abort();
        let _ = slow_server.await;
        fast_server.abort();
        let _ = fast_server.await;
    }
}
