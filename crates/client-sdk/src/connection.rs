use anyhow::{Context, Result, anyhow, bail};
use common::NodeId;
use futures_util::stream::{FuturesUnordered, StreamExt};
use reqwest::Certificate;
use reqwest::Client;
use reqwest::ClientBuilder;
use reqwest::Url;
use reqwest::blocking::Client as BlockingClient;
use reqwest::blocking::ClientBuilder as BlockingClientBuilder;
use std::collections::HashSet;
use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::time::Duration;
use std::time::Instant;
use transport_sdk::{ClientIdentityMaterial, RendezvousClientConfig, TransportPathKind};

use crate::latency_probe::LatencyProbeConfig;
use crate::{IronMeshClient, PlannedConnectionBootstrapTarget};

const RELAY_REQUEST_BASE_URL: &str = "https://relay.invalid/";
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const STARTUP_PROBE_RESPONSE_BYTES: usize = 64;
const STARTUP_PROBE_FAILURE_PENALTY_MS: f64 = 500.0;
const STARTUP_PROBE_TIMEOUT: Duration = Duration::from_secs(10);

pub fn load_root_certificate(path: &Path) -> Result<Certificate> {
    let pem = fs::read(path)
        .with_context(|| format!("failed to read server CA certificate {}", path.display()))?;
    Certificate::from_pem(&pem)
        .with_context(|| format!("failed to parse server CA certificate {}", path.display()))
}

pub fn load_root_certificate_pem(pem: &str) -> Result<Certificate> {
    Certificate::from_pem(pem.as_bytes()).context("failed to parse inline server CA certificate")
}

pub fn build_reqwest_client_from_pem(server_ca_pem: Option<&str>) -> Result<Client> {
    let builder = configure_reqwest_client_builder(Client::builder());
    let builder = if let Some(pem) = server_ca_pem {
        builder.add_root_certificate(load_root_certificate_pem(pem)?)
    } else {
        builder
    };
    builder.build().context("failed building HTTP client")
}

pub fn build_reqwest_client_from_pem_for_url(
    server_ca_pem: Option<&str>,
    url: &Url,
) -> Result<Client> {
    let builder = configure_reqwest_client_builder(Client::builder());
    let builder = if let Some(pem) = server_ca_pem {
        builder.add_root_certificate(load_root_certificate_pem(pem)?)
    } else {
        builder
    };
    let builder = apply_best_effort_url_resolution(builder, url);
    builder.build().context("failed building HTTP client")
}

pub fn build_blocking_reqwest_client_from_pem(
    server_ca_pem: Option<&str>,
) -> Result<BlockingClient> {
    let builder = configure_blocking_reqwest_client_builder(BlockingClient::builder());
    let builder = if let Some(pem) = server_ca_pem {
        builder.add_root_certificate(load_root_certificate_pem(pem)?)
    } else {
        builder
    };
    builder
        .build()
        .context("failed building blocking HTTP client")
}

pub fn build_blocking_reqwest_client_from_pem_for_url(
    server_ca_pem: Option<&str>,
    url: &Url,
) -> Result<BlockingClient> {
    let builder = configure_blocking_reqwest_client_builder(BlockingClient::builder());
    let builder = if let Some(pem) = server_ca_pem {
        builder.add_root_certificate(load_root_certificate_pem(pem)?)
    } else {
        builder
    };
    let builder = apply_best_effort_url_resolution_blocking(builder, url);
    builder
        .build()
        .context("failed building blocking HTTP client")
}

pub fn build_http_client_from_pem(
    server_ca_pem: Option<&str>,
    base_url_str: &str,
) -> Result<IronMeshClient> {
    build_http_client_from_pem_with_target_node_id(server_ca_pem, base_url_str, None)
}

fn build_http_client_from_pem_with_target_node_id(
    server_ca_pem: Option<&str>,
    base_url_str: &str,
    target_node_id: Option<NodeId>,
) -> Result<IronMeshClient> {
    let base_url = Url::parse(base_url_str)
        .with_context(|| format!("failed to parse server base URL from {}", base_url_str))?;
    let http = build_reqwest_client_from_pem_for_url(server_ca_pem, &base_url)?;
    Ok(
        IronMeshClient::from_direct_http_client_with_target_node_id_and_ca_pem(
            base_url.as_str(),
            http,
            target_node_id,
            server_ca_pem.map(ToString::to_string),
        ),
    )
}

pub fn build_http_client_with_identity_from_pem(
    server_ca_pem: Option<&str>,
    base_url_str: &str,
    identity: &ClientIdentityMaterial,
) -> Result<IronMeshClient> {
    build_http_client_with_identity_from_pem_with_target_node_id(
        server_ca_pem,
        base_url_str,
        identity,
        None,
    )
}

fn build_http_client_with_identity_from_pem_with_target_node_id(
    server_ca_pem: Option<&str>,
    base_url_str: &str,
    identity: &ClientIdentityMaterial,
    target_node_id: Option<NodeId>,
) -> Result<IronMeshClient> {
    let base_url = Url::parse(base_url_str)
        .with_context(|| format!("failed to parse server base URL from {}", base_url_str))?;
    let http = build_reqwest_client_from_pem_for_url(server_ca_pem, &base_url)?;
    Ok(
        IronMeshClient::from_direct_http_client_with_target_node_id_and_ca_pem(
            base_url.as_str(),
            http,
            target_node_id,
            server_ca_pem.map(ToString::to_string),
        )
        .with_client_identity(identity.clone()),
    )
}

pub fn build_http_client_with_identity_from_planned_target(
    target: &PlannedConnectionBootstrapTarget,
    identity: &ClientIdentityMaterial,
) -> Result<IronMeshClient> {
    if let Some(server_base_url) = planned_target_direct_http_base_url(target)? {
        return build_http_client_with_identity_from_pem_with_target_node_id(
            target
                .server_ca_pem
                .as_deref()
                .or(target.cluster_ca_pem.as_deref()),
            server_base_url,
            identity,
            target.target_node_id,
        );
    }

    let target_node_id = target
        .target_node_id
        .ok_or_else(|| anyhow!("relay-backed client transport target is missing target_node_id"))?;
    let rendezvous_client_identity_pem = identity.rendezvous_client_identity_pem.as_deref();
    if target.rendezvous_mtls_required && rendezvous_client_identity_pem.is_none() {
        bail!(
            "relay-backed client transport requires rendezvous_client_identity_pem when rendezvous_mtls_required is true"
        );
    }
    let rendezvous = transport_sdk::RendezvousControlClient::new(
        RendezvousClientConfig {
            cluster_id: target.cluster_id,
            rendezvous_urls: target.rendezvous_urls.clone(),
            heartbeat_interval_secs: 15,
        },
        target
            .rendezvous_ca_pem
            .as_deref()
            .or(target.cluster_ca_pem.as_deref()),
        rendezvous_client_identity_pem.map(str::as_bytes),
    )?;

    Ok(
        IronMeshClient::with_relay_transport(RELAY_REQUEST_BASE_URL, rendezvous, target_node_id)
            .with_client_identity(identity.clone()),
    )
}

pub fn build_http_client_with_identity_from_planned_targets(
    targets: &[PlannedConnectionBootstrapTarget],
    identity: &ClientIdentityMaterial,
) -> Result<IronMeshClient> {
    let mut clients = Vec::new();
    let mut build_errors = Vec::new();

    for target in targets {
        match build_http_client_with_identity_from_planned_target(target, identity) {
            Ok(client) => clients.push(client),
            Err(error) if target.relay_mode != transport_sdk::RelayMode::Required => {
                build_errors.push(error.to_string());
            }
            Err(error) => return Err(error),
        }
    }

    if clients.is_empty() {
        bail!(
            "bootstrap does not contain any buildable client transport targets{}",
            format_build_error_suffix(&build_errors)
        );
    }

    if clients.len() == 1 {
        return IronMeshClient::combine(clients);
    }

    let ordered = order_clients_by_startup_probe(clients, true)?;
    IronMeshClient::combine(ordered)
}

pub fn build_http_client_from_planned_targets(
    targets: &[PlannedConnectionBootstrapTarget],
) -> Result<IronMeshClient> {
    let mut clients = Vec::new();
    let mut build_errors = Vec::new();

    for target in targets {
        let Some(server_base_url) = (match planned_target_direct_http_base_url(target) {
            Ok(server_base_url) => server_base_url,
            Err(error) => {
                build_errors.push(error.to_string());
                continue;
            }
        }) else {
            continue;
        };

        match build_http_client_from_pem_with_target_node_id(
            target
                .server_ca_pem
                .as_deref()
                .or(target.cluster_ca_pem.as_deref()),
            server_base_url,
            target.target_node_id,
        ) {
            Ok(client) => clients.push(client),
            Err(error) => build_errors.push(error.to_string()),
        }
    }

    if clients.is_empty() {
        bail!(
            "bootstrap does not contain any buildable direct client transport targets{}",
            format_build_error_suffix(&build_errors)
        );
    }

    if clients.len() == 1 {
        return IronMeshClient::combine(clients);
    }

    let ordered = order_clients_by_startup_probe(clients, false)?;
    IronMeshClient::combine(ordered)
}

pub fn build_client_with_optional_identity_from_planned_target(
    target: &PlannedConnectionBootstrapTarget,
    identity: Option<&ClientIdentityMaterial>,
) -> Result<IronMeshClient> {
    match identity {
        Some(identity) => build_http_client_with_identity_from_planned_target(target, identity),
        None => {
            if let Some(server_base_url) = planned_target_direct_http_base_url(target)? {
                return build_http_client_from_pem_with_target_node_id(
                    target
                        .server_ca_pem
                        .as_deref()
                        .or(target.cluster_ca_pem.as_deref()),
                    server_base_url,
                    target.target_node_id,
                );
            }

            bail!("relay-backed client transport requires enrolled client identity material");
        }
    }
}

pub fn build_http_client(
    server_ca_cert: Option<&Path>,
    base_url_str: &str,
) -> Result<IronMeshClient> {
    let server_ca_pem = server_ca_cert
        .map(|path| {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read server CA certificate {}", path.display()))
        })
        .transpose()?;
    build_http_client_from_pem(server_ca_pem.as_deref(), base_url_str)
}

pub fn build_http_client_with_identity(
    server_ca_cert: Option<&Path>,
    base_url_str: &str,
    identity: &ClientIdentityMaterial,
) -> Result<IronMeshClient> {
    let server_ca_pem = server_ca_cert
        .map(|path| {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read server CA certificate {}", path.display()))
        })
        .transpose()?;
    build_http_client_with_identity_from_pem(server_ca_pem.as_deref(), base_url_str, identity)
}

pub fn build_blocking_http_client(server_ca_cert: Option<&Path>) -> Result<BlockingClient> {
    let server_ca_pem = server_ca_cert
        .map(|path| {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read server CA certificate {}", path.display()))
        })
        .transpose()?;
    build_blocking_reqwest_client_from_pem(server_ca_pem.as_deref())
}

fn configure_reqwest_client_builder(builder: ClientBuilder) -> ClientBuilder {
    // Keep connection attempts short so clients can fail over quickly when a
    // hostname publishes an unreachable IPv6 address ahead of a working IPv4 one.
    builder.connect_timeout(HTTP_CONNECT_TIMEOUT)
}

fn configure_blocking_reqwest_client_builder(
    builder: BlockingClientBuilder,
) -> BlockingClientBuilder {
    builder.connect_timeout(HTTP_CONNECT_TIMEOUT)
}

fn apply_best_effort_url_resolution(builder: ClientBuilder, url: &Url) -> ClientBuilder {
    if let Some((host, addrs)) = preferred_socket_addrs_for_url(url) {
        builder.resolve_to_addrs(&host, &addrs)
    } else {
        builder
    }
}

fn apply_best_effort_url_resolution_blocking(
    builder: BlockingClientBuilder,
    url: &Url,
) -> BlockingClientBuilder {
    if let Some((host, addrs)) = preferred_socket_addrs_for_url(url) {
        builder.resolve_to_addrs(&host, &addrs)
    } else {
        builder
    }
}

fn order_clients_by_startup_probe(
    clients: Vec<IronMeshClient>,
    signed_probe: bool,
) -> Result<Vec<IronMeshClient>> {
    let worker = std::thread::Builder::new()
        .name("ironmesh-client-startup-probe".to_string())
        .spawn(
            move || -> Result<Vec<(usize, IronMeshClient, Result<f64>)>> {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .context("failed to build startup probe runtime")?;

                Ok(runtime.block_on(async move {
                    let mut probes = FuturesUnordered::new();
                    for (index, client) in clients.into_iter().enumerate() {
                        probes.push(async move {
                            let probe = if signed_probe {
                                probe_signed_client_startup_quality(&client).await
                            } else {
                                probe_direct_client_startup_quality(&client).await
                            };
                            (index, client, probe)
                        });
                    }

                    let mut results = Vec::new();
                    while let Some(result) = probes.next().await {
                        results.push(result);
                    }
                    results
                }))
            },
        )
        .context("failed to spawn startup probe worker")?;

    let probed = worker
        .join()
        .map_err(|_| anyhow!("startup probe worker panicked"))??;

    let mut success = Vec::new();
    let mut failed = Vec::new();
    let mut probe_errors = Vec::new();

    for (index, client, probe) in probed {
        match probe {
            Ok(score) => success.push((score, index, client)),
            Err(error) => {
                probe_errors.push(format!("{error:#}"));
                failed.push((index, client));
            }
        }
    }

    if success.is_empty() {
        bail!(
            "startup connection quality probe failed for all client transport targets{}",
            format_build_error_suffix(&probe_errors)
        );
    }

    success.sort_by(|left, right| {
        left.0
            .partial_cmp(&right.0)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.1.cmp(&right.1))
    });
    failed.sort_by_key(|(index, _)| *index);

    let mut ordered = success
        .into_iter()
        .map(|(_, _, client)| client)
        .collect::<Vec<_>>();
    ordered.extend(failed.into_iter().map(|(_, client)| client));
    Ok(ordered)
}

async fn probe_signed_client_startup_quality(client: &IronMeshClient) -> Result<f64> {
    let target_label = startup_probe_target_label(client);
    if let Some(rendezvous) = client.rendezvous_client()
        && let Some(diagnostic) = rendezvous.client_identity_expiry_diagnostic()
    {
        bail!(diagnostic);
    }

    let result = tokio::time::timeout(
        STARTUP_PROBE_TIMEOUT,
        client.run_latency_probe(LatencyProbeConfig {
            sample_count: 2,
            warmup_count: 0,
            response_bytes: STARTUP_PROBE_RESPONSE_BYTES,
            server_delay_ms: 0,
            pause_between_samples_ms: 0,
        }),
    )
    .await
    .with_context(|| {
        format!(
            "startup signed latency probe timed out after {:?} for {target_label}",
            STARTUP_PROBE_TIMEOUT
        )
    })??;

    let latency_ms = result
        .summary
        .avg_total_duration_ms
        .or(result.cold_connect_duration_ms)
        .unwrap_or_default();
    Ok(latency_ms + result.summary.failure_count as f64 * STARTUP_PROBE_FAILURE_PENALTY_MS)
}

async fn probe_direct_client_startup_quality(client: &IronMeshClient) -> Result<f64> {
    let target_label = startup_probe_target_label(client);
    let started_at = Instant::now();
    let response = tokio::time::timeout(STARTUP_PROBE_TIMEOUT, client.get_relative_path("/health"))
        .await
        .with_context(|| {
            format!(
                "startup direct health probe timed out after {:?} for {target_label}",
                STARTUP_PROBE_TIMEOUT
            )
        })??;
    if !response.status.is_success() {
        bail!(
            "health probe returned {} for {}",
            response.status,
            target_label
        );
    }
    Ok(started_at.elapsed().as_secs_f64() * 1000.0)
}

fn startup_probe_target_label(client: &IronMeshClient) -> String {
    client
        .connection_diagnostics()
        .endpoints
        .first()
        .map(|endpoint| endpoint.locator.clone())
        .unwrap_or_else(|| "<unknown-target>".to_string())
}

fn format_build_error_suffix(errors: &[String]) -> String {
    if errors.is_empty() {
        String::new()
    } else {
        format!(": {}", errors.join(" | "))
    }
}

fn planned_target_direct_http_base_url(
    target: &PlannedConnectionBootstrapTarget,
) -> Result<Option<&str>> {
    match target.path_kind {
        TransportPathKind::DirectHttps => {
            target.server_base_url.as_deref().map(Some).ok_or_else(|| {
                anyhow!("direct HTTPS client transport target is missing server_base_url")
            })
        }
        TransportPathKind::DirectQuic => bail!(
            "direct QUIC client transport target {} is not supported until a native QUIC transport is implemented",
            planned_target_label(target)
        ),
        TransportPathKind::RelayTunnel => {
            if target.server_base_url.is_some() {
                bail!(
                    "relay-backed client transport target {} unexpectedly includes server_base_url",
                    planned_target_label(target)
                );
            }
            Ok(None)
        }
    }
}

fn planned_target_label(target: &PlannedConnectionBootstrapTarget) -> String {
    target
        .server_base_url
        .clone()
        .or_else(|| {
            target
                .target_node_id
                .map(|node_id| format!("node {node_id}"))
        })
        .unwrap_or_else(|| format!("{:?}", target.path_kind))
}

fn preferred_socket_addrs_for_url(url: &Url) -> Option<(String, Vec<SocketAddr>)> {
    let host = url.host_str()?.trim();
    if host.is_empty() || host.parse::<IpAddr>().is_ok() {
        return None;
    }
    let port = url.port_or_known_default()?;
    let addrs = (host, port).to_socket_addrs().ok()?;
    let addrs = prioritize_socket_addrs(addrs);
    if addrs.is_empty() {
        None
    } else {
        Some((host.to_string(), addrs))
    }
}

fn prioritize_socket_addrs(addrs: impl IntoIterator<Item = SocketAddr>) -> Vec<SocketAddr> {
    let mut seen = HashSet::new();
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();

    for addr in addrs {
        if !seen.insert(addr) {
            continue;
        }
        if addr.is_ipv4() {
            ipv4.push(addr);
        } else {
            ipv6.push(addr);
        }
    }

    ipv4.extend(ipv6);
    ipv4
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::NodeId;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use transport_sdk::RelayMode;
    use transport_sdk::TransportPathKind;
    use uuid::Uuid;

    fn sample_identity() -> ClientIdentityMaterial {
        let mut identity =
            ClientIdentityMaterial::generate(Uuid::now_v7(), None, Some("test-device".to_string()))
                .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        identity
    }

    #[test]
    fn load_root_certificate_reports_missing_file() {
        let missing_path =
            std::env::temp_dir().join(format!("ironmesh-missing-{}.pem", Uuid::now_v7()));
        let error =
            load_root_certificate(&missing_path).expect_err("missing certificate file should fail");
        assert!(
            error
                .to_string()
                .contains("failed to read server CA certificate")
        );
    }

    #[test]
    fn build_http_client_from_pem_rejects_invalid_base_url() {
        let error = match build_http_client_from_pem(None, "://bad-url") {
            Ok(_) => panic!("invalid URL should fail"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("failed to parse server base URL")
        );
    }

    #[test]
    fn prioritize_socket_addrs_prefers_ipv4_and_deduplicates() {
        let ipv6 = SocketAddr::from((Ipv6Addr::LOCALHOST, 443));
        let ipv4 = SocketAddr::from((Ipv4Addr::LOCALHOST, 443));
        let prioritized = prioritize_socket_addrs([ipv6, ipv4, ipv6, ipv4]);
        assert_eq!(prioritized, vec![ipv4, ipv6]);
    }

    #[test]
    fn build_http_client_with_identity_from_planned_target_uses_direct_transport() {
        let identity = sample_identity();
        let client = build_http_client_with_identity_from_planned_target(
            &PlannedConnectionBootstrapTarget {
                cluster_id: identity.cluster_id,
                rendezvous_urls: vec!["https://rendezvous.example".to_string()],
                rendezvous_mtls_required: false,
                relay_mode: RelayMode::Fallback,
                path_kind: TransportPathKind::DirectHttps,
                server_base_url: Some("https://node-a.example".to_string()),
                target_node_id: Some(NodeId::new_v4()),
                server_ca_pem: None,
                cluster_ca_pem: None,
                rendezvous_ca_pem: None,
                pairing_token: None,
                device_label: None,
                device_id: None,
            },
            &identity,
        )
        .expect("direct client should build");

        assert!(!client.uses_relay_transport());
        assert!(client.rendezvous_client().is_none());
    }

    #[test]
    fn build_http_client_with_identity_from_planned_target_requires_relay_target_node_id() {
        let identity = sample_identity();
        let error = match build_http_client_with_identity_from_planned_target(
            &PlannedConnectionBootstrapTarget {
                cluster_id: identity.cluster_id,
                rendezvous_urls: vec!["https://rendezvous.example".to_string()],
                rendezvous_mtls_required: false,
                relay_mode: RelayMode::Required,
                path_kind: TransportPathKind::RelayTunnel,
                server_base_url: None,
                target_node_id: None,
                server_ca_pem: None,
                cluster_ca_pem: None,
                rendezvous_ca_pem: None,
                pairing_token: None,
                device_label: None,
                device_id: None,
            },
            &identity,
        ) {
            Ok(_) => panic!("missing relay node id should fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("relay-backed client transport target is missing target_node_id")
        );
    }

    #[test]
    fn build_http_client_with_identity_from_planned_target_requires_rendezvous_identity_for_mtls() {
        let identity = sample_identity();
        let error = match build_http_client_with_identity_from_planned_target(
            &PlannedConnectionBootstrapTarget {
                cluster_id: identity.cluster_id,
                rendezvous_urls: vec!["https://rendezvous.example".to_string()],
                rendezvous_mtls_required: true,
                relay_mode: RelayMode::Required,
                path_kind: TransportPathKind::RelayTunnel,
                server_base_url: None,
                target_node_id: Some(NodeId::new_v4()),
                server_ca_pem: None,
                cluster_ca_pem: None,
                rendezvous_ca_pem: None,
                pairing_token: None,
                device_label: None,
                device_id: None,
            },
            &identity,
        ) {
            Ok(_) => panic!("missing rendezvous identity should fail"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("requires rendezvous_client_identity_pem")
        );
    }

    #[test]
    fn build_http_client_with_identity_from_planned_target_rejects_direct_quic() {
        let identity = sample_identity();
        let error = match build_http_client_with_identity_from_planned_target(
            &PlannedConnectionBootstrapTarget {
                cluster_id: identity.cluster_id,
                rendezvous_urls: vec!["https://rendezvous.example".to_string()],
                rendezvous_mtls_required: false,
                relay_mode: RelayMode::Fallback,
                path_kind: TransportPathKind::DirectQuic,
                server_base_url: Some("https://node-a.example:4433".to_string()),
                target_node_id: Some(NodeId::new_v4()),
                server_ca_pem: None,
                cluster_ca_pem: None,
                rendezvous_ca_pem: None,
                pairing_token: None,
                device_label: None,
                device_id: None,
            },
            &identity,
        ) {
            Ok(_) => panic!("direct QUIC target should fail closed until transport exists"),
            Err(error) => error,
        };

        assert!(error.to_string().contains(
            "direct QUIC client transport target https://node-a.example:4433 is not supported"
        ));
    }

    #[test]
    fn build_client_with_optional_identity_from_planned_target_rejects_direct_quic_without_identity()
     {
        let error = match build_client_with_optional_identity_from_planned_target(
            &PlannedConnectionBootstrapTarget {
                cluster_id: Uuid::now_v7(),
                rendezvous_urls: vec!["https://rendezvous.example".to_string()],
                rendezvous_mtls_required: false,
                relay_mode: RelayMode::Fallback,
                path_kind: TransportPathKind::DirectQuic,
                server_base_url: Some("https://node-a.example:4433".to_string()),
                target_node_id: Some(NodeId::new_v4()),
                server_ca_pem: None,
                cluster_ca_pem: None,
                rendezvous_ca_pem: None,
                pairing_token: None,
                device_label: None,
                device_id: None,
            },
            None,
        ) {
            Ok(_) => panic!("direct QUIC target should fail closed without identity as well"),
            Err(error) => error,
        };

        assert!(error.to_string().contains(
            "direct QUIC client transport target https://node-a.example:4433 is not supported"
        ));
    }

    #[test]
    fn build_http_client_from_planned_targets_rejects_direct_quic_when_no_http_targets_exist() {
        let error =
            match build_http_client_from_planned_targets(&[PlannedConnectionBootstrapTarget {
                cluster_id: Uuid::now_v7(),
                rendezvous_urls: vec!["https://rendezvous.example".to_string()],
                rendezvous_mtls_required: false,
                relay_mode: RelayMode::Fallback,
                path_kind: TransportPathKind::DirectQuic,
                server_base_url: Some("https://node-a.example:4433".to_string()),
                target_node_id: Some(NodeId::new_v4()),
                server_ca_pem: None,
                cluster_ca_pem: None,
                rendezvous_ca_pem: None,
                pairing_token: None,
                device_label: None,
                device_id: None,
            }]) {
                Ok(_) => panic!("direct QUIC target should not be built as HTTP"),
                Err(error) => error,
            };

        assert!(error.to_string().contains(
            "direct QUIC client transport target https://node-a.example:4433 is not supported"
        ));
    }
}
