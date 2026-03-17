use anyhow::{Context, Result, anyhow, bail};
use reqwest::Certificate;
use reqwest::Client;
use reqwest::Url;
use reqwest::blocking::Client as BlockingClient;
use std::fs;
use std::path::Path;
use transport_sdk::{ClientIdentityMaterial, RendezvousClientConfig};

use crate::{IronMeshClient, PlannedConnectionBootstrapTarget};

const RELAY_REQUEST_BASE_URL: &str = "https://relay.invalid/";

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
    let builder = Client::builder();
    let builder = if let Some(pem) = server_ca_pem {
        builder.add_root_certificate(load_root_certificate_pem(pem)?)
    } else {
        builder
    };
    builder.build().context("failed building HTTP client")
}

pub fn build_blocking_reqwest_client_from_pem(
    server_ca_pem: Option<&str>,
) -> Result<BlockingClient> {
    let builder = BlockingClient::builder();
    let builder = if let Some(pem) = server_ca_pem {
        builder.add_root_certificate(load_root_certificate_pem(pem)?)
    } else {
        builder
    };
    builder
        .build()
        .context("failed building blocking HTTP client")
}

pub fn build_http_client_from_pem(
    server_ca_pem: Option<&str>,
    base_url_str: &str,
    bearer_token: &Option<String>,
) -> Result<IronMeshClient> {
    let base_url = Url::parse(base_url_str)
        .with_context(|| format!("failed to parse server base URL from {}", base_url_str))?;
    let http = build_reqwest_client_from_pem(server_ca_pem)?;

    let client = IronMeshClient::from_direct_http_client(base_url.as_str(), http);
    Ok(match bearer_token.as_ref() {
        Some(token) => client.with_bearer_token(token.clone()),
        None => client,
    })
}

pub fn build_http_client_with_identity_from_pem(
    server_ca_pem: Option<&str>,
    base_url_str: &str,
    identity: &ClientIdentityMaterial,
) -> Result<IronMeshClient> {
    let base_url = Url::parse(base_url_str)
        .with_context(|| format!("failed to parse server base URL from {}", base_url_str))?;
    let http = build_reqwest_client_from_pem(server_ca_pem)?;
    Ok(
        IronMeshClient::from_direct_http_client(base_url.as_str(), http)
            .with_client_identity(identity.clone()),
    )
}

pub fn build_http_client_with_identity_from_planned_target(
    target: &PlannedConnectionBootstrapTarget,
    identity: &ClientIdentityMaterial,
) -> Result<IronMeshClient> {
    if let Some(server_base_url) = target.server_base_url.as_deref() {
        return build_http_client_with_identity_from_pem(
            target
                .server_ca_pem
                .as_deref()
                .or(target.cluster_ca_pem.as_deref()),
            server_base_url,
            identity,
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

pub fn build_http_client(
    server_ca_cert: Option<&Path>,
    base_url_str: &str,
    bearer_token: &Option<String>,
) -> Result<IronMeshClient> {
    let server_ca_pem = server_ca_cert
        .map(|path| {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read server CA certificate {}", path.display()))
        })
        .transpose()?;
    build_http_client_from_pem(server_ca_pem.as_deref(), base_url_str, bearer_token)
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
