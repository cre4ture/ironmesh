use anyhow::{Context, Result};
use reqwest::Certificate;
use reqwest::Client;
use reqwest::Url;
use reqwest::blocking::Client as BlockingClient;
use std::fs;
use std::path::Path;

use crate::IronMeshClient;

pub fn load_root_certificate(path: &Path) -> Result<Certificate> {
    let pem = fs::read(path)
        .with_context(|| format!("failed to read server CA certificate {}", path.display()))?;
    Certificate::from_pem(&pem)
        .with_context(|| format!("failed to parse server CA certificate {}", path.display()))
}

pub fn build_http_client(server_ca_cert: Option<&Path>, base_url_str: &str, bearer_token: &Option<String>) -> Result<IronMeshClient> {
    let base_url = Url::parse(base_url_str)
        .with_context(|| format!("failed to parse server base URL from {}", base_url_str))?;
    let builder = Client::builder();
    let builder = if let Some(path) = server_ca_cert {
        builder.add_root_certificate(load_root_certificate(path)?)
    } else {
        if base_url.scheme() == "https" {
            anyhow::bail!("server-ca-cert needed for HTTPS server");
        }
        builder
    };
    let http = builder.build().context("failed building HTTP client")?;

    let client = IronMeshClient::with_http_client(base_url.as_str(), http);
    let client = match bearer_token.as_ref() {
        Some(token) => client.with_bearer_token(token.clone()),
        None => {
            if base_url.scheme() == "https" {
                anyhow::bail!("authentication required for HTTPS server");
            }
            client
        }
    };

    Ok(client)
}

pub fn build_blocking_http_client(server_ca_cert: Option<&Path>) -> Result<BlockingClient> {
    let builder = BlockingClient::builder();
    let builder = if let Some(path) = server_ca_cert {
        builder.add_root_certificate(load_root_certificate(path)?)
    } else {
        builder
    };
    builder
        .build()
        .context("failed building blocking HTTP client")
}

