use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct RendezvousMtlsConfig {
    pub client_ca_cert_path: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct RendezvousServiceConfig {
    pub bind_addr: SocketAddr,
    pub public_url: String,
    pub relay_public_urls: Vec<String>,
    pub mtls: Option<RendezvousMtlsConfig>,
}

impl RendezvousServiceConfig {
    pub fn from_env() -> Result<Self> {
        let bind_addr: SocketAddr = std::env::var("IRONMESH_RENDEZVOUS_BIND")
            .unwrap_or_else(|_| "127.0.0.1:19090".to_string())
            .parse()
            .context("invalid IRONMESH_RENDEZVOUS_BIND")?;

        let public_url = std::env::var("IRONMESH_RENDEZVOUS_PUBLIC_URL")
            .unwrap_or_else(|_| format!("http://{bind_addr}"));

        let relay_public_urls = std::env::var("IRONMESH_RELAY_PUBLIC_URLS")
            .ok()
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .filter(|urls| !urls.is_empty())
            .unwrap_or_else(|| vec![public_url.clone()]);

        let mtls = match (
            std::env::var("IRONMESH_RENDEZVOUS_CLIENT_CA_CERT").ok(),
            std::env::var("IRONMESH_RENDEZVOUS_TLS_CERT").ok(),
            std::env::var("IRONMESH_RENDEZVOUS_TLS_KEY").ok(),
        ) {
            (Some(client_ca_cert_path), Some(cert_path), Some(key_path)) => {
                Some(RendezvousMtlsConfig {
                    client_ca_cert_path: PathBuf::from(client_ca_cert_path),
                    cert_path: PathBuf::from(cert_path),
                    key_path: PathBuf::from(key_path),
                })
            }
            (None, None, None) => None,
            _ => {
                anyhow::bail!(
                    "IRONMESH_RENDEZVOUS_CLIENT_CA_CERT, IRONMESH_RENDEZVOUS_TLS_CERT, and IRONMESH_RENDEZVOUS_TLS_KEY must be set together"
                )
            }
        };

        Ok(Self {
            bind_addr,
            public_url,
            relay_public_urls,
            mtls,
        })
    }
}
