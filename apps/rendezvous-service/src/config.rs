use std::net::SocketAddr;

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct RendezvousServiceConfig {
    pub bind_addr: SocketAddr,
    pub public_url: String,
    pub relay_public_urls: Vec<String>,
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

        Ok(Self {
            bind_addr,
            public_url,
            relay_public_urls,
        })
    }
}
