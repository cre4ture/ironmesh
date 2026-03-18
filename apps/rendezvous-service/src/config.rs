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
    pub allow_insecure_http: bool,
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

        let allow_insecure_http = std::env::var("IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP")
            .ok()
            .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);

        let config = Self {
            bind_addr,
            public_url,
            relay_public_urls,
            mtls,
            allow_insecure_http,
        };
        config.validate_startup_security()?;
        Ok(config)
    }

    pub fn validate_startup_security(&self) -> Result<()> {
        if self.mtls.is_some() || self.allow_insecure_http {
            return Ok(());
        }

        anyhow::bail!(
            "rendezvous-service refuses insecure HTTP startup without mTLS; configure IRONMESH_RENDEZVOUS_CLIENT_CA_CERT, IRONMESH_RENDEZVOUS_TLS_CERT, and IRONMESH_RENDEZVOUS_TLS_KEY, or set IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP=true for local development/testing only"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_startup_security_rejects_plain_http_by_default() {
        let config = RendezvousServiceConfig {
            bind_addr: "127.0.0.1:19090".parse().expect("bind addr should parse"),
            public_url: "http://127.0.0.1:19090".to_string(),
            relay_public_urls: vec!["http://127.0.0.1:19090".to_string()],
            mtls: None,
            allow_insecure_http: false,
        };

        let error = config
            .validate_startup_security()
            .expect_err("plain HTTP rendezvous should be rejected by default");
        assert!(error.to_string().contains("ALLOW_INSECURE_HTTP"));
    }

    #[test]
    fn validate_startup_security_allows_explicit_insecure_http() {
        let config = RendezvousServiceConfig {
            bind_addr: "127.0.0.1:19090".parse().expect("bind addr should parse"),
            public_url: "http://127.0.0.1:19090".to_string(),
            relay_public_urls: vec!["http://127.0.0.1:19090".to_string()],
            mtls: None,
            allow_insecure_http: true,
        };

        config
            .validate_startup_security()
            .expect("explicit dev/test insecure HTTP should be allowed");
    }
}
