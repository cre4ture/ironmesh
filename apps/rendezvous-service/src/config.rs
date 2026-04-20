use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use common::{ClusterId, NodeId};
pub use rendezvous_server::{
    RendezvousClientCa, RendezvousMtlsConfig, RendezvousServerConfig, RendezvousServerTlsIdentity,
};

use crate::failover::{
    DecryptedRendezvousFailoverPackage, load_rendezvous_failover_package, normalize_public_url,
};

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_INFO: &str = git_version::git_version!(
    prefix = "Build revision: ",
    args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]
);
const LONG_VERSION: &str = git_version::git_version!(
    prefix = concat!(env!("CARGO_PKG_VERSION"), "\nBuild revision: "),
    args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]
);

#[derive(Debug, Clone, Default, PartialEq, Eq, Parser)]
#[command(name = "ironmesh-rendezvous-service")]
#[command(about = "Standalone Ironmesh rendezvous plus relay service")]
#[command(version = PACKAGE_VERSION)]
#[command(long_version = LONG_VERSION)]
#[command(after_help = BUILD_INFO)]
pub struct RendezvousServiceCliConfig {
    #[arg(long = "bind-addr", value_name = "ADDR")]
    pub bind_addr: Option<SocketAddr>,
    #[arg(
        long = "failover-package",
        env = "IRONMESH_RENDEZVOUS_FAILOVER_PACKAGE",
        value_name = "FILE"
    )]
    pub failover_package_path: Option<PathBuf>,
    #[arg(
        long = "failover-passphrase",
        env = "IRONMESH_RENDEZVOUS_FAILOVER_PASSPHRASE",
        value_name = "PASSPHRASE"
    )]
    pub failover_passphrase: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LoadedRendezvousFailoverMetadata {
    pub package_path: PathBuf,
    pub cluster_id: ClusterId,
    pub source_node_id: NodeId,
    pub target_node_id: NodeId,
}

#[derive(Debug, Clone)]
pub struct RendezvousServiceConfig {
    pub bind_addr: SocketAddr,
    pub public_url: String,
    pub relay_public_urls: Vec<String>,
    pub mtls: Option<RendezvousMtlsConfig>,
    pub allow_insecure_http: bool,
    pub failover_package: Option<LoadedRendezvousFailoverMetadata>,
}

impl RendezvousServiceCliConfig {
    pub fn from_env_args() -> Result<Self> {
        Self::parse().validate()
    }

    fn validate(self) -> Result<Self> {
        match (&self.failover_package_path, &self.failover_passphrase) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => bail!(
                "IRONMESH_RENDEZVOUS_FAILOVER_PACKAGE and IRONMESH_RENDEZVOUS_FAILOVER_PASSPHRASE must be set together"
            ),
        }

        if self.failover_package_path.is_some() && self.bind_addr.is_none() {
            bail!("--bind-addr is required when using a failover package");
        }

        Ok(self)
    }
}

impl RendezvousServiceConfig {
    pub fn from_env() -> Result<Self> {
        let args = RendezvousServiceCliConfig::from_env_args()?;
        Self::from_env_and_args(&args)
    }

    pub fn from_env_and_args(args: &RendezvousServiceCliConfig) -> Result<Self> {
        Self::from_lookup(args, |key| std::env::var(key).ok())
    }

    fn from_lookup<F>(args: &RendezvousServiceCliConfig, lookup_env: F) -> Result<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        if args.failover_package_path.is_some() && args.bind_addr.is_none() {
            bail!("--bind-addr is required when using a failover package");
        }

        let bind_addr = match args.bind_addr {
            Some(bind_addr) => bind_addr,
            None => lookup_env("IRONMESH_RENDEZVOUS_BIND")
                .unwrap_or_else(|| "127.0.0.1:19090".to_string())
                .parse()
                .context("invalid IRONMESH_RENDEZVOUS_BIND")?,
        };

        let failover_package = args
            .failover_package_path
            .as_deref()
            .map(|package_path| {
                load_rendezvous_failover_package(
                    package_path,
                    args.failover_passphrase
                        .as_deref()
                        .expect("failover package passphrase should be present"),
                )
            })
            .transpose()?;

        let configured_public_url = lookup_env("IRONMESH_RENDEZVOUS_PUBLIC_URL");
        let public_url = match (configured_public_url, failover_package.as_ref()) {
            (Some(configured), Some(package)) => {
                if normalize_public_url(&configured)
                    != normalize_public_url(&package.package.public_url)
                {
                    bail!(
                        "IRONMESH_RENDEZVOUS_PUBLIC_URL {} does not match failover package public_url {}",
                        configured,
                        package.package.public_url
                    );
                }
                configured
            }
            (Some(configured), None) => configured,
            (None, Some(package)) => package.package.public_url.clone(),
            (None, None) => format!("http://{bind_addr}"),
        };

        let relay_public_urls = lookup_env("IRONMESH_RELAY_PUBLIC_URLS")
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

        let client_ca_cert_path = lookup_env("IRONMESH_RENDEZVOUS_CLIENT_CA_CERT");
        let cert_path = lookup_env("IRONMESH_RENDEZVOUS_TLS_CERT");
        let key_path = lookup_env("IRONMESH_RENDEZVOUS_TLS_KEY");
        let mtls = build_mtls_config(
            client_ca_cert_path,
            cert_path,
            key_path,
            failover_package.as_ref(),
        )?;

        let allow_insecure_http = lookup_env("IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP")
            .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);

        let config = Self {
            bind_addr,
            public_url,
            relay_public_urls,
            mtls,
            allow_insecure_http,
            failover_package: failover_package.as_ref().map(|package| {
                LoadedRendezvousFailoverMetadata {
                    package_path: package.package_path.clone(),
                    cluster_id: package.package.cluster_id,
                    source_node_id: package.package.source_node_id,
                    target_node_id: package.package.target_node_id,
                }
            }),
        };
        config.validate_startup_security()?;
        Ok(config)
    }

    pub fn validate_startup_security(&self) -> Result<()> {
        if self.mtls.is_some() || self.allow_insecure_http {
            return Ok(());
        }

        anyhow::bail!(
            "ironmesh-rendezvous-service refuses insecure HTTP startup without mTLS; configure IRONMESH_RENDEZVOUS_CLIENT_CA_CERT plus IRONMESH_RENDEZVOUS_TLS_CERT and IRONMESH_RENDEZVOUS_TLS_KEY, or use a failover package with IRONMESH_RENDEZVOUS_FAILOVER_PACKAGE and IRONMESH_RENDEZVOUS_FAILOVER_PASSPHRASE, or set IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP=true for local development/testing only"
        )
    }

    pub fn server_config(&self) -> RendezvousServerConfig {
        RendezvousServerConfig {
            bind_addr: self.bind_addr,
            public_url: self.public_url.clone(),
            relay_public_urls: self.relay_public_urls.clone(),
            mtls: self.mtls.clone(),
        }
    }
}

fn build_mtls_config(
    client_ca_cert_path: Option<String>,
    cert_path: Option<String>,
    key_path: Option<String>,
    failover_package: Option<&DecryptedRendezvousFailoverPackage>,
) -> Result<Option<RendezvousMtlsConfig>> {
    if let Some(package) = failover_package {
        if cert_path.is_some() || key_path.is_some() {
            bail!(
                "IRONMESH_RENDEZVOUS_TLS_CERT and IRONMESH_RENDEZVOUS_TLS_KEY cannot be combined with a failover package"
            );
        }

        let client_ca = if let Some(client_ca_cert_pem) = package.client_ca_cert_pem.as_ref() {
            RendezvousClientCa::InlinePem {
                cert_pem: client_ca_cert_pem.clone(),
            }
        } else if let Some(client_ca_cert_path) = client_ca_cert_path {
            RendezvousClientCa::File {
                cert_path: PathBuf::from(client_ca_cert_path),
            }
        } else {
            bail!(
                "legacy failover packages require IRONMESH_RENDEZVOUS_CLIENT_CA_CERT because they do not embed the client CA"
            );
        };

        return Ok(Some(RendezvousMtlsConfig {
            client_ca,
            server_identity: RendezvousServerTlsIdentity::InlinePem {
                cert_pem: package.cert_pem.clone(),
                key_pem: package.key_pem.clone(),
            },
        }));
    }

    match (client_ca_cert_path, cert_path, key_path) {
        (Some(client_ca_cert_path), Some(cert_path), Some(key_path)) => {
            Ok(Some(RendezvousMtlsConfig {
                client_ca: RendezvousClientCa::File {
                    cert_path: PathBuf::from(client_ca_cert_path),
                },
                server_identity: RendezvousServerTlsIdentity::Files {
                    cert_path: PathBuf::from(cert_path),
                    key_path: PathBuf::from(key_path),
                },
            }))
        }
        (None, None, None) => Ok(None),
        _ => bail!(
            "IRONMESH_RENDEZVOUS_CLIENT_CA_CERT, IRONMESH_RENDEZVOUS_TLS_CERT, and IRONMESH_RENDEZVOUS_TLS_KEY must be set together"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::failover::{
        build_legacy_test_failover_package_json, build_test_failover_package_json,
    };

    #[test]
    fn validate_startup_security_rejects_plain_http_by_default() {
        let config = RendezvousServiceConfig {
            bind_addr: "127.0.0.1:19090".parse().expect("bind addr should parse"),
            public_url: "http://127.0.0.1:19090".to_string(),
            relay_public_urls: vec!["http://127.0.0.1:19090".to_string()],
            mtls: None,
            allow_insecure_http: false,
            failover_package: None,
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
            failover_package: None,
        };

        config
            .validate_startup_security()
            .expect("explicit dev/test insecure HTTP should be allowed");
    }

    #[test]
    fn cli_config_parses_failover_args() {
        let cli = RendezvousServiceCliConfig::try_parse_from([
            "ironmesh-rendezvous-service",
            "--bind-addr=0.0.0.0:44042",
            "--failover-package",
            "/tmp/failover.json",
            "--failover-passphrase=swordfish",
        ])
        .expect("cli config should parse")
        .validate()
        .expect("cli config should validate");

        assert_eq!(
            cli.bind_addr,
            Some("0.0.0.0:44042".parse().expect("bind addr should parse"))
        );
        assert_eq!(
            cli.failover_package_path,
            Some(PathBuf::from("/tmp/failover.json"))
        );
        assert_eq!(cli.failover_passphrase.as_deref(), Some("swordfish"));
    }

    #[test]
    fn from_lookup_uses_failover_package_public_url_and_inline_identity() {
        let dir = std::env::temp_dir().join(format!(
            "ironmesh-rendezvous-config-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should create");
        let package_path = dir.join("failover.json");
        std::fs::write(
            &package_path,
            build_test_failover_package_json(
                "https://creax.de:44042",
                "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
                "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
                "correct horse battery staple",
            ),
        )
        .expect("test failover package should write");

        let cli = RendezvousServiceCliConfig {
            bind_addr: Some("0.0.0.0:44042".parse().expect("bind addr should parse")),
            failover_package_path: Some(package_path.clone()),
            failover_passphrase: Some("correct horse battery staple".to_string()),
        };
        let env = HashMap::<String, String>::new();
        let config = RendezvousServiceConfig::from_lookup(&cli, |key| env.get(key).cloned())
            .expect("config should load failover package");

        assert_eq!(config.public_url, "https://creax.de:44042");
        assert_eq!(
            config.relay_public_urls,
            vec!["https://creax.de:44042".to_string()]
        );
        assert_eq!(
            config
                .failover_package
                .as_ref()
                .expect("failover metadata should be present")
                .package_path,
            package_path
        );
        let mtls = config.mtls.expect("mTLS config should be present");
        match mtls.client_ca {
            RendezvousClientCa::InlinePem { cert_pem } => {
                assert!(cert_pem.contains("client-ca"));
            }
            RendezvousClientCa::File { .. } => {
                panic!("failover package should produce inline client CA material");
            }
        }
        match mtls.server_identity {
            RendezvousServerTlsIdentity::InlinePem { cert_pem, key_pem } => {
                assert!(cert_pem.contains("BEGIN CERTIFICATE"));
                assert!(key_pem.contains("BEGIN PRIVATE KEY"));
            }
            RendezvousServerTlsIdentity::Files { .. } => {
                panic!("failover package should produce inline TLS identity");
            }
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn from_lookup_rejects_failover_public_url_mismatch() {
        let dir = std::env::temp_dir().join(format!(
            "ironmesh-rendezvous-config-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should create");
        let package_path = dir.join("failover.json");
        std::fs::write(
            &package_path,
            build_test_failover_package_json(
                "https://creax.de:44042",
                "cert",
                "key",
                "correct horse battery staple",
            ),
        )
        .expect("test failover package should write");

        let cli = RendezvousServiceCliConfig {
            bind_addr: Some("0.0.0.0:44042".parse().expect("bind addr should parse")),
            failover_package_path: Some(package_path),
            failover_passphrase: Some("correct horse battery staple".to_string()),
        };
        let env = HashMap::from([(
            "IRONMESH_RENDEZVOUS_PUBLIC_URL".to_string(),
            "https://other.example:44042".to_string(),
        )]);
        let err = RendezvousServiceConfig::from_lookup(&cli, |key| env.get(key).cloned())
            .expect_err("mismatched public URL should fail");
        assert!(
            err.to_string()
                .contains("does not match failover package public_url")
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn from_lookup_legacy_failover_package_uses_env_client_ca() {
        let dir = std::env::temp_dir().join(format!(
            "ironmesh-rendezvous-config-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should create");
        let package_path = dir.join("failover.json");
        std::fs::write(
            &package_path,
            build_legacy_test_failover_package_json(
                "https://creax.de:44042",
                "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
                "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
                "correct horse battery staple",
            ),
        )
        .expect("test failover package should write");

        let cli = RendezvousServiceCliConfig {
            bind_addr: Some("0.0.0.0:44042".parse().expect("bind addr should parse")),
            failover_package_path: Some(package_path),
            failover_passphrase: Some("correct horse battery staple".to_string()),
        };
        let env = HashMap::from([(
            "IRONMESH_RENDEZVOUS_CLIENT_CA_CERT".to_string(),
            "/tmp/cluster-ca.pem".to_string(),
        )]);

        let config = RendezvousServiceConfig::from_lookup(&cli, |key| env.get(key).cloned())
            .expect("legacy failover package should still load");

        match config
            .mtls
            .expect("mTLS config should be present")
            .client_ca
        {
            RendezvousClientCa::File { cert_path } => {
                assert_eq!(cert_path, PathBuf::from("/tmp/cluster-ca.pem"));
            }
            RendezvousClientCa::InlinePem { .. } => {
                panic!("legacy failover packages should fall back to file-based client CA");
            }
        }

        let _ = std::fs::remove_dir_all(dir);
    }
}
