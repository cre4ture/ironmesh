use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use common::{ClusterId, NodeId};
pub use rendezvous_server::{
    ClusterCaRegistry, GlobalClusterRegistrationConfig, RendezvousClientCa, RendezvousMtlsConfig,
    RendezvousServerConfig, RendezvousServerTlsIdentity,
};

use crate::failover::{
    DecryptedRendezvousFailoverPackage, load_rendezvous_failover_package, normalize_public_url,
};

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_INFO: &str = git_version::git_version!(
    prefix = "Build revision: ",
    fallback = "Build revision: unknown",
    args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]
);
const LONG_VERSION: &str = git_version::git_version!(
    prefix = concat!(env!("CARGO_PKG_VERSION"), "\nBuild revision: "),
    fallback = concat!(env!("CARGO_PKG_VERSION"), "\nBuild revision: unknown"),
    args = ["--tags", "--always", "--dirty=-dirty", "--abbrev=12"]
);

#[derive(Debug, Clone, Default, PartialEq, Eq, Parser)]
#[command(name = "ironmesh-rendezvous-service")]
#[command(about = "Standalone BerryKeep rendezvous plus relay service")]
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
    pub target_node_id: Option<NodeId>,
}

#[derive(Debug, Clone)]
pub struct RendezvousServiceConfig {
    pub bind_addr: SocketAddr,
    pub public_url: String,
    pub relay_public_urls: Vec<String>,
    pub peer_rendezvous_urls: Vec<String>,
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
        let peer_rendezvous_urls = lookup_env("IRONMESH_RENDEZVOUS_PEER_URLS")
            .map(|value| {
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            })
            .filter(|urls| !urls.is_empty())
            .unwrap_or_default();

        let client_ca_cert_path = lookup_env("IRONMESH_RENDEZVOUS_CLIENT_CA_CERT");
        let cert_path = lookup_env("IRONMESH_RENDEZVOUS_TLS_CERT");
        let key_path = lookup_env("IRONMESH_RENDEZVOUS_TLS_KEY");
        let allow_insecure_http = lookup_env("IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP")
            .map(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false);
        let global_registration_enabled =
            lookup_env("IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_ENABLED")
                .map(|value| {
                    parse_bool_env("IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_ENABLED", &value)
                })
                .transpose()?
                .unwrap_or(false);
        let global_registry_path = lookup_env("IRONMESH_RENDEZVOUS_GLOBAL_CLUSTER_REGISTRY");
        let global_admin_token = lookup_env("IRONMESH_RENDEZVOUS_GLOBAL_ADMIN_TOKEN");
        let global_rate_limit =
            lookup_env("IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_RATE_LIMIT_PER_MINUTE");
        let global_challenge_ttl = lookup_env("IRONMESH_RENDEZVOUS_GLOBAL_CHALLENGE_TTL_SECS");
        let global_max_pending = lookup_env("IRONMESH_RENDEZVOUS_GLOBAL_MAX_PENDING_CHALLENGES");
        let global_settings_present = global_registration_enabled
            || global_registry_path.is_some()
            || global_admin_token.is_some()
            || global_rate_limit.is_some()
            || global_challenge_ttl.is_some()
            || global_max_pending.is_some();

        let mtls = if global_settings_present {
            build_global_mtls_config(
                global_registration_enabled,
                global_registry_path,
                global_admin_token,
                global_rate_limit,
                global_challenge_ttl,
                global_max_pending,
                client_ca_cert_path,
                cert_path,
                key_path,
                failover_package.as_ref(),
                allow_insecure_http,
                &public_url,
                &relay_public_urls,
            )?
        } else {
            build_mtls_config(
                client_ca_cert_path,
                cert_path,
                key_path,
                failover_package.as_ref(),
            )?
        };

        let config = Self {
            bind_addr,
            public_url,
            relay_public_urls,
            peer_rendezvous_urls,
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
        if let Some(RendezvousMtlsConfig {
            client_ca: RendezvousClientCa::Global { .. },
            ..
        }) = self.mtls.as_ref()
        {
            if self.allow_insecure_http {
                bail!(
                    "IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP cannot be enabled for global rendezvous registration"
                );
            }
            if self.failover_package.is_some() {
                bail!("global rendezvous registration cannot use a failover package");
            }
            if !is_https_url(&self.public_url)
                || self.relay_public_urls.iter().any(|url| !is_https_url(url))
            {
                bail!("global rendezvous registration requires HTTPS public and relay URLs");
            }
            return Ok(());
        }

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
            peer_rendezvous_urls: self.peer_rendezvous_urls.clone(),
            mtls: self.mtls.clone(),
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn build_global_mtls_config(
    enabled: bool,
    registry_path: Option<String>,
    admin_token: Option<String>,
    rate_limit_per_minute: Option<String>,
    challenge_ttl_secs: Option<String>,
    max_pending_challenges: Option<String>,
    client_ca_cert_path: Option<String>,
    cert_path: Option<String>,
    key_path: Option<String>,
    failover_package: Option<&DecryptedRendezvousFailoverPackage>,
    allow_insecure_http: bool,
    public_url: &str,
    relay_public_urls: &[String],
) -> Result<Option<RendezvousMtlsConfig>> {
    if !enabled {
        bail!(
            "global rendezvous settings require IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_ENABLED=true"
        );
    }
    if client_ca_cert_path.is_some() {
        bail!(
            "IRONMESH_RENDEZVOUS_CLIENT_CA_CERT cannot be combined with global rendezvous registration"
        );
    }
    if failover_package.is_some() {
        bail!("global rendezvous registration cannot use a failover package");
    }
    if allow_insecure_http {
        bail!(
            "IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP cannot be enabled for global rendezvous registration"
        );
    }
    if !is_https_url(public_url) || relay_public_urls.iter().any(|url| !is_https_url(url)) {
        bail!("global rendezvous registration requires HTTPS public and relay URLs");
    }

    let registry_path = registry_path
        .filter(|value| !value.trim().is_empty())
        .context(
            "global rendezvous registration requires IRONMESH_RENDEZVOUS_GLOBAL_CLUSTER_REGISTRY",
        )?;
    let admin_token = admin_token
        .filter(|value| !value.trim().is_empty())
        .context("global rendezvous registration requires a non-empty IRONMESH_RENDEZVOUS_GLOBAL_ADMIN_TOKEN")?;
    let rate_limit_per_minute = parse_positive_env_u32(
        "IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_RATE_LIMIT_PER_MINUTE",
        rate_limit_per_minute,
        10,
    )?;
    let challenge_ttl_secs = parse_positive_env_u64(
        "IRONMESH_RENDEZVOUS_GLOBAL_CHALLENGE_TTL_SECS",
        challenge_ttl_secs,
        300,
    )?;
    let max_pending_challenges = parse_positive_env_usize(
        "IRONMESH_RENDEZVOUS_GLOBAL_MAX_PENDING_CHALLENGES",
        max_pending_challenges,
        1_024,
    )?;
    let (cert_path, key_path) = match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => (cert_path, key_path),
        _ => bail!(
            "global rendezvous registration requires IRONMESH_RENDEZVOUS_TLS_CERT and IRONMESH_RENDEZVOUS_TLS_KEY"
        ),
    };

    Ok(Some(RendezvousMtlsConfig {
        client_ca: RendezvousClientCa::Global {
            cluster_registry: ClusterCaRegistry::open(PathBuf::from(registry_path))?,
            registration: GlobalClusterRegistrationConfig {
                admin_token,
                rate_limit_per_minute,
                challenge_ttl: std::time::Duration::from_secs(challenge_ttl_secs),
                max_pending_challenges,
            },
        },
        server_identity: RendezvousServerTlsIdentity::Files {
            cert_path: PathBuf::from(cert_path),
            key_path: PathBuf::from(key_path),
        },
    }))
}

fn parse_bool_env(name: &str, value: &str) -> Result<bool> {
    match value.trim() {
        "1" | "true" | "TRUE" | "yes" | "YES" => Ok(true),
        "0" | "false" | "FALSE" | "no" | "NO" => Ok(false),
        _ => bail!("invalid {name}; expected true or false"),
    }
}

fn parse_positive_env_u32(name: &str, value: Option<String>, default: u32) -> Result<u32> {
    let value = value
        .map(|value| value.parse().with_context(|| format!("invalid {name}")))
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        bail!("{name} must be greater than zero");
    }
    Ok(value)
}

fn parse_positive_env_u64(name: &str, value: Option<String>, default: u64) -> Result<u64> {
    let value = value
        .map(|value| value.parse().with_context(|| format!("invalid {name}")))
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        bail!("{name} must be greater than zero");
    }
    Ok(value)
}

fn parse_positive_env_usize(name: &str, value: Option<String>, default: usize) -> Result<usize> {
    let value = value
        .map(|value| value.parse().with_context(|| format!("invalid {name}")))
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        bail!("{name} must be greater than zero");
    }
    Ok(value)
}

fn is_https_url(value: &str) -> bool {
    value
        .trim()
        .parse::<axum::http::Uri>()
        .ok()
        .is_some_and(|uri| {
            uri.scheme_str()
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"))
                && uri.authority().is_some()
        })
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

    fn with_standalone_service_target(package_json: &str) -> String {
        let mut value = serde_json::from_str::<serde_json::Value>(package_json)
            .expect("test failover package JSON should parse");
        value
            .as_object_mut()
            .expect("test failover package JSON should be an object")
            .insert(
                "deployment_target".to_string(),
                serde_json::Value::String("standalone_service".to_string()),
            );
        serde_json::to_string(&value).expect("test failover package JSON should serialize")
    }

    #[test]
    fn validate_startup_security_rejects_plain_http_by_default() {
        let config = RendezvousServiceConfig {
            bind_addr: "127.0.0.1:19090".parse().expect("bind addr should parse"),
            public_url: "http://127.0.0.1:19090".to_string(),
            relay_public_urls: vec!["http://127.0.0.1:19090".to_string()],
            peer_rendezvous_urls: Vec::new(),
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
            peer_rendezvous_urls: Vec::new(),
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
        assert!(config.peer_rendezvous_urls.is_empty());
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
            RendezvousClientCa::Global { .. } => {
                panic!("failover package must not configure global client trust");
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
    fn from_lookup_accepts_standalone_labeled_failover_package() {
        let dir = std::env::temp_dir().join(format!(
            "ironmesh-rendezvous-config-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should create");
        let package_path = dir.join("failover.json");
        std::fs::write(
            &package_path,
            with_standalone_service_target(&build_test_failover_package_json(
                "https://creax.de:44042",
                "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
                "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
                "correct horse battery staple",
            )),
        )
        .expect("test failover package should write");

        let cli = RendezvousServiceCliConfig {
            bind_addr: Some("0.0.0.0:44042".parse().expect("bind addr should parse")),
            failover_package_path: Some(package_path),
            failover_passphrase: Some("correct horse battery staple".to_string()),
        };
        let env = HashMap::<String, String>::new();
        let config = RendezvousServiceConfig::from_lookup(&cli, |key| env.get(key).cloned())
            .expect("standalone-labeled failover package should load");

        assert_eq!(config.public_url, "https://creax.de:44042");
        assert_eq!(
            config.relay_public_urls,
            vec!["https://creax.de:44042".to_string()]
        );
        assert!(config.peer_rendezvous_urls.is_empty());

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
            with_standalone_service_target(&build_test_failover_package_json(
                "https://creax.de:44042",
                "cert",
                "key",
                "correct horse battery staple",
            )),
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
            with_standalone_service_target(&build_legacy_test_failover_package_json(
                "https://creax.de:44042",
                "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n",
                "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n",
                "correct horse battery staple",
            )),
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
            RendezvousClientCa::Global { .. } => {
                panic!("legacy failover package must not configure global client trust");
            }
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn from_lookup_parses_peer_rendezvous_urls() {
        let cli = RendezvousServiceCliConfig::default();
        let env = HashMap::from([
            (
                "IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP".to_string(),
                "true".to_string(),
            ),
            (
                "IRONMESH_RENDEZVOUS_PEER_URLS".to_string(),
                " https://peer-a.example ,https://peer-b.example/ ".to_string(),
            ),
        ]);

        let config = RendezvousServiceConfig::from_lookup(&cli, |key| env.get(key).cloned())
            .expect("peer rendezvous URLs should parse");

        assert_eq!(
            config.peer_rendezvous_urls,
            vec![
                "https://peer-a.example".to_string(),
                "https://peer-b.example/".to_string()
            ]
        );
    }

    #[test]
    fn from_lookup_uses_the_exact_global_registration_rate_limit_env_name() {
        let registry_path = std::env::temp_dir().join(format!(
            "ironmesh-global-rendezvous-config-{}.json",
            uuid::Uuid::now_v7()
        ));
        let cli = RendezvousServiceCliConfig::default();
        let env = HashMap::from([
            (
                "IRONMESH_RENDEZVOUS_PUBLIC_URL".to_string(),
                "https://rendezvous.example".to_string(),
            ),
            (
                "IRONMESH_RENDEZVOUS_TLS_CERT".to_string(),
                "/tmp/rendezvous.pem".to_string(),
            ),
            (
                "IRONMESH_RENDEZVOUS_TLS_KEY".to_string(),
                "/tmp/rendezvous.key".to_string(),
            ),
            (
                "IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_ENABLED".to_string(),
                "true".to_string(),
            ),
            (
                "IRONMESH_RENDEZVOUS_GLOBAL_CLUSTER_REGISTRY".to_string(),
                registry_path.display().to_string(),
            ),
            (
                "IRONMESH_RENDEZVOUS_GLOBAL_ADMIN_TOKEN".to_string(),
                "operator-secret".to_string(),
            ),
            (
                "IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_RATE_LIMIT_PER_MINUTE".to_string(),
                "7".to_string(),
            ),
            (
                "IRONMESH_RENDEZVOUS_GLOBAL_RATE_LIMIT_PER_MINUTE".to_string(),
                "0".to_string(),
            ),
        ]);

        let config = RendezvousServiceConfig::from_lookup(&cli, |key| env.get(key).cloned())
            .expect("global registration config should load");
        let mtls = config.mtls.expect("global mode should configure TLS");
        match mtls.client_ca {
            RendezvousClientCa::Global {
                cluster_registry,
                registration,
            } => {
                assert_eq!(cluster_registry.path(), registry_path.as_path());
                assert_eq!(registration.rate_limit_per_minute, 7);
                assert_eq!(
                    registration.challenge_ttl,
                    std::time::Duration::from_secs(300)
                );
                assert_eq!(registration.max_pending_challenges, 1_024);
                assert_eq!(registration.admin_token, "operator-secret");
            }
            _ => panic!("global configuration must not use a static client CA"),
        }

        let mut wrong_name_only = env;
        wrong_name_only.remove("IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_RATE_LIMIT_PER_MINUTE");
        let config =
            RendezvousServiceConfig::from_lookup(&cli, |key| wrong_name_only.get(key).cloned())
                .expect("the obsolete rate limit variable must not be used as an alias");
        let mtls = config.mtls.expect("global mode should configure TLS");
        match mtls.client_ca {
            RendezvousClientCa::Global { registration, .. } => {
                assert_eq!(registration.rate_limit_per_minute, 10);
            }
            _ => panic!("global configuration must not use a static client CA"),
        }
    }

    #[test]
    fn global_registration_rate_limit_validation_names_the_public_contract() {
        let error = parse_positive_env_u32(
            "IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_RATE_LIMIT_PER_MINUTE",
            Some("0".to_string()),
            10,
        )
        .expect_err("zero global registration rate limit must be rejected");
        assert_eq!(
            error.to_string(),
            "IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_RATE_LIMIT_PER_MINUTE must be greater than zero"
        );
    }

    #[test]
    fn from_lookup_rejects_insecure_or_static_ca_global_registration() {
        let registry_path = std::env::temp_dir().join(format!(
            "ironmesh-global-rendezvous-config-{}.json",
            uuid::Uuid::now_v7()
        ));
        let cli = RendezvousServiceCliConfig::default();
        let base = [
            (
                "IRONMESH_RENDEZVOUS_PUBLIC_URL".to_string(),
                "https://rendezvous.example".to_string(),
            ),
            (
                "IRONMESH_RENDEZVOUS_TLS_CERT".to_string(),
                "/tmp/rendezvous.pem".to_string(),
            ),
            (
                "IRONMESH_RENDEZVOUS_TLS_KEY".to_string(),
                "/tmp/rendezvous.key".to_string(),
            ),
            (
                "IRONMESH_RENDEZVOUS_GLOBAL_REGISTRATION_ENABLED".to_string(),
                "true".to_string(),
            ),
            (
                "IRONMESH_RENDEZVOUS_GLOBAL_CLUSTER_REGISTRY".to_string(),
                registry_path.display().to_string(),
            ),
            (
                "IRONMESH_RENDEZVOUS_GLOBAL_ADMIN_TOKEN".to_string(),
                "operator-secret".to_string(),
            ),
        ];

        let mut insecure = HashMap::from(base.clone());
        insecure.insert(
            "IRONMESH_RENDEZVOUS_ALLOW_INSECURE_HTTP".to_string(),
            "true".to_string(),
        );
        let error = RendezvousServiceConfig::from_lookup(&cli, |key| insecure.get(key).cloned())
            .expect_err("global registration must reject insecure HTTP override");
        assert!(error.to_string().contains("ALLOW_INSECURE_HTTP"));

        let mut static_ca = HashMap::from(base);
        static_ca.insert(
            "IRONMESH_RENDEZVOUS_CLIENT_CA_CERT".to_string(),
            "/tmp/client-ca.pem".to_string(),
        );
        let error = RendezvousServiceConfig::from_lookup(&cli, |key| static_ca.get(key).cloned())
            .expect_err("global registration must reject a static client CA");
        assert!(error.to_string().contains("CLIENT_CA_CERT"));
    }
}
