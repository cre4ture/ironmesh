#![cfg(windows)]

use anyhow::{Context, Result, anyhow};
use client_sdk::{
    BootstrapEndpoint, BootstrapEndpointUse, BootstrapTrustRoots, ConnectionBootstrap, RelayMode,
    normalize_server_base_url,
};
use reqwest::Url;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME: &str = ".ironmesh-connection.json";

#[derive(Debug, Clone)]
pub struct ResolvedConnectionConfig {
    pub cluster_id: Uuid,
    pub base_url: Url,
    pub server_ca_pem: Option<String>,
    pub pairing_token: Option<String>,
    pub force_reenroll: bool,
    pub device_id: Option<String>,
    pub device_label: Option<String>,
    pub bootstrap_path: PathBuf,
}

pub fn default_connection_bootstrap_path(sync_root_path: &Path) -> PathBuf {
    sync_root_path.join(DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME)
}

pub fn is_internal_connection_bootstrap_relative_path(path: &str) -> bool {
    let normalized = path.trim().trim_matches(['/', '\\']).replace('\\', "/");
    normalized == DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME
        || normalized.ends_with(&format!("/{DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME}"))
}

pub fn resolve_connection_config(
    sync_root_path: &Path,
    server_base_url: Option<&str>,
    server_ca_cert: Option<&Path>,
    bootstrap_file: Option<&Path>,
    pairing_token: Option<&str>,
    device_id: Option<&str>,
    device_label: Option<&str>,
) -> Result<ResolvedConnectionConfig> {
    let bootstrap_path = bootstrap_file
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_connection_bootstrap_path(sync_root_path));
    let direct_ca_pem = server_ca_cert
        .map(|path| {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read server CA certificate {}", path.display()))
        })
        .transpose()?;

    if bootstrap_path.exists() {
        let bundle = ConnectionBootstrap::from_path(&bootstrap_path)?;
        let bootstrap_pairing_token = normalize_optional(bundle.pairing_token.as_deref());
        let resolved = bundle.resolve_blocking()?;
        let base_url = Url::parse(&resolved.server_base_url)
            .with_context(|| format!("invalid resolved server URL {}", resolved.server_base_url))?;
        return Ok(ResolvedConnectionConfig {
            cluster_id: resolved.cluster_id,
            base_url,
            server_ca_pem: direct_ca_pem.or(resolved.server_ca_pem),
            pairing_token: normalize_optional(pairing_token).or(resolved.pairing_token),
            force_reenroll: bootstrap_pairing_token.is_some(),
            device_id: normalize_optional(device_id).or(resolved.device_id),
            device_label: normalize_optional(device_label).or(resolved.device_label),
            bootstrap_path,
        });
    }

    let base_url = normalize_server_base_url(server_base_url.ok_or_else(|| {
        anyhow!("server-base-url or bootstrap-file is required for first connection")
    })?)?;
    Ok(ResolvedConnectionConfig {
        cluster_id: Uuid::now_v7(),
        base_url,
        server_ca_pem: direct_ca_pem,
        pairing_token: normalize_optional(pairing_token),
        force_reenroll: false,
        device_id: normalize_optional(device_id),
        device_label: normalize_optional(device_label),
        bootstrap_path,
    })
}

pub fn persist_connection_config(
    path: &Path,
    cluster_id: Uuid,
    base_url: &Url,
    server_ca_pem: Option<&str>,
    device_id: Option<&str>,
    device_label: Option<&str>,
) -> Result<()> {
    let bundle = ConnectionBootstrap {
        version: 1,
        cluster_id,
        rendezvous_urls: vec![base_url.to_string()],
        rendezvous_mtls_required: false,
        direct_endpoints: vec![BootstrapEndpoint {
            url: base_url.to_string(),
            usage: Some(BootstrapEndpointUse::PublicApi),
        }],
        relay_mode: RelayMode::Fallback,
        trust_roots: BootstrapTrustRoots {
            cluster_ca_pem: normalize_optional(server_ca_pem),
            public_api_ca_pem: normalize_optional(server_ca_pem),
            rendezvous_ca_pem: normalize_optional(server_ca_pem),
        },
        pairing_token: None,
        device_label: normalize_optional(device_label),
        device_id: normalize_optional(device_id),
    };
    bundle.write_to_path(path)
}

fn normalize_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_connection_bootstrap_path_uses_sync_root() {
        let path = default_connection_bootstrap_path(Path::new("C:\\sync-root"));
        assert_eq!(
            path,
            Path::new("C:\\sync-root").join(".ironmesh-connection.json")
        );
    }

    #[test]
    fn internal_connection_bootstrap_path_detection_matches_nested_and_root_relative_paths() {
        assert!(is_internal_connection_bootstrap_relative_path(
            ".ironmesh-connection.json"
        ));
        assert!(is_internal_connection_bootstrap_relative_path(
            "nested/.ironmesh-connection.json"
        ));
        assert!(!is_internal_connection_bootstrap_relative_path(
            "nested/not-connection.json"
        ));
    }
}
