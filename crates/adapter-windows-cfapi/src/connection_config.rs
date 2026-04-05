#![cfg(windows)]

use crate::local_state::local_appdata_connection_bootstrap_path;
use anyhow::{Context, Result, anyhow};
use client_sdk::{
    BootstrapEndpoint, BootstrapEndpointUse, BootstrapTrustRoots, ClientIdentityMaterial,
    ConnectionBootstrap, IronMeshClient, RelayMode, normalize_server_base_url,
};
use reqwest::Url;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME: &str = ".ironmesh-connection.json";

#[derive(Debug, Clone)]
pub struct ResolvedConnectionConfig {
    pub cluster_id: Uuid,
    pub bootstrap: ConnectionBootstrap,
    pub connection_target: String,
    pub enrollment_base_url: Option<Url>,
    pub server_ca_pem: Option<String>,
    pub pairing_token: Option<String>,
    pub force_reenroll: bool,
    pub device_id: Option<String>,
    pub device_label: Option<String>,
    pub bootstrap_path: PathBuf,
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
    let bootstrap_path = discover_connection_bootstrap_path(sync_root_path, bootstrap_file);
    let direct_ca_pem = server_ca_cert
        .map(|path| {
            fs::read_to_string(path)
                .with_context(|| format!("failed to read server CA certificate {}", path.display()))
        })
        .transpose()?;

    if bootstrap_path.exists() {
        let mut bundle = ConnectionBootstrap::from_path(&bootstrap_path)?;
        if let Some(server_ca_pem) = direct_ca_pem.as_ref() {
            bundle.trust_roots.public_api_ca_pem = Some(server_ca_pem.clone());
        }
        let enrollment_base_url = bundle.candidate_endpoints()?.into_iter().next();
        return Ok(ResolvedConnectionConfig {
            cluster_id: bundle.cluster_id,
            connection_target: bundle.connection_target_label()?,
            enrollment_base_url,
            server_ca_pem: direct_ca_pem
                .clone()
                .or(bundle.trust_roots.public_api_ca_pem.clone()),
            pairing_token: normalize_optional(pairing_token).or(bundle.pairing_token.clone()),
            force_reenroll: false,
            device_id: normalize_optional(device_id).or(bundle.device_id.clone()),
            device_label: normalize_optional(device_label).or(bundle.device_label.clone()),
            bootstrap_path,
            bootstrap: bundle,
        });
    }

    let base_url = normalize_server_base_url(server_base_url.ok_or_else(|| {
        anyhow!("server-base-url or bootstrap-file is required for first connection")
    })?)?;
    let bootstrap = ConnectionBootstrap {
        version: 1,
        cluster_id: Uuid::now_v7(),
        rendezvous_urls: vec![base_url.to_string()],
        rendezvous_mtls_required: false,
        direct_endpoints: vec![BootstrapEndpoint {
            url: base_url.to_string(),
            usage: Some(BootstrapEndpointUse::PublicApi),
            node_id: None,
        }],
        relay_mode: RelayMode::Fallback,
        trust_roots: BootstrapTrustRoots {
            cluster_ca_pem: normalize_optional(direct_ca_pem.as_deref()),
            public_api_ca_pem: normalize_optional(direct_ca_pem.as_deref()),
            rendezvous_ca_pem: normalize_optional(direct_ca_pem.as_deref()),
        },
        pairing_token: normalize_optional(pairing_token),
        device_label: normalize_optional(device_label),
        device_id: normalize_optional(device_id),
    };
    Ok(ResolvedConnectionConfig {
        cluster_id: bootstrap.cluster_id,
        bootstrap,
        connection_target: base_url.to_string(),
        enrollment_base_url: Some(base_url),
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
    bootstrap: &ConnectionBootstrap,
    server_ca_pem: Option<&str>,
    device_id: Option<&str>,
    device_label: Option<&str>,
) -> Result<()> {
    let mut bundle = bootstrap.clone();
    if let Some(server_ca_pem) = normalize_optional(server_ca_pem) {
        bundle.trust_roots.public_api_ca_pem = Some(server_ca_pem);
    }
    bundle.pairing_token = None;
    if let Some(device_id) = normalize_optional(device_id) {
        bundle.device_id = Some(device_id);
    }
    if let Some(device_label) = normalize_optional(device_label) {
        bundle.device_label = Some(device_label);
    }
    bundle.write_to_path(path)
}

pub fn persist_local_appdata_connection_config(
    sync_root_path: &Path,
    bootstrap: &ConnectionBootstrap,
    server_ca_pem: Option<&str>,
    device_id: Option<&str>,
    device_label: Option<&str>,
) -> Result<()> {
    persist_connection_config(
        &local_appdata_connection_bootstrap_path(sync_root_path),
        bootstrap,
        server_ca_pem,
        device_id,
        device_label,
    )
}

fn discover_connection_bootstrap_path(
    sync_root_path: &Path,
    bootstrap_file: Option<&Path>,
) -> PathBuf {
    if let Some(path) = bootstrap_file {
        return path.to_path_buf();
    }

    local_appdata_connection_bootstrap_path(sync_root_path)
}

impl ResolvedConnectionConfig {
    pub fn build_client(
        &self,
        client_identity: Option<&ClientIdentityMaterial>,
    ) -> Result<IronMeshClient> {
        match client_identity {
            Some(identity) => self.bootstrap.build_client_with_identity(identity),
            None => self.bootstrap.build_client(),
        }
    }
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
    fn resolve_connection_config_without_existing_bootstrap_targets_local_appdata_path() {
        let sync_root = std::env::temp_dir().join(format!(
            "ironmesh-sync-root-local-appdata-bootstrap-{}",
            Uuid::now_v7()
        ));
        std::fs::create_dir_all(&sync_root).expect("sync root should exist");

        let resolved = resolve_connection_config(
            &sync_root,
            Some("https://public.example"),
            None,
            None,
            None,
            None,
            None,
        )
        .expect("resolve should succeed");

        assert_eq!(
            resolved.bootstrap_path,
            local_appdata_connection_bootstrap_path(&sync_root)
        );

        let _ = std::fs::remove_dir_all(sync_root);
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

    #[test]
    fn persist_connection_config_preserves_rendezvous_bootstrap_metadata() {
        let path = std::env::temp_dir().join(format!(
            "ironmesh-windows-bootstrap-{}.json",
            Uuid::now_v7()
        ));
        let bootstrap = ConnectionBootstrap {
            version: 1,
            cluster_id: Uuid::now_v7(),
            rendezvous_urls: vec!["https://rendezvous.example".to_string()],
            rendezvous_mtls_required: true,
            direct_endpoints: vec![BootstrapEndpoint {
                url: "https://public.example".to_string(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: Some(Uuid::new_v4()),
            }],
            relay_mode: RelayMode::Required,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: Some("cluster-ca".to_string()),
                public_api_ca_pem: Some("public-ca".to_string()),
                rendezvous_ca_pem: Some("rendezvous-ca".to_string()),
            },
            pairing_token: Some("pairing".to_string()),
            device_label: Some("old-label".to_string()),
            device_id: Some(Uuid::now_v7().to_string()),
        };

        persist_connection_config(
            &path,
            &bootstrap,
            Some("override-ca"),
            Some("019cf235-6922-7902-9221-0df1a3192c62"),
            Some("new-label"),
        )
        .expect("persist should succeed");

        let persisted = ConnectionBootstrap::from_path(&path).expect("bootstrap should reload");
        assert_eq!(persisted.cluster_id, bootstrap.cluster_id);
        assert_eq!(persisted.rendezvous_urls, bootstrap.rendezvous_urls);
        assert!(persisted.rendezvous_mtls_required);
        assert_eq!(persisted.relay_mode, RelayMode::Required);
        assert_eq!(persisted.direct_endpoints, bootstrap.direct_endpoints);
        assert_eq!(
            persisted.trust_roots.public_api_ca_pem.as_deref(),
            Some("override-ca")
        );
        assert_eq!(
            persisted.trust_roots.rendezvous_ca_pem.as_deref(),
            Some("rendezvous-ca")
        );
        assert_eq!(persisted.pairing_token, None);
        assert_eq!(persisted.device_label.as_deref(), Some("new-label"));
        assert_eq!(
            persisted.device_id.as_deref(),
            Some("019cf235-6922-7902-9221-0df1a3192c62")
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn resolve_connection_config_keeps_relay_bootstrap_without_direct_probe() {
        let sync_root = std::env::temp_dir().join(format!("ironmesh-sync-root-{}", Uuid::now_v7()));
        std::fs::create_dir_all(&sync_root).expect("sync root should exist");
        let bootstrap_path = local_appdata_connection_bootstrap_path(&sync_root);
        let bootstrap = ConnectionBootstrap {
            version: 1,
            cluster_id: Uuid::now_v7(),
            rendezvous_urls: vec!["https://rendezvous.example".to_string()],
            rendezvous_mtls_required: false,
            direct_endpoints: vec![BootstrapEndpoint {
                url: "https://public.invalid".to_string(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: Some(Uuid::new_v4()),
            }],
            relay_mode: RelayMode::Required,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: None,
                public_api_ca_pem: None,
                rendezvous_ca_pem: Some("rendezvous-ca".to_string()),
            },
            pairing_token: None,
            device_label: Some("relay-device".to_string()),
            device_id: Some(Uuid::now_v7().to_string()),
        };
        bootstrap
            .write_to_path(&bootstrap_path)
            .expect("bootstrap should persist");

        let resolved = resolve_connection_config(
            &sync_root,
            None,
            None,
            Some(&bootstrap_path),
            None,
            None,
            None,
        )
        .expect("resolve should succeed");

        assert_eq!(resolved.cluster_id, bootstrap.cluster_id);
        assert_eq!(resolved.bootstrap.relay_mode, RelayMode::Required);
        assert_eq!(
            resolved.enrollment_base_url.as_ref().map(Url::as_str),
            Some("https://public.invalid/")
        );
        assert!(resolved.connection_target.starts_with("relay://"));

        let _ = std::fs::remove_file(bootstrap_path);
        let _ = std::fs::remove_dir_all(sync_root);
    }

    #[test]
    fn resolve_connection_config_does_not_force_reenroll_for_bootstrap_pairing_token() {
        let sync_root = std::env::temp_dir().join(format!(
            "ironmesh-sync-root-no-force-reenroll-{}",
            Uuid::now_v7()
        ));
        std::fs::create_dir_all(&sync_root).expect("sync root should exist");
        let bootstrap_path = local_appdata_connection_bootstrap_path(&sync_root);
        let bootstrap = ConnectionBootstrap {
            version: 1,
            cluster_id: Uuid::now_v7(),
            rendezvous_urls: vec!["https://rendezvous.example".to_string()],
            rendezvous_mtls_required: false,
            direct_endpoints: vec![BootstrapEndpoint {
                url: "https://public.example".to_string(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: Some(Uuid::new_v4()),
            }],
            relay_mode: RelayMode::Fallback,
            trust_roots: BootstrapTrustRoots {
                cluster_ca_pem: None,
                public_api_ca_pem: None,
                rendezvous_ca_pem: None,
            },
            pairing_token: Some("pairing-token".to_string()),
            device_label: Some("existing-device".to_string()),
            device_id: Some(Uuid::now_v7().to_string()),
        };
        bootstrap
            .write_to_path(&bootstrap_path)
            .expect("bootstrap should persist");

        let resolved = resolve_connection_config(
            &sync_root,
            None,
            None,
            Some(&bootstrap_path),
            None,
            None,
            None,
        )
        .expect("resolve should succeed");

        assert_eq!(resolved.pairing_token.as_deref(), Some("pairing-token"));
        assert!(
            !resolved.force_reenroll,
            "bootstrap startup should keep existing sibling identities instead of forcing reenrollment"
        );

        let _ = std::fs::remove_file(bootstrap_path);
        let _ = std::fs::remove_dir_all(sync_root);
    }

    #[test]
    fn resolve_connection_config_does_not_read_legacy_sync_root_bootstrap_without_explicit_path() {
        let sync_root = std::env::temp_dir().join(format!(
            "ironmesh-sync-root-legacy-bootstrap-{}",
            Uuid::now_v7()
        ));
        std::fs::create_dir_all(&sync_root).expect("sync root should exist");
        let legacy_bootstrap_path = sync_root.join(DEFAULT_CONNECTION_BOOTSTRAP_FILE_NAME);
        let bootstrap = ConnectionBootstrap {
            version: 1,
            cluster_id: Uuid::now_v7(),
            rendezvous_urls: vec!["https://rendezvous.example".to_string()],
            rendezvous_mtls_required: false,
            direct_endpoints: vec![BootstrapEndpoint {
                url: "https://public.example".to_string(),
                usage: Some(BootstrapEndpointUse::PublicApi),
                node_id: Some(Uuid::new_v4()),
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
        };
        bootstrap
            .write_to_path(&legacy_bootstrap_path)
            .expect("legacy bootstrap should persist");

        let error = resolve_connection_config(&sync_root, None, None, None, None, None, None)
            .expect_err("legacy sync-root bootstrap should no longer be used implicitly");
        assert!(
            error
                .to_string()
                .contains("server-base-url or bootstrap-file is required for first connection")
        );

        let _ = std::fs::remove_file(legacy_bootstrap_path);
        let _ = std::fs::remove_dir_all(sync_root);
    }
}
