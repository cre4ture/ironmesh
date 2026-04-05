#![cfg(windows)]

use crate::local_state::local_appdata_client_identity_path;
use anyhow::{Context, Result, bail};
use client_sdk::{
    ClientIdentityMaterial, DeviceEnrollmentRequest, enroll_device_blocking_from_pem,
};
use reqwest::Url;
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const DEFAULT_CLIENT_IDENTITY_FILE_NAME: &str = ".ironmesh-client-identity.json";

#[derive(Debug, Clone)]
pub struct ClientEnrollmentOptions {
    pub cluster_id: Uuid,
    pub pairing_token: Option<String>,
    pub force_reenroll: bool,
    pub device_id: Option<String>,
    pub device_label: Option<String>,
    pub client_identity_file: Option<PathBuf>,
    pub server_ca_pem: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PersistedClientIdentityDiscovery {
    pub candidate_paths: Vec<PathBuf>,
    pub selected_path: Option<PathBuf>,
}

pub fn resolve_or_enroll_client_identity(
    base_url: Option<&Url>,
    sync_root_path: &Path,
    bootstrap_file: Option<&Path>,
    options: &ClientEnrollmentOptions,
) -> Result<Option<ClientIdentityMaterial>> {
    if !options.force_reenroll
        && let Some(identity) = load_persisted_client_identity(
            sync_root_path,
            bootstrap_file,
            options.client_identity_file.as_deref(),
        )?
    {
        return Ok(Some(identity));
    }

    let pairing_token = options
        .pairing_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(pairing_token) = pairing_token else {
        return Ok(None);
    };

    let base_url = base_url.ok_or_else(|| {
        anyhow::anyhow!(
            "device enrollment requires a reachable direct public API endpoint in the connection bootstrap"
        )
    })?;
    let identity = enroll_client_identity(base_url, pairing_token, options)?;
    if let Some(identity_file) = options.client_identity_file.as_deref() {
        persist_client_identity(identity_file, &identity)?;
    }
    persist_local_appdata_client_identity(sync_root_path, &identity)?;
    Ok(Some(identity))
}

pub fn load_persisted_client_identity(
    sync_root_path: &Path,
    bootstrap_file: Option<&Path>,
    client_identity_file: Option<&Path>,
) -> Result<Option<ClientIdentityMaterial>> {
    let discovery = inspect_persisted_client_identity_paths(
        sync_root_path,
        bootstrap_file,
        client_identity_file,
    );
    if let Some(identity_file) = discovery.selected_path {
        return load_client_identity(&identity_file).map(Some);
    }

    Ok(None)
}

pub fn inspect_persisted_client_identity_paths(
    sync_root_path: &Path,
    bootstrap_file: Option<&Path>,
    client_identity_file: Option<&Path>,
) -> PersistedClientIdentityDiscovery {
    let candidate_paths =
        candidate_client_identity_paths(sync_root_path, bootstrap_file, client_identity_file);
    let selected_path = candidate_paths.iter().find(|path| path.exists()).cloned();
    PersistedClientIdentityDiscovery {
        candidate_paths,
        selected_path,
    }
}

fn sibling_client_identity_path(bootstrap_path: &Path) -> PathBuf {
    if let Some(stem) = bootstrap_path.file_stem() {
        let mut file_name = stem.to_os_string();
        file_name.push(".client-identity.json");
        return bootstrap_path.with_file_name(file_name);
    }

    bootstrap_path.with_file_name("ironmesh-client-identity.json")
}

pub fn is_internal_client_identity_relative_path(path: &str) -> bool {
    let normalized = path.trim().trim_matches(['/', '\\']).replace('\\', "/");
    normalized == DEFAULT_CLIENT_IDENTITY_FILE_NAME
        || normalized.ends_with(&format!("/{DEFAULT_CLIENT_IDENTITY_FILE_NAME}"))
}

fn enroll_client_identity(
    base_url: &Url,
    pairing_token: &str,
    options: &ClientEnrollmentOptions,
) -> Result<ClientIdentityMaterial> {
    let requested_device_id = normalize_optional(options.device_id.as_deref())
        .map(|value| {
            value
                .parse()
                .with_context(|| format!("invalid device_id {}", value))
        })
        .transpose()?;
    let label = normalize_optional(options.device_label.as_deref());
    let mut identity =
        ClientIdentityMaterial::generate(options.cluster_id, requested_device_id, label.clone())?;
    identity.public_key_pem = identity.public_key_pem.trim().to_string();
    let enrolled = enroll_device_blocking_from_pem(
        base_url,
        options.server_ca_pem.as_deref(),
        &DeviceEnrollmentRequest {
            cluster_id: options.cluster_id,
            pairing_token: pairing_token.to_string(),
            device_id: Some(identity.device_id.to_string()),
            label,
            public_key_pem: identity.public_key_pem.clone(),
        },
    )?;
    identity.apply_issued_identity(&enrolled.issued_identity()?)?;
    identity.rendezvous_client_identity_pem = enrolled.rendezvous_client_identity_pem;

    Ok(identity)
}

fn normalize_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn load_client_identity(path: &Path) -> Result<ClientIdentityMaterial> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read client identity file {}", path.display()))?;
    let identity = serde_json::from_str::<ClientIdentityMaterial>(&raw)
        .with_context(|| format!("failed to parse client identity file {}", path.display()))?;
    validate_client_identity(&identity, path)?;
    Ok(identity)
}

fn persist_client_identity(path: &Path, identity: &ClientIdentityMaterial) -> Result<()> {
    validate_client_identity(identity, path)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create client identity directory {}",
                parent.display()
            )
        })?;
    }
    let payload = identity
        .to_json_pretty()
        .context("failed to serialize client identity")?;
    fs::write(path, payload)
        .with_context(|| format!("failed to write client identity file {}", path.display()))
}

pub fn persist_local_appdata_client_identity(
    sync_root_path: &Path,
    identity: &ClientIdentityMaterial,
) -> Result<()> {
    persist_client_identity(
        &local_appdata_client_identity_path(sync_root_path),
        identity,
    )
}

fn candidate_client_identity_paths(
    sync_root_path: &Path,
    bootstrap_file: Option<&Path>,
    client_identity_file: Option<&Path>,
) -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    push_unique_path(&mut candidates, client_identity_file.map(Path::to_path_buf));
    push_unique_path(
        &mut candidates,
        Some(local_appdata_client_identity_path(sync_root_path)),
    );
    push_unique_path(
        &mut candidates,
        bootstrap_file.map(sibling_client_identity_path),
    );

    candidates
}

fn push_unique_path(candidates: &mut Vec<PathBuf>, candidate: Option<PathBuf>) {
    let Some(candidate) = candidate else {
        return;
    };
    if candidates.iter().any(|existing| existing == &candidate) {
        return;
    }
    candidates.push(candidate);
}

fn validate_client_identity(identity: &ClientIdentityMaterial, path: &Path) -> Result<()> {
    identity
        .validate()
        .with_context(|| format!("invalid client identity file {}", path.display()))?;
    if identity
        .credential_pem
        .as_deref()
        .is_none_or(|credential| credential.trim().is_empty())
    {
        bail!(
            "client identity file {} is missing credential_pem",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sibling_client_identity_path_uses_bootstrap_sibling_when_bootstrap_file_is_provided() {
        let bootstrap_path = Path::new("C:\\config\\ironmesh-client-bootstrap.json");
        let path = sibling_client_identity_path(bootstrap_path);
        assert_eq!(
            path,
            Path::new("C:\\config\\ironmesh-client-bootstrap.client-identity.json")
        );
    }

    #[test]
    fn internal_client_identity_path_detection_matches_nested_and_root_relative_paths() {
        assert!(is_internal_client_identity_relative_path(
            ".ironmesh-client-identity.json"
        ));
        assert!(is_internal_client_identity_relative_path(
            "nested/.ironmesh-client-identity.json"
        ));
        assert!(!is_internal_client_identity_relative_path(
            "nested/not-client-identity.json"
        ));
    }

    #[test]
    fn persisted_client_identity_round_trips_without_legacy_token_field() {
        let path =
            std::env::temp_dir().join(format!("ironmesh-client-identity-{}.json", Uuid::now_v7()));
        let mut identity = ClientIdentityMaterial::generate(
            Uuid::now_v7(),
            None,
            Some("windows-adapter-test".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        identity.rendezvous_client_identity_pem = Some("rendezvous-client-identity".to_string());
        identity.issued_at_unix = Some(123);
        identity.expires_at_unix = Some(456);

        persist_client_identity(&path, &identity).expect("identity should persist");

        let raw = std::fs::read_to_string(&path).expect("identity file should exist");
        assert!(
            !raw.contains("device_token"),
            "persisted identity should not contain legacy token field"
        );

        let reloaded = load_client_identity(&path).expect("identity should reload");
        assert_eq!(reloaded, identity);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn load_persisted_client_identity_does_not_read_legacy_sync_root_file_without_explicit_path() {
        let sync_root = std::env::temp_dir().join(format!(
            "ironmesh-sync-root-legacy-identity-{}",
            Uuid::now_v7()
        ));
        std::fs::create_dir_all(&sync_root).expect("sync root should exist");
        let legacy_identity_path = sync_root.join(DEFAULT_CLIENT_IDENTITY_FILE_NAME);
        let mut identity = ClientIdentityMaterial::generate(
            Uuid::now_v7(),
            None,
            Some("legacy-sync-root-test".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        persist_client_identity(&legacy_identity_path, &identity)
            .expect("legacy identity should persist");

        let loaded = load_persisted_client_identity(&sync_root, None, None)
            .expect("legacy lookup should not fail");
        assert!(
            loaded.is_none(),
            "legacy sync-root identity should no longer be loaded implicitly"
        );

        let _ = std::fs::remove_file(legacy_identity_path);
        let _ = std::fs::remove_dir_all(sync_root);
    }

    #[test]
    fn inspect_persisted_client_identity_paths_prefers_local_appdata_then_bootstrap_sibling() {
        let sync_root = Path::new(r"C:\Users\Example\IronMesh\Wiz3");
        let bootstrap_path = Path::new(r"C:\config\ironmesh-client-bootstrap.json");
        let discovery =
            inspect_persisted_client_identity_paths(sync_root, Some(bootstrap_path), None);

        assert_eq!(discovery.selected_path, None);
        assert_eq!(discovery.candidate_paths.len(), 2);
        assert!(
            discovery.candidate_paths[0].ends_with(Path::new("Ironmesh").join("sync-roots"))
                || discovery.candidate_paths[0]
                    .to_string_lossy()
                    .contains(r"\Ironmesh\sync-roots\")
        );
        assert_eq!(
            discovery.candidate_paths[1],
            Path::new(r"C:\config\ironmesh-client-bootstrap.client-identity.json")
        );
    }
}
