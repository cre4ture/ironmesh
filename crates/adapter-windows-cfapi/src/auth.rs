#![cfg(windows)]

use anyhow::{Context, Result, bail};
use client_sdk::{DeviceEnrollmentRequest, enroll_device_blocking_from_pem};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_DEVICE_AUTH_FILE_NAME: &str = ".ironmesh-device-auth.json";

#[derive(Debug, Clone)]
pub struct DeviceEnrollmentOptions {
    pub pairing_token: Option<String>,
    pub force_reenroll: bool,
    pub device_id: Option<String>,
    pub device_label: Option<String>,
    pub device_token_file: Option<PathBuf>,
    pub server_ca_pem: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthRecord {
    pub device_id: String,
    pub device_token: String,
    pub label: Option<String>,
}

pub fn resolve_or_enroll_device_auth(
    base_url: &Url,
    sync_root_path: &Path,
    options: &DeviceEnrollmentOptions,
) -> Result<Option<DeviceAuthRecord>> {
    let auth_file = options
        .device_token_file
        .clone()
        .unwrap_or_else(|| default_device_auth_path(sync_root_path));

    if auth_file.exists() && !options.force_reenroll {
        return load_device_auth(&auth_file).map(Some);
    }

    let pairing_token = options
        .pairing_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let Some(pairing_token) = pairing_token else {
        return Ok(None);
    };

    let record = enroll_device(base_url, pairing_token, options)?;
    persist_device_auth(&auth_file, &record)?;
    Ok(Some(record))
}

pub fn default_device_auth_path(sync_root_path: &Path) -> PathBuf {
    sync_root_path.join(DEFAULT_DEVICE_AUTH_FILE_NAME)
}

pub fn is_internal_device_auth_relative_path(path: &str) -> bool {
    let normalized = path.trim().trim_matches(['/', '\\']).replace('\\', "/");
    normalized == DEFAULT_DEVICE_AUTH_FILE_NAME
        || normalized.ends_with(&format!("/{DEFAULT_DEVICE_AUTH_FILE_NAME}"))
}

fn enroll_device(
    base_url: &Url,
    pairing_token: &str,
    options: &DeviceEnrollmentOptions,
) -> Result<DeviceAuthRecord> {
    let enrolled = enroll_device_blocking_from_pem(
        base_url,
        options.server_ca_pem.as_deref(),
        &DeviceEnrollmentRequest {
            pairing_token: pairing_token.to_string(),
            device_id: normalize_optional(options.device_id.as_deref()),
            label: normalize_optional(options.device_label.as_deref()),
        },
    )?;

    Ok(DeviceAuthRecord {
        device_id: enrolled.device_id,
        device_token: enrolled.device_token,
        label: enrolled.label,
    })
}

fn normalize_optional(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn load_device_auth(path: &Path) -> Result<DeviceAuthRecord> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read device auth file {}", path.display()))?;
    let record = serde_json::from_str::<DeviceAuthRecord>(&raw)
        .with_context(|| format!("failed to parse device auth file {}", path.display()))?;
    validate_device_auth(&record, path)?;
    Ok(record)
}

fn persist_device_auth(path: &Path, record: &DeviceAuthRecord) -> Result<()> {
    validate_device_auth(record, path)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create auth directory {}", parent.display()))?;
    }
    let payload =
        serde_json::to_string_pretty(record).context("failed to serialize device auth")?;
    fs::write(path, payload)
        .with_context(|| format!("failed to write device auth file {}", path.display()))
}

fn validate_device_auth(record: &DeviceAuthRecord, path: &Path) -> Result<()> {
    if record.device_id.trim().is_empty() {
        bail!("device auth file {} is missing device_id", path.display());
    }
    if record.device_token.trim().is_empty() {
        bail!(
            "device auth file {} is missing device_token",
            path.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_device_auth_path_uses_sync_root() {
        let path = default_device_auth_path(Path::new("C:\\sync-root"));
        assert_eq!(
            path,
            Path::new("C:\\sync-root").join(".ironmesh-device-auth.json")
        );
    }

    #[test]
    fn internal_device_auth_path_detection_matches_nested_and_root_relative_paths() {
        assert!(is_internal_device_auth_relative_path(
            ".ironmesh-device-auth.json"
        ));
        assert!(is_internal_device_auth_relative_path(
            "nested/.ironmesh-device-auth.json"
        ));
        assert!(!is_internal_device_auth_relative_path(
            "nested/not-auth.json"
        ));
    }
}
