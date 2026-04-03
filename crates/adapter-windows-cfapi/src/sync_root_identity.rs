#![cfg(windows)]

use crate::helpers::normalize_path;
use anyhow::{Context, Result, anyhow, bail};
use std::path::Path;
use uuid::Uuid;
use wincs::ext::PathExt;
use windows::{
    Storage::{
        Provider::StorageProviderSyncRootInfo,
        Streams::DataReader,
    },
    Win32::Foundation::ERROR_NOT_FOUND,
};

const SYNC_ROOT_IDENTITY_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRootIdentity {
    pub schema_version: u32,
    pub provider_instance_id: Uuid,
    pub cluster_id: Uuid,
    pub sync_root_id: String,
    pub prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredSyncRootContext {
    pub windows_sync_root_id: String,
    pub identity: SyncRootIdentity,
}

impl SyncRootIdentity {
    pub fn new(
        provider_instance_id: Uuid,
        cluster_id: Uuid,
        sync_root_id: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SYNC_ROOT_IDENTITY_SCHEMA_VERSION,
            provider_instance_id,
            cluster_id,
            sync_root_id: sync_root_id.into(),
            prefix: normalize_prefix_value(prefix.into()),
        }
    }

    pub fn encoded(&self) -> Vec<u8> {
        let mut lines = Vec::with_capacity(5);
        lines.push(format!("v={}", self.schema_version));
        lines.push(format!("pi={}", self.provider_instance_id));
        lines.push(format!("cid={}", self.cluster_id));
        lines.push(format!("srid={}", self.sync_root_id.trim()));
        lines.push(format!("prefix={}", self.prefix));
        lines.join("\n").into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let text =
            std::str::from_utf8(bytes).context("sync root identity blob is not valid UTF-8")?;
        let mut schema_version = None;
        let mut provider_instance_id = None;
        let mut cluster_id = None;
        let mut sync_root_id = None;
        let mut prefix = None;

        for line in text.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key {
                "v" => {
                    schema_version = Some(
                        value
                            .trim()
                            .parse::<u32>()
                            .with_context(|| format!("invalid sync root identity version {value}"))?,
                    );
                }
                "pi" => {
                    provider_instance_id = Some(
                        Uuid::parse_str(value.trim())
                            .with_context(|| format!("invalid provider instance id {value}"))?,
                    );
                }
                "cid" => {
                    cluster_id = Some(
                        Uuid::parse_str(value.trim())
                            .with_context(|| format!("invalid cluster id {value}"))?,
                    );
                }
                "srid" => {
                    sync_root_id = Some(value.trim().to_string());
                }
                "prefix" => {
                    prefix = Some(normalize_prefix_value(value));
                }
                _ => {}
            }
        }

        let schema_version =
            schema_version.ok_or_else(|| anyhow!("sync root identity is missing v"))?;
        if schema_version != SYNC_ROOT_IDENTITY_SCHEMA_VERSION {
            bail!(
                "unsupported sync root identity schema version {} (expected {})",
                schema_version,
                SYNC_ROOT_IDENTITY_SCHEMA_VERSION
            );
        }

        let provider_instance_id = provider_instance_id
            .ok_or_else(|| anyhow!("sync root identity is missing provider instance id"))?;
        let cluster_id =
            cluster_id.ok_or_else(|| anyhow!("sync root identity is missing cluster id"))?;
        let sync_root_id = sync_root_id
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("sync root identity is missing sync root id"))?;
        let prefix = prefix.unwrap_or_default();

        Ok(Self {
            schema_version,
            provider_instance_id,
            cluster_id,
            sync_root_id,
            prefix,
        })
    }
}

pub fn normalize_prefix(prefix: Option<&str>) -> String {
    normalize_prefix_value(prefix.unwrap_or_default())
}

pub fn load_registered_sync_root_context(root_path: &Path) -> Result<Option<RegisteredSyncRootContext>> {
    let Some(info) = try_get_sync_root_info(root_path)? else {
        return Ok(None);
    };

    let windows_sync_root_id = info
        .Id()
        .context("failed to read Windows sync root id")?
        .to_string_lossy();
    let context_buffer = info
        .Context()
        .context("failed to read Windows sync root context blob")?;
    let context_len = context_buffer
        .Length()
        .context("failed to read Windows sync root context length")?
        as usize;
    if context_len == 0 {
        bail!(
            "sync root {} at {} is missing IronMesh registration metadata",
            windows_sync_root_id,
            root_path.display()
        );
    }

    let reader =
        DataReader::FromBuffer(&context_buffer).context("failed to create context blob reader")?;
    let mut bytes = vec![0u8; context_len];
    reader
        .ReadBytes(&mut bytes)
        .context("failed to decode sync root context blob")?;

    Ok(Some(RegisteredSyncRootContext {
        windows_sync_root_id,
        identity: SyncRootIdentity::decode(&bytes)?,
    }))
}

fn try_get_sync_root_info(root_path: &Path) -> Result<Option<StorageProviderSyncRootInfo>> {
    match root_path.sync_root_info() {
        Ok(info) => Ok(Some(info)),
        Err(err) if err.code() == ERROR_NOT_FOUND.to_hresult() => Ok(None),
        Err(err) => Err(anyhow!(
            "failed to query Windows sync root registration for {}: {}",
            root_path.display(),
            err
        )),
    }
}

fn normalize_prefix_value(prefix: impl AsRef<str>) -> String {
    let prefix = normalize_path(prefix.as_ref());
    prefix.trim_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sync_root_identity_round_trips_compact_text_blob() {
        let identity = SyncRootIdentity::new(
            Uuid::parse_str("0195ff90-a273-7ef4-9ea5-b2c6e6b99539").unwrap(),
            Uuid::parse_str("0195ff90-a57d-7680-b9d9-5a7d5714957b").unwrap(),
            "ironmesh.sync.root",
            "/docs/team/",
        );

        let decoded = SyncRootIdentity::decode(&identity.encoded()).expect("decode should work");

        assert_eq!(decoded, identity);
        assert_eq!(decoded.prefix, "docs/team");
    }
}
