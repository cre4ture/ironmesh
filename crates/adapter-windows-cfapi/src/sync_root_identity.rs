#![cfg(windows)]

use crate::helpers::normalize_path;
use anyhow::{Context, Result, anyhow, bail};
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::{ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT, ERROR_NOT_FOUND},
    Storage::CloudFilters::{
        CF_SYNC_ROOT_INFO_STANDARD, CF_SYNC_ROOT_STANDARD_INFO, CfGetSyncRootInfoByPath,
    },
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
                    schema_version =
                        Some(value.trim().parse::<u32>().with_context(|| {
                            format!("invalid sync root identity version {value}")
                        })?);
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

pub fn load_registered_sync_root_context(
    root_path: &Path,
) -> Result<Option<RegisteredSyncRootContext>> {
    let Some((provider_name, identity_bytes)) = try_get_sync_root_info(root_path)? else {
        return Ok(None);
    };

    Ok(Some(RegisteredSyncRootContext {
        windows_sync_root_id: provider_name,
        identity: SyncRootIdentity::decode(&identity_bytes).with_context(|| {
            format!(
                "failed to decode sync root identity for {}",
                root_path.display()
            )
        })?,
    }))
}

fn try_get_sync_root_info(root_path: &Path) -> Result<Option<(String, Vec<u8>)>> {
    let mut info_buffer = vec![0u8; size_of::<CF_SYNC_ROOT_STANDARD_INFO>() + 65_536];
    let mut returned_length = 0u32;
    let root_path_utf16 = root_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();
    let hr = unsafe {
        CfGetSyncRootInfoByPath(
            root_path_utf16.as_ptr(),
            CF_SYNC_ROOT_INFO_STANDARD,
            info_buffer.as_mut_ptr().cast(),
            info_buffer.len() as u32,
            &mut returned_length,
        )
    };

    if hr < 0 {
        let hr_u32 = hr as u32;
        if hr_u32 == hresult_from_win32(ERROR_NOT_FOUND)
            || hr_u32 == hresult_from_win32(ERROR_CLOUD_FILE_NOT_UNDER_SYNC_ROOT)
        {
            return Ok(None);
        }
        return Err(anyhow!(
            "failed to query CFAPI sync root info for {}: HRESULT 0x{:08x}",
            root_path.display(),
            hr_u32
        ));
    }

    if returned_length < size_of::<CF_SYNC_ROOT_STANDARD_INFO>() as u32 {
        bail!(
            "CFAPI returned short sync root info buffer for {} ({} bytes)",
            root_path.display(),
            returned_length
        );
    }

    let info = unsafe { &*(info_buffer.as_ptr() as *const CF_SYNC_ROOT_STANDARD_INFO) };
    let identity_offset = (&info.SyncRootIdentity as *const [u8; 1] as usize)
        .saturating_sub(info as *const CF_SYNC_ROOT_STANDARD_INFO as usize);
    let identity_length = info.SyncRootIdentityLength as usize;
    let available = (returned_length as usize).saturating_sub(identity_offset);
    let clamped_length = identity_length.min(available);
    if clamped_length == 0 {
        bail!(
            "sync root at {} is missing IronMesh registration metadata",
            root_path.display()
        );
    }

    Ok(Some((
        wide_c_string_to_string_lossy(&info.ProviderName),
        info_buffer[identity_offset..identity_offset + clamped_length].to_vec(),
    )))
}

fn normalize_prefix_value(prefix: impl AsRef<str>) -> String {
    let prefix = normalize_path(prefix.as_ref());
    prefix.trim_matches('/').to_string()
}

fn hresult_from_win32(error: u32) -> u32 {
    if error == 0 {
        0
    } else {
        (error & 0x0000_FFFF) | 0x8007_0000
    }
}

fn wide_c_string_to_string_lossy(buffer: &[u16]) -> String {
    let len = buffer
        .iter()
        .position(|value| *value == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..len])
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
