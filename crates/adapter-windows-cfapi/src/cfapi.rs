use crate::cfapi_safe_wrap::{
    convert_to_placeholder, hydrate_placeholder_hresult, open_read_attributes_file,
    path_placeholder_state_from_find, read_placeholder_standard_info, report_provider_progress2,
    set_in_sync_state, set_pin_state, update_placeholder, update_placeholder_hresult,
    with_cf_oplock_handle,
};
use crate::helpers::{encode_placeholder_file_identity, hresult_nonneg};
use anyhow::{Context, Result};
use std::mem::offset_of;
use std::os::windows::fs::MetadataExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use windows_sys::Win32::Storage::CloudFilters::{
    CF_CONNECTION_KEY, CF_FILE_RANGE, CF_PIN_STATE, CF_PLACEHOLDER_STANDARD_INFO,
    CF_PLACEHOLDER_STATE, CF_PLACEHOLDER_STATE_PLACEHOLDER, CF_SET_PIN_FLAGS,
    CF_UPDATE_FLAG_DEHYDRATE, CF_UPDATE_FLAG_MARK_IN_SYNC,
};

pub struct PlaceholderStandardInfo {
    info: CF_PLACEHOLDER_STANDARD_INFO,
    raw: Vec<u8>,
}

impl PlaceholderStandardInfo {
    fn from_parts(info: CF_PLACEHOLDER_STANDARD_INFO, raw: Vec<u8>) -> Self {
        Self { info, raw }
    }

    pub fn info(&self) -> &CF_PLACEHOLDER_STANDARD_INFO {
        &self.info
    }

    pub fn file_identity(&self) -> &[u8] {
        let info = self.info();
        let len = info.FileIdentityLength as usize;
        if len == 0 {
            return &[];
        }

        let offset = offset_of!(CF_PLACEHOLDER_STANDARD_INFO, FileIdentity);
        let available = self.raw.len().saturating_sub(offset);
        let clamped_len = len.min(available);
        &self.raw[offset..offset + clamped_len]
    }
}

pub fn cf_convert_to_placeholder(file: &std::fs::File) -> Result<()> {
    cf_convert_to_placeholder_with_identity(file, None)
}

pub fn cf_convert_to_placeholder_with_identity(
    file: &std::fs::File,
    file_identity: Option<&[u8]>,
) -> Result<()> {
    convert_to_placeholder(
        file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
        file_identity,
    )
}

pub fn cf_update_placeholder_file_identity(
    file: &std::fs::File,
    file_identity: &[u8],
) -> Result<()> {
    update_placeholder(
        file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
        file_identity,
        None,
        0,
    )
}

pub fn cf_update_placeholder_file_identity_with_oplock(
    path: &Path,
    file_identity: &[u8],
) -> Result<()> {
    use windows_sys::Win32::Storage::CloudFilters::{
        CF_OPEN_FILE_FLAG_EXCLUSIVE, CF_OPEN_FILE_FLAG_WRITE_ACCESS,
    };

    with_cf_oplock_handle(
        path,
        CF_OPEN_FILE_FLAG_EXCLUSIVE | CF_OPEN_FILE_FLAG_WRITE_ACCESS,
        |handle| update_placeholder(handle, file_identity, None, 0),
    )
}

pub fn cf_ensure_placeholder_identity(file: &std::fs::File, relative_path: &str) -> Result<()> {
    match cf_get_placeholder_standard_info_with_identity(file) {
        Ok(info) if !info.file_identity().is_empty() => Ok(()),
        Ok(_) => {
            let identity = encode_placeholder_file_identity(relative_path, None);
            tracing::info!(
                "cfapi placeholder-identity: repairing missing FileIdentity path={} identity_len={}",
                relative_path,
                identity.len()
            );
            cf_update_placeholder_file_identity(file, &identity)
        }
        Err(_) => {
            let identity = encode_placeholder_file_identity(relative_path, None);
            tracing::info!(
                "cfapi placeholder-identity: converting to placeholder with synthesized FileIdentity path={} identity_len={}",
                relative_path,
                identity.len()
            );
            cf_convert_to_placeholder_with_identity(file, Some(&identity))
        }
    }
}

pub fn cf_set_in_sync(file: &std::fs::File) -> Result<()> {
    cf_set_in_sync_state(
        file,
        windows_sys::Win32::Storage::CloudFilters::CF_IN_SYNC_STATE_IN_SYNC,
        None,
    )
}

pub fn cf_set_not_in_sync(file: &std::fs::File) -> Result<i64> {
    let mut usn = 0i64;
    cf_set_in_sync_state(
        file,
        windows_sys::Win32::Storage::CloudFilters::CF_IN_SYNC_STATE_NOT_IN_SYNC,
        Some(&mut usn),
    )?;
    Ok(usn)
}

pub fn cf_set_in_sync_with_usn(file: &std::fs::File, usn: &mut i64) -> Result<()> {
    cf_set_in_sync_state(
        file,
        windows_sys::Win32::Storage::CloudFilters::CF_IN_SYNC_STATE_IN_SYNC,
        Some(usn),
    )
}

pub fn cf_set_in_sync_state(
    file: &std::fs::File,
    in_sync_state: windows_sys::Win32::Storage::CloudFilters::CF_IN_SYNC_STATE,
    in_sync_usn: Option<&mut i64>,
) -> Result<()> {
    set_in_sync_state(
        file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
        in_sync_state,
        in_sync_usn,
    )
}

pub fn cf_set_pin_state(
    file: &std::fs::File,
    pin_state: CF_PIN_STATE,
    pin_flags: CF_SET_PIN_FLAGS,
) -> Result<()> {
    set_pin_state(
        file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
        pin_state,
        pin_flags,
    )
}

pub fn cf_hydrate_placeholder(file: &std::fs::File) -> Result<()> {
    tracing::info!("cfapi hydrate-placeholder: issuing CfHydratePlaceholder");
    let hr =
        hydrate_placeholder_hresult(file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE);
    tracing::info!(
        "cfapi hydrate-placeholder: CfHydratePlaceholder returned HRESULT 0x{:08x}",
        hr as u32
    );
    hresult_nonneg(hr, "CfHydratePlaceholder")
}

pub fn cf_hydrate_placeholder_with_oplock(path: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::CloudFilters::{
        CF_OPEN_FILE_FLAG_EXCLUSIVE, CF_OPEN_FILE_FLAG_WRITE_ACCESS,
    };

    tracing::info!(
        "cfapi hydrate-placeholder: opening protected oplock handle path={}",
        path.display()
    );
    let result = with_cf_oplock_handle(
        path,
        CF_OPEN_FILE_FLAG_EXCLUSIVE | CF_OPEN_FILE_FLAG_WRITE_ACCESS,
        |handle| {
            tracing::info!(
                "cfapi hydrate-placeholder: issuing CfHydratePlaceholder via oplock handle"
            );
            let hr = hydrate_placeholder_hresult(handle);
            tracing::info!(
                "cfapi hydrate-placeholder: CfHydratePlaceholder via oplock handle returned HRESULT 0x{:08x}",
                hr as u32
            );
            hresult_nonneg(hr, "CfHydratePlaceholder")
        },
    );
    result
}

pub fn cf_dehydrate_placeholder_with_oplock(path: &Path, relative_path: &str) -> Result<()> {
    use windows_sys::Win32::Storage::CloudFilters::{
        CF_OPEN_FILE_FLAG_EXCLUSIVE, CF_OPEN_FILE_FLAG_WRITE_ACCESS,
    };

    tracing::info!(
        "cfapi dehydrate-placeholder: opening protected oplock handle for CfUpdatePlaceholder path={}",
        path.display()
    );
    with_cf_oplock_handle(
        path,
        CF_OPEN_FILE_FLAG_EXCLUSIVE | CF_OPEN_FILE_FLAG_WRITE_ACCESS,
        |handle| {
            let placeholder_info = cf_get_placeholder_standard_info_for_handle(handle)
                .with_context(|| {
                    format!(
                        "reading placeholder info before CfUpdatePlaceholder for {}",
                        path.display()
                    )
                })?;
            let synthesized_identity;
            let file_identity = if placeholder_info.file_identity().is_empty() {
                synthesized_identity = encode_placeholder_file_identity(relative_path, None);
                synthesized_identity.as_slice()
            } else {
                placeholder_info.file_identity()
            };
            let dehydrate_range = CF_FILE_RANGE {
                StartingOffset: 0,
                Length: placeholder_info.info().OnDiskDataSize,
            };

            tracing::info!(
                "cfapi dehydrate-placeholder: issuing CfUpdatePlaceholder with CF_UPDATE_FLAG_DEHYDRATE via oplock handle identity_len={} dehydrate_length={}",
                file_identity.len(),
                dehydrate_range.Length
            );
            let hr = update_placeholder_hresult(
                handle,
                file_identity,
                Some(std::slice::from_ref(&dehydrate_range)),
                CF_UPDATE_FLAG_MARK_IN_SYNC | CF_UPDATE_FLAG_DEHYDRATE,
            );
            tracing::info!(
                "cfapi dehydrate-placeholder: CfUpdatePlaceholder via oplock handle returned HRESULT 0x{:08x}",
                hr as u32
            );
            hresult_nonneg(hr, "CfUpdatePlaceholder")
        },
    )
}

pub fn cf_report_provider_progress2(
    connection_key: CF_CONNECTION_KEY,
    transfer_key: i64,
    request_key: i64,
    provider_progress_total: i64,
    provider_progress_completed: i64,
    target_session_id: u32,
) -> Result<()> {
    report_provider_progress2(
        connection_key,
        transfer_key,
        request_key,
        provider_progress_total,
        provider_progress_completed,
        target_session_id,
    )
}

fn cf_get_placeholder_standard_info_for_handle(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<PlaceholderStandardInfo> {
    let (info, raw) = read_placeholder_standard_info(handle)?;
    Ok(PlaceholderStandardInfo::from_parts(info, raw))
}

pub fn cf_get_placeholder_standard_info(
    file: &std::fs::File,
) -> Result<windows_sys::Win32::Storage::CloudFilters::CF_PLACEHOLDER_STANDARD_INFO> {
    Ok(*cf_get_placeholder_standard_info_with_identity(file)?.info())
}

pub fn cf_get_placeholder_standard_info_with_identity(
    file: &std::fs::File,
) -> Result<PlaceholderStandardInfo> {
    cf_get_placeholder_standard_info_for_handle(
        file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE
    )
}

pub fn get_and_log_placeholder_info(
    file: &std::fs::File,
    label: &str,
    rel_path: &str,
) -> Result<CF_PLACEHOLDER_STANDARD_INFO> {
    match cf_get_placeholder_standard_info(file) {
        Ok(returned) => {
            tracing::info!(
                "{}: CfGetPlaceholderInfo for {}: returned FileId: {}, OnDiskDataSize: {}, ModifiedDataSize: {}, InSyncState: {:?}",
                label,
                rel_path,
                returned.FileId,
                returned.OnDiskDataSize,
                returned.ModifiedDataSize,
                returned.InSyncState
            );
            Ok(returned)
        }
        Err(err) => {
            tracing::info!(
                "{}: CfGetPlaceholderInfo error for {}: {}",
                label,
                rel_path,
                err
            );
            Err(err)
        }
    }
}

pub fn is_placeholder(file: &std::fs::File) -> bool {
    cf_get_placeholder_standard_info(file).is_ok()
}

pub fn path_placeholder_state(path: &Path) -> Result<CF_PLACEHOLDER_STATE> {
    path_placeholder_state_from_find(path)
}

pub fn path_is_placeholder(path: &Path) -> bool {
    path_placeholder_state(path)
        .map(|state| (state & CF_PLACEHOLDER_STATE_PLACEHOLDER) != 0)
        .unwrap_or(false)
}

pub fn open_sync_path(path: &Path, write: bool) -> std::io::Result<std::fs::File> {
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

    if write {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
        return options.open(path);
    }

    open_read_attributes_file(path)
}

pub fn describe_path_state(path: &Path) -> String {
    let metadata_summary = match std::fs::metadata(path) {
        Ok(metadata) => format!(
            "exists=true dir={} len={} attrs=0x{:08x}",
            metadata.is_dir(),
            metadata.len(),
            metadata.file_attributes()
        ),
        Err(err) => format!("exists=false metadata_error={err}"),
    };

    let placeholder_state_summary = match path_placeholder_state(path) {
        Ok(state) => format!("placeholder_state=0x{state:08x}"),
        Err(err) => format!("placeholder_state_error={err}"),
    };

    let placeholder_info_summary = match open_sync_path(path, false) {
        Ok(file) => match cf_get_placeholder_standard_info(&file) {
            Ok(info) => format!(
                "placeholder_info={{file_id={} on_disk={} validated={} modified={} in_sync={:?} pin={:?}}}",
                info.FileId,
                info.OnDiskDataSize,
                info.ValidatedDataSize,
                info.ModifiedDataSize,
                info.InSyncState,
                info.PinState
            ),
            Err(err) => format!("placeholder_info_error={err}"),
        },
        Err(err) => format!("open_error={err}"),
    };

    format!(
        "{} {} {}",
        metadata_summary, placeholder_state_summary, placeholder_info_summary
    )
}

pub fn try_convert_materialized_file(
    file_path: &Path,
    rel_path: &str,
    metadata: &std::fs::Metadata,
) {
    if path_is_placeholder(file_path) {
        tracing::info!(
            "convert-materialized: skipping convert for {} because placeholder state already present",
            rel_path
        );
        return;
    }

    {
        let attrs = metadata.file_attributes();
        tracing::info!(
            "monitor: attempting convert path={} attrs=0x{:08x} size={}",
            file_path.display(),
            attrs,
            metadata.len()
        );
    }
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(file_path)
    {
        Ok(fh_file) => {
            let result = cf_ensure_placeholder_identity(&fh_file, rel_path);
            if result.is_ok() {
                tracing::info!(
                    "convert-materialized: converted materialized file to placeholder: {}",
                    rel_path
                );
            } else {
                tracing::info!(
                    "convert-materialized: failed to convert materialized file to placeholder {}: {:?}",
                    rel_path,
                    result.err()
                );
                if let Ok(m) = std::fs::metadata(file_path) {
                    let attrs = m.file_attributes();
                    tracing::info!("convert-materialized: post-fail attrs=0x{:08x} size={}", attrs, m.len());
                }
            }
        }
        Err(err) => {
            tracing::info!(
                "convert-materialized: failed to open materialized file {} for conversion: {}",
                rel_path,
                err
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::PlaceholderStandardInfo;
    use std::mem::{offset_of, size_of};
    use windows_sys::Win32::Storage::CloudFilters::CF_PLACEHOLDER_STANDARD_INFO;

    #[test]
    fn placeholder_standard_info_reads_identity_from_field_offset() {
        let identity = b"v=2\np=docs/readme.txt";
        let mut raw = vec![0u8; size_of::<CF_PLACEHOLDER_STANDARD_INFO>() + identity.len()];
        let offset = offset_of!(CF_PLACEHOLDER_STANDARD_INFO, FileIdentity);
        raw[offset..offset + identity.len()].copy_from_slice(identity);

        let info = CF_PLACEHOLDER_STANDARD_INFO {
            FileIdentityLength: identity.len() as u32,
            ..Default::default()
        };
        let placeholder_info = PlaceholderStandardInfo::from_parts(info, raw);

        assert_eq!(placeholder_info.file_identity(), identity);
    }
}
