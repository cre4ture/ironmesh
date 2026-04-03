use crate::helpers::{encode_placeholder_file_identity, hresult_nonneg, utf16_path};
use anyhow::{Context, Result};
use core::ffi::c_void;
use std::mem::size_of;
use std::os::windows::fs::MetadataExt;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use windows_sys::Win32::Storage::CloudFilters::{
    CF_CONNECTION_KEY, CF_PIN_STATE, CF_PLACEHOLDER_STANDARD_INFO, CF_PLACEHOLDER_STATE,
    CF_PLACEHOLDER_STATE_PLACEHOLDER, CF_SET_PIN_FLAGS,
};

struct ProtectedCfHandle(windows_sys::Win32::Foundation::HANDLE);

impl ProtectedCfHandle {
    fn raw(&self) -> windows_sys::Win32::Foundation::HANDLE {
        self.0
    }
}

impl Drop for ProtectedCfHandle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Storage::CloudFilters::CfCloseHandle(self.0);
        }
    }
}

pub struct PlaceholderStandardInfo {
    info: CF_PLACEHOLDER_STANDARD_INFO,
    raw: Vec<u8>,
}

impl PlaceholderStandardInfo {
    fn from_raw(raw: Vec<u8>) -> Self {
        let info = unsafe {
            std::ptr::read_unaligned(raw.as_ptr().cast::<CF_PLACEHOLDER_STANDARD_INFO>())
        };
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

        let offset = size_of::<CF_PLACEHOLDER_STANDARD_INFO>() - 1;
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
    use windows_sys::Win32::Storage::CloudFilters::CfConvertToPlaceholder;

    let file_identity = file_identity.unwrap_or(&[]);
    let hr = unsafe {
        CfConvertToPlaceholder(
            file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
            if file_identity.is_empty() {
                std::ptr::null()
            } else {
                file_identity.as_ptr().cast::<c_void>()
            },
            file_identity.len() as u32,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    hresult_nonneg(hr, "CfConvertToPlaceholder")
}

pub fn cf_update_placeholder_file_identity(
    file: &std::fs::File,
    file_identity: &[u8],
) -> Result<()> {
    use windows_sys::Win32::Storage::CloudFilters::CfUpdatePlaceholder;

    let hr = unsafe {
        CfUpdatePlaceholder(
            file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
            std::ptr::null(),
            if file_identity.is_empty() {
                std::ptr::null()
            } else {
                file_identity.as_ptr().cast::<c_void>()
            },
            file_identity.len() as u32,
            std::ptr::null(),
            0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    hresult_nonneg(hr, "CfUpdatePlaceholder")
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
    use windows_sys::Win32::Storage::CloudFilters::{CF_SET_IN_SYNC_FLAG_NONE, CfSetInSyncState};

    let hr = unsafe {
        CfSetInSyncState(
            file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
            in_sync_state,
            CF_SET_IN_SYNC_FLAG_NONE,
            in_sync_usn
                .map(|value| value as *mut i64)
                .unwrap_or(std::ptr::null_mut()),
        )
    };
    hresult_nonneg(hr, "CfSetInSyncState")
}

pub fn cf_set_pin_state(
    file: &std::fs::File,
    pin_state: CF_PIN_STATE,
    pin_flags: CF_SET_PIN_FLAGS,
) -> Result<()> {
    use windows_sys::Win32::Storage::CloudFilters::CfSetPinState;

    let hr = unsafe {
        CfSetPinState(
            file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
            pin_state,
            pin_flags,
            std::ptr::null_mut(),
        )
    };
    hresult_nonneg(hr, "CfSetPinState")
}

pub fn cf_hydrate_placeholder(file: &std::fs::File) -> Result<()> {
    use windows_sys::Win32::Storage::CloudFilters::{CF_HYDRATE_FLAG_NONE, CfHydratePlaceholder};

    tracing::info!("cfapi hydrate-placeholder: issuing CfHydratePlaceholder");
    let hr = unsafe {
        CfHydratePlaceholder(
            file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE,
            0,
            -1,
            CF_HYDRATE_FLAG_NONE,
            std::ptr::null_mut(),
        )
    };
    tracing::info!(
        "cfapi hydrate-placeholder: CfHydratePlaceholder returned HRESULT 0x{:08x}",
        hr as u32
    );
    hresult_nonneg(hr, "CfHydratePlaceholder")
}

pub fn cf_hydrate_placeholder_with_oplock(path: &Path) -> Result<()> {
    use windows_sys::Win32::Storage::CloudFilters::{
        CF_HYDRATE_FLAG_NONE, CF_OPEN_FILE_FLAG_EXCLUSIVE, CF_OPEN_FILE_FLAG_WRITE_ACCESS,
        CfHydratePlaceholder,
    };

    tracing::info!(
        "cfapi hydrate-placeholder: opening protected oplock handle path={}",
        path.display()
    );
    let protected_handle = cf_open_file_with_oplock(
        path,
        CF_OPEN_FILE_FLAG_EXCLUSIVE | CF_OPEN_FILE_FLAG_WRITE_ACCESS,
    )?;

    tracing::info!("cfapi hydrate-placeholder: issuing CfHydratePlaceholder via oplock handle");
    let hr = unsafe {
        CfHydratePlaceholder(
            protected_handle.raw(),
            0,
            -1,
            CF_HYDRATE_FLAG_NONE,
            std::ptr::null_mut(),
        )
    };
    tracing::info!(
        "cfapi hydrate-placeholder: CfHydratePlaceholder via oplock handle returned HRESULT 0x{:08x}",
        hr as u32
    );
    hresult_nonneg(hr, "CfHydratePlaceholder")
}

fn cf_open_file_with_oplock(
    path: &Path,
    flags: windows_sys::Win32::Storage::CloudFilters::CF_OPEN_FILE_FLAGS,
) -> Result<ProtectedCfHandle> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::CloudFilters::CfOpenFileWithOplock;

    let wide_path = utf16_path(path);
    let mut protected_handle = INVALID_HANDLE_VALUE;
    let hr = unsafe { CfOpenFileWithOplock(wide_path.as_ptr(), flags, &mut protected_handle) };
    hresult_nonneg(hr, "CfOpenFileWithOplock")?;
    Ok(ProtectedCfHandle(protected_handle))
}

pub fn cf_dehydrate_placeholder_with_oplock(path: &Path, relative_path: &str) -> Result<()> {
    use windows_sys::Win32::Storage::CloudFilters::{
        CF_FILE_RANGE, CF_OPEN_FILE_FLAG_EXCLUSIVE, CF_OPEN_FILE_FLAG_WRITE_ACCESS,
        CF_UPDATE_FLAG_DEHYDRATE, CF_UPDATE_FLAG_MARK_IN_SYNC, CfUpdatePlaceholder,
    };

    tracing::info!(
        "cfapi dehydrate-placeholder: opening protected oplock handle for CfUpdatePlaceholder path={}",
        path.display()
    );
    let protected_handle = cf_open_file_with_oplock(
        path,
        CF_OPEN_FILE_FLAG_EXCLUSIVE | CF_OPEN_FILE_FLAG_WRITE_ACCESS,
    )?;
    let placeholder_info = cf_get_placeholder_standard_info_for_handle(protected_handle.raw())
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
    let hr = unsafe {
        CfUpdatePlaceholder(
            protected_handle.raw(),
            std::ptr::null(),
            if file_identity.is_empty() {
                std::ptr::null()
            } else {
                file_identity.as_ptr().cast::<c_void>()
            },
            file_identity.len() as u32,
            &dehydrate_range,
            1,
            CF_UPDATE_FLAG_MARK_IN_SYNC | CF_UPDATE_FLAG_DEHYDRATE,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    tracing::info!(
        "cfapi dehydrate-placeholder: CfUpdatePlaceholder via oplock handle returned HRESULT 0x{:08x}",
        hr as u32
    );
    hresult_nonneg(hr, "CfUpdatePlaceholder")
}

pub fn cf_report_provider_progress2(
    connection_key: CF_CONNECTION_KEY,
    transfer_key: i64,
    request_key: i64,
    provider_progress_total: i64,
    provider_progress_completed: i64,
    target_session_id: u32,
) -> Result<()> {
    use windows_sys::Win32::Storage::CloudFilters::CfReportProviderProgress2;

    let hr = unsafe {
        CfReportProviderProgress2(
            connection_key,
            transfer_key,
            request_key,
            provider_progress_total,
            provider_progress_completed,
            target_session_id,
        )
    };
    hresult_nonneg(hr, "CfReportProviderProgress2")
}

fn cf_get_placeholder_standard_info_for_handle(
    handle: windows_sys::Win32::Foundation::HANDLE,
) -> Result<PlaceholderStandardInfo> {
    use windows_sys::Win32::Storage::CloudFilters::{
        CF_PLACEHOLDER_INFO_STANDARD, CF_PLACEHOLDER_STANDARD_INFO, CfGetPlaceholderInfo,
    };

    const HRESULT_MORE_DATA: i32 = 0x800700EAu32 as i32;

    let mut buffer_len = 4096usize.max(size_of::<CF_PLACEHOLDER_STANDARD_INFO>());
    loop {
        let mut info_buf = vec![0u8; buffer_len];
        let mut returned = 0u32;
        let hr_info = unsafe {
            CfGetPlaceholderInfo(
                handle,
                CF_PLACEHOLDER_INFO_STANDARD,
                info_buf.as_mut_ptr().cast::<c_void>(),
                info_buf.len() as u32,
                &mut returned,
            )
        };

        if hr_info == HRESULT_MORE_DATA && returned as usize > info_buf.len() {
            buffer_len = returned as usize;
            continue;
        }

        hresult_nonneg(hr_info, "CfGetPlaceholderInfo")?;
        info_buf.truncate((returned as usize).max(size_of::<CF_PLACEHOLDER_STANDARD_INFO>()));
        return Ok(PlaceholderStandardInfo::from_raw(info_buf));
    }
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
    get_and_log_placeholder_info(file, "", "").is_ok()
}

pub fn path_placeholder_state(path: &Path) -> Result<CF_PLACEHOLDER_STATE> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::CloudFilters::CfGetPlaceholderStateFromAttributeTag;
    use windows_sys::Win32::Storage::FileSystem::{FindClose, FindFirstFileW, WIN32_FIND_DATAW};

    let wide_path = utf16_path(path);
    let mut find_data = WIN32_FIND_DATAW::default();
    let handle = unsafe { FindFirstFileW(wide_path.as_ptr(), &mut find_data) };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("FindFirstFileW failed for {}", path.display()));
    }

    let state = unsafe {
        CfGetPlaceholderStateFromAttributeTag(find_data.dwFileAttributes, find_data.dwReserved0)
    };
    unsafe {
        FindClose(handle);
    }
    Ok(state)
}

pub fn path_is_placeholder(path: &Path) -> bool {
    path_placeholder_state(path)
        .map(|state| (state & CF_PLACEHOLDER_STATE_PLACEHOLDER) != 0)
        .unwrap_or(false)
}

pub fn open_sync_path(path: &Path, write: bool) -> std::io::Result<std::fs::File> {
    use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    };

    if write {
        let mut options = std::fs::OpenOptions::new();
        options
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
        return options.open(path);
    }

    let wide_path = utf16_path(path);
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    let file = unsafe { std::fs::File::from_raw_handle(handle as _) };
    Ok(file)
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
            "x: skipping convert for {} because placeholder state already present",
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
                    "x: converted materialized file to placeholder: {}",
                    rel_path
                );
            } else {
                tracing::info!(
                    "x: failed to convert materialized file to placeholder {}: {:?}",
                    rel_path,
                    result.err()
                );
                if let Ok(m) = std::fs::metadata(file_path) {
                    let attrs = m.file_attributes();
                    tracing::info!("x: post-fail attrs=0x{:08x} size={}", attrs, m.len());
                }
            }
        }
        Err(err) => {
            tracing::info!(
                "x: failed to open materialized file {} for conversion: {}",
                rel_path,
                err
            );
        }
    }
}
