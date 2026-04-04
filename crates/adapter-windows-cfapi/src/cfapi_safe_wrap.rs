use crate::helpers::{hresult_nonneg, utf16_path};
use crate::runtime::{
    CallbackContext, handle_callback_cancel_fetch_data, handle_callback_fetch_data,
    handle_callback_file_close_completion, handle_callback_file_open,
    handle_callback_notify_dehydrate, handle_callback_notify_dehydrate_completion,
};
use anyhow::{Context, Result};
use core::ffi::c_void;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::os::windows::io::FromRawHandle;
use std::path::Path;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE, NTSTATUS};
use windows_sys::Win32::Storage::CloudFilters::*;
use windows_sys::Win32::Storage::FileSystem::*;

#[derive(Debug, Clone)]
pub(crate) struct CallbackProcessLogInfo {
    pub(crate) process_id: u32,
    pub(crate) image_path: String,
    pub(crate) package_name: String,
    pub(crate) application_id: String,
    pub(crate) command_line: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FetchDataCallbackParams {
    pub(crate) flags: CF_CALLBACK_FETCH_DATA_FLAGS,
    pub(crate) required_file_offset: i64,
    pub(crate) required_length: i64,
    pub(crate) optional_file_offset: i64,
    pub(crate) optional_length: i64,
    pub(crate) last_dehydration_reason: i32,
    pub(crate) last_dehydration_time: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CancelFetchDataCallbackParams {
    pub(crate) file_offset: i64,
    pub(crate) length: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NotifyDehydrateCallbackParams {
    pub(crate) flags: i32,
    pub(crate) reason: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NotifyDehydrateCompletionCallbackParams {
    pub(crate) flags: i32,
    pub(crate) reason: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CloseCompletionCallbackParams {
    pub(crate) flags: i32,
}

struct ProtectedCfHandle(HANDLE);

impl ProtectedCfHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for ProtectedCfHandle {
    fn drop(&mut self) {
        unsafe {
            CfCloseHandle(self.0);
        }
    }
}


pub(crate) fn empty_fs_metadata() -> CF_FS_METADATA {
    unsafe { std::mem::zeroed() }
}

pub(crate) fn create_placeholders(
    sync_root: &[u16],
    create_infos: &mut [CF_PLACEHOLDER_CREATE_INFO],
    flags: CF_CREATE_FLAGS,
    entries_processed: Option<&mut u32>,
    operation: &str,
) -> Result<()> {
    if create_infos.is_empty() {
        return Ok(());
    }

    let hr = unsafe {
        CfCreatePlaceholders(
            sync_root.as_ptr(),
            create_infos.as_mut_ptr(),
            create_infos.len() as u32,
            flags,
            entries_processed
                .map(|value| value as *mut u32)
                .unwrap_or(null_mut()),
        )
    };
    hresult_nonneg(hr, operation)
}

pub(crate) fn connect_sync_root(
    root_path: &[u16],
    callback_context: &mut CallbackContext,
) -> Result<(CF_CONNECTION_KEY, Box<[CF_CALLBACK_REGISTRATION]>)> {
    let callback_table = vec![
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NOTIFY_FILE_OPEN_COMPLETION,
            Callback: Some(callback_file_open),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_FETCH_DATA,
            Callback: Some(callback_fetch_data),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_CANCEL_FETCH_DATA,
            Callback: Some(callback_cancel_fetch_data),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE,
            Callback: Some(callback_notify_dehydrate),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NOTIFY_DEHYDRATE_COMPLETION,
            Callback: Some(callback_notify_dehydrate_completion),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NOTIFY_FILE_CLOSE_COMPLETION,
            Callback: Some(callback_file_close_completion),
        },
        CF_CALLBACK_REGISTRATION {
            Type: CF_CALLBACK_TYPE_NONE,
            Callback: None,
        },
    ]
    .into_boxed_slice();

    let mut connection_key: CF_CONNECTION_KEY = 0;
    let hr = unsafe {
        CfConnectSyncRoot(
            root_path.as_ptr(),
            callback_table.as_ptr(),
            (callback_context as *mut CallbackContext).cast::<c_void>(),
            CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO,
            &mut connection_key,
        )
    };
    hresult_nonneg(hr, "CfConnectSyncRoot")?;

    Ok((connection_key, callback_table))
}

pub(crate) fn disconnect_sync_root(connection_key: CF_CONNECTION_KEY) {
    unsafe {
        let _ = CfDisconnectSyncRoot(connection_key);
    }
}

pub(crate) fn unregister_sync_root(root_path: &[u16]) -> i32 {
    unsafe { CfUnregisterSyncRoot(root_path.as_ptr()) }
}

pub(crate) fn execute_ack_dehydrate(
    callback_info: &CF_CALLBACK_INFO,
    completion_status: NTSTATUS,
) -> Result<()> {
    let mut op_params = CF_OPERATION_PARAMETERS {
        ParamSize: size_of::<CF_OPERATION_PARAMETERS>() as u32,
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            AckDehydrate: CF_OPERATION_PARAMETERS_0_5 {
                Flags: CF_OPERATION_ACK_DEHYDRATE_FLAG_NONE,
                CompletionStatus: completion_status,
                FileIdentity: callback_info.FileIdentity,
                FileIdentityLength: callback_info.FileIdentityLength,
            },
        },
    };

    let op_info = CF_OPERATION_INFO {
        StructSize: size_of::<CF_OPERATION_INFO>() as u32,
        Type: CF_OPERATION_TYPE_ACK_DEHYDRATE,
        ConnectionKey: callback_info.ConnectionKey,
        TransferKey: callback_info.TransferKey,
        CorrelationVector: callback_info.CorrelationVector,
        SyncStatus: null(),
        RequestKey: callback_info.RequestKey,
    };

    let hr = unsafe { CfExecute(&op_info, &mut op_params) };
    hresult_nonneg(hr, "CfExecute(AckDehydrate)")
}

pub(crate) fn execute_transfer_data_chunk(
    callback_info: &CF_CALLBACK_INFO,
    offset: u64,
    payload: &[u8],
) -> Result<()> {
    if payload.is_empty() {
        return Ok(());
    }

    let transfer_data = CF_OPERATION_PARAMETERS_0_0 {
        Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
        CompletionStatus: 0,
        Buffer: payload.as_ptr().cast::<c_void>(),
        Offset: offset as i64,
        Length: payload.len() as i64,
    };

    let mut op_params = CF_OPERATION_PARAMETERS {
        ParamSize: size_of::<CF_OPERATION_PARAMETERS>() as u32,
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            TransferData: transfer_data,
        },
    };

    let op_info = CF_OPERATION_INFO {
        StructSize: size_of::<CF_OPERATION_INFO>() as u32,
        Type: CF_OPERATION_TYPE_TRANSFER_DATA,
        ConnectionKey: callback_info.ConnectionKey,
        TransferKey: callback_info.TransferKey,
        CorrelationVector: callback_info.CorrelationVector,
        SyncStatus: null(),
        RequestKey: callback_info.RequestKey,
    };

    let hr = unsafe { CfExecute(&op_info, &mut op_params) };
    hresult_nonneg(hr, "CfExecute")
}

pub(crate) fn execute_transfer_data_failure(
    callback_info: &CF_CALLBACK_INFO,
    offset: u64,
    length: u64,
    completion_status: NTSTATUS,
) -> Result<()> {
    let transfer_data = CF_OPERATION_PARAMETERS_0_0 {
        Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
        CompletionStatus: completion_status,
        Buffer: null(),
        Offset: offset as i64,
        Length: length as i64,
    };

    let mut op_params = CF_OPERATION_PARAMETERS {
        ParamSize: size_of::<CF_OPERATION_PARAMETERS>() as u32,
        Anonymous: CF_OPERATION_PARAMETERS_0 {
            TransferData: transfer_data,
        },
    };

    let op_info = CF_OPERATION_INFO {
        StructSize: size_of::<CF_OPERATION_INFO>() as u32,
        Type: CF_OPERATION_TYPE_TRANSFER_DATA,
        ConnectionKey: callback_info.ConnectionKey,
        TransferKey: callback_info.TransferKey,
        CorrelationVector: callback_info.CorrelationVector,
        SyncStatus: null(),
        RequestKey: callback_info.RequestKey,
    };

    let hr = unsafe { CfExecute(&op_info, &mut op_params) };
    hresult_nonneg(hr, "CfExecute(TransferDataFailure)")
}

pub(crate) fn string_from_pcwstr(value: windows_sys::core::PCWSTR) -> String {
    if value.is_null() {
        return String::new();
    }

    let mut len = 0usize;
    unsafe {
        while *value.add(len) != 0 {
            len += 1;
        }
        let raw = std::slice::from_raw_parts(value, len);
        String::from_utf16_lossy(raw)
    }
}

pub(crate) fn callback_target_session_id(callback_info: &CF_CALLBACK_INFO) -> u32 {
    if callback_info.ProcessInfo.is_null() {
        0
    } else {
        unsafe { (*callback_info.ProcessInfo).SessionId }
    }
}

pub(crate) fn callback_process_log_info(
    callback_info: &CF_CALLBACK_INFO,
) -> CallbackProcessLogInfo {
    if callback_info.ProcessInfo.is_null() {
        return CallbackProcessLogInfo {
            process_id: 0,
            image_path: "<unknown>".to_string(),
            package_name: "<unknown>".to_string(),
            application_id: "<unknown>".to_string(),
            command_line: "<unknown>".to_string(),
        };
    }

    let process_info = unsafe { &*callback_info.ProcessInfo };
    let image_path = string_from_pcwstr(process_info.ImagePath);
    let package_name = string_from_pcwstr(process_info.PackageName);
    let application_id = string_from_pcwstr(process_info.ApplicationId);
    let command_line = string_from_pcwstr(process_info.CommandLine);

    CallbackProcessLogInfo {
        process_id: process_info.ProcessId,
        image_path: if image_path.is_empty() {
            "<unknown>".to_string()
        } else {
            image_path
        },
        package_name: if package_name.is_empty() {
            "<unknown>".to_string()
        } else {
            package_name
        },
        application_id: if application_id.is_empty() {
            "<unknown>".to_string()
        } else {
            application_id
        },
        command_line: if command_line.is_empty() {
            "<unknown>".to_string()
        } else {
            command_line
        },
    }
}

pub(crate) fn callback_file_identity<'a>(callback_info: &'a CF_CALLBACK_INFO) -> &'a [u8] {
    if callback_info.FileIdentity.is_null() || callback_info.FileIdentityLength == 0 {
        &[]
    } else {
        unsafe {
            std::slice::from_raw_parts(
                callback_info.FileIdentity.cast::<u8>(),
                callback_info.FileIdentityLength as usize,
            )
        }
    }
}

pub(crate) fn convert_to_placeholder(handle: HANDLE, file_identity: Option<&[u8]>) -> Result<()> {
    let file_identity = file_identity.unwrap_or(&[]);
    let hr = unsafe {
        CfConvertToPlaceholder(
            handle,
            if file_identity.is_empty() {
                null()
            } else {
                file_identity.as_ptr().cast::<c_void>()
            },
            file_identity.len() as u32,
            0,
            null_mut(),
            null_mut(),
        )
    };
    hresult_nonneg(hr, "CfConvertToPlaceholder")
}

pub(crate) fn update_placeholder(
    handle: HANDLE,
    file_identity: &[u8],
    dehydrate_ranges: Option<&[CF_FILE_RANGE]>,
    update_flags: CF_UPDATE_FLAGS,
) -> Result<()> {
    let hr = update_placeholder_hresult(handle, file_identity, dehydrate_ranges, update_flags);
    hresult_nonneg(hr, "CfUpdatePlaceholder")
}

pub(crate) fn update_placeholder_hresult(
    handle: HANDLE,
    file_identity: &[u8],
    dehydrate_ranges: Option<&[CF_FILE_RANGE]>,
    update_flags: CF_UPDATE_FLAGS,
) -> i32 {
    unsafe {
        CfUpdatePlaceholder(
            handle,
            null(),
            if file_identity.is_empty() {
                null()
            } else {
                file_identity.as_ptr().cast::<c_void>()
            },
            file_identity.len() as u32,
            dehydrate_ranges
                .map(|ranges| ranges.as_ptr())
                .unwrap_or(null()),
            dehydrate_ranges
                .map(|ranges| ranges.len() as u32)
                .unwrap_or(0),
            update_flags,
            null_mut(),
            null_mut(),
        )
    }
}

pub(crate) fn set_in_sync_state(
    handle: HANDLE,
    in_sync_state: CF_IN_SYNC_STATE,
    in_sync_usn: Option<&mut i64>,
) -> Result<()> {
    let hr = unsafe {
        CfSetInSyncState(
            handle,
            in_sync_state,
            CF_SET_IN_SYNC_FLAG_NONE,
            in_sync_usn
                .map(|value| value as *mut i64)
                .unwrap_or(null_mut()),
        )
    };
    hresult_nonneg(hr, "CfSetInSyncState")
}

pub(crate) fn set_pin_state(
    handle: HANDLE,
    pin_state: CF_PIN_STATE,
    pin_flags: CF_SET_PIN_FLAGS,
) -> Result<()> {
    let hr = unsafe { CfSetPinState(handle, pin_state, pin_flags, null_mut()) };
    hresult_nonneg(hr, "CfSetPinState")
}

pub(crate) fn hydrate_placeholder_hresult(handle: HANDLE) -> i32 {
    unsafe { CfHydratePlaceholder(handle, 0, -1, CF_HYDRATE_FLAG_NONE, null_mut()) }
}

pub(crate) fn with_cf_oplock_handle<T, F>(
    path: &Path,
    flags: CF_OPEN_FILE_FLAGS,
    callback: F,
) -> Result<T>
where
    F: FnOnce(HANDLE) -> Result<T>,
{
    let wide_path = utf16_path(path);
    let mut protected_handle = INVALID_HANDLE_VALUE;
    let hr = unsafe { CfOpenFileWithOplock(wide_path.as_ptr(), flags, &mut protected_handle) };
    hresult_nonneg(hr, "CfOpenFileWithOplock")?;
    let protected_handle = ProtectedCfHandle(protected_handle);
    callback(protected_handle.raw())
}

pub(crate) fn report_provider_progress2(
    connection_key: CF_CONNECTION_KEY,
    transfer_key: i64,
    request_key: i64,
    provider_progress_total: i64,
    provider_progress_completed: i64,
    target_session_id: u32,
) -> Result<()> {
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

pub(crate) fn read_placeholder_standard_info(
    handle: HANDLE,
) -> Result<(CF_PLACEHOLDER_STANDARD_INFO, Vec<u8>)> {
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
        let info = unsafe {
            std::ptr::read_unaligned(info_buf.as_ptr().cast::<CF_PLACEHOLDER_STANDARD_INFO>())
        };
        return Ok((info, info_buf));
    }
}

pub(crate) fn path_placeholder_state_from_find(path: &Path) -> Result<CF_PLACEHOLDER_STATE> {
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

pub(crate) fn open_read_attributes_file(path: &Path) -> std::io::Result<std::fs::File> {
    let wide_path = utf16_path(path);
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    Ok(unsafe { std::fs::File::from_raw_handle(handle as _) })
}

pub(crate) fn local_file_identity_for_path(path: &Path) -> Result<(u32, u64)> {
    let file = open_read_attributes_file(path)
        .with_context(|| format!("failed to open {} for local file identity", path.display()))?;
    let mut info = BY_HANDLE_FILE_INFORMATION::default();
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle() as HANDLE, &mut info) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("GetFileInformationByHandle failed for {}", path.display()));
    }

    let file_index = ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64;
    Ok((info.dwVolumeSerialNumber, file_index))
}

fn callback_context(callback_info: &CF_CALLBACK_INFO) -> Option<&CallbackContext> {
    unsafe { (callback_info.CallbackContext as *const CallbackContext).as_ref() }
}

fn fetch_data_callback_params(
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) -> Option<FetchDataCallbackParams> {
    let callback_parameters = unsafe { callback_parameters.as_ref()? };
    let fetch_data = unsafe { callback_parameters.Anonymous.FetchData };
    Some(FetchDataCallbackParams {
        flags: fetch_data.Flags,
        required_file_offset: fetch_data.RequiredFileOffset,
        required_length: fetch_data.RequiredLength,
        optional_file_offset: fetch_data.OptionalFileOffset,
        optional_length: fetch_data.OptionalLength,
        last_dehydration_reason: fetch_data.LastDehydrationReason,
        last_dehydration_time: fetch_data.LastDehydrationTime,
    })
}

fn cancel_fetch_data_callback_params(
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) -> Option<CancelFetchDataCallbackParams> {
    let callback_parameters = unsafe { callback_parameters.as_ref()? };
    let cancel = unsafe { callback_parameters.Anonymous.Cancel };
    let fetch = unsafe { cancel.Anonymous.FetchData };
    Some(CancelFetchDataCallbackParams {
        file_offset: fetch.FileOffset,
        length: fetch.Length,
    })
}

fn notify_dehydrate_callback_params(
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) -> Option<NotifyDehydrateCallbackParams> {
    let callback_parameters = unsafe { callback_parameters.as_ref()? };
    let dehydrate = unsafe { callback_parameters.Anonymous.Dehydrate };
    Some(NotifyDehydrateCallbackParams {
        flags: dehydrate.Flags,
        reason: dehydrate.Reason,
    })
}

fn notify_dehydrate_completion_callback_params(
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) -> Option<NotifyDehydrateCompletionCallbackParams> {
    let callback_parameters = unsafe { callback_parameters.as_ref()? };
    let dehydrate = unsafe { callback_parameters.Anonymous.DehydrateCompletion };
    Some(NotifyDehydrateCompletionCallbackParams {
        flags: dehydrate.Flags,
        reason: dehydrate.Reason,
    })
}

fn close_completion_callback_params(
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) -> Option<CloseCompletionCallbackParams> {
    let callback_parameters = unsafe { callback_parameters.as_ref()? };
    let close_completion = unsafe { callback_parameters.Anonymous.CloseCompletion };
    Some(CloseCompletionCallbackParams {
        flags: close_completion.Flags,
    })
}

unsafe extern "system" fn callback_fetch_data(
    callback_info: *const CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) {
    let Some(callback_info_ref) = (unsafe { callback_info.as_ref() }) else {
        return;
    };
    let Some(context) = callback_context(callback_info_ref) else {
        return;
    };
    let Some(fetch_data) = fetch_data_callback_params(callback_parameters) else {
        return;
    };

    handle_callback_fetch_data(callback_info_ref, context, fetch_data);
}

unsafe extern "system" fn callback_cancel_fetch_data(
    callback_info: *const CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) {
    let Some(callback_info_ref) = (unsafe { callback_info.as_ref() }) else {
        return;
    };
    let Some(context) = callback_context(callback_info_ref) else {
        return;
    };
    let Some(cancel) = cancel_fetch_data_callback_params(callback_parameters) else {
        return;
    };

    handle_callback_cancel_fetch_data(callback_info_ref, context, cancel);
}

unsafe extern "system" fn callback_notify_dehydrate(
    callback_info: *const CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) {
    let Some(callback_info_ref) = (unsafe { callback_info.as_ref() }) else {
        return;
    };
    let Some(dehydrate) = notify_dehydrate_callback_params(callback_parameters) else {
        return;
    };

    handle_callback_notify_dehydrate(
        callback_info_ref,
        callback_context(callback_info_ref),
        dehydrate,
    );
}

unsafe extern "system" fn callback_notify_dehydrate_completion(
    callback_info: *const CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) {
    let Some(callback_info_ref) = (unsafe { callback_info.as_ref() }) else {
        return;
    };
    let Some(context) = callback_context(callback_info_ref) else {
        return;
    };
    let Some(dehydrate) = notify_dehydrate_completion_callback_params(callback_parameters) else {
        return;
    };

    handle_callback_notify_dehydrate_completion(callback_info_ref, context, dehydrate);
}

unsafe extern "system" fn callback_file_open(
    callback_info: *const CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) {
    if callback_parameters.is_null() {
        return;
    }
    let Some(callback_info_ref) = (unsafe { callback_info.as_ref() }) else {
        return;
    };
    let Some(context) = callback_context(callback_info_ref) else {
        return;
    };

    handle_callback_file_open(callback_info_ref, context);
}

unsafe extern "system" fn callback_file_close_completion(
    callback_info: *const CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) {
    let Some(callback_info_ref) = (unsafe { callback_info.as_ref() }) else {
        tracing::info!("close-completion: null callback_info or callback_parameters");
        return;
    };
    let Some(close_completion) = close_completion_callback_params(callback_parameters) else {
        tracing::info!("close-completion: null callback_info or callback_parameters");
        return;
    };
    let Some(context) = callback_context(callback_info_ref) else {
        tracing::info!("close-completion: null context ptr");
        return;
    };

    handle_callback_file_close_completion(callback_info_ref, context, close_completion);
}
