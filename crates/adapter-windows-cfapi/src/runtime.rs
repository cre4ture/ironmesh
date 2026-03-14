use crate::adapter::{CfapiAction, CfapiActionPlan};
use crate::auth::is_internal_device_auth_relative_path;
use crate::close_upload::{
    UploadDebounceState, UploadWorkerContext, schedule_debounced_close_upload,
};
use crate::connection_config::is_internal_connection_bootstrap_relative_path;
use crate::helpers::{normalize_path, path_to_relative, utf16_path, utf16_string};
use anyhow::{Result, anyhow};
use std::collections::BTreeMap;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRootRegistration {
    pub sync_root_id: String,
    pub display_name: String,
    pub root_path: PathBuf,
}

impl SyncRootRegistration {
    pub fn new(
        sync_root_id: impl Into<String>,
        display_name: impl Into<String>,
        root_path: impl Into<PathBuf>,
    ) -> Self {
        Self {
            sync_root_id: sync_root_id.into(),
            display_name: display_name.into(),
            root_path: root_path.into(),
        }
    }
}

pub trait Hydrator: Send + Sync + 'static {
    fn hydrate(&self, path: &str, remote_version: &str) -> Result<Vec<u8>>;
}

pub trait Uploader: Send + Sync + 'static {
    fn upload_reader(
        &self,
        path: &str,
        reader: &mut dyn std::io::Read,
        length: u64,
    ) -> Result<Option<String>>;

    fn delete_path(&self, _path: &str) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Default, Clone)]
pub struct DemoHydrator;

impl Hydrator for DemoHydrator {
    fn hydrate(&self, path: &str, remote_version: &str) -> Result<Vec<u8>> {
        Ok(
            format!("ironmesh cfapi hydration: path={path} version={remote_version}\n")
                .into_bytes(),
        )
    }
}

#[derive(Debug, Default, Clone)]
pub struct DemoUploader;

impl Uploader for DemoUploader {
    fn upload_reader(
        &self,
        path: &str,
        reader: &mut dyn std::io::Read,
        length: u64,
    ) -> Result<Option<String>> {
        // Read from the provided reader in chunks to avoid a single large allocation
        let mut read_bytes = 0usize;
        let mut buffer = [0u8; 8192];
        while read_bytes < length as usize {
            let to_read = std::cmp::min(buffer.len(), length as usize - read_bytes);
            let n = reader.read(&mut buffer[..to_read]).unwrap_or(0);
            if n == 0 {
                break;
            }
            read_bytes += n;
        }

        eprintln!("demo upload: path={} bytes={}", path, read_bytes);
        Ok(Some("demo-upload".to_string()))
    }

    fn delete_path(&self, path: &str) -> Result<()> {
        eprintln!("demo delete: path={path}");
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct CfapiRuntime {
    remote_versions_by_path: Mutex<BTreeMap<String, String>>,
}

impl CfapiRuntime {
    pub fn from_action_plan(plan: &CfapiActionPlan) -> Self {
        let mut remote_versions_by_path = BTreeMap::new();

        for action in &plan.actions {
            match action {
                CfapiAction::EnsurePlaceholder {
                    path,
                    remote_version,
                }
                | CfapiAction::HydrateOnDemand {
                    path,
                    remote_version,
                } => {
                    remote_versions_by_path.insert(normalize_path(path), remote_version.clone());
                }
                CfapiAction::EnsureDirectory { .. }
                | CfapiAction::QueueUploadOnClose { .. }
                | CfapiAction::MarkConflict { .. } => {}
            }
        }

        Self {
            remote_versions_by_path: Mutex::new(remote_versions_by_path),
        }
    }

    pub fn known_paths(&self) -> Vec<String> {
        self.remote_versions_by_path
            .lock()
            .expect("remote version map lock poisoned")
            .keys()
            .cloned()
            .collect()
    }

    pub fn handle_fetch_data(
        &self,
        relative_path: &str,
        hydrator: &dyn Hydrator,
    ) -> Result<Vec<u8>> {
        eprintln!("handle_fetch_data: requested path={relative_path}");
        let normalized = normalize_path(relative_path);
        let remote_versions = self
            .remote_versions_by_path
            .lock()
            .expect("remote version map lock poisoned");
        let remote_version = remote_versions
            .get(&normalized)
            .ok_or_else(|| anyhow!("unknown placeholder path: {relative_path}"))?;

        hydrator.hydrate(&normalized, remote_version)
    }

    pub fn set_remote_version(&self, relative_path: &str, remote_version: impl Into<String>) {
        self.remote_versions_by_path
            .lock()
            .expect("remote version map lock poisoned")
            .insert(normalize_path(relative_path), remote_version.into());
    }

    pub fn sync_from_action_plan(&self, plan: &CfapiActionPlan) -> usize {
        let mut changed = 0usize;
        let mut remote_versions = self
            .remote_versions_by_path
            .lock()
            .expect("remote version map lock poisoned");
        for action in &plan.actions {
            match action {
                CfapiAction::EnsurePlaceholder {
                    path,
                    remote_version,
                }
                | CfapiAction::HydrateOnDemand {
                    path,
                    remote_version,
                } => {
                    let normalized = normalize_path(path);
                    let update = match remote_versions.get(&normalized) {
                        Some(existing) => existing != remote_version,
                        None => true,
                    };
                    if update {
                        remote_versions.insert(normalized, remote_version.clone());
                        changed += 1;
                    }
                }
                CfapiAction::EnsureDirectory { .. }
                | CfapiAction::QueueUploadOnClose { .. }
                | CfapiAction::MarkConflict { .. } => {}
            }
        }
        changed
    }
}

// `normalize_path` now lives in `helpers.rs`.

pub fn create_placeholder(sync_root: &std::path::Path, rel_path: &str) -> anyhow::Result<()> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Storage::CloudFilters::*;
    let full_path =
        sync_root.join(rel_path.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
    let wide: Vec<u16> = full_path.as_os_str().encode_wide().chain(Some(0)).collect();
    let mut create_info = CF_PLACEHOLDER_CREATE_INFO {
        RelativeFileName: wide.as_ptr(),
        Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
        FileIdentity: null_mut(),
        FileIdentityLength: 0,
        FsMetadata: unsafe { std::mem::zeroed() },
        Result: 0,
        CreateUsn: 0,
    };
    let hr = unsafe {
        CfCreatePlaceholders(
            sync_root
                .as_os_str()
                .encode_wide()
                .chain(Some(0))
                .collect::<Vec<u16>>()
                .as_ptr(),
            &mut create_info,
            1,
            CF_CREATE_FLAG_STOP_ON_ERROR,
            std::ptr::null_mut(),
        )
    };
    hresult_to_result(hr, "CfCreatePlaceholders (monitor)")
}
pub fn hresult_to_result(hr: i32, operation: &str) -> anyhow::Result<()> {
    if hr == 0 {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{} failed with HRESULT 0x{:08x}",
            operation,
            hr
        ))
    }
}
use std::collections::HashSet;
use std::ffi::c_void;

use std::mem::{size_of, zeroed};

use std::path::Path;
use std::ptr::null;

use windows_sys::Win32::Storage::CloudFilters::*;
use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_NORMAL, FILE_BASIC_INFO};

pub struct SyncRootConnection {
    connection_key: CF_CONNECTION_KEY,
    _callback_table: Box<[CF_CALLBACK_REGISTRATION]>,
    _callback_context: Box<CallbackContext>,
}

impl Drop for SyncRootConnection {
    fn drop(&mut self) {
        unsafe {
            let _ = CfDisconnectSyncRoot(self.connection_key);
        }
        eprintln!(
            "dropped CFAPI connection with key {}, disconnected from sync root",
            self.connection_key
        )
    }
}

struct CallbackContext {
    sync_root: PathBuf,
    runtime: Arc<CfapiRuntime>,
    hydrator: Box<dyn Hydrator>,
    hydrated_once_paths: Mutex<HashSet<String>>,
    paths_by_file_id: Mutex<std::collections::HashMap<i64, String>>,
    upload_worker: Arc<UploadWorkerContext>,
    upload_debounce: Arc<UploadDebounceState>,
}

pub fn register_sync_root(registration: &SyncRootRegistration) -> Result<()> {
    validate_registration(registration)?;
    std::fs::create_dir_all(&registration.root_path)?;

    let root_path = utf16_path(&registration.root_path);
    let provider_name = utf16_string(&registration.display_name);
    let provider_version = utf16_string("0.1.0");
    let sync_root_identity = registration.sync_root_id.as_bytes();

    let registration_desc = CF_SYNC_REGISTRATION {
        StructSize: size_of::<CF_SYNC_REGISTRATION>() as u32,
        ProviderName: provider_name.as_ptr(),
        ProviderVersion: provider_version.as_ptr(),
        SyncRootIdentity: sync_root_identity.as_ptr().cast::<c_void>(),
        SyncRootIdentityLength: sync_root_identity.len() as u32,
        FileIdentity: sync_root_identity.as_ptr().cast::<c_void>(),
        FileIdentityLength: sync_root_identity.len() as u32,
        ProviderId: unsafe { zeroed() },
    };

    let policies = CF_SYNC_POLICIES {
        StructSize: size_of::<CF_SYNC_POLICIES>() as u32,
        Hydration: CF_HYDRATION_POLICY {
            Primary: CF_HYDRATION_POLICY_PROGRESSIVE,
            Modifier: CF_HYDRATION_POLICY_MODIFIER_NONE,
        },
        Population: CF_POPULATION_POLICY {
            Primary: CF_POPULATION_POLICY_FULL,
            Modifier: CF_POPULATION_POLICY_MODIFIER_NONE,
        },
        InSync: CF_INSYNC_POLICY_NONE,
        HardLink: CF_HARDLINK_POLICY_NONE,
        PlaceholderManagement: CF_PLACEHOLDER_MANAGEMENT_POLICY_DEFAULT,
    };

    let hr = unsafe {
        CfRegisterSyncRoot(
            root_path.as_ptr(),
            &registration_desc,
            &policies,
            CF_REGISTER_FLAG_DISABLE_ON_DEMAND_POPULATION_ON_ROOT | CF_REGISTER_FLAG_UPDATE,
        )
    };

    hresult_to_result(hr, "CfRegisterSyncRoot")
}

pub fn unregister_sync_root(root_path: &Path) -> Result<()> {
    let root_path_utf16 = utf16_path(root_path);
    let hr = unsafe { CfUnregisterSyncRoot(root_path_utf16.as_ptr()) };
    hresult_to_result(hr, "CfUnregisterSyncRoot")
}

fn parse_size_from_remote_version(remote_version: &str) -> Option<i64> {
    let (_, size_str) = remote_version.rsplit_once(":size=")?;
    size_str.parse::<i64>().ok().filter(|size| *size >= 0)
}

fn encode_file_identity(relative_path: &str, remote_version: &str) -> Vec<u8> {
    format!("path={relative_path}\nversion={remote_version}").into_bytes()
}

fn decode_path_from_file_identity(file_identity: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(file_identity).ok()?;
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("path=") {
            return Some(normalize_path(path));
        }
    }
    None
}

pub fn apply_action_plan(root_path: &Path, plan: &CfapiActionPlan) -> Result<()> {
    std::fs::create_dir_all(root_path)?;

    let mut placeholders: BTreeMap<String, String> = BTreeMap::new();
    for action in &plan.actions {
        match action {
            CfapiAction::EnsureDirectory { path } => {
                std::fs::create_dir_all(root_path.join(path.replace('/', "\\")))?;
            }
            CfapiAction::EnsurePlaceholder {
                path,
                remote_version,
            }
            | CfapiAction::HydrateOnDemand {
                path,
                remote_version,
            } => {
                let normalized = normalize_path(path);
                let full_path = root_path.join(normalized.replace('/', "\\"));
                if full_path.exists() {
                    continue;
                }
                if let Some(parent) = Path::new(&normalized).parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(root_path.join(parent))?;
                }
                placeholders.insert(normalized, remote_version.clone());
            }
            CfapiAction::QueueUploadOnClose { .. } | CfapiAction::MarkConflict { .. } => {}
        }
    }

    if placeholders.is_empty() {
        return Ok(());
    }

    struct PlaceholderInput {
        base_dir: PathBuf,
        child_name: String,
        relative_name_utf16: Vec<u16>,
        identity: Vec<u8>,
        metadata: CF_FS_METADATA,
    }

    let mut inputs = Vec::with_capacity(placeholders.len());
    for (relative_path, remote_version) in placeholders {
        let (parent_rel, child_name) = match relative_path.rsplit_once('/') {
            Some((parent, child)) => (parent, child),
            None => ("", relative_path.as_str()),
        };
        if child_name.is_empty() || child_name.contains('\\') || child_name.contains('/') {
            return Err(anyhow!(
                "invalid placeholder child name derived from path '{}'",
                relative_path
            ));
        }
        let base_dir = if parent_rel.is_empty() {
            root_path.to_path_buf()
        } else {
            root_path.join(parent_rel.replace('/', "\\"))
        };
        let basic_info = FILE_BASIC_INFO {
            FileAttributes: FILE_ATTRIBUTE_NORMAL,
            ..Default::default()
        };
        let file_size = parse_size_from_remote_version(&remote_version).unwrap_or(0);
        let metadata = CF_FS_METADATA {
            BasicInfo: basic_info,
            FileSize: file_size,
        };

        inputs.push(PlaceholderInput {
            base_dir,
            child_name: child_name.to_string(),
            relative_name_utf16: utf16_string(child_name),
            identity: encode_file_identity(&relative_path, &remote_version),
            metadata,
        });
    }

    let mut by_base_dir: BTreeMap<PathBuf, Vec<usize>> = BTreeMap::new();
    for (idx, input) in inputs.iter().enumerate() {
        by_base_dir
            .entry(input.base_dir.clone())
            .or_default()
            .push(idx);
    }

    for (base_dir, indices) in by_base_dir {
        let mut create_infos = Vec::with_capacity(indices.len());
        for &idx in &indices {
            let input = &inputs[idx];
            create_infos.push(CF_PLACEHOLDER_CREATE_INFO {
                RelativeFileName: input.relative_name_utf16.as_ptr(),
                FsMetadata: input.metadata,
                FileIdentity: input.identity.as_ptr().cast::<c_void>(),
                FileIdentityLength: input.identity.len() as u32,
                Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
                Result: 0,
                CreateUsn: 0,
            });
        }

        let base_path = utf16_path(&base_dir);
        let mut entries_processed = 0u32;
        let hr = unsafe {
            CfCreatePlaceholders(
                base_path.as_ptr(),
                create_infos.as_mut_ptr(),
                create_infos.len() as u32,
                CF_CREATE_FLAG_STOP_ON_ERROR,
                &mut entries_processed,
            )
        };

        let result = hresult_to_result(hr, "CfCreatePlaceholders (apply_action_plan)");
        if let Err(err) = &result {
            eprintln!("apply_action_plan: error creating placeholders: {err}");
            eprintln!("base_dir={}", base_dir.display());
            for idx in indices {
                let input = &inputs[idx];
                eprintln!(
                    "placeholder: relative_name={} identity={:?} metadata={{attributes={:x} filesize={}}}",
                    input.child_name,
                    input.identity,
                    input.metadata.BasicInfo.FileAttributes,
                    input.metadata.FileSize
                );
            }
            return result;
        }
    }

    Ok(())
}

pub fn connect_sync_root(
    registration: &SyncRootRegistration,
    runtime: Arc<CfapiRuntime>,
    hydrator: Box<dyn Hydrator>,
    uploader: std::sync::Arc<dyn Uploader>,
) -> Result<SyncRootConnection> {
    let root_path = utf16_path(&registration.root_path);
    let upload_worker = Arc::new(UploadWorkerContext {
        sync_root: registration.root_path.clone(),
        runtime: runtime.clone(),
        uploader: uploader.clone(),
    });
    let upload_debounce = Arc::new(UploadDebounceState::default());
    let mut callback_context = Box::new(CallbackContext {
        sync_root: registration.root_path.clone(),
        runtime,
        hydrator,
        hydrated_once_paths: Mutex::new(HashSet::new()),
        paths_by_file_id: Mutex::new(std::collections::HashMap::new()),
        upload_worker,
        upload_debounce,
    });

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
            (&mut *callback_context as *mut CallbackContext).cast::<c_void>(),
            CF_CONNECT_FLAG_NONE,
            &mut connection_key,
        )
    };
    hresult_to_result(hr, "CfConnectSyncRoot")?;

    eprintln!(
        "connected to CFAPI callbacks with connection key {}",
        connection_key
    );

    Ok(SyncRootConnection {
        connection_key,
        _callback_table: callback_table,
        _callback_context: callback_context,
    })
}

fn string_from_pcwstr(value: windows_sys::core::PCWSTR) -> String {
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

unsafe extern "system" fn callback_fetch_data(
    callback_info: *const CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) {
    if callback_info.is_null() || callback_parameters.is_null() {
        return;
    }

    let callback_info_ref = unsafe { &*callback_info };
    let context_ptr = callback_info_ref.CallbackContext as *const CallbackContext;
    if context_ptr.is_null() {
        return;
    }
    let context = unsafe { &*context_ptr };

    let normalized_path = string_from_pcwstr(callback_info_ref.NormalizedPath);
    let mut relative_path = if normalized_path.is_empty() {
        String::new()
    } else {
        path_to_relative(&context.sync_root, &normalized_path)
    };
    if relative_path.is_empty()
        && let Ok(paths_by_file_id) = context.paths_by_file_id.lock()
        && let Some(mapped) = paths_by_file_id.get(&callback_info_ref.FileId)
    {
        relative_path = mapped.clone();
    }
    if relative_path.is_empty()
        && !callback_info_ref.FileIdentity.is_null()
        && callback_info_ref.FileIdentityLength > 0
    {
        let file_identity = unsafe {
            std::slice::from_raw_parts(
                callback_info_ref.FileIdentity.cast::<u8>(),
                callback_info_ref.FileIdentityLength as usize,
            )
        };
        if let Some(decoded_path) = decode_path_from_file_identity(file_identity) {
            relative_path = decoded_path;
        }
    }
    if relative_path.is_empty() {
        eprintln!(
            "cfapi fetch-data could not resolve relative path: normalized_path='{}' file_id={}",
            normalized_path, callback_info_ref.FileId
        );
        return;
    }

    let payload = match context
        .runtime
        .handle_fetch_data(&relative_path, context.hydrator.as_ref())
    {
        Ok(data) => data,
        Err(err) => {
            eprintln!("cfapi fetch-data hydration error: {err}");
            return;
        }
    };

    if let Ok(mut hydrated_paths) = context.hydrated_once_paths.lock() {
        hydrated_paths.insert(relative_path.clone());
    }

    if let Err(err) = execute_transfer_data(callback_info_ref, callback_parameters, &payload) {
        eprintln!("cfapi transfer-data execution error: {err}");
    }
}

unsafe extern "system" fn callback_file_open(
    callback_info: *const CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) {
    if callback_info.is_null() || callback_parameters.is_null() {
        return;
    }

    let callback_info_ref = unsafe { &*callback_info };
    let context_ptr = callback_info_ref.CallbackContext as *const CallbackContext;
    if context_ptr.is_null() {
        return;
    }
    let context = unsafe { &*context_ptr };

    // Map FileId -> relative path for follow-up callbacks that may not include NormalizedPath.
    let normalized_path = string_from_pcwstr(callback_info_ref.NormalizedPath);
    let relative = path_to_relative(&context.sync_root, &normalized_path);
    if !relative.is_empty()
        && let Ok(mut paths_by_file_id) = context.paths_by_file_id.lock()
    {
        paths_by_file_id.insert(callback_info_ref.FileId, relative.clone());
    }
}

unsafe extern "system" fn callback_file_close_completion(
    callback_info: *const CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) {
    if callback_info.is_null() || callback_parameters.is_null() {
        eprintln!("close-completion: null callback_info or callback_parameters");
        return;
    }

    let callback_info_ref = unsafe { &*callback_info };
    let context_ptr = callback_info_ref.CallbackContext as *const CallbackContext;
    if context_ptr.is_null() {
        eprintln!("close-completion: null context ptr");
        return;
    }
    let context = unsafe { &*context_ptr };
    let normalized_path = string_from_pcwstr(callback_info_ref.NormalizedPath);

    let close_completion = unsafe { (*callback_parameters).Anonymous.CloseCompletion };
    eprintln!(
        "close-completion: flags={:x} path={}",
        close_completion.Flags, normalized_path
    );
    if (close_completion.Flags & CF_CALLBACK_CLOSE_COMPLETION_FLAG_DELETED) != 0 {
        eprintln!("close-completion: file deleted, skipping upload");
        return;
    }

    if normalized_path.is_empty() {
        eprintln!("close-completion: empty normalized path");
        return;
    }

    let relative_path = path_to_relative(&context.sync_root, &normalized_path);
    if is_internal_device_auth_relative_path(&relative_path)
        || is_internal_connection_bootstrap_relative_path(&relative_path)
    {
        eprintln!(
            "close-completion: skipping internal config file {}",
            relative_path
        );
        return;
    }
    if !relative_path.is_empty()
        && let Ok(mut paths_by_file_id) = context.paths_by_file_id.lock()
    {
        paths_by_file_id.insert(callback_info_ref.FileId, relative_path.clone());
    }
    eprintln!(
        "close-completion: relative_path={}, normalized_path={}, sync_root={:?}",
        relative_path, normalized_path, context.sync_root
    );
    schedule_debounced_close_upload(
        context.upload_worker.clone(),
        context.upload_debounce.clone(),
        relative_path,
    );
}

fn execute_transfer_data(
    callback_info: &CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
    payload: &[u8],
) -> Result<()> {
    let fetch_data = unsafe { (*callback_parameters).Anonymous.FetchData };
    let required_offset = fetch_data.RequiredFileOffset.max(0) as usize;
    let required_length = fetch_data.RequiredLength.max(0) as usize;

    let start = required_offset.min(payload.len());
    let max_len = payload.len().saturating_sub(start);
    let transfer_len = required_length.min(max_len);
    let transfer_slice = &payload[start..start + transfer_len];

    let transfer_data = CF_OPERATION_PARAMETERS_0_0 {
        Flags: CF_OPERATION_TRANSFER_DATA_FLAG_NONE,
        CompletionStatus: 0,
        Buffer: transfer_slice.as_ptr().cast::<c_void>(),
        Offset: required_offset as i64,
        Length: transfer_slice.len() as i64,
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
    hresult_to_result(hr, "CfExecute")
}

fn validate_registration(registration: &SyncRootRegistration) -> Result<()> {
    if registration.sync_root_id.trim().is_empty() {
        return Err(anyhow!("sync root id cannot be empty"));
    }
    if registration.display_name.trim().is_empty() {
        return Err(anyhow!("display name cannot be empty"));
    }
    if registration.root_path.as_os_str().is_empty() {
        return Err(anyhow!("root path cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_validation_rejects_empty_inputs() {
        let registration = SyncRootRegistration::new("", "Ironmesh", "C:/ironmesh");
        assert!(register_sync_root(&registration).is_err());

        let registration = SyncRootRegistration::new("id", "", "C:/ironmesh");
        assert!(register_sync_root(&registration).is_err());
    }

    #[test]
    fn runtime_fetches_hydration_for_known_file() {
        let plan = CfapiActionPlan {
            actions: vec![CfapiAction::HydrateOnDemand {
                path: "docs/readme.md".to_string(),
                remote_version: "v7".to_string(),
            }],
        };

        let runtime = CfapiRuntime::from_action_plan(&plan);
        let hydrated = runtime
            .handle_fetch_data("docs/readme.md", &DemoHydrator)
            .expect("hydration should succeed for known file");

        let payload = String::from_utf8(hydrated).expect("demo hydrator emits utf8 payload");
        assert!(payload.contains("docs/readme.md"));
        assert!(payload.contains("v7"));
    }

    #[test]
    fn runtime_rejects_unknown_file() {
        let runtime = CfapiRuntime::default();
        assert!(
            runtime
                .handle_fetch_data("missing.txt", &DemoHydrator)
                .is_err()
        );
    }

    #[test]
    fn runtime_normalizes_backslash_paths() {
        let plan = CfapiActionPlan {
            actions: vec![CfapiAction::HydrateOnDemand {
                path: "docs\\notes.txt".to_string(),
                remote_version: "v3".to_string(),
            }],
        };

        let runtime = CfapiRuntime::from_action_plan(&plan);
        let hydrated = runtime
            .handle_fetch_data("docs/notes.txt", &DemoHydrator)
            .expect("path normalization should resolve equivalent separators");

        let payload = String::from_utf8(hydrated).expect("demo hydrator emits utf8 payload");
        assert!(payload.contains("docs/notes.txt"));
    }
}
