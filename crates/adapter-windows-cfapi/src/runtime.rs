use crate::adapter::{CfapiAction, CfapiActionPlan};
use crate::auth::is_internal_client_identity_relative_path;
use crate::cfapi::{
    cf_ensure_placeholder_identity, cf_get_placeholder_standard_info,
    cf_get_placeholder_standard_info_with_identity, cf_report_provider_progress2, cf_set_in_sync,
    cf_set_not_in_sync, describe_path_state, open_sync_path, path_placeholder_state,
};
use crate::cfapi_safe_wrap::{
    CancelFetchDataCallbackParams, CloseCompletionCallbackParams, FetchDataCallbackParams,
    NotifyDehydrateCallbackParams, NotifyDehydrateCompletionCallbackParams, callback_file_identity,
    callback_process_log_info, callback_target_session_id,
    connect_sync_root as cf_connect_sync_root, create_placeholders as cf_create_placeholders,
    disconnect_sync_root as cf_disconnect_sync_root, empty_fs_metadata,
    execute_ack_dehydrate as cf_execute_ack_dehydrate,
    execute_transfer_data_chunk as cf_execute_transfer_data_chunk,
    execute_transfer_data_failure as cf_execute_transfer_data_failure, string_from_pcwstr,
    unregister_sync_root as cf_unregister_sync_root,
};
use crate::close_upload::{
    UploadDebounceState, UploadWorkerContext, schedule_debounced_close_upload,
};
use crate::connection_config::is_internal_connection_bootstrap_relative_path;
use crate::helpers::{
    PlaceholderFileIdentity, decode_path_from_file_identity,
    encode_placeholder_file_identity_metadata, normalize_path, path_to_relative, utf16_path,
    utf16_string,
};
use crate::placeholder_metadata::{
    record_in_sync_local_file_state, refresh_remote_placeholder_state,
};
use crate::snapshot_cache::is_internal_remote_snapshot_relative_path;
use crate::sync_root_identity::{
    SyncRootIdentity, load_registered_sync_root_context, normalize_prefix,
};
use anyhow::{Context, Result, anyhow};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::ffi::c_void;
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;
use widestring::U16String;
use wincs::{
    HydrationPolicy, HydrationType, PopulationType, Registration, SecurityId, SyncRootId,
    SyncRootIdBuilder,
};
use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND, NTSTATUS, STATUS_CLOUD_FILE_NOT_IN_SYNC,
    STATUS_CLOUD_FILE_NOT_UNDER_SYNC_ROOT, STATUS_CLOUD_FILE_PINNED,
    STATUS_CLOUD_FILE_REQUEST_CANCELED, STATUS_CLOUD_FILE_UNSUCCESSFUL, STATUS_SUCCESS,
};
use windows_sys::Win32::Storage::CloudFilters::*;
use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_NORMAL, FILE_BASIC_INFO};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncRootRegistration {
    pub sync_root_id: String,
    pub display_name: String,
    pub root_path: PathBuf,
    pub cluster_id: uuid::Uuid,
    pub prefix: String,
}

impl SyncRootRegistration {
    pub fn new(
        sync_root_id: impl Into<String>,
        display_name: impl Into<String>,
        root_path: impl Into<PathBuf>,
        cluster_id: uuid::Uuid,
        prefix: Option<&str>,
    ) -> Self {
        Self {
            sync_root_id: sync_root_id.into(),
            display_name: display_name.into(),
            root_path: root_path.into(),
            cluster_id,
            prefix: normalize_prefix(prefix),
        }
    }
}

pub trait Hydrator: Send + Sync + 'static {
    fn hydrate(&self, path: &str, remote_version: &str) -> Result<Vec<u8>>;

    fn hydrate_range_to_writer(
        &self,
        request: HydrationRequest<'_>,
        writer: &mut dyn Write,
        on_progress: &mut dyn FnMut(HydrationProgress),
        should_cancel: &dyn Fn() -> bool,
    ) -> Result<HydrationResult> {
        if should_cancel() {
            return Err(anyhow!("hydration canceled for {}", request.path));
        }

        let payload = self.hydrate(request.path, request.remote_version)?;
        let range_start = request.offset.min(payload.len() as u64);
        let range_end_exclusive = range_start
            .saturating_add(request.length)
            .min(payload.len() as u64);
        let range_length = range_end_exclusive.saturating_sub(range_start);

        on_progress(HydrationProgress {
            object_size_bytes: payload.len() as u64,
            range_start,
            range_length,
            bytes_transferred: 0,
        });

        let slice = &payload[range_start as usize..range_end_exclusive as usize];
        writer
            .write_all(slice)
            .map_err(|err| anyhow!("failed to write hydrated bytes for {}: {err}", request.path))?;
        writer
            .flush()
            .map_err(|err| anyhow!("failed to flush hydrated bytes for {}: {err}", request.path))?;

        on_progress(HydrationProgress {
            object_size_bytes: payload.len() as u64,
            range_start,
            range_length,
            bytes_transferred: slice.len() as u64,
        });

        Ok(HydrationResult {
            object_size_bytes: payload.len() as u64,
            range_start,
            range_length,
            bytes_transferred: slice.len() as u64,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HydrationRequest<'a> {
    pub path: &'a str,
    pub remote_version: &'a str,
    pub offset: u64,
    pub length: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HydrationProgress {
    pub object_size_bytes: u64,
    pub range_start: u64,
    pub range_length: u64,
    pub bytes_transferred: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HydrationResult {
    pub object_size_bytes: u64,
    pub range_start: u64,
    pub range_length: u64,
    pub bytes_transferred: u64,
}

pub trait Uploader: Send + Sync + 'static {
    fn upload_reader(
        &self,
        path: &str,
        reader: &mut dyn std::io::Read,
        length: u64,
    ) -> Result<Option<String>>;

    fn rename_path(&self, _from_path: &str, _to_path: &str) -> Result<bool> {
        Ok(false)
    }

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

        tracing::info!("demo upload: path={} bytes={}", path, read_bytes);
        Ok(Some("demo-upload".to_string()))
    }

    fn delete_path(&self, path: &str) -> Result<()> {
        tracing::info!("demo delete: path={path}");
        Ok(())
    }

    fn rename_path(&self, from_path: &str, to_path: &str) -> Result<bool> {
        tracing::info!("demo rename: from_path={from_path} to_path={to_path}");
        Ok(true)
    }
}

#[derive(Debug, Default)]
pub struct CfapiRuntime {
    remote_versions_by_path: Mutex<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DesiredSyncState {
    InSync,
    NotInSync,
}

fn placeholder_info_matches_desired_sync_state(
    info: &CF_PLACEHOLDER_STANDARD_INFO,
    desired_state: DesiredSyncState,
) -> bool {
    match desired_state {
        DesiredSyncState::InSync => info.InSyncState == CF_IN_SYNC_STATE_IN_SYNC,
        DesiredSyncState::NotInSync => info.InSyncState == CF_IN_SYNC_STATE_NOT_IN_SYNC,
    }
}

fn path_matches_desired_sync_state(path: &Path, desired_state: DesiredSyncState) -> bool {
    let file = match open_sync_path(path, false) {
        Ok(file) => file,
        Err(_) => return false,
    };
    let info = match cf_get_placeholder_standard_info(&file) {
        Ok(info) => info,
        Err(_) => return false,
    };

    placeholder_info_matches_desired_sync_state(&info, desired_state)
}

fn path_placeholder_identity_missing(path: &Path) -> bool {
    let file = match open_sync_path(path, false) {
        Ok(file) => file,
        Err(_) => return false,
    };
    match cf_get_placeholder_standard_info_with_identity(&file) {
        Ok(info) => info.file_identity().is_empty(),
        Err(_) => false,
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SyncStateReconcileStats {
    pub marked_in_sync: usize,
    pub marked_not_in_sync: usize,
    pub marked_directories_in_sync: usize,
    pub marked_directories_not_in_sync: usize,
    pub skipped_missing: usize,
    pub skipped_non_placeholder: usize,
    pub failed: usize,
}

impl CfapiRuntime {
    pub fn from_action_plan(plan: &CfapiActionPlan) -> Self {
        let mut remote_versions_by_path = BTreeMap::new();

        for action in &plan.actions {
            match action {
                CfapiAction::EnsurePlaceholder {
                    path,
                    remote_version,
                    ..
                }
                | CfapiAction::HydrateOnDemand {
                    path,
                    remote_version,
                    ..
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
        tracing::info!("handle_fetch_data: requested path={relative_path}");
        let normalized = normalize_path(relative_path);
        let remote_version = self.resolve_remote_version(&normalized)?;

        hydrator.hydrate(&normalized, &remote_version)
    }

    pub fn resolve_remote_version(&self, relative_path: &str) -> Result<String> {
        let normalized = normalize_path(relative_path);
        self.remote_versions_by_path
            .lock()
            .expect("remote version map lock poisoned")
            .get(&normalized)
            .cloned()
            .ok_or_else(|| anyhow!("unknown placeholder path: {relative_path}"))
    }

    pub fn set_remote_version(&self, relative_path: &str, remote_version: impl Into<String>) {
        self.remote_versions_by_path
            .lock()
            .expect("remote version map lock poisoned")
            .insert(normalize_path(relative_path), remote_version.into());
    }

    pub fn sync_from_action_plan(&self, plan: &CfapiActionPlan) -> usize {
        let mut next_remote_versions = BTreeMap::new();
        for action in &plan.actions {
            match action {
                CfapiAction::EnsurePlaceholder {
                    path,
                    remote_version,
                    ..
                }
                | CfapiAction::HydrateOnDemand {
                    path,
                    remote_version,
                    ..
                } => {
                    next_remote_versions.insert(normalize_path(path), remote_version.clone());
                }
                CfapiAction::EnsureDirectory { .. }
                | CfapiAction::QueueUploadOnClose { .. }
                | CfapiAction::MarkConflict { .. } => {}
            }
        }
        let mut remote_versions = self
            .remote_versions_by_path
            .lock()
            .expect("remote version map lock poisoned");
        let changed = remote_versions
            .iter()
            .any(|(path, version)| next_remote_versions.get(path) != Some(version))
            || next_remote_versions
                .iter()
                .any(|(path, version)| remote_versions.get(path) != Some(version));
        *remote_versions = next_remote_versions;
        usize::from(changed)
    }
}

// `normalize_path` now lives in `helpers.rs`.

pub fn create_placeholder(
    sync_root: &std::path::Path,
    rel_path: &str,
    provider_instance_id: uuid::Uuid,
) -> anyhow::Result<()> {
    use windows_sys::Win32::Storage::CloudFilters::*;
    let relative_name = rel_path.replace('/', "\\");
    let wide: Vec<u16> = relative_name.encode_utf16().chain(Some(0)).collect();
    let mut identity = PlaceholderFileIdentity::new(rel_path);
    identity.provider_instance_id = Some(provider_instance_id);
    let encoded_identity = encode_placeholder_file_identity_metadata(&identity);
    let mut create_info = CF_PLACEHOLDER_CREATE_INFO {
        RelativeFileName: wide.as_ptr(),
        Flags: CF_PLACEHOLDER_CREATE_FLAG_MARK_IN_SYNC,
        FileIdentity: encoded_identity.as_ptr().cast::<c_void>(),
        FileIdentityLength: encoded_identity.len() as u32,
        FsMetadata: empty_fs_metadata(),
        Result: 0,
        CreateUsn: 0,
    };
    let sync_root_utf16 = sync_root
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<u16>>();
    cf_create_placeholders(
        &sync_root_utf16,
        std::slice::from_mut(&mut create_info),
        CF_CREATE_FLAG_STOP_ON_ERROR,
        None,
        "CfCreatePlaceholders (monitor)",
    )
}

pub struct SyncRootConnection {
    connection_key: CF_CONNECTION_KEY,
    _callback_table: Box<[CF_CALLBACK_REGISTRATION]>,
    _callback_context: Box<CallbackContext>,
}

impl Drop for SyncRootConnection {
    fn drop(&mut self) {
        cf_disconnect_sync_root(self.connection_key);
        tracing::info!(
            "dropped CFAPI connection with key {}, disconnected from sync root",
            self.connection_key
        )
    }
}

pub(crate) struct CallbackContext {
    sync_root: PathBuf,
    provider_instance_id: uuid::Uuid,
    runtime: Arc<CfapiRuntime>,
    hydrator: Box<dyn Hydrator>,
    hydrated_once_paths: Mutex<HashSet<String>>,
    paths_by_file_id: Mutex<HashMap<i64, String>>,
    fetch_cancellations: Mutex<HashMap<i64, Arc<AtomicBool>>>,
    upload_worker: Arc<UploadWorkerContext>,
    upload_debounce: Arc<UploadDebounceState>,
}

pub fn register_sync_root(registration: &SyncRootRegistration) -> Result<SyncRootIdentity> {
    validate_registration(registration)?;
    std::fs::create_dir_all(&registration.root_path)?;

    let expected_shell_sync_root_id = build_shell_sync_root_id(registration)?;
    let expected_shell_sync_root_id_string =
        expected_shell_sync_root_id.as_hstring().to_string_lossy();
    let expected_identity = |provider_instance_id| {
        SyncRootIdentity::new(
            provider_instance_id,
            registration.cluster_id,
            registration.sync_root_id.clone(),
            registration.prefix.clone(),
        )
    };

    if let Some(existing) = load_registered_sync_root_context(&registration.root_path)? {
        if existing.identity.sync_root_id != registration.sync_root_id
            || existing.identity.cluster_id != registration.cluster_id
            || existing.identity.prefix != registration.prefix
        {
            return Err(anyhow!(
                "sync root {} at {} is registered to a different IronMesh root (registered: sync_root_id={} cluster_id={} prefix='{}'; requested: sync_root_id={} cluster_id={} prefix='{}')",
                registration.display_name,
                registration.root_path.display(),
                existing.identity.sync_root_id,
                existing.identity.cluster_id,
                existing.identity.prefix,
                registration.sync_root_id,
                registration.cluster_id,
                registration.prefix
            ));
        }
        return Ok(existing.identity);
    }

    if std::fs::read_dir(&registration.root_path)?
        .next()
        .transpose()?
        .is_some()
    {
        return Err(anyhow!(
            "refusing to register non-empty folder {} as a new sync root",
            registration.root_path.display()
        ));
    }

    let display_name = U16String::from_str(&registration.display_name);
    let provider_version = U16String::from_str(env!("CARGO_PKG_VERSION"));
    let icon_resource = current_executable_icon_resource()?;
    let sync_root_identity = expected_identity(uuid::Uuid::now_v7());
    let sync_root_identity_blob = sync_root_identity.encoded();
    tracing::info!(
        "sync-root registration: path={} hydration_type=Progressive hydration_policy=allow_platform_dehydration population_type=AlwaysFull allow_pinning=true cluster_id={} prefix='{}' provider_instance_id={}",
        registration.root_path.display(),
        registration.cluster_id,
        registration.prefix,
        sync_root_identity.provider_instance_id
    );

    Registration::from_sync_root_id(&expected_shell_sync_root_id)
        .display_name(display_name.as_ref())
        .icon(icon_resource, 0)
        .version(provider_version.as_ref())
        .hydration_type(HydrationType::Progressive)
        .hydration_policy(HydrationPolicy::default().allow_platform_dehydration())
        // The current adapter eagerly materializes the full namespace and does not
        // implement on-demand FETCH_PLACEHOLDERS callbacks, so Explorer must treat
        // the sync root as fully populated.
        .population_type(PopulationType::AlwaysFull)
        .allow_pinning()
        .show_siblings_as_group()
        .blob(&sync_root_identity_blob)
        .register(&registration.root_path)
        .map_err(|error| anyhow!("failed to register sync root with Explorer shell: {error}"))?;

    match load_registered_sync_root_context(&registration.root_path) {
        Ok(Some(existing)) => {
            tracing::info!(
                "sync-root registration: confirmed Windows registration id={} provider_instance_id={}",
                existing.windows_sync_root_id,
                existing.identity.provider_instance_id
            );
        }
        Ok(None) => {
            tracing::warn!(
                "sync-root registration: Windows did not report id={} immediately after registration",
                expected_shell_sync_root_id_string
            );
        }
        Err(err) => {
            tracing::warn!(
                "sync-root registration: failed to re-query Windows registration {}: {:#}",
                expected_shell_sync_root_id_string,
                err
            );
        }
    }

    Ok(sync_root_identity)
}

pub fn unregister_sync_root(root_path: &Path) -> Result<()> {
    if root_path.as_os_str().is_empty() {
        return Err(anyhow!("root path cannot be empty"));
    }

    let root_path_utf16 = utf16_path(root_path);
    let hr = cf_unregister_sync_root(&root_path_utf16);
    let hr_u32 = hr as u32;
    let file_not_found_hr = 0x8007_0000u32 | ERROR_FILE_NOT_FOUND;
    let path_not_found_hr = 0x8007_0000u32 | ERROR_PATH_NOT_FOUND;
    if hr == 0
        || hr == STATUS_CLOUD_FILE_NOT_UNDER_SYNC_ROOT
        || hr_u32 == file_not_found_hr
        || hr_u32 == path_not_found_hr
    {
        return Ok(());
    }

    Err(anyhow!(
        "failed to unregister sync root {}: HRESULT 0x{:08x}",
        root_path.display(),
        hr
    ))
}

fn parse_size_from_remote_version(remote_version: &str) -> Option<i64> {
    let (_, size_str) = remote_version.rsplit_once(":size=")?;
    size_str.parse::<i64>().ok().filter(|size| *size >= 0)
}

fn placeholder_file_size(remote_version: &str, remote_size: Option<u64>) -> i64 {
    remote_size
        .and_then(|size| i64::try_from(size).ok())
        .filter(|size| *size >= 0)
        .or_else(|| parse_size_from_remote_version(remote_version))
        .unwrap_or(0)
}

pub fn apply_action_plan(
    root_path: &Path,
    plan: &CfapiActionPlan,
    provider_instance_id: uuid::Uuid,
) -> Result<()> {
    std::fs::create_dir_all(root_path)?;

    let mut placeholders: BTreeMap<String, (String, String, Option<u64>)> = BTreeMap::new();
    let mut created_placeholder_paths = BTreeSet::new();
    for action in &plan.actions {
        match action {
            CfapiAction::EnsureDirectory { path } => {
                std::fs::create_dir_all(root_path.join(path.replace('/', "\\")))?;
            }
            CfapiAction::EnsurePlaceholder {
                path,
                remote_version,
                remote_content_hash,
                remote_size,
            }
            | CfapiAction::HydrateOnDemand {
                path,
                remote_version,
                remote_content_hash,
                remote_size,
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
                placeholders.insert(
                    normalized.clone(),
                    (
                        remote_version.clone(),
                        remote_content_hash.clone(),
                        *remote_size,
                    ),
                );
                created_placeholder_paths.insert(normalized);
            }
            CfapiAction::QueueUploadOnClose { .. } | CfapiAction::MarkConflict { .. } => {}
        }
    }

    if !placeholders.is_empty() {
        struct PlaceholderInput {
            base_dir: PathBuf,
            child_name: String,
            relative_name_utf16: Vec<u16>,
            identity: Vec<u8>,
            metadata: CF_FS_METADATA,
        }

        let mut inputs = Vec::with_capacity(placeholders.len());
        for (relative_path, (remote_version, remote_content_hash, remote_size)) in placeholders {
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
            let file_size = placeholder_file_size(&remote_version, remote_size);
            let metadata = CF_FS_METADATA {
                BasicInfo: basic_info,
                FileSize: file_size,
            };
            let mut identity = PlaceholderFileIdentity::new(&relative_path);
            identity.provider_instance_id = Some(provider_instance_id);
            identity.remote_version = Some(remote_version.clone());
            identity.remote_content_hash = Some(remote_content_hash.clone());
            identity.remote_size_bytes = remote_size;

            inputs.push(PlaceholderInput {
                base_dir,
                child_name: child_name.to_string(),
                relative_name_utf16: utf16_string(child_name),
                identity: encode_placeholder_file_identity_metadata(&identity),
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
            let result = cf_create_placeholders(
                &base_path,
                &mut create_infos,
                CF_CREATE_FLAG_STOP_ON_ERROR,
                Some(&mut entries_processed),
                "CfCreatePlaceholders (apply_action_plan)",
            );
            if let Err(err) = &result {
                tracing::info!("apply_action_plan: error creating placeholders: {err}");
                tracing::info!("base_dir={}", base_dir.display());
                for idx in indices {
                    let input = &inputs[idx];
                    tracing::info!(
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
    }

    for action in &plan.actions {
        match action {
            CfapiAction::EnsurePlaceholder {
                path,
                remote_version,
                remote_content_hash,
                remote_size,
            }
            | CfapiAction::HydrateOnDemand {
                path,
                remote_version,
                remote_content_hash,
                remote_size,
            } => {
                if created_placeholder_paths.contains(&normalize_path(path)) {
                    continue;
                }
                if let Err(err) = refresh_remote_placeholder_state(
                    root_path,
                    path,
                    provider_instance_id,
                    Some(remote_version),
                    Some(remote_content_hash),
                    *remote_size,
                ) {
                    tracing::info!(
                        "apply_action_plan: failed to refresh placeholder metadata for {}: {:#}",
                        path,
                        err
                    );
                }
            }
            CfapiAction::MarkConflict {
                path,
                remote_version,
                remote_content_hash,
                remote_size,
                ..
            } => {
                if let Err(err) = refresh_remote_placeholder_state(
                    root_path,
                    path,
                    provider_instance_id,
                    remote_version.as_deref(),
                    remote_content_hash.as_deref(),
                    *remote_size,
                ) {
                    tracing::info!(
                        "apply_action_plan: failed to refresh conflict placeholder metadata for {}: {:#}",
                        path,
                        err
                    );
                }
            }
            CfapiAction::EnsureDirectory { .. } | CfapiAction::QueueUploadOnClose { .. } => {}
        }
    }

    Ok(())
}

fn collect_directory_candidates(plan: &CfapiActionPlan) -> BTreeSet<String> {
    let mut directories = BTreeSet::new();

    for action in &plan.actions {
        match action {
            CfapiAction::EnsureDirectory { path } => {
                record_ancestor_directories(&mut directories, path, true);
            }
            CfapiAction::EnsurePlaceholder { path, .. }
            | CfapiAction::HydrateOnDemand { path, .. }
            | CfapiAction::QueueUploadOnClose { path, .. }
            | CfapiAction::MarkConflict { path, .. } => {
                record_ancestor_directories(&mut directories, path, false);
            }
        }
    }

    directories
}

fn record_ancestor_directories(directories: &mut BTreeSet<String>, path: &str, include_self: bool) {
    let normalized = normalize_path(path);
    let segments = normalized
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return;
    }

    let limit = if include_self {
        segments.len()
    } else {
        segments.len().saturating_sub(1)
    };
    for depth in 1..=limit {
        directories.insert(segments[..depth].join("/"));
    }
}

fn path_has_pending_sync_activity(root_path: &Path, path: &Path) -> bool {
    let relative_path = path_to_relative(root_path, &path.to_string_lossy());
    if relative_path.is_empty()
        || is_internal_client_identity_relative_path(&relative_path)
        || is_internal_connection_bootstrap_relative_path(&relative_path)
        || is_internal_remote_snapshot_relative_path(&relative_path)
    {
        return false;
    }

    let metadata = match std::fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(_) => return true,
    };
    let file = match open_sync_path(path, false) {
        Ok(file) => file,
        Err(_) => return true,
    };
    let info = match cf_get_placeholder_standard_info(&file) {
        Ok(info) => info,
        Err(_) => return !metadata.is_dir(),
    };

    info.InSyncState != CF_IN_SYNC_STATE_IN_SYNC || info.ModifiedDataSize != 0
}

fn directory_should_be_in_sync(root_path: &Path, relative_path: &str) -> bool {
    let full_path = root_path.join(relative_path.replace('/', "\\"));
    if !full_path.exists() {
        return false;
    }

    for entry in WalkDir::new(&full_path).min_depth(1).into_iter().flatten() {
        if path_has_pending_sync_activity(root_path, entry.path()) {
            return false;
        }
    }

    true
}

fn reconcile_directory_sync_states_for_candidates(
    root_path: &Path,
    directory_paths: &BTreeSet<String>,
    stats: &mut SyncStateReconcileStats,
) {
    for relative_path in directory_paths.iter().rev() {
        let full_path = root_path.join(relative_path.replace('/', "\\"));
        if !full_path.exists() {
            stats.skipped_missing += 1;
            tracing::info!(
                "sync-state: skipped missing directory path={} state={}",
                relative_path,
                describe_path_state(&full_path)
            );
            continue;
        }

        let state_before = describe_path_state(&full_path);
        let metadata = match std::fs::metadata(&full_path) {
            Ok(metadata) => metadata,
            Err(err) => {
                stats.failed += 1;
                tracing::info!(
                    "sync-state: failed to read directory metadata for {}: {} state_before={}",
                    full_path.display(),
                    err,
                    state_before
                );
                continue;
            }
        };
        if !metadata.is_dir() {
            continue;
        }

        let desired_state = if directory_should_be_in_sync(root_path, relative_path) {
            DesiredSyncState::InSync
        } else {
            DesiredSyncState::NotInSync
        };

        let placeholder_state =
            path_placeholder_state(&full_path).unwrap_or(CF_PLACEHOLDER_STATE_NO_STATES);
        if matches!(
            placeholder_state,
            CF_PLACEHOLDER_STATE_INVALID | CF_PLACEHOLDER_STATE_NO_STATES
        ) {
            let file = match open_sync_path(&full_path, true) {
                Ok(file) => file,
                Err(err) => {
                    stats.failed += 1;
                    tracing::info!(
                        "sync-state: failed to open directory {} for sync-state update desired={:?}: {} state_before={}",
                        full_path.display(),
                        desired_state,
                        err,
                        state_before
                    );
                    continue;
                }
            };
            if let Err(err) = cf_ensure_placeholder_identity(&file, relative_path) {
                stats.failed += 1;
                tracing::info!(
                    "sync-state: failed to ensure directory placeholder identity for {} before sync-state update desired={:?}: {} state_before={}",
                    full_path.display(),
                    desired_state,
                    err,
                    state_before
                );
                continue;
            }
        } else if path_matches_desired_sync_state(&full_path, desired_state) {
            tracing::info!(
                "sync-state: skipped directory already {:?} path={} state_before={}",
                desired_state,
                relative_path,
                state_before
            );
            continue;
        }

        let file = match open_sync_path(&full_path, true) {
            Ok(file) => file,
            Err(err) => {
                stats.failed += 1;
                tracing::info!(
                    "sync-state: failed to open directory {} for sync-state update desired={:?}: {} state_before={}",
                    full_path.display(),
                    desired_state,
                    err,
                    state_before
                );
                continue;
            }
        };

        let result = match desired_state {
            DesiredSyncState::InSync => cf_set_in_sync(&file).map(|_| {
                stats.marked_directories_in_sync += 1;
            }),
            DesiredSyncState::NotInSync => cf_set_not_in_sync(&file).map(|_| {
                stats.marked_directories_not_in_sync += 1;
            }),
        };

        if let Err(err) = result {
            stats.failed += 1;
            tracing::info!(
                "sync-state: failed to set directory {:?} for {}: {:#} state_before={}",
                desired_state,
                full_path.display(),
                err,
                state_before
            );
        } else {
            tracing::info!(
                "sync-state: applied directory desired={:?} path={} state_before={} state_after={}",
                desired_state,
                relative_path,
                state_before,
                describe_path_state(&full_path)
            );
        }
    }
}

pub(crate) fn reconcile_ancestor_directory_sync_states(root_path: &Path, relative_path: &str) {
    let mut directory_paths = BTreeSet::new();
    record_ancestor_directories(&mut directory_paths, relative_path, false);
    if directory_paths.is_empty() {
        return;
    }

    let mut stats = SyncStateReconcileStats::default();
    reconcile_directory_sync_states_for_candidates(root_path, &directory_paths, &mut stats);
    tracing::info!(
        "sync-state: ancestor directory reconcile for {} => {:?}",
        relative_path,
        stats
    );
}

pub fn reconcile_sync_states(root_path: &Path, plan: &CfapiActionPlan) -> SyncStateReconcileStats {
    let mut desired_states = BTreeMap::<String, DesiredSyncState>::new();
    for action in &plan.actions {
        match action {
            CfapiAction::EnsurePlaceholder { path, .. }
            | CfapiAction::HydrateOnDemand { path, .. } => {
                desired_states.insert(normalize_path(path), DesiredSyncState::InSync);
            }
            CfapiAction::QueueUploadOnClose { path, .. }
            | CfapiAction::MarkConflict { path, .. } => {
                desired_states.insert(normalize_path(path), DesiredSyncState::NotInSync);
            }
            CfapiAction::EnsureDirectory { .. } => {}
        }
    }
    let directory_candidates = collect_directory_candidates(plan);

    tracing::info!(
        "sync-state: reconciling {} file paths and {} directories under {}",
        desired_states.len(),
        directory_candidates.len(),
        root_path.display()
    );
    let mut stats = SyncStateReconcileStats::default();
    for (relative_path, desired_state) in desired_states {
        let full_path = root_path.join(relative_path.replace('/', "\\"));
        if !full_path.exists() {
            stats.skipped_missing += 1;
            tracing::info!(
                "sync-state: skipped missing path={} desired={:?} state={}",
                relative_path,
                desired_state,
                describe_path_state(&full_path)
            );
            continue;
        }

        let state_before = describe_path_state(&full_path);
        let metadata = match std::fs::metadata(&full_path) {
            Ok(metadata) => metadata,
            Err(err) => {
                stats.failed += 1;
                tracing::info!(
                    "sync-state: failed to read metadata for {} desired={:?}: {} state_before={}",
                    full_path.display(),
                    desired_state,
                    err,
                    state_before
                );
                continue;
            }
        };

        if metadata.is_dir() {
            stats.skipped_non_placeholder += 1;
            tracing::info!(
                "sync-state: skipped non-placeholder path={} desired={:?} state_before={}",
                relative_path,
                desired_state,
                state_before
            );
            continue;
        }

        let placeholder_state =
            path_placeholder_state(&full_path).unwrap_or(CF_PLACEHOLDER_STATE_NO_STATES);
        match placeholder_state {
            CF_PLACEHOLDER_STATE_INVALID | CF_PLACEHOLDER_STATE_NO_STATES => {
                tracing::info!(
                    "sync-state: path is not a placeholder, attempting convert with identity path={} desired={:?} state_before={}",
                    relative_path,
                    desired_state,
                    state_before
                );
                match open_sync_path(&full_path, true) {
                    Ok(file) => {
                        if let Err(err) = cf_ensure_placeholder_identity(&file, &relative_path) {
                            stats.failed += 1;
                            tracing::info!(
                                "sync-state: failed to ensure placeholder identity for {} desired={:?}: {} state_before={}",
                                full_path.display(),
                                desired_state,
                                err,
                                state_before
                            );
                        }
                    }
                    Err(err) => {
                        stats.failed += 1;
                        tracing::info!(
                            "sync-state: failed to open {} for placeholder conversion desired={:?}: {} state_before={}",
                            full_path.display(),
                            desired_state,
                            err,
                            state_before
                        );
                        continue;
                    }
                }
            }
            _ if path_placeholder_identity_missing(&full_path) => {
                tracing::info!(
                    "sync-state: repairing missing placeholder identity path={} desired={:?} state_before={}",
                    relative_path,
                    desired_state,
                    state_before
                );
                match open_sync_path(&full_path, true) {
                    Ok(file) => {
                        if let Err(err) = cf_ensure_placeholder_identity(&file, &relative_path) {
                            stats.failed += 1;
                            tracing::info!(
                                "sync-state: failed to repair placeholder identity for {} desired={:?}: {} state_before={}",
                                full_path.display(),
                                desired_state,
                                err,
                                state_before
                            );
                            continue;
                        }
                    }
                    Err(err) => {
                        stats.failed += 1;
                        tracing::info!(
                            "sync-state: failed to open {} for placeholder identity repair desired={:?}: {} state_before={}",
                            full_path.display(),
                            desired_state,
                            err,
                            state_before
                        );
                        continue;
                    }
                }
            }
            _ if path_matches_desired_sync_state(&full_path, desired_state) => {
                tracing::info!(
                    "sync-state: skipped path already {:?} path={} state_before={}",
                    desired_state,
                    relative_path,
                    state_before
                );
                continue;
            }
            _ => {}
        }

        let file = match open_sync_path(&full_path, true) {
            Ok(file) => file,
            Err(err) => {
                stats.failed += 1;
                tracing::info!(
                    "sync-state: failed to open {} for sync-state update desired={:?}: {} state_before={}",
                    full_path.display(),
                    desired_state,
                    err,
                    state_before
                );
                continue;
            }
        };

        let result = match desired_state {
            DesiredSyncState::InSync => cf_set_in_sync(&file).map(|_| {
                stats.marked_in_sync += 1;
            }),
            DesiredSyncState::NotInSync => cf_set_not_in_sync(&file).map(|_| {
                stats.marked_not_in_sync += 1;
            }),
        };

        if let Err(err) = result {
            stats.failed += 1;
            tracing::info!(
                "sync-state: failed to set {:?} for {}: {:#} state_before={}",
                desired_state,
                full_path.display(),
                err,
                state_before
            );
        } else {
            tracing::info!(
                "sync-state: applied desired={:?} path={} state_before={} state_after={}",
                desired_state,
                relative_path,
                state_before,
                describe_path_state(&full_path)
            );
        }
    }

    reconcile_directory_sync_states_for_candidates(root_path, &directory_candidates, &mut stats);
    stats
}

pub fn connect_sync_root(
    registration: &SyncRootRegistration,
    provider_instance_id: uuid::Uuid,
    runtime: Arc<CfapiRuntime>,
    hydrator: Box<dyn Hydrator>,
    uploader: std::sync::Arc<dyn Uploader>,
) -> Result<SyncRootConnection> {
    let root_path = utf16_path(&registration.root_path);
    let upload_worker = Arc::new(UploadWorkerContext {
        sync_root: registration.root_path.clone(),
        provider_instance_id,
        runtime: runtime.clone(),
        uploader: uploader.clone(),
    });
    let upload_debounce = Arc::new(UploadDebounceState::default());
    let mut callback_context = Box::new(CallbackContext {
        sync_root: registration.root_path.clone(),
        provider_instance_id,
        runtime,
        hydrator,
        hydrated_once_paths: Mutex::new(HashSet::new()),
        paths_by_file_id: Mutex::new(HashMap::new()),
        fetch_cancellations: Mutex::new(HashMap::new()),
        upload_worker,
        upload_debounce,
    });
    let (connection_key, callback_table) = cf_connect_sync_root(&root_path, &mut callback_context)?;

    tracing::info!(
        "connected to CFAPI callbacks with connection key {}",
        connection_key
    );

    Ok(SyncRootConnection {
        connection_key,
        _callback_table: callback_table,
        _callback_context: callback_context,
    })
}

fn callback_request_identity(callback_info: &CF_CALLBACK_INFO) -> i64 {
    if callback_info.RequestKey != 0 {
        callback_info.RequestKey
    } else if callback_info.TransferKey != 0 {
        callback_info.TransferKey
    } else {
        callback_info.FileId
    }
}

fn describe_fetch_data_request_kind(flags: CF_CALLBACK_FETCH_DATA_FLAGS) -> String {
    let mut labels = Vec::new();

    if flags == CF_CALLBACK_FETCH_DATA_FLAG_NONE {
        labels.push("implicit-hydration".to_string());
    }
    if (flags & CF_CALLBACK_FETCH_DATA_FLAG_RECOVERY) != 0 {
        labels.push("recovery".to_string());
    }
    if (flags & CF_CALLBACK_FETCH_DATA_FLAG_EXPLICIT_HYDRATION) != 0 {
        labels.push("explicit-hydration".to_string());
    }

    let known_flags =
        CF_CALLBACK_FETCH_DATA_FLAG_RECOVERY | CF_CALLBACK_FETCH_DATA_FLAG_EXPLICIT_HYDRATION;
    let unknown_flags = flags & !known_flags;
    if unknown_flags != 0 {
        labels.push(format!("unknown-flags(0x{:x})", unknown_flags as u32));
    }

    if labels.is_empty() {
        "unspecified".to_string()
    } else {
        labels.join("+")
    }
}

fn resolve_relative_path_from_callback(
    callback_info: &CF_CALLBACK_INFO,
    context: &CallbackContext,
) -> Option<String> {
    let normalized_path = string_from_pcwstr(callback_info.NormalizedPath);
    let mut relative_path = if normalized_path.is_empty() {
        String::new()
    } else {
        path_to_relative(&context.sync_root, &normalized_path)
    };
    if relative_path.is_empty()
        && let Ok(paths_by_file_id) = context.paths_by_file_id.lock()
        && let Some(mapped) = paths_by_file_id.get(&callback_info.FileId)
    {
        relative_path = mapped.clone();
    }
    if relative_path.is_empty() && !callback_file_identity(callback_info).is_empty() {
        if let Some(decoded_path) =
            decode_path_from_file_identity(callback_file_identity(callback_info))
        {
            relative_path = decoded_path;
        }
    }

    if relative_path.is_empty() {
        None
    } else {
        Some(relative_path)
    }
}

fn report_fetch_progress(
    callback_info: &CF_CALLBACK_INFO,
    progress: HydrationProgress,
) -> Result<()> {
    let total = progress
        .object_size_bytes
        .max(progress.range_start.saturating_add(progress.range_length));
    let completed = progress
        .range_start
        .saturating_add(progress.bytes_transferred)
        .min(total);
    cf_report_provider_progress2(
        callback_info.ConnectionKey,
        callback_info.TransferKey,
        callback_info.RequestKey,
        total as i64,
        completed as i64,
        callback_target_session_id(callback_info),
    )
}

fn dehydrate_completion_status(
    placeholder_info: &CF_PLACEHOLDER_STANDARD_INFO,
    has_in_flight_upload: bool,
) -> NTSTATUS {
    if placeholder_info.PinState == CF_PIN_STATE_PINNED {
        STATUS_CLOUD_FILE_PINNED
    } else if has_in_flight_upload
        || placeholder_info.InSyncState != CF_IN_SYNC_STATE_IN_SYNC
        || placeholder_info.ModifiedDataSize != 0
    {
        STATUS_CLOUD_FILE_NOT_IN_SYNC
    } else {
        STATUS_SUCCESS
    }
}

fn execute_ack_dehydrate(
    callback_info: &CF_CALLBACK_INFO,
    completion_status: NTSTATUS,
) -> Result<()> {
    cf_execute_ack_dehydrate(callback_info, completion_status)
}

struct CfapiTransferWriter<'a> {
    callback_info: &'a CF_CALLBACK_INFO,
    next_offset: u64,
}

impl<'a> CfapiTransferWriter<'a> {
    fn new(callback_info: &'a CF_CALLBACK_INFO, start_offset: u64) -> Self {
        Self {
            callback_info,
            next_offset: start_offset,
        }
    }
}

impl Write for CfapiTransferWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        execute_transfer_data_chunk(self.callback_info, self.next_offset, buf)
            .map_err(std::io::Error::other)?;
        self.next_offset = self.next_offset.saturating_add(buf.len() as u64);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) fn handle_callback_fetch_data(
    callback_info_ref: &CF_CALLBACK_INFO,
    context: &CallbackContext,
    fetch_data: FetchDataCallbackParams,
) {
    let relative_path = match resolve_relative_path_from_callback(callback_info_ref, context) {
        Some(path) => path,
        None => {
            let normalized_path = string_from_pcwstr(callback_info_ref.NormalizedPath);
            tracing::info!(
                "cfapi fetch-data could not resolve relative path: normalized_path='{}' file_id={}",
                normalized_path,
                callback_info_ref.FileId
            );
            return;
        }
    };

    let remote_version = match context.runtime.resolve_remote_version(&relative_path) {
        Ok(version) => version,
        Err(err) => {
            tracing::info!("cfapi fetch-data missing remote version: {err}");
            return;
        }
    };

    let range_start = fetch_data.required_file_offset.max(0) as u64;
    let range_length = fetch_data.required_length.max(0) as u64;
    let optional_range_start = fetch_data.optional_file_offset.max(0) as u64;
    let optional_range_length = fetch_data.optional_length.max(0) as u64;
    let request_identity = callback_request_identity(callback_info_ref);
    let request_kind = describe_fetch_data_request_kind(fetch_data.flags);
    let process_info = callback_process_log_info(callback_info_ref);
    let full_path = context.sync_root.join(relative_path.replace('/', "\\"));
    let already_hydrated_once = context
        .hydrated_once_paths
        .lock()
        .map(|paths| paths.contains(&relative_path))
        .unwrap_or(false);
    let upload_snapshot = context
        .upload_debounce
        .debug_snapshot_for_path(&relative_path, 8);
    tracing::info!(
        "cfapi hydration-trigger: request={} transfer={} file_id={} session={} process_id={} process_image={} package_name={} application_id={} command_line={} path={} request_kind={} fetch_flags=0x{:x} required_offset={} required_length={} optional_offset={} optional_length={} last_dehydration_reason={} last_dehydration_time={}",
        request_identity,
        callback_info_ref.TransferKey,
        callback_info_ref.FileId,
        callback_target_session_id(callback_info_ref),
        process_info.process_id,
        process_info.image_path,
        process_info.package_name,
        process_info.application_id,
        process_info.command_line,
        relative_path,
        request_kind,
        fetch_data.flags as u32,
        range_start,
        range_length,
        optional_range_start,
        optional_range_length,
        fetch_data.last_dehydration_reason,
        fetch_data.last_dehydration_time
    );
    tracing::info!(
        "cfapi fetch-data begin: request={} transfer={} file_id={} session={} path={} remote_version={} offset={} length={} already_hydrated_once={} upload_debounce={} state={}",
        request_identity,
        callback_info_ref.TransferKey,
        callback_info_ref.FileId,
        callback_target_session_id(callback_info_ref),
        relative_path,
        remote_version,
        range_start,
        range_length,
        already_hydrated_once,
        upload_snapshot.to_log_string(),
        describe_path_state(&full_path)
    );
    let cancel_flag = Arc::new(AtomicBool::new(false));
    if let Ok(mut fetch_cancellations) = context.fetch_cancellations.lock() {
        fetch_cancellations.insert(request_identity, cancel_flag.clone());
    }

    let mut writer = CfapiTransferWriter::new(callback_info_ref, range_start);
    let mut progress_callback = |progress: HydrationProgress| {
        if let Err(err) = report_fetch_progress(callback_info_ref, progress) {
            tracing::info!("cfapi progress-report error: {err}");
        }
    };
    let should_cancel = || cancel_flag.load(Ordering::SeqCst);

    let result = context.hydrator.hydrate_range_to_writer(
        HydrationRequest {
            path: &relative_path,
            remote_version: &remote_version,
            offset: range_start,
            length: range_length,
        },
        &mut writer,
        &mut progress_callback,
        &should_cancel,
    );

    if let Ok(mut fetch_cancellations) = context.fetch_cancellations.lock() {
        fetch_cancellations.remove(&request_identity);
    }

    match result {
        Ok(result) => {
            if let Ok(mut hydrated_paths) = context.hydrated_once_paths.lock() {
                hydrated_paths.insert(relative_path.clone());
            }
            if result.object_size_bytes > 0 {
                match open_sync_path(&full_path, false)
                    .and_then(|file| cf_get_placeholder_standard_info(&file).map_err(std::io::Error::other))
                {
                    Ok(info)
                        if info.ModifiedDataSize == 0
                            && info.OnDiskDataSize >= result.object_size_bytes as i64 =>
                    {
                        if let Err(err) = record_in_sync_local_file_state(
                            &context.sync_root,
                            &relative_path,
                            context.provider_instance_id,
                        )
                        {
                            tracing::info!(
                                "cfapi fetch-data complete: failed to record in-sync local file hash for {}: {:#}",
                                relative_path,
                                err
                            );
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::info!(
                            "cfapi fetch-data complete: failed to inspect hydrated file {} for local hash capture: {}",
                            relative_path,
                            err
                        );
                    }
                }
            }
            tracing::info!(
                "cfapi fetch-data complete: request={} path={} object_size={} range_start={} range_length={} bytes_transferred={} state_after={} upload_debounce={}",
                request_identity,
                relative_path,
                result.object_size_bytes,
                result.range_start,
                result.range_length,
                result.bytes_transferred,
                describe_path_state(&full_path),
                context
                    .upload_debounce
                    .debug_snapshot_for_path(&relative_path, 8)
                    .to_log_string()
            );
        }
        Err(err) => {
            let request_end = range_start.saturating_add(range_length);
            let failure_offset = writer.next_offset.min(request_end);
            let failure_length = request_end.saturating_sub(failure_offset);
            let completion_status = if cancel_flag.load(Ordering::SeqCst) {
                STATUS_CLOUD_FILE_REQUEST_CANCELED
            } else {
                STATUS_CLOUD_FILE_UNSUCCESSFUL
            };
            if failure_length > 0 {
                if let Err(exec_err) = execute_transfer_data_failure(
                    callback_info_ref,
                    failure_offset,
                    failure_length,
                    completion_status,
                ) {
                    tracing::info!(
                        "cfapi fetch-data failure completion error: request={} path={} status=0x{:08x} offset={} length={} error={:#}",
                        request_identity,
                        relative_path,
                        completion_status as u32,
                        failure_offset,
                        failure_length,
                        exec_err
                    );
                }
            }
            tracing::info!(
                "cfapi fetch-data hydration error: request={} path={} error={:#} completion_status=0x{:08x} failure_offset={} failure_length={} state_after={} upload_debounce={}",
                request_identity,
                relative_path,
                err,
                completion_status as u32,
                failure_offset,
                failure_length,
                describe_path_state(&full_path),
                context
                    .upload_debounce
                    .debug_snapshot_for_path(&relative_path, 8)
                    .to_log_string()
            );
        }
    }
}

pub(crate) fn handle_callback_cancel_fetch_data(
    callback_info_ref: &CF_CALLBACK_INFO,
    context: &CallbackContext,
    cancel: CancelFetchDataCallbackParams,
) {
    let request_identity = callback_request_identity(callback_info_ref);
    if let Ok(fetch_cancellations) = context.fetch_cancellations.lock()
        && let Some(cancel_flag) = fetch_cancellations.get(&request_identity)
    {
        cancel_flag.store(true, Ordering::SeqCst);
    }

    let relative_path = resolve_relative_path_from_callback(callback_info_ref, context)
        .unwrap_or_else(|| String::from("<unknown>"));
    tracing::info!(
        "cfapi cancel-fetch-data: path={} offset={} length={}",
        relative_path,
        cancel.file_offset,
        cancel.length
    );
}

pub(crate) fn handle_callback_notify_dehydrate(
    callback_info_ref: &CF_CALLBACK_INFO,
    context: Option<&CallbackContext>,
    dehydrate: NotifyDehydrateCallbackParams,
) {
    let request_identity = callback_request_identity(callback_info_ref);
    let Some(context) = context else {
        let _ = execute_ack_dehydrate(callback_info_ref, STATUS_CLOUD_FILE_NOT_IN_SYNC);
        return;
    };

    let relative_path = match resolve_relative_path_from_callback(callback_info_ref, context) {
        Some(path) => path,
        None => {
            let normalized_path = string_from_pcwstr(callback_info_ref.NormalizedPath);
            tracing::info!(
                "cfapi notify-dehydrate: request={} could not resolve relative path normalized_path='{}' file_id={} flags=0x{:x} reason={}",
                request_identity,
                normalized_path,
                callback_info_ref.FileId,
                dehydrate.flags,
                dehydrate.reason
            );
            if let Err(err) =
                execute_ack_dehydrate(callback_info_ref, STATUS_CLOUD_FILE_NOT_IN_SYNC)
            {
                tracing::info!("cfapi notify-dehydrate ack error: {err}");
            }
            return;
        }
    };

    let full_path = context.sync_root.join(relative_path.replace('/', "\\"));
    let upload_snapshot = context
        .upload_debounce
        .debug_snapshot_for_path(&relative_path, 8);
    let completion_status = match open_sync_path(&full_path, false) {
        Ok(file) => match cf_get_placeholder_standard_info(&file) {
            Ok(placeholder_info) => dehydrate_completion_status(
                &placeholder_info,
                context
                    .upload_debounce
                    .has_in_flight_upload_for_path(&relative_path),
            ),
            Err(err) => {
                tracing::info!(
                    "cfapi notify-dehydrate: request={} path={} failed to read placeholder info: {} state={} upload_debounce={}",
                    request_identity,
                    relative_path,
                    err,
                    describe_path_state(&full_path),
                    upload_snapshot.to_log_string()
                );
                STATUS_CLOUD_FILE_NOT_IN_SYNC
            }
        },
        Err(err) => {
            tracing::info!(
                "cfapi notify-dehydrate: request={} path={} failed to open target: {} state={} upload_debounce={}",
                request_identity,
                relative_path,
                err,
                describe_path_state(&full_path),
                upload_snapshot.to_log_string()
            );
            STATUS_CLOUD_FILE_NOT_IN_SYNC
        }
    };

    tracing::info!(
        "cfapi notify-dehydrate: request={} transfer={} file_id={} path={} flags=0x{:x} reason={} decision_status=0x{:08x} state={} upload_debounce={}",
        request_identity,
        callback_info_ref.TransferKey,
        callback_info_ref.FileId,
        relative_path,
        dehydrate.flags,
        dehydrate.reason,
        completion_status as u32,
        describe_path_state(&full_path),
        upload_snapshot.to_log_string()
    );

    if let Err(err) = execute_ack_dehydrate(callback_info_ref, completion_status) {
        tracing::info!(
            "cfapi notify-dehydrate ack error: request={} path={} status=0x{:08x} error={:#}",
            request_identity,
            relative_path,
            completion_status as u32,
            err
        );
    }
}

pub(crate) fn handle_callback_notify_dehydrate_completion(
    callback_info_ref: &CF_CALLBACK_INFO,
    context: &CallbackContext,
    dehydrate: NotifyDehydrateCompletionCallbackParams,
) {
    let relative_path = resolve_relative_path_from_callback(callback_info_ref, context)
        .unwrap_or_else(|| String::from("<unknown>"));

    if relative_path != "<unknown>"
        && (dehydrate.flags & CF_CALLBACK_DEHYDRATE_COMPLETION_FLAG_DEHYDRATED) != 0
        && let Ok(mut hydrated_paths) = context.hydrated_once_paths.lock()
    {
        hydrated_paths.remove(&relative_path);
    }

    let full_path = if relative_path == "<unknown>" {
        context.sync_root.clone()
    } else {
        context.sync_root.join(relative_path.replace('/', "\\"))
    };

    tracing::info!(
        "cfapi dehydrate-completion: file_id={} path={} flags=0x{:x} reason={} state={} upload_debounce={}",
        callback_info_ref.FileId,
        relative_path,
        dehydrate.flags,
        dehydrate.reason,
        describe_path_state(&full_path),
        context
            .upload_debounce
            .debug_snapshot_for_path(&relative_path, 8)
            .to_log_string()
    );
}

pub(crate) fn handle_callback_file_open(
    callback_info_ref: &CF_CALLBACK_INFO,
    context: &CallbackContext,
) {
    // Map FileId -> relative path for follow-up callbacks that may not include NormalizedPath.
    let normalized_path = string_from_pcwstr(callback_info_ref.NormalizedPath);
    let relative = path_to_relative(&context.sync_root, &normalized_path);
    if !relative.is_empty()
        && let Ok(mut paths_by_file_id) = context.paths_by_file_id.lock()
    {
        paths_by_file_id.insert(callback_info_ref.FileId, relative.clone());
    }
}

pub(crate) fn handle_callback_file_close_completion(
    callback_info_ref: &CF_CALLBACK_INFO,
    context: &CallbackContext,
    close_completion: CloseCompletionCallbackParams,
) {
    let normalized_path = string_from_pcwstr(callback_info_ref.NormalizedPath);
    let process_info = callback_process_log_info(callback_info_ref);

    if process_info.process_id == std::process::id() {
        tracing::debug!(
            "close-completion: ignoring provider-originated close flags={:x} path={} process_id={} process_image={}",
            close_completion.flags,
            normalized_path,
            process_info.process_id,
            process_info.image_path
        );
        return;
    }

    tracing::debug!(
        "close-completion: flags={:x} path={} process_id={} process_image={}",
        close_completion.flags,
        normalized_path,
        process_info.process_id,
        process_info.image_path
    );
    if (close_completion.flags & CF_CALLBACK_CLOSE_COMPLETION_FLAG_DELETED) != 0 {
        tracing::debug!("close-completion: file deleted, skipping upload");
        return;
    }

    if normalized_path.is_empty() {
        tracing::debug!("close-completion: empty normalized path");
        return;
    }

    let relative_path = path_to_relative(&context.sync_root, &normalized_path);
    if is_internal_client_identity_relative_path(&relative_path)
        || is_internal_connection_bootstrap_relative_path(&relative_path)
        || is_internal_remote_snapshot_relative_path(&relative_path)
    {
        tracing::debug!(
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
    tracing::debug!(
        "close-completion: relative_path={} normalized_path={} sync_root={:?}",
        relative_path,
        normalized_path,
        context.sync_root
    );
    let full_path = context.sync_root.join(relative_path.replace('/', "\\"));
    match open_sync_path(&full_path, false) {
        Ok(file) => match cf_get_placeholder_standard_info_with_identity(&file) {
            Ok(info) if info.info().ModifiedDataSize == 0 => {
                tracing::debug!(
                    "close-completion: clean placeholder {} on_disk={} validated={} in_sync={} pin={}",
                    relative_path,
                    info.info().OnDiskDataSize,
                    info.info().ValidatedDataSize,
                    info.info().InSyncState,
                    info.info().PinState
                );
                return;
            }
            Ok(info) => {
                tracing::info!(
                    "close-completion: scheduling upload for dirty placeholder {} modified={} on_disk={} in_sync={} pin={}",
                    relative_path,
                    info.info().ModifiedDataSize,
                    info.info().OnDiskDataSize,
                    info.info().InSyncState,
                    info.info().PinState
                );
            }
            Err(err) => {
                tracing::info!(
                    "close-completion: placeholder info unavailable for {}; scheduling upload conservatively: {}",
                    relative_path,
                    err
                );
            }
        },
        Err(err) => {
            tracing::info!(
                "close-completion: could not open {} to inspect placeholder state before scheduling upload: {}",
                full_path.display(),
                err
            );
        }
    }
    schedule_debounced_close_upload(
        context.upload_worker.clone(),
        context.upload_debounce.clone(),
        relative_path,
    );
}

fn execute_transfer_data_chunk(
    callback_info: &CF_CALLBACK_INFO,
    offset: u64,
    payload: &[u8],
) -> Result<()> {
    cf_execute_transfer_data_chunk(callback_info, offset, payload)
}

fn execute_transfer_data_failure(
    callback_info: &CF_CALLBACK_INFO,
    offset: u64,
    length: u64,
    completion_status: NTSTATUS,
) -> Result<()> {
    cf_execute_transfer_data_failure(callback_info, offset, length, completion_status)
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
    if registration.prefix.contains('\\') {
        return Err(anyhow!("prefix must use normalized forward-slash separators"));
    }
    Ok(())
}

fn build_shell_sync_root_id(registration: &SyncRootRegistration) -> Result<SyncRootId> {
    SyncRootIdBuilder::new(U16String::from_str("Ironmesh"))
        .user_security_id(
            SecurityId::current_user().context("failed to resolve current Windows security id")?,
        )
        .account_name(U16String::from_str(&registration.sync_root_id))
        .build()
        .map_err(|error| anyhow!("failed to build shell sync root id: {error}"))
}

fn current_executable_icon_resource() -> Result<U16String> {
    let current_executable = std::env::current_exe()
        .context("failed to resolve current executable path for icon resource")?;
    Ok(U16String::from_os_str(current_executable.as_os_str()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registration_validation_rejects_empty_inputs() {
        let cluster_id = uuid::Uuid::nil();
        let registration = SyncRootRegistration::new("", "Ironmesh", "C:/ironmesh", cluster_id, None);
        assert!(register_sync_root(&registration).is_err());

        let registration =
            SyncRootRegistration::new("id", "", "C:/ironmesh", cluster_id, None);
        assert!(register_sync_root(&registration).is_err());
    }

    #[test]
    fn runtime_fetches_hydration_for_known_file() {
        let plan = CfapiActionPlan {
            actions: vec![CfapiAction::HydrateOnDemand {
                path: "docs/readme.md".to_string(),
                remote_version: "v7".to_string(),
                remote_content_hash: "h7".to_string(),
                remote_size: None,
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
                remote_content_hash: "h3".to_string(),
                remote_size: None,
            }],
        };

        let runtime = CfapiRuntime::from_action_plan(&plan);
        let hydrated = runtime
            .handle_fetch_data("docs/notes.txt", &DemoHydrator)
            .expect("path normalization should resolve equivalent separators");

        let payload = String::from_utf8(hydrated).expect("demo hydrator emits utf8 payload");
        assert!(payload.contains("docs/notes.txt"));
    }

    #[test]
    fn dehydrate_request_allows_clean_unpinned_in_sync_placeholder() {
        let info = CF_PLACEHOLDER_STANDARD_INFO {
            InSyncState: CF_IN_SYNC_STATE_IN_SYNC,
            PinState: CF_PIN_STATE_UNSPECIFIED,
            ModifiedDataSize: 0,
            ..Default::default()
        };

        assert_eq!(dehydrate_completion_status(&info, false), STATUS_SUCCESS);
    }

    #[test]
    fn dehydrate_request_rejects_pinned_placeholder() {
        let info = CF_PLACEHOLDER_STANDARD_INFO {
            InSyncState: CF_IN_SYNC_STATE_IN_SYNC,
            PinState: CF_PIN_STATE_PINNED,
            ModifiedDataSize: 0,
            ..Default::default()
        };

        assert_eq!(
            dehydrate_completion_status(&info, false),
            STATUS_CLOUD_FILE_PINNED
        );
    }

    #[test]
    fn dehydrate_request_rejects_dirty_or_pending_placeholder() {
        let mut info = CF_PLACEHOLDER_STANDARD_INFO {
            InSyncState: CF_IN_SYNC_STATE_IN_SYNC,
            PinState: CF_PIN_STATE_UNSPECIFIED,
            ModifiedDataSize: 128,
            ..Default::default()
        };
        assert_eq!(
            dehydrate_completion_status(&info, false),
            STATUS_CLOUD_FILE_NOT_IN_SYNC
        );

        info.ModifiedDataSize = 0;
        info.InSyncState = CF_IN_SYNC_STATE_NOT_IN_SYNC;
        assert_eq!(
            dehydrate_completion_status(&info, false),
            STATUS_CLOUD_FILE_NOT_IN_SYNC
        );

        info.InSyncState = CF_IN_SYNC_STATE_IN_SYNC;
        assert_eq!(
            dehydrate_completion_status(&info, true),
            STATUS_CLOUD_FILE_NOT_IN_SYNC
        );
    }

    #[test]
    fn placeholder_sync_state_match_helper_uses_in_sync_state_only() {
        let mut info = CF_PLACEHOLDER_STANDARD_INFO {
            InSyncState: CF_IN_SYNC_STATE_IN_SYNC,
            ..Default::default()
        };
        assert!(placeholder_info_matches_desired_sync_state(
            &info,
            DesiredSyncState::InSync
        ));
        assert!(!placeholder_info_matches_desired_sync_state(
            &info,
            DesiredSyncState::NotInSync
        ));

        info.InSyncState = CF_IN_SYNC_STATE_NOT_IN_SYNC;
        assert!(placeholder_info_matches_desired_sync_state(
            &info,
            DesiredSyncState::NotInSync
        ));
        assert!(!placeholder_info_matches_desired_sync_state(
            &info,
            DesiredSyncState::InSync
        ));
    }

    #[test]
    fn reconcile_sync_states_maps_plan_actions_to_expected_targets() {
        let plan = CfapiActionPlan {
            actions: vec![
                CfapiAction::EnsureDirectory {
                    path: "docs".to_string(),
                },
                CfapiAction::EnsurePlaceholder {
                    path: "docs/readme.md".to_string(),
                    remote_version: "v1".to_string(),
                    remote_content_hash: "h1".to_string(),
                    remote_size: None,
                },
                CfapiAction::HydrateOnDemand {
                    path: "docs/photo.jpg".to_string(),
                    remote_version: "v2".to_string(),
                    remote_content_hash: "h2".to_string(),
                    remote_size: None,
                },
                CfapiAction::QueueUploadOnClose {
                    path: "draft.txt".to_string(),
                    local_version: Some("local".to_string()),
                },
                CfapiAction::MarkConflict {
                    path: "conflict.txt".to_string(),
                    local_version: Some("local".to_string()),
                    remote_version: Some("remote".to_string()),
                    remote_content_hash: Some("hr".to_string()),
                    remote_size: None,
                },
            ],
        };

        let temp_root =
            std::env::temp_dir().join(format!("ironmesh-sync-state-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_root).expect("temp root should be created");
        let stats = reconcile_sync_states(&temp_root, &plan);

        assert_eq!(stats.marked_in_sync, 0);
        assert_eq!(stats.marked_not_in_sync, 0);
        assert_eq!(stats.marked_directories_in_sync, 0);
        assert_eq!(stats.marked_directories_not_in_sync, 0);
        assert_eq!(stats.skipped_missing, 5);
        assert_eq!(stats.skipped_non_placeholder, 0);
        assert_eq!(stats.failed, 0);

        let _ = std::fs::remove_dir_all(temp_root);
    }
}
