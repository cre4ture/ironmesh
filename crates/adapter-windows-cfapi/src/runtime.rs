use crate::adapter::{CfapiAction, CfapiActionPlan};
use crate::auth::is_internal_client_identity_relative_path;
use crate::cfapi::{
    cf_convert_to_placeholder, cf_get_placeholder_standard_info, cf_report_provider_progress2,
    cf_set_in_sync, cf_set_not_in_sync, describe_path_state, open_sync_path,
    path_placeholder_state,
};
use crate::close_upload::{
    UploadDebounceState, UploadWorkerContext, schedule_debounced_close_upload,
};
use crate::connection_config::is_internal_connection_bootstrap_relative_path;
use crate::helpers::{normalize_path, path_to_relative, utf16_path, utf16_string};
use anyhow::{Context, Result, anyhow};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use walkdir::WalkDir;
use windows_sys::Win32::Foundation::{
    NTSTATUS, STATUS_CLOUD_FILE_NOT_IN_SYNC, STATUS_CLOUD_FILE_NOT_UNDER_SYNC_ROOT,
    STATUS_CLOUD_FILE_PINNED, STATUS_SUCCESS,
};

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
use std::ffi::c_void;

use std::mem::size_of;

use std::path::Path;
use std::ptr::null;

use widestring::U16String;
use wincs::{
    HydrationPolicy, HydrationType, PopulationType, Registration, SecurityId, SyncRootId,
    SyncRootIdBuilder,
};
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
        tracing::info!(
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
    paths_by_file_id: Mutex<HashMap<i64, String>>,
    fetch_cancellations: Mutex<HashMap<i64, Arc<AtomicBool>>>,
    upload_worker: Arc<UploadWorkerContext>,
    upload_debounce: Arc<UploadDebounceState>,
}

pub fn register_sync_root(registration: &SyncRootRegistration) -> Result<()> {
    validate_registration(registration)?;
    std::fs::create_dir_all(&registration.root_path)?;
    if let Ok(existing_sync_root_id) = SyncRootId::from_path(&registration.root_path) {
        let _ = existing_sync_root_id.unregister();
    }

    let sync_root_id = build_shell_sync_root_id(registration)?;
    let display_name = U16String::from_str(&registration.display_name);
    let provider_version = U16String::from_str(env!("CARGO_PKG_VERSION"));
    let icon_resource = current_executable_icon_resource()?;
    tracing::info!(
        "sync-root registration: path={} hydration_type=Progressive hydration_policy=allow_platform_dehydration population_type=AlwaysFull allow_pinning=true",
        registration.root_path.display()
    );

    Registration::from_sync_root_id(&sync_root_id)
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
        .register(&registration.root_path)
        .map_err(|error| anyhow!("failed to register sync root with Explorer shell: {error}"))
}

pub fn unregister_sync_root(root_path: &Path) -> Result<()> {
    if root_path.as_os_str().is_empty() {
        return Err(anyhow!("root path cannot be empty"));
    }

    let root_path_utf16 = utf16_path(root_path);
    let hr = unsafe { CfUnregisterSyncRoot(root_path_utf16.as_ptr()) };
    if hr == 0 || hr == STATUS_CLOUD_FILE_NOT_UNDER_SYNC_ROOT {
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

        let placeholder_state =
            path_placeholder_state(&full_path).unwrap_or(CF_PLACEHOLDER_STATE_NO_STATES);
        if matches!(
            placeholder_state,
            CF_PLACEHOLDER_STATE_INVALID | CF_PLACEHOLDER_STATE_NO_STATES
        ) && let Err(err) = cf_convert_to_placeholder(&file)
        {
            stats.failed += 1;
            tracing::info!(
                "sync-state: failed to convert directory {} to placeholder before sync-state update desired={:?}: {} state_before={}",
                full_path.display(),
                desired_state,
                err,
                state_before
            );
            continue;
        }

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
                    "sync-state: path is not a placeholder, attempting convert path={} desired={:?} state_before={}",
                    relative_path,
                    desired_state,
                    state_before
                );
                match open_sync_path(&full_path, true) {
                    Ok(file) => {
                        if let Err(err) = cf_convert_to_placeholder(&file) {
                            stats.failed += 1;
                            tracing::info!(
                                "sync-state: failed to convert to placeholder {} desired={:?}: {} state_before={}",
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
        paths_by_file_id: Mutex::new(HashMap::new()),
        fetch_cancellations: Mutex::new(HashMap::new()),
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
            (&mut *callback_context as *mut CallbackContext).cast::<c_void>(),
            CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO,
            &mut connection_key,
        )
    };
    hresult_to_result(hr, "CfConnectSyncRoot")?;

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

fn callback_request_identity(callback_info: &CF_CALLBACK_INFO) -> i64 {
    if callback_info.RequestKey != 0 {
        callback_info.RequestKey
    } else if callback_info.TransferKey != 0 {
        callback_info.TransferKey
    } else {
        callback_info.FileId
    }
}

fn callback_target_session_id(callback_info: &CF_CALLBACK_INFO) -> u32 {
    if callback_info.ProcessInfo.is_null() {
        0
    } else {
        unsafe { (*callback_info.ProcessInfo).SessionId }
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
    if relative_path.is_empty()
        && !callback_info.FileIdentity.is_null()
        && callback_info.FileIdentityLength > 0
    {
        let file_identity = unsafe {
            std::slice::from_raw_parts(
                callback_info.FileIdentity.cast::<u8>(),
                callback_info.FileIdentityLength as usize,
            )
        };
        if let Some(decoded_path) = decode_path_from_file_identity(file_identity) {
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
    hresult_to_result(hr, "CfExecute(AckDehydrate)")
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

    let fetch_data = unsafe { (*callback_parameters).Anonymous.FetchData };
    let range_start = fetch_data.RequiredFileOffset.max(0) as u64;
    let range_length = fetch_data.RequiredLength.max(0) as u64;
    let request_identity = callback_request_identity(callback_info_ref);
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
            tracing::info!(
                "cfapi fetch-data hydration error: request={} path={} error={:#} state_after={} upload_debounce={}",
                request_identity,
                relative_path,
                err,
                describe_path_state(&full_path),
                context
                    .upload_debounce
                    .debug_snapshot_for_path(&relative_path, 8)
                    .to_log_string()
            );
        }
    }
}

unsafe extern "system" fn callback_cancel_fetch_data(
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

    let request_identity = callback_request_identity(callback_info_ref);
    if let Ok(fetch_cancellations) = context.fetch_cancellations.lock()
        && let Some(cancel_flag) = fetch_cancellations.get(&request_identity)
    {
        cancel_flag.store(true, Ordering::SeqCst);
    }

    let cancel = unsafe { (*callback_parameters).Anonymous.Cancel };
    let fetch = unsafe { cancel.Anonymous.FetchData };
    let relative_path = resolve_relative_path_from_callback(callback_info_ref, context)
        .unwrap_or_else(|| String::from("<unknown>"));
    tracing::info!(
        "cfapi cancel-fetch-data: path={} offset={} length={}",
        relative_path,
        fetch.FileOffset,
        fetch.Length
    );
}

unsafe extern "system" fn callback_notify_dehydrate(
    callback_info: *const CF_CALLBACK_INFO,
    callback_parameters: *const CF_CALLBACK_PARAMETERS,
) {
    if callback_info.is_null() || callback_parameters.is_null() {
        return;
    }

    let callback_info_ref = unsafe { &*callback_info };
    let request_identity = callback_request_identity(callback_info_ref);
    let context_ptr = callback_info_ref.CallbackContext as *const CallbackContext;
    if context_ptr.is_null() {
        let _ = execute_ack_dehydrate(callback_info_ref, STATUS_CLOUD_FILE_NOT_IN_SYNC);
        return;
    }
    let context = unsafe { &*context_ptr };
    let dehydrate = unsafe { (*callback_parameters).Anonymous.Dehydrate };

    let relative_path = match resolve_relative_path_from_callback(callback_info_ref, context) {
        Some(path) => path,
        None => {
            let normalized_path = string_from_pcwstr(callback_info_ref.NormalizedPath);
            tracing::info!(
                "cfapi notify-dehydrate: request={} could not resolve relative path normalized_path='{}' file_id={} flags=0x{:x} reason={}",
                request_identity,
                normalized_path,
                callback_info_ref.FileId,
                dehydrate.Flags,
                dehydrate.Reason
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
        dehydrate.Flags,
        dehydrate.Reason,
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

unsafe extern "system" fn callback_notify_dehydrate_completion(
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
    let dehydrate = unsafe { (*callback_parameters).Anonymous.DehydrateCompletion };
    let relative_path = resolve_relative_path_from_callback(callback_info_ref, context)
        .unwrap_or_else(|| String::from("<unknown>"));

    if relative_path != "<unknown>"
        && (dehydrate.Flags & CF_CALLBACK_DEHYDRATE_COMPLETION_FLAG_DEHYDRATED) != 0
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
        dehydrate.Flags,
        dehydrate.Reason,
        describe_path_state(&full_path),
        context
            .upload_debounce
            .debug_snapshot_for_path(&relative_path, 8)
            .to_log_string()
    );
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
        tracing::info!("close-completion: null callback_info or callback_parameters");
        return;
    }

    let callback_info_ref = unsafe { &*callback_info };
    let context_ptr = callback_info_ref.CallbackContext as *const CallbackContext;
    if context_ptr.is_null() {
        tracing::info!("close-completion: null context ptr");
        return;
    }
    let context = unsafe { &*context_ptr };
    let normalized_path = string_from_pcwstr(callback_info_ref.NormalizedPath);

    let close_completion = unsafe { (*callback_parameters).Anonymous.CloseCompletion };
    tracing::info!(
        "close-completion: flags={:x} path={}",
        close_completion.Flags,
        normalized_path
    );
    if (close_completion.Flags & CF_CALLBACK_CLOSE_COMPLETION_FLAG_DELETED) != 0 {
        tracing::info!("close-completion: file deleted, skipping upload");
        return;
    }

    if normalized_path.is_empty() {
        tracing::info!("close-completion: empty normalized path");
        return;
    }

    let relative_path = path_to_relative(&context.sync_root, &normalized_path);
    if is_internal_client_identity_relative_path(&relative_path)
        || is_internal_connection_bootstrap_relative_path(&relative_path)
    {
        tracing::info!(
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
    tracing::info!(
        "close-completion: relative_path={}, normalized_path={}, sync_root={:?}",
        relative_path,
        normalized_path,
        context.sync_root
    );
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
    fn reconcile_sync_states_maps_plan_actions_to_expected_targets() {
        let plan = CfapiActionPlan {
            actions: vec![
                CfapiAction::EnsureDirectory {
                    path: "docs".to_string(),
                },
                CfapiAction::EnsurePlaceholder {
                    path: "docs/readme.md".to_string(),
                    remote_version: "v1".to_string(),
                },
                CfapiAction::HydrateOnDemand {
                    path: "docs/photo.jpg".to_string(),
                    remote_version: "v2".to_string(),
                },
                CfapiAction::QueueUploadOnClose {
                    path: "draft.txt".to_string(),
                    local_version: Some("local".to_string()),
                },
                CfapiAction::MarkConflict {
                    path: "conflict.txt".to_string(),
                    local_version: Some("local".to_string()),
                    remote_version: Some("remote".to_string()),
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
