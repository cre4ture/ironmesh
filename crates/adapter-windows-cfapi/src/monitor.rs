use std::collections::{HashMap, HashSet};
use std::os::windows::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::adapter::{CfapiAction, CfapiActionPlan};
use crate::auth::is_internal_client_identity_relative_path;
use crate::cfapi::{
    cf_dehydrate_placeholder_with_oplock, cf_get_placeholder_standard_info,
    cf_get_placeholder_standard_info_with_identity, cf_hydrate_placeholder_with_oplock,
    cf_set_in_sync, describe_path_state, open_sync_path, path_is_placeholder,
    path_placeholder_state, try_convert_materialized_file,
};
use crate::cfapi_safe_wrap::local_file_identity_for_path;
use crate::connection_config::is_internal_connection_bootstrap_relative_path;
use crate::helpers::{decode_path_from_file_identity, path_to_relative};
use crate::placeholder_metadata::{
    record_in_sync_content_fingerprint, record_in_sync_local_file_state,
    record_in_sync_remote_file_state,
};
#[cfg(test)]
use crate::runtime::UploadReceipt;
use crate::runtime::Uploader;
use crate::snapshot_cache::is_internal_remote_snapshot_relative_path;
use windows_sys::Win32::Storage::CloudFilters::{
    CF_IN_SYNC_STATE_IN_SYNC, CF_PIN_STATE_PINNED, CF_PIN_STATE_UNPINNED,
    CF_PLACEHOLDER_STATE_NO_STATES, CF_PLACEHOLDER_STATE_PARTIAL,
};
use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_PINNED, FILE_ATTRIBUTE_UNPINNED};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct LocalFileIdentity {
    volume_serial_number: u32,
    file_index: u64,
}

impl LocalFileIdentity {
    fn from_path(path: &std::path::Path) -> Option<Self> {
        let (volume_serial_number, file_index) = local_file_identity_for_path(path).ok()?;
        Some(Self {
            volume_serial_number,
            file_index,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SeenEntry {
    is_dir: bool,
    file_attributes: u32,
    local_file_identity: Option<LocalFileIdentity>,
    placeholder_identity_path: Option<String>,
    placeholder_state: Option<PlaceholderSnapshot>,
}

impl SeenEntry {
    fn has_pinned_attribute(&self) -> bool {
        (self.file_attributes & FILE_ATTRIBUTE_PINNED) != 0
    }

    fn has_unpinned_attribute(&self) -> bool {
        (self.file_attributes & FILE_ATTRIBUTE_UNPINNED) != 0
    }

    fn to_log_string(&self) -> String {
        let placeholder_state = self
            .placeholder_state
            .map(|state| state.to_log_string())
            .unwrap_or_else(|| String::from("none"));
        let local_file_identity = self
            .local_file_identity
            .map(|identity| {
                format!(
                    "{:08x}:{:016x}",
                    identity.volume_serial_number, identity.file_index
                )
            })
            .unwrap_or_else(|| String::from("none"));
        let placeholder_identity_path = self
            .placeholder_identity_path
            .clone()
            .unwrap_or_else(|| String::from("none"));
        format!(
            "dir={} attrs=0x{:08x} pinned_attr={} unpinned_attr={} file_id={} placeholder_identity={} placeholder_probe={}",
            self.is_dir,
            self.file_attributes,
            self.has_pinned_attribute(),
            self.has_unpinned_attribute(),
            local_file_identity,
            placeholder_identity_path,
            placeholder_state
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalRenamePair {
    from_path: String,
    to_path: String,
    detection: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlaceholderSnapshot {
    on_disk_data_size: i64,
    modified_data_size: i64,
    in_sync_state: i32,
    pin_state: i32,
    is_partial: bool,
}

impl PlaceholderSnapshot {
    fn from_path(path: &std::path::Path, placeholder_state_bits: u32) -> Option<Self> {
        let file = match open_sync_path(path, false) {
            Ok(file) => file,
            Err(err) => {
                tracing::info!(
                    "monitor: dehydrate probe open failed path={} error={} state={}",
                    path.display(),
                    err,
                    describe_path_state(path)
                );
                return None;
            }
        };
        let info = match cf_get_placeholder_standard_info(&file) {
            Ok(info) => info,
            Err(err) => {
                tracing::info!(
                    "monitor: dehydrate probe placeholder-info failed path={} error={} state={}",
                    path.display(),
                    err,
                    describe_path_state(path)
                );
                return None;
            }
        };
        Some(Self {
            on_disk_data_size: info.OnDiskDataSize,
            modified_data_size: info.ModifiedDataSize,
            in_sync_state: info.InSyncState,
            pin_state: info.PinState,
            is_partial: (placeholder_state_bits & CF_PLACEHOLDER_STATE_PARTIAL) != 0,
        })
    }

    fn should_dehydrate(self) -> bool {
        self.pin_state == CF_PIN_STATE_UNPINNED
            && self.in_sync_state == CF_IN_SYNC_STATE_IN_SYNC
            && self.modified_data_size == 0
            && self.on_disk_data_size > 0
    }

    fn should_hydrate(self) -> bool {
        self.pin_state == CF_PIN_STATE_PINNED
            && self.in_sync_state == CF_IN_SYNC_STATE_IN_SYNC
            && self.modified_data_size == 0
            && self.is_partial
    }

    fn block_reason(self) -> &'static str {
        if self.pin_state != CF_PIN_STATE_UNPINNED {
            "pin-state-not-unpinned"
        } else if self.in_sync_state != CF_IN_SYNC_STATE_IN_SYNC {
            "not-in-sync"
        } else if self.modified_data_size != 0 {
            "modified-data-present"
        } else if self.on_disk_data_size <= 0 {
            "already-dehydrated"
        } else {
            "eligible"
        }
    }

    fn to_log_string(self) -> String {
        format!(
            "on_disk={} modified={} in_sync={} pin={} partial={}",
            self.on_disk_data_size,
            self.modified_data_size,
            self.in_sync_state,
            self.pin_state,
            self.is_partial
        )
    }
}

fn should_schedule_placeholder_hydration(
    previous_entry: Option<&SeenEntry>,
    entry: &SeenEntry,
    placeholder_state: PlaceholderSnapshot,
) -> bool {
    if !entry.has_pinned_attribute() || !placeholder_state.should_hydrate() {
        return false;
    }

    let previous_was_hydrate_eligible = previous_entry
        .filter(|previous| previous.has_pinned_attribute())
        .and_then(|previous| previous.placeholder_state)
        .is_some_and(PlaceholderSnapshot::should_hydrate);

    previous_entry != Some(entry) && !previous_was_hydrate_eligible
}

pub struct SyncRootMonitor {
    name: String,
    sync_root: PathBuf,
    provider_instance_id: uuid::Uuid,
    uploader: Arc<dyn Uploader>,
    seen: HashMap<String, SeenEntry>,
    dehydrations_in_flight: Arc<Mutex<HashSet<String>>>,
    hydrations_in_flight: Arc<Mutex<HashSet<String>>>,
    remote_applied_tracker: RemoteAppliedTracker,
    refresh_gate: Arc<Mutex<()>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DehydrateScanSummary {
    total_entries: usize,
    pinned_attribute_count: usize,
    unpinned_attribute_count: usize,
    probed_placeholder_count: usize,
    hydrate_eligible_count: usize,
    eligible_count: usize,
}

#[derive(Clone, Debug, Default)]
pub struct RemoteAppliedTracker {
    directories: Arc<Mutex<HashSet<String>>>,
}

impl RemoteAppliedTracker {
    pub fn record_plan(&self, plan: &CfapiActionPlan) {
        let mut directories = self
            .directories
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        for action in &plan.actions {
            match action {
                CfapiAction::EnsureDirectory { path } => {
                    record_remote_applied_directory(path, &mut directories);
                }
                CfapiAction::EnsurePlaceholder { path, .. }
                | CfapiAction::HydrateOnDemand { path, .. } => {
                    for parent in parent_directories_for_path(path) {
                        record_remote_applied_directory(&parent, &mut directories);
                    }
                }
                CfapiAction::QueueUploadOnClose { .. } | CfapiAction::MarkConflict { .. } => {}
            }
        }
    }

    fn take_directory_suppression(&self, path: &str) -> bool {
        let normalized = normalize_monitor_relative_path(path);
        if normalized.is_empty() {
            return false;
        }

        self.directories
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&normalized)
    }
}

impl SyncRootMonitor {
    pub fn new(
        name: &str,
        sync_root: PathBuf,
        provider_instance_id: uuid::Uuid,
        uploader: Arc<dyn Uploader>,
    ) -> Self {
        Self {
            name: name.to_string(),
            sync_root,
            provider_instance_id,
            uploader,
            seen: HashMap::new(),
            dehydrations_in_flight: Arc::new(Mutex::new(HashSet::new())),
            hydrations_in_flight: Arc::new(Mutex::new(HashSet::new())),
            remote_applied_tracker: RemoteAppliedTracker::default(),
            refresh_gate: Arc::new(Mutex::new(())),
        }
    }

    pub fn remote_applied_tracker(&self) -> RemoteAppliedTracker {
        self.remote_applied_tracker.clone()
    }

    pub fn refresh_gate(&self) -> Arc<Mutex<()>> {
        self.refresh_gate.clone()
    }

    pub fn run(&mut self) {
        use std::time::Duration;
        loop {
            self.walk();
            std::thread::sleep(Duration::from_secs(5));
        }
    }

    pub fn seed_seen(&mut self) {
        self.seen = self.snapshot_entries();
    }

    pub fn seed_remote_entries(&mut self, plan: &CfapiActionPlan) {
        self.seed_remote_entries_with_suppressed_paths(plan, &std::collections::BTreeSet::new());
    }

    pub fn seed_remote_entries_with_suppressed_paths(
        &mut self,
        plan: &CfapiActionPlan,
        suppressed_paths: &std::collections::BTreeSet<String>,
    ) {
        let mut seeded = HashMap::new();
        for action in &plan.actions {
            match action {
                CfapiAction::EnsureDirectory { path } => {
                    self.seed_existing_entry(&mut seeded, path, true);
                }
                CfapiAction::EnsurePlaceholder { path, .. }
                | CfapiAction::HydrateOnDemand { path, .. } => {
                    self.seed_existing_entry(&mut seeded, path, false);
                    for parent in parent_directories_for_path(path) {
                        self.seed_existing_entry(&mut seeded, &parent, true);
                    }
                }
                CfapiAction::QueueUploadOnClose { .. } | CfapiAction::MarkConflict { .. } => {}
            }
        }
        for path in suppressed_paths {
            self.seed_existing_entry(&mut seeded, path, false);
            for parent in parent_directories_for_path(path) {
                self.seed_existing_entry(&mut seeded, &parent, true);
            }
        }
        self.seen = seeded;
    }

    pub fn walk(&mut self) {
        let refresh_gate = self.refresh_gate.clone();
        let _refresh_gate = refresh_gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut current = self.snapshot_entries();
        let handled_renames = self.handle_local_file_renames(&current);
        let dehydrate_summary = summarize_dehydrate_scan(&current);
        let paths = current.keys().cloned().collect::<Vec<_>>();
        for rel_path in paths {
            if handled_renames.contains(&rel_path) {
                continue;
            }
            let path = self
                .sync_root
                .join(rel_path.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
            self.handle_entry(&path, rel_path, &mut current);
        }

        self.log_dehydrate_scan_summary(dehydrate_summary);
        self.handle_deleted_entries(&current, &handled_renames);
        self.seen = current;
    }

    fn handle_local_file_renames(
        &self,
        current: &HashMap<String, SeenEntry>,
    ) -> std::collections::HashSet<String> {
        let rename_pairs = detect_local_file_renames(&self.seen, current);
        let mut handled_paths = std::collections::HashSet::new();

        for rename in rename_pairs {
            let full_path = self.sync_root.join(
                rename
                    .to_path
                    .replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()),
            );
            tracing::info!(
                "{}: detected local file rename {} -> {} detection={} state_before={} state_after={}",
                self.name,
                rename.from_path,
                rename.to_path,
                rename.detection,
                self.seen
                    .get(&rename.from_path)
                    .map(|entry| entry.to_log_string())
                    .unwrap_or_else(|| String::from("<missing>")),
                current
                    .get(&rename.to_path)
                    .map(|entry| entry.to_log_string())
                    .unwrap_or_else(|| String::from("<missing>")),
            );

            match self
                .uploader
                .rename_path(&rename.from_path, &rename.to_path)
            {
                Ok(true) => {
                    handled_paths.insert(rename.from_path.clone());
                    handled_paths.insert(rename.to_path.clone());
                    tracing::info!(
                        "{}: remote rename applied {} -> {} raw_state={}",
                        self.name,
                        rename.from_path,
                        rename.to_path,
                        describe_path_state(&full_path)
                    );
                    if let Some(entry) = current.get(&rename.to_path)
                        && let Err(err) = repair_locally_renamed_materialized_file(
                            &self.sync_root,
                            &full_path,
                            &rename.to_path,
                            self.provider_instance_id,
                            entry,
                        )
                    {
                        tracing::info!(
                            "{}: failed to repair local renamed file {} after remote rename: {:#} state={}",
                            self.name,
                            rename.to_path,
                            err,
                            describe_path_state(&full_path)
                        );
                    }
                }
                Ok(false) => {
                    tracing::info!(
                        "{}: uploader declined rename optimization {} -> {}; falling back to upload/delete",
                        self.name,
                        rename.from_path,
                        rename.to_path
                    );
                }
                Err(err) => {
                    tracing::info!(
                        "{}: remote rename failed {} -> {}: {:#}; falling back to upload/delete",
                        self.name,
                        rename.from_path,
                        rename.to_path,
                        err
                    );
                }
            }
        }

        handled_paths
    }

    fn log_dehydrate_scan_summary(&self, summary: DehydrateScanSummary) {
        let hydrate_in_flight_count = self
            .hydrations_in_flight
            .lock()
            .expect("hydrations_in_flight lock poisoned")
            .len();
        let in_flight_count = self
            .dehydrations_in_flight
            .lock()
            .expect("dehydrations_in_flight lock poisoned")
            .len();
        if summary.pinned_attribute_count == 0
            && summary.unpinned_attribute_count == 0
            && summary.probed_placeholder_count == 0
            && summary.hydrate_eligible_count == 0
            && summary.eligible_count == 0
            && hydrate_in_flight_count == 0
            && in_flight_count == 0
        {
            return;
        }

        tracing::info!(
            "{}: dehydrate-scan total_entries={} pinned_attr={} unpinned_attr={} probed_placeholders={} hydrate_eligible={} eligible={} hydrate_in_flight={} in_flight={}",
            self.name,
            summary.total_entries,
            summary.pinned_attribute_count,
            summary.unpinned_attribute_count,
            summary.probed_placeholder_count,
            summary.hydrate_eligible_count,
            summary.eligible_count,
            hydrate_in_flight_count,
            in_flight_count
        );
    }

    fn snapshot_entries(&self) -> HashMap<String, SeenEntry> {
        let mut current = HashMap::new();
        let walker = walkdir::WalkDir::new(&self.sync_root).into_iter();
        for entry in walker.flatten() {
            let path = entry.path();
            let rel_path = path_to_relative(&self.sync_root, &path.to_string_lossy());
            if rel_path.is_empty()
                || is_internal_client_identity_relative_path(&rel_path)
                || is_internal_connection_bootstrap_relative_path(&rel_path)
                || is_internal_remote_snapshot_relative_path(&rel_path)
            {
                continue;
            }

            current.insert(rel_path, snapshot_entry(path, entry.file_type().is_dir()));
        }

        current
    }

    fn seed_existing_entry(
        &self,
        seeded: &mut HashMap<String, SeenEntry>,
        rel_path: &str,
        is_dir_hint: bool,
    ) {
        let normalized = rel_path.trim_matches(['/', '\\']).replace('\\', "/");
        if normalized.is_empty()
            || is_internal_client_identity_relative_path(&normalized)
            || is_internal_connection_bootstrap_relative_path(&normalized)
            || is_internal_remote_snapshot_relative_path(&normalized)
        {
            return;
        }

        let full_path = self
            .sync_root
            .join(normalized.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
        let metadata = match std::fs::metadata(&full_path) {
            Ok(metadata) => metadata,
            Err(_) => return,
        };
        seeded.insert(
            normalized,
            snapshot_entry(&full_path, metadata.is_dir() || is_dir_hint),
        );
    }

    fn handle_entry(
        &mut self,
        path: &std::path::Path,
        rel_path: String,
        current: &mut HashMap<String, SeenEntry>,
    ) {
        if rel_path.is_empty() {
            return;
        }
        if is_internal_client_identity_relative_path(&rel_path)
            || is_internal_connection_bootstrap_relative_path(&rel_path)
            || is_internal_remote_snapshot_relative_path(&rel_path)
        {
            return;
        }
        let entry = match current.get(&rel_path) {
            Some(entry) => entry,
            None => return,
        };
        let previous_entry = self.seen.get(&rel_path);
        let entry_unchanged = previous_entry == Some(entry);

        if !entry_unchanged
            && (entry.has_unpinned_attribute()
                || previous_entry.is_some_and(SeenEntry::has_unpinned_attribute)
                || entry.placeholder_state.is_some()
                || previous_entry
                    .and_then(|value| value.placeholder_state)
                    .is_some())
        {
            tracing::info!(
                "{}: path-state changed path={} previous={} current={} raw_state={}",
                self.name,
                rel_path,
                previous_entry
                    .map(|value| value.to_log_string())
                    .unwrap_or_else(|| String::from("<new>")),
                entry.to_log_string(),
                describe_path_state(path)
            );
        }

        self.maybe_schedule_placeholder_hydrate(path, &rel_path, previous_entry, entry);
        self.maybe_schedule_placeholder_dehydrate(path, &rel_path, previous_entry, entry);

        if entry_unchanged {
            return;
        }

        if entry.is_dir {
            if self
                .remote_applied_tracker
                .take_directory_suppression(&rel_path)
            {
                tracing::info!(
                    "{}: suppressing local upload for remote-applied directory {}",
                    self.name,
                    rel_path
                );
                return;
            }
            tracing::info!("{}: detected new directory {}", self.name, rel_path);
            let mut cursor = std::io::Cursor::new(b"<DIR>".to_vec());
            let remote_path = directory_marker_path(&rel_path);
            let _ = self
                .uploader
                .upload_reader(&remote_path, &mut cursor, b"<DIR>".len() as u64);
        } else {
            let metadata = match std::fs::metadata(path) {
                Ok(m) => m,
                Err(_) => return,
            };
            // Check if file is already a CFAPI placeholder using Windows file attributes
            let is_placeholder = path_is_placeholder(path);
            if is_placeholder {
                tracing::info!(
                    "{}: skipping placeholder creation for CFAPI placeholder file {}",
                    self.name,
                    rel_path
                );
            } else if path.exists() {
                // File is materialized, convert to placeholder using a file HANDLE
                try_convert_materialized_file(path, &rel_path, &metadata);
                // upload content to server
                match self.uploader.upload_reader(
                    &rel_path,
                    &mut std::fs::File::open(path).unwrap(),
                    metadata.len(),
                ) {
                    Ok(receipt) => {
                        if let Some(clean_content_fingerprint) =
                            receipt.clean_content_fingerprint.as_deref()
                            && let Err(err) = record_in_sync_content_fingerprint(
                                &self.sync_root,
                                &rel_path,
                                self.provider_instance_id,
                                clean_content_fingerprint,
                            )
                        {
                            tracing::info!(
                                "{}: failed to record in-sync content fingerprint for {}: {:#}",
                                self.name,
                                rel_path,
                                err
                            );
                        }
                        tracing::info!("{}: uploaded file {}", self.name, rel_path);
                    }
                    Err(e) => {
                        tracing::info!("{}: failed to upload file {}: {}", self.name, rel_path, e);
                    }
                }
            } else {
                // File does not exist, create placeholder
                use crate::runtime::create_placeholder;
                if let Err(e) =
                    create_placeholder(&self.sync_root, &rel_path, self.provider_instance_id)
                {
                    tracing::info!(
                        "{}: failed to create placeholder for {}: {}",
                        self.name,
                        rel_path,
                        e
                    );
                } else {
                    tracing::info!("{}: created placeholder for {}", self.name, rel_path);
                }
            }
        }
    }

    fn maybe_schedule_placeholder_dehydrate(
        &self,
        path: &std::path::Path,
        rel_path: &str,
        previous_entry: Option<&SeenEntry>,
        entry: &SeenEntry,
    ) {
        if !entry.has_unpinned_attribute() {
            return;
        }

        let Some(placeholder_state) = entry.placeholder_state else {
            if previous_entry != Some(entry) {
                tracing::info!(
                    "{}: dehydrate candidate missing placeholder probe path={} entry={} raw_state={}",
                    self.name,
                    rel_path,
                    entry.to_log_string(),
                    describe_path_state(path)
                );
            }
            return;
        };
        if !placeholder_state.should_dehydrate() {
            if previous_entry != Some(entry) {
                tracing::info!(
                    "{}: dehydrate candidate rejected path={} snapshot={} reason={} raw_state={}",
                    self.name,
                    rel_path,
                    placeholder_state.to_log_string(),
                    placeholder_state.block_reason(),
                    describe_path_state(path)
                );
            }
            return;
        }

        if previous_entry != Some(entry) {
            tracing::info!(
                "{}: dehydrate candidate accepted path={} snapshot={} raw_state={} action=request-provider-dehydrate",
                self.name,
                rel_path,
                placeholder_state.to_log_string(),
                describe_path_state(path),
            );
        }

        {
            let mut in_flight = self
                .dehydrations_in_flight
                .lock()
                .expect("dehydrations_in_flight lock poisoned");
            if !in_flight.insert(rel_path.to_string()) {
                if previous_entry != Some(entry) {
                    tracing::info!(
                        "{}: dehydrate already in flight for {} snapshot={} raw_state={}",
                        self.name,
                        rel_path,
                        placeholder_state.to_log_string(),
                        describe_path_state(path)
                    );
                }
                return;
            }
        }

        let rel_path = rel_path.to_string();
        let full_path = path.to_path_buf();
        let monitor_name = self.name.clone();
        let in_flight = self.dehydrations_in_flight.clone();
        std::thread::spawn(move || {
            tracing::info!(
                "{}: dehydrating unpinned placeholder {} state_before={} snapshot={}",
                monitor_name,
                rel_path,
                describe_path_state(&full_path),
                placeholder_state.to_log_string()
            );

            let result = cf_dehydrate_placeholder_with_oplock(&full_path, &rel_path);

            match result {
                Ok(()) => {
                    tracing::info!(
                        "{}: dehydrated placeholder {} state_after={}",
                        monitor_name,
                        rel_path,
                        describe_path_state(&full_path)
                    );
                }
                Err(err) => {
                    tracing::info!(
                        "{}: failed to dehydrate placeholder {}: {:#} state_after={}",
                        monitor_name,
                        rel_path,
                        err,
                        describe_path_state(&full_path)
                    );
                }
            }

            in_flight
                .lock()
                .expect("dehydrations_in_flight lock poisoned")
                .remove(&rel_path);
            tracing::info!(
                "{}: dehydrate worker finished for {} current_state={}",
                monitor_name,
                rel_path,
                describe_path_state(&full_path)
            );
        });
    }

    fn maybe_schedule_placeholder_hydrate(
        &self,
        path: &std::path::Path,
        rel_path: &str,
        previous_entry: Option<&SeenEntry>,
        entry: &SeenEntry,
    ) {
        if !entry.has_pinned_attribute() {
            return;
        }

        let Some(placeholder_state) = entry.placeholder_state else {
            if previous_entry != Some(entry) {
                tracing::info!(
                    "{}: hydrate candidate missing placeholder probe path={} entry={} raw_state={}",
                    self.name,
                    rel_path,
                    entry.to_log_string(),
                    describe_path_state(path)
                );
            }
            return;
        };
        if !placeholder_state.should_hydrate() {
            if previous_entry != Some(entry) {
                let reason = if placeholder_state.pin_state != CF_PIN_STATE_PINNED {
                    "pin-state-not-pinned"
                } else if placeholder_state.in_sync_state != CF_IN_SYNC_STATE_IN_SYNC {
                    "not-in-sync"
                } else if placeholder_state.modified_data_size != 0 {
                    "modified-data-present"
                } else if !placeholder_state.is_partial {
                    "already-fully-hydrated"
                } else {
                    "not-eligible"
                };
                tracing::info!(
                    "{}: hydrate candidate rejected path={} snapshot={} reason={} raw_state={}",
                    self.name,
                    rel_path,
                    placeholder_state.to_log_string(),
                    reason,
                    describe_path_state(path)
                );
            }
            return;
        }

        if !should_schedule_placeholder_hydration(previous_entry, entry, placeholder_state) {
            return;
        }

        if previous_entry != Some(entry) {
            tracing::info!(
                "{}: hydrate candidate accepted path={} snapshot={} raw_state={} action=request-provider-hydrate",
                self.name,
                rel_path,
                placeholder_state.to_log_string(),
                describe_path_state(path),
            );
        }

        {
            let mut in_flight = self
                .hydrations_in_flight
                .lock()
                .expect("hydrations_in_flight lock poisoned");
            if !in_flight.insert(rel_path.to_string()) {
                if previous_entry != Some(entry) {
                    tracing::info!(
                        "{}: hydrate already in flight for {} snapshot={} raw_state={}",
                        self.name,
                        rel_path,
                        placeholder_state.to_log_string(),
                        describe_path_state(path)
                    );
                }
                return;
            }
        }

        let rel_path = rel_path.to_string();
        let full_path = path.to_path_buf();
        let monitor_name = self.name.clone();
        let in_flight = self.hydrations_in_flight.clone();
        std::thread::spawn(move || {
            tracing::info!(
                "{}: hydrating pinned placeholder {} state_before={} snapshot={}",
                monitor_name,
                rel_path,
                describe_path_state(&full_path),
                placeholder_state.to_log_string()
            );

            let result = cf_hydrate_placeholder_with_oplock(&full_path);

            match result {
                Ok(()) => {
                    tracing::info!(
                        "{}: hydrated pinned placeholder {} state_after={}",
                        monitor_name,
                        rel_path,
                        describe_path_state(&full_path)
                    );
                }
                Err(err) => {
                    tracing::info!(
                        "{}: failed to hydrate pinned placeholder {}: {:#} state_after={}",
                        monitor_name,
                        rel_path,
                        err,
                        describe_path_state(&full_path)
                    );
                }
            }

            in_flight
                .lock()
                .expect("hydrations_in_flight lock poisoned")
                .remove(&rel_path);
            tracing::info!(
                "{}: hydrate worker finished for {} current_state={}",
                monitor_name,
                rel_path,
                describe_path_state(&full_path)
            );
        });
    }

    fn handle_deleted_entries(
        &self,
        current: &HashMap<String, SeenEntry>,
        handled_renames: &std::collections::HashSet<String>,
    ) {
        let mut deleted_paths = self
            .seen
            .iter()
            .filter_map(|(path, entry)| {
                if current.contains_key(path) {
                    None
                } else {
                    Some((path.as_str(), entry.clone()))
                }
            })
            .collect::<Vec<_>>();
        deleted_paths.sort_by(|(left_path, _), (right_path, _)| right_path.cmp(left_path));

        for (path, entry) in deleted_paths {
            if is_internal_client_identity_relative_path(path)
                || is_internal_connection_bootstrap_relative_path(path)
                || is_internal_remote_snapshot_relative_path(path)
            {
                continue;
            }
            if handled_renames.contains(path) {
                tracing::info!(
                    "{}: skipping delete handling for renamed path {}",
                    self.name,
                    path
                );
                continue;
            }
            if entry.is_dir {
                let canonical_path = directory_marker_path(path);
                tracing::info!("{}: detected deleted directory {}", self.name, path);
                if let Err(err) = self.uploader.delete_path(&canonical_path) {
                    tracing::info!(
                        "{}: failed to delete remote directory marker {}: {}",
                        self.name,
                        canonical_path,
                        err
                    );
                }

                // Clean up legacy plain-key folder entries created by earlier buggy builds.
                if let Err(err) = self.uploader.delete_path(path) {
                    tracing::info!(
                        "{}: failed to delete legacy remote directory key {}: {}",
                        self.name,
                        path,
                        err
                    );
                }
            } else {
                tracing::info!("{}: detected deleted file {}", self.name, path);
                if let Err(err) = self.uploader.delete_path(path) {
                    tracing::info!(
                        "{}: failed to delete remote file {}: {}",
                        self.name,
                        path,
                        err
                    );
                }
            }
        }
    }
}

fn directory_marker_path(path: &str) -> String {
    let trimmed = normalize_monitor_relative_path(path);
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{trimmed}/")
    }
}

fn normalize_monitor_relative_path(path: &str) -> String {
    path.trim_matches(['/', '\\']).replace('\\', "/")
}

fn record_remote_applied_directory(path: &str, directories: &mut HashSet<String>) {
    let normalized = normalize_monitor_relative_path(path);
    if normalized.is_empty() {
        return;
    }

    directories.insert(normalized.clone());
    for parent in parent_directories_for_path(&normalized) {
        directories.insert(parent);
    }
}

fn placeholder_identity_path_for_entry(
    path: &std::path::Path,
    is_placeholder: bool,
) -> Option<String> {
    if !is_placeholder {
        return None;
    }

    let file = open_sync_path(path, false).ok()?;
    let info = cf_get_placeholder_standard_info_with_identity(&file).ok()?;
    let file_identity = info.file_identity();
    if file_identity.is_empty() {
        return None;
    }

    decode_path_from_file_identity(file_identity)
}

fn repair_locally_renamed_materialized_file(
    sync_root: &std::path::Path,
    path: &std::path::Path,
    rel_path: &str,
    provider_instance_id: uuid::Uuid,
    entry: &SeenEntry,
) -> anyhow::Result<()> {
    if entry.is_dir {
        return Ok(());
    }

    let is_placeholder = path_is_placeholder(path);
    tracing::info!(
        "monitor: repairing local renamed file {} mode={} entry_snapshot={} state_before={}",
        rel_path,
        if is_placeholder {
            "placeholder-metadata-only"
        } else {
            "materialized-convert-and-fingerprint"
        },
        entry.to_log_string(),
        describe_path_state(path)
    );

    if is_placeholder {
        // Renamed placeholders must be repaired without reading file content, or the
        // fingerprinting path will implicitly hydrate them. Repoint the stored
        // FileIdentity metadata to the new relative path and restore the clean
        // in-sync state as a metadata-only operation.
        record_in_sync_remote_file_state(sync_root, rel_path, provider_instance_id)?;
        let file = open_sync_path(path, true)?;
        cf_set_in_sync(&file)?;
        tracing::info!(
            "monitor: repaired local renamed file {} mode=placeholder-metadata-only state_after={}",
            rel_path,
            describe_path_state(path)
        );
        return Ok(());
    }

    let metadata = std::fs::metadata(path)?;
    try_convert_materialized_file(path, rel_path, &metadata);

    let file = open_sync_path(path, true)?;
    cf_set_in_sync(&file)?;
    record_in_sync_local_file_state(sync_root, rel_path, provider_instance_id)?;
    tracing::info!(
        "monitor: repaired local renamed file {} mode=materialized-convert-and-fingerprint state_after={}",
        rel_path,
        describe_path_state(path)
    );
    Ok(())
}

fn detect_local_file_renames(
    previous: &HashMap<String, SeenEntry>,
    current: &HashMap<String, SeenEntry>,
) -> Vec<LocalRenamePair> {
    let mut pairs = Vec::new();
    let mut matched_sources = std::collections::HashSet::new();
    let mut matched_destinations = std::collections::HashSet::new();

    for (to_path, entry) in current {
        if previous.contains_key(to_path) || entry.is_dir {
            continue;
        }
        let Some(from_path) = entry.placeholder_identity_path.as_deref() else {
            continue;
        };
        if from_path == to_path
            || matched_sources.contains(from_path)
            || matched_destinations.contains(to_path)
            || current.contains_key(from_path)
        {
            continue;
        }
        if previous
            .get(from_path)
            .is_some_and(|candidate| !candidate.is_dir)
        {
            matched_sources.insert(from_path.to_string());
            matched_destinations.insert(to_path.clone());
            pairs.push(LocalRenamePair {
                from_path: from_path.to_string(),
                to_path: to_path.clone(),
                detection: "placeholder-identity",
            });
        }
    }

    let mut deleted_by_identity: HashMap<LocalFileIdentity, Vec<String>> = HashMap::new();
    for (from_path, entry) in previous {
        if current.contains_key(from_path) || entry.is_dir || matched_sources.contains(from_path) {
            continue;
        }
        let Some(identity) = entry.local_file_identity else {
            continue;
        };
        deleted_by_identity
            .entry(identity)
            .or_default()
            .push(from_path.clone());
    }

    for (to_path, entry) in current {
        if previous.contains_key(to_path) || entry.is_dir || matched_destinations.contains(to_path)
        {
            continue;
        }
        let Some(identity) = entry.local_file_identity else {
            continue;
        };
        let Some(from_paths) = deleted_by_identity.get(&identity) else {
            continue;
        };
        if from_paths.len() != 1 {
            continue;
        }
        let from_path = &from_paths[0];
        if matched_sources.contains(from_path) || current.contains_key(from_path) {
            continue;
        }

        matched_sources.insert(from_path.clone());
        matched_destinations.insert(to_path.clone());
        pairs.push(LocalRenamePair {
            from_path: from_path.clone(),
            to_path: to_path.clone(),
            detection: "file-index",
        });
    }

    pairs.sort_by(|left, right| left.from_path.cmp(&right.from_path));
    pairs
}

fn snapshot_entry(path: &std::path::Path, is_dir: bool) -> SeenEntry {
    let metadata = std::fs::metadata(path).ok();
    let file_attributes = metadata
        .as_ref()
        .map(|metadata| metadata.file_attributes())
        .unwrap_or_default();
    let is_placeholder = !is_dir && path_is_placeholder(path);
    let should_probe = !is_dir
        && ((file_attributes & FILE_ATTRIBUTE_UNPINNED) != 0
            || (file_attributes & FILE_ATTRIBUTE_PINNED) != 0);
    SeenEntry {
        is_dir,
        file_attributes,
        local_file_identity: (!is_dir)
            .then(|| LocalFileIdentity::from_path(path))
            .flatten(),
        placeholder_identity_path: placeholder_identity_path_for_entry(path, is_placeholder),
        placeholder_state: if !should_probe {
            None
        } else {
            let placeholder_state_bits =
                path_placeholder_state(path).unwrap_or(CF_PLACEHOLDER_STATE_NO_STATES);
            PlaceholderSnapshot::from_path(path, placeholder_state_bits)
        },
    }
}

fn summarize_dehydrate_scan(entries: &HashMap<String, SeenEntry>) -> DehydrateScanSummary {
    let mut summary = DehydrateScanSummary {
        total_entries: entries.len(),
        ..Default::default()
    };
    for entry in entries.values() {
        if entry.has_pinned_attribute() {
            summary.pinned_attribute_count += 1;
        }
        if entry.has_unpinned_attribute() {
            summary.unpinned_attribute_count += 1;
        }
        if entry.placeholder_state.is_some() {
            summary.probed_placeholder_count += 1;
        }
        if entry
            .placeholder_state
            .is_some_and(PlaceholderSnapshot::should_hydrate)
        {
            summary.hydrate_eligible_count += 1;
        }
        if entry
            .placeholder_state
            .is_some_and(PlaceholderSnapshot::should_dehydrate)
        {
            summary.eligible_count += 1;
        }
    }
    summary
}

fn parent_directories_for_path(path: &str) -> Vec<String> {
    let normalized = path.trim_matches(['/', '\\']).replace('\\', "/");
    let segments = normalized
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    if segments.len() < 2 {
        return Vec::new();
    }

    let mut parents = Vec::with_capacity(segments.len().saturating_sub(1));
    for index in 1..segments.len() {
        parents.push(segments[..index].join("/"));
    }
    parents
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::sync::Mutex;
    use windows_sys::Win32::Storage::CloudFilters::{
        CF_IN_SYNC_STATE_NOT_IN_SYNC, CF_PIN_STATE_PINNED, CF_PIN_STATE_UNSPECIFIED,
    };

    #[derive(Default)]
    struct MockUploader {
        uploads: Mutex<Vec<String>>,
        deletes: Mutex<Vec<String>>,
    }

    impl Uploader for MockUploader {
        fn upload_reader(
            &self,
            path: &str,
            reader: &mut dyn Read,
            _length: u64,
        ) -> anyhow::Result<UploadReceipt> {
            let mut sink = Vec::new();
            let _ = reader.read_to_end(&mut sink)?;
            self.uploads
                .lock()
                .expect("uploads lock poisoned")
                .push(path.to_string());
            Ok(UploadReceipt::default())
        }

        fn delete_path(&self, path: &str) -> anyhow::Result<()> {
            self.deletes
                .lock()
                .expect("deletes lock poisoned")
                .push(path.to_string());
            Ok(())
        }
    }

    #[test]
    fn seed_seen_makes_startup_walk_passive_for_existing_entries() {
        let unique = uuid::Uuid::new_v4();
        let sync_root = std::env::temp_dir().join(format!("ironmesh-monitor-seed-seen-{unique}"));
        std::fs::create_dir_all(sync_root.join("docs")).expect("failed to create sync root");
        std::fs::write(sync_root.join("docs").join("readme.txt"), b"hello")
            .expect("failed to seed existing file");

        let uploader = Arc::new(MockUploader::default());
        let mut monitor = SyncRootMonitor::new(
            "monitor-test",
            sync_root.clone(),
            uuid::Uuid::nil(),
            uploader.clone(),
        );
        monitor.seed_seen();
        monitor.walk();

        assert!(
            uploader
                .uploads
                .lock()
                .expect("uploads lock poisoned")
                .is_empty(),
            "startup walk should not upload pre-existing entries after seed_seen"
        );
        assert!(
            uploader
                .deletes
                .lock()
                .expect("deletes lock poisoned")
                .is_empty(),
            "startup walk should not emit deletes after seed_seen"
        );

        let _ = std::fs::remove_dir_all(sync_root);
    }

    #[test]
    fn seed_remote_entries_keeps_local_only_files_pending_for_upload() {
        let unique = uuid::Uuid::new_v4();
        let sync_root = std::env::temp_dir().join(format!("ironmesh-monitor-remote-seed-{unique}"));
        std::fs::create_dir_all(sync_root.join("docs")).expect("failed to create sync root");
        std::fs::write(
            sync_root.join("docs").join("readme.txt"),
            b"remote baseline",
        )
        .expect("failed to seed remote placeholder stand-in");
        std::fs::write(sync_root.join("local-only.txt"), b"local upload")
            .expect("failed to seed local-only file");

        let uploader = Arc::new(MockUploader::default());
        let mut monitor = SyncRootMonitor::new(
            "monitor-test",
            sync_root.clone(),
            uuid::Uuid::nil(),
            uploader.clone(),
        );
        monitor.seed_remote_entries(&CfapiActionPlan {
            actions: vec![CfapiAction::EnsurePlaceholder {
                path: "docs/readme.txt".to_string(),
                remote_version: "v1".to_string(),
                remote_content_hash: "h1".to_string(),
                remote_size: None,
                remote_content_fingerprint: None,
            }],
        });
        monitor.walk();

        let uploads = uploader
            .uploads
            .lock()
            .expect("uploads lock poisoned")
            .clone();
        assert!(
            uploads.iter().any(|path| path == "local-only.txt"),
            "startup walk should still upload pre-existing local-only files"
        );
        assert!(
            uploads
                .iter()
                .all(|path| path != "docs/" && path != "docs/readme.txt"),
            "startup walk should not re-upload remote-seeded entries"
        );

        let _ = std::fs::remove_dir_all(sync_root);
    }

    #[test]
    fn remote_applied_directory_is_suppressed_but_later_local_directory_uploads() {
        let unique = uuid::Uuid::new_v4();
        let sync_root =
            std::env::temp_dir().join(format!("ironmesh-monitor-remote-apply-{unique}"));
        std::fs::create_dir_all(&sync_root).expect("failed to create sync root");

        let uploader = Arc::new(MockUploader::default());
        let mut monitor = SyncRootMonitor::new(
            "monitor-test",
            sync_root.clone(),
            uuid::Uuid::nil(),
            uploader.clone(),
        );
        monitor.seed_seen();
        let remote_applied = monitor.remote_applied_tracker();

        std::fs::create_dir_all(sync_root.join("docs")).expect("failed to create remote directory");
        remote_applied.record_plan(&CfapiActionPlan {
            actions: vec![CfapiAction::EnsureDirectory {
                path: "docs".to_string(),
            }],
        });
        monitor.walk();

        assert!(
            uploader
                .uploads
                .lock()
                .expect("uploads lock poisoned")
                .is_empty(),
            "remote-applied directory should not be echoed back as local upload"
        );

        std::fs::create_dir_all(sync_root.join("local")).expect("failed to create local directory");
        monitor.walk();

        let uploads = uploader
            .uploads
            .lock()
            .expect("uploads lock poisoned")
            .clone();
        assert!(
            uploads.iter().any(|path| path == "local/"),
            "later local directory should still upload normally, uploads={uploads:?}"
        );
        assert!(
            uploads.iter().all(|path| path != "docs/"),
            "remote-applied directory should remain suppressed, uploads={uploads:?}"
        );

        let _ = std::fs::remove_dir_all(sync_root);
    }

    #[test]
    fn placeholder_snapshot_only_dehydrates_clean_unpinned_hydrated_file() {
        let eligible = PlaceholderSnapshot {
            on_disk_data_size: 1024,
            modified_data_size: 0,
            in_sync_state: CF_IN_SYNC_STATE_IN_SYNC,
            pin_state: CF_PIN_STATE_UNPINNED,
            is_partial: false,
        };
        assert!(eligible.should_dehydrate());

        let pinned = PlaceholderSnapshot {
            pin_state: CF_PIN_STATE_PINNED,
            ..eligible
        };
        assert!(!pinned.should_dehydrate());

        let unspecified = PlaceholderSnapshot {
            pin_state: CF_PIN_STATE_UNSPECIFIED,
            ..eligible
        };
        assert!(!unspecified.should_dehydrate());

        let dirty = PlaceholderSnapshot {
            modified_data_size: 1,
            ..eligible
        };
        assert!(!dirty.should_dehydrate());

        let not_in_sync = PlaceholderSnapshot {
            in_sync_state: CF_IN_SYNC_STATE_NOT_IN_SYNC,
            ..eligible
        };
        assert!(!not_in_sync.should_dehydrate());

        let already_dehydrated = PlaceholderSnapshot {
            on_disk_data_size: 0,
            ..eligible
        };
        assert!(!already_dehydrated.should_dehydrate());

        let partial_pinned = PlaceholderSnapshot {
            on_disk_data_size: 1024,
            modified_data_size: 0,
            in_sync_state: CF_IN_SYNC_STATE_IN_SYNC,
            pin_state: CF_PIN_STATE_PINNED,
            is_partial: true,
        };
        assert!(partial_pinned.should_hydrate());

        let fully_hydrated_pinned = PlaceholderSnapshot {
            is_partial: false,
            ..partial_pinned
        };
        assert!(!fully_hydrated_pinned.should_hydrate());
    }

    #[test]
    fn startup_seed_does_not_schedule_hydration_for_unchanged_pinned_placeholder() {
        let pinned_partial = PlaceholderSnapshot {
            on_disk_data_size: 0,
            modified_data_size: 0,
            in_sync_state: CF_IN_SYNC_STATE_IN_SYNC,
            pin_state: CF_PIN_STATE_PINNED,
            is_partial: true,
        };
        let entry = SeenEntry {
            is_dir: false,
            file_attributes: FILE_ATTRIBUTE_PINNED,
            local_file_identity: None,
            placeholder_identity_path: Some("movies/example.mp4".to_string()),
            placeholder_state: Some(pinned_partial),
        };

        assert!(
            !should_schedule_placeholder_hydration(Some(&entry), &entry, pinned_partial),
            "seeded startup snapshot should not auto-hydrate an unchanged pinned placeholder",
        );
    }

    #[test]
    fn monitor_only_schedules_hydration_when_entry_newly_becomes_eligible() {
        let pinned_partial = PlaceholderSnapshot {
            on_disk_data_size: 0,
            modified_data_size: 0,
            in_sync_state: CF_IN_SYNC_STATE_IN_SYNC,
            pin_state: CF_PIN_STATE_PINNED,
            is_partial: true,
        };
        let previous = SeenEntry {
            is_dir: false,
            file_attributes: 0,
            local_file_identity: None,
            placeholder_identity_path: Some("movies/example.mp4".to_string()),
            placeholder_state: None,
        };
        let current = SeenEntry {
            is_dir: false,
            file_attributes: FILE_ATTRIBUTE_PINNED,
            local_file_identity: None,
            placeholder_identity_path: Some("movies/example.mp4".to_string()),
            placeholder_state: Some(pinned_partial),
        };

        assert!(
            should_schedule_placeholder_hydration(Some(&previous), &current, pinned_partial),
            "a placeholder that newly becomes pinned and partially hydrated should be eligible",
        );
        assert!(
            !should_schedule_placeholder_hydration(Some(&current), &current, pinned_partial),
            "already-eligible placeholders should not reschedule hydration on every walk",
        );
    }
}
