use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::adapter::{CfapiAction, CfapiActionPlan};
use crate::auth::is_internal_client_identity_relative_path;
use crate::cfapi::{
    cf_dehydrate_placeholder, cf_get_placeholder_standard_info, describe_path_state,
    open_sync_path, path_is_placeholder, try_convert_materialized_file,
};
use crate::connection_config::is_internal_connection_bootstrap_relative_path;
use crate::helpers::path_to_relative;
use crate::runtime::Uploader;
use std::os::windows::fs::MetadataExt;
use windows_sys::Win32::Storage::CloudFilters::{CF_IN_SYNC_STATE_IN_SYNC, CF_PIN_STATE_UNPINNED};
use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_UNPINNED;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SeenEntry {
    is_dir: bool,
    file_attributes: u32,
    placeholder_state: Option<PlaceholderSnapshot>,
}

impl SeenEntry {
    fn has_unpinned_attribute(self) -> bool {
        (self.file_attributes & FILE_ATTRIBUTE_UNPINNED) != 0
    }

    fn to_log_string(self) -> String {
        let placeholder_state = self
            .placeholder_state
            .map(|state| state.to_log_string())
            .unwrap_or_else(|| String::from("none"));
        format!(
            "dir={} attrs=0x{:08x} unpinned_attr={} placeholder_probe={}",
            self.is_dir,
            self.file_attributes,
            self.has_unpinned_attribute(),
            placeholder_state
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PlaceholderSnapshot {
    on_disk_data_size: i64,
    modified_data_size: i64,
    in_sync_state: i32,
    pin_state: i32,
}

impl PlaceholderSnapshot {
    fn from_path(path: &std::path::Path) -> Option<Self> {
        let file = match open_sync_path(path, false) {
            Ok(file) => file,
            Err(err) => {
                eprintln!(
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
                eprintln!(
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
        })
    }

    fn should_dehydrate(self) -> bool {
        self.pin_state == CF_PIN_STATE_UNPINNED
            && self.in_sync_state == CF_IN_SYNC_STATE_IN_SYNC
            && self.modified_data_size == 0
            && self.on_disk_data_size > 0
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
            "on_disk={} modified={} in_sync={} pin={}",
            self.on_disk_data_size, self.modified_data_size, self.in_sync_state, self.pin_state
        )
    }
}

pub struct SyncRootMonitor {
    name: String,
    sync_root: PathBuf,
    uploader: Arc<dyn Uploader>,
    seen: HashMap<String, SeenEntry>,
    dehydrations_in_flight: Arc<Mutex<std::collections::HashSet<String>>>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DehydrateScanSummary {
    total_entries: usize,
    unpinned_attribute_count: usize,
    probed_placeholder_count: usize,
    eligible_count: usize,
}

impl SyncRootMonitor {
    pub fn new(name: &str, sync_root: PathBuf, uploader: Arc<dyn Uploader>) -> Self {
        Self {
            name: name.to_string(),
            sync_root,
            uploader,
            seen: HashMap::new(),
            dehydrations_in_flight: Arc::new(Mutex::new(std::collections::HashSet::new())),
        }
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
        self.seen = seeded;
    }

    pub fn walk(&mut self) {
        let mut current = self.snapshot_entries();
        let dehydrate_summary = summarize_dehydrate_scan(&current);
        let paths = current.keys().cloned().collect::<Vec<_>>();
        for rel_path in paths {
            let path = self
                .sync_root
                .join(rel_path.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
            self.handle_entry(&path, rel_path, &mut current);
        }

        self.log_dehydrate_scan_summary(dehydrate_summary);
        self.handle_deleted_entries(&current);
        self.seen = current;
    }

    fn log_dehydrate_scan_summary(&self, summary: DehydrateScanSummary) {
        let in_flight_count = self
            .dehydrations_in_flight
            .lock()
            .expect("dehydrations_in_flight lock poisoned")
            .len();
        if summary.unpinned_attribute_count == 0
            && summary.probed_placeholder_count == 0
            && summary.eligible_count == 0
            && in_flight_count == 0
        {
            return;
        }

        eprintln!(
            "{}: dehydrate-scan total_entries={} unpinned_attr={} probed_placeholders={} eligible={} in_flight={}",
            self.name,
            summary.total_entries,
            summary.unpinned_attribute_count,
            summary.probed_placeholder_count,
            summary.eligible_count,
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
        {
            return;
        }
        let entry = match current.get(&rel_path).copied() {
            Some(entry) => entry,
            None => return,
        };
        let previous_entry = self.seen.get(&rel_path).copied();

        if previous_entry != Some(entry)
            && (entry.has_unpinned_attribute()
                || previous_entry.is_some_and(SeenEntry::has_unpinned_attribute)
                || entry.placeholder_state.is_some()
                || previous_entry
                    .and_then(|value| value.placeholder_state)
                    .is_some())
        {
            eprintln!(
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

        self.maybe_schedule_placeholder_dehydrate(path, &rel_path, previous_entry, entry);

        if previous_entry == Some(entry) {
            return;
        }

        if entry.is_dir {
            eprintln!("{}: detected new directory {}", self.name, rel_path);
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
                eprintln!(
                    "{}: skipping placeholder creation for CFAPI placeholder file {}",
                    self.name, rel_path
                );
            } else if path.exists() {
                // File is materialized, convert to placeholder using a file HANDLE
                try_convert_materialized_file(path, &rel_path, &metadata);
                // upload content to server
                if let Err(e) = self.uploader.upload_reader(
                    &rel_path,
                    &mut std::fs::File::open(path).unwrap(),
                    metadata.len(),
                ) {
                    eprintln!("{}: failed to upload file {}: {}", self.name, rel_path, e);
                } else {
                    eprintln!("{}: uploaded file {}", self.name, rel_path);
                }
            } else {
                // File does not exist, create placeholder
                use crate::runtime::create_placeholder;
                if let Err(e) = create_placeholder(&self.sync_root, &rel_path) {
                    eprintln!(
                        "{}: failed to create placeholder for {}: {}",
                        self.name, rel_path, e
                    );
                } else {
                    eprintln!("{}: created placeholder for {}", self.name, rel_path);
                }
            }
        }
    }

    fn maybe_schedule_placeholder_dehydrate(
        &self,
        path: &std::path::Path,
        rel_path: &str,
        previous_entry: Option<SeenEntry>,
        entry: SeenEntry,
    ) {
        if !entry.has_unpinned_attribute() {
            return;
        }

        let Some(placeholder_state) = entry.placeholder_state else {
            if previous_entry != Some(entry) {
                eprintln!(
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
                eprintln!(
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

        eprintln!(
            "{}: dehydrate candidate accepted path={} snapshot={} raw_state={}",
            self.name,
            rel_path,
            placeholder_state.to_log_string(),
            describe_path_state(path)
        );

        {
            let mut in_flight = self
                .dehydrations_in_flight
                .lock()
                .expect("dehydrations_in_flight lock poisoned");
            if !in_flight.insert(rel_path.to_string()) {
                eprintln!(
                    "{}: dehydrate already in flight for {} snapshot={} raw_state={}",
                    self.name,
                    rel_path,
                    placeholder_state.to_log_string(),
                    describe_path_state(path)
                );
                return;
            }
        }

        let rel_path = rel_path.to_string();
        let full_path = path.to_path_buf();
        let monitor_name = self.name.clone();
        let in_flight = self.dehydrations_in_flight.clone();
        std::thread::spawn(move || {
            eprintln!(
                "{}: dehydrating unpinned placeholder {} state_before={} snapshot={}",
                monitor_name,
                rel_path,
                describe_path_state(&full_path),
                placeholder_state.to_log_string()
            );

            let result = open_sync_path(&full_path, true)
                .map_err(anyhow::Error::from)
                .and_then(|file| cf_dehydrate_placeholder(&file));

            match result {
                Ok(()) => {
                    eprintln!(
                        "{}: dehydrated placeholder {} state_after={}",
                        monitor_name,
                        rel_path,
                        describe_path_state(&full_path)
                    );
                }
                Err(err) => {
                    eprintln!(
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
            eprintln!(
                "{}: dehydrate worker finished for {} current_state={}",
                monitor_name,
                rel_path,
                describe_path_state(&full_path)
            );
        });
    }

    fn handle_deleted_entries(&self, current: &HashMap<String, SeenEntry>) {
        let mut deleted_paths = self
            .seen
            .iter()
            .filter_map(|(path, entry)| {
                if current.contains_key(path) {
                    None
                } else {
                    Some((path.as_str(), *entry))
                }
            })
            .collect::<Vec<_>>();
        deleted_paths.sort_by(|(left_path, _), (right_path, _)| right_path.cmp(left_path));

        for (path, entry) in deleted_paths {
            if is_internal_client_identity_relative_path(path)
                || is_internal_connection_bootstrap_relative_path(path)
            {
                continue;
            }
            if entry.is_dir {
                let canonical_path = directory_marker_path(path);
                eprintln!("{}: detected deleted directory {}", self.name, path);
                if let Err(err) = self.uploader.delete_path(&canonical_path) {
                    eprintln!(
                        "{}: failed to delete remote directory marker {}: {}",
                        self.name, canonical_path, err
                    );
                }

                // Clean up legacy plain-key folder entries created by earlier buggy builds.
                if let Err(err) = self.uploader.delete_path(path) {
                    eprintln!(
                        "{}: failed to delete legacy remote directory key {}: {}",
                        self.name, path, err
                    );
                }
            } else {
                eprintln!("{}: detected deleted file {}", self.name, path);
                if let Err(err) = self.uploader.delete_path(path) {
                    eprintln!(
                        "{}: failed to delete remote file {}: {}",
                        self.name, path, err
                    );
                }
            }
        }
    }
}

fn directory_marker_path(path: &str) -> String {
    let trimmed = path.trim_matches(['/', '\\']);
    if trimmed.is_empty() {
        String::new()
    } else {
        format!("{}{}", trimmed.replace('\\', "/"), "/")
    }
}

fn snapshot_entry(path: &std::path::Path, is_dir: bool) -> SeenEntry {
    let file_attributes = std::fs::metadata(path)
        .map(|metadata| metadata.file_attributes())
        .unwrap_or_default();
    SeenEntry {
        is_dir,
        file_attributes,
        placeholder_state: if is_dir || (file_attributes & FILE_ATTRIBUTE_UNPINNED) == 0 {
            None
        } else {
            PlaceholderSnapshot::from_path(path)
        },
    }
}

fn summarize_dehydrate_scan(entries: &HashMap<String, SeenEntry>) -> DehydrateScanSummary {
    let mut summary = DehydrateScanSummary {
        total_entries: entries.len(),
        ..Default::default()
    };
    for entry in entries.values().copied() {
        if entry.has_unpinned_attribute() {
            summary.unpinned_attribute_count += 1;
        }
        if entry.placeholder_state.is_some() {
            summary.probed_placeholder_count += 1;
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
        ) -> anyhow::Result<Option<String>> {
            let mut sink = Vec::new();
            let _ = reader.read_to_end(&mut sink)?;
            self.uploads
                .lock()
                .expect("uploads lock poisoned")
                .push(path.to_string());
            Ok(None)
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
        let mut monitor = SyncRootMonitor::new("monitor-test", sync_root.clone(), uploader.clone());
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
        let mut monitor = SyncRootMonitor::new("monitor-test", sync_root.clone(), uploader.clone());
        monitor.seed_remote_entries(&CfapiActionPlan {
            actions: vec![CfapiAction::EnsurePlaceholder {
                path: "docs/readme.txt".to_string(),
                remote_version: "v1".to_string(),
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
    fn placeholder_snapshot_only_dehydrates_clean_unpinned_hydrated_file() {
        let eligible = PlaceholderSnapshot {
            on_disk_data_size: 1024,
            modified_data_size: 0,
            in_sync_state: CF_IN_SYNC_STATE_IN_SYNC,
            pin_state: CF_PIN_STATE_UNPINNED,
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
    }
}
