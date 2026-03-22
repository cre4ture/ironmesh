use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::adapter::{CfapiAction, CfapiActionPlan};
use crate::auth::is_internal_client_identity_relative_path;
use crate::cfapi::{path_is_placeholder, try_convert_materialized_file};
use crate::connection_config::is_internal_connection_bootstrap_relative_path;
use crate::helpers::path_to_relative;
use crate::runtime::Uploader;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SeenEntry {
    is_dir: bool,
}

pub struct SyncRootMonitor {
    name: String,
    sync_root: PathBuf,
    uploader: Arc<dyn Uploader>,
    seen: HashMap<String, SeenEntry>,
}

impl SyncRootMonitor {
    pub fn new(name: &str, sync_root: PathBuf, uploader: Arc<dyn Uploader>) -> Self {
        Self {
            name: name.to_string(),
            sync_root,
            uploader,
            seen: HashMap::new(),
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
        let paths = current.keys().cloned().collect::<Vec<_>>();
        for rel_path in paths {
            let path = self
                .sync_root
                .join(rel_path.replace('/', std::path::MAIN_SEPARATOR.to_string().as_str()));
            self.handle_entry(&path, rel_path, &mut current);
        }

        self.handle_deleted_entries(&current);
        self.seen = current;
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

            current.insert(
                rel_path,
                SeenEntry {
                    is_dir: entry.file_type().is_dir(),
                },
            );
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
            SeenEntry {
                is_dir: if metadata.is_dir() { true } else { is_dir_hint },
            },
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

        if self.seen.get(&rel_path) == Some(&entry) {
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
}
