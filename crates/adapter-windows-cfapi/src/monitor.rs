use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

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

    pub fn walk(&mut self) {
        let mut current = HashMap::new();
        let walker = walkdir::WalkDir::new(&self.sync_root).into_iter();
        for entry in walker.flatten() {
            let path = entry.path();
            let rel_path = path_to_relative(&self.sync_root, &path.to_string_lossy());
            self.handle_entry(path, rel_path, &mut current);
        }

        self.handle_deleted_entries(&current);
        self.seen = current;
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
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };
        let entry = SeenEntry {
            is_dir: metadata.is_dir(),
        };
        current.insert(rel_path.clone(), entry);

        if self.seen.get(&rel_path) == Some(&entry) {
            return;
        }

        if metadata.is_dir() {
            eprintln!("{}: detected new directory {}", self.name, rel_path);
            let mut cursor = std::io::Cursor::new(b"<DIR>".to_vec());
            let remote_path = directory_marker_path(&rel_path);
            let _ = self
                .uploader
                .upload_reader(&remote_path, &mut cursor, b"<DIR>".len() as u64);
        } else {
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
