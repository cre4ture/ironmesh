use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

use crate::cfapi::{path_is_placeholder, try_convert_materialized_file};
use crate::helpers::path_to_relative;
use crate::runtime::Uploader;

pub struct SyncRootMonitor {
    name: String,
    sync_root: PathBuf,
    uploader: Arc<dyn Uploader>,
    seen: HashSet<String>,
}

impl SyncRootMonitor {
    pub fn new(name: &str, sync_root: PathBuf, uploader: Arc<dyn Uploader>) -> Self {
        Self {
            name: name.to_string(),
            sync_root,
            uploader,
            seen: HashSet::new(),
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
        let walker = walkdir::WalkDir::new(&self.sync_root).into_iter();
        for entry in walker.flatten() {
            let path = entry.path();
            let rel_path = path_to_relative(&self.sync_root, &path.to_string_lossy());
            self.handle_entry(path, rel_path);
        }
    }

    fn handle_entry(&mut self, path: &std::path::Path, rel_path: String) {
        if rel_path.is_empty() || self.seen.contains(&rel_path) {
            return;
        }
        let metadata = match std::fs::metadata(path) {
            Ok(m) => m,
            Err(_) => return,
        };
        if metadata.is_dir() {
            eprintln!("{}: detected new directory {}", self.name, rel_path);
            let mut cursor = std::io::Cursor::new(b"<DIR>".to_vec());
            let _ = self
                .uploader
                .upload_reader(&rel_path, &mut cursor, b"<DIR>".len() as u64);
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
                if let Err(e) = self.uploader.upload_reader(&rel_path, &mut std::fs::File::open(path).unwrap(), metadata.len()) {
                    eprintln!(
                        "{}: failed to upload file {}: {}",
                        self.name, rel_path, e
                    );
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
        self.seen.insert(rel_path);
    }
}
