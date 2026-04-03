use crate::cfapi::{
    cf_ensure_placeholder_identity, cf_get_placeholder_standard_info, cf_set_in_sync_with_usn,
    cf_set_not_in_sync, describe_path_state,
};
use crate::runtime::{CfapiRuntime, Uploader, reconcile_ancestor_directory_sync_states};
use crate::snapshot_cache::record_local_file_hash;
use anyhow::Result;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

const CLOSE_UPLOAD_QUIET_PERIOD: Duration = Duration::from_millis(750);
const CLOSE_UPLOAD_RETRY_DELAY: Duration = Duration::from_millis(1000);

pub(crate) struct UploadWorkerContext {
    pub(crate) sync_root: PathBuf,
    pub(crate) runtime: Arc<CfapiRuntime>,
    pub(crate) uploader: Arc<dyn Uploader>,
}

#[derive(Default)]
pub(crate) struct UploadDebounceState {
    pending_generations: Mutex<std::collections::HashMap<String, u64>>,
    uploads_in_flight: Mutex<HashSet<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UploadDebounceSnapshot {
    pub pending_count: usize,
    pub uploads_in_flight_count: usize,
    pub path_generation: Option<u64>,
    pub path_in_flight: bool,
    pub pending_paths_sample: Vec<String>,
    pub uploads_in_flight_sample: Vec<String>,
}

impl UploadDebounceSnapshot {
    pub(crate) fn to_log_string(&self) -> String {
        format!(
            "pending_count={} in_flight_count={} path_generation={:?} path_in_flight={} pending_sample={:?} in_flight_sample={:?}",
            self.pending_count,
            self.uploads_in_flight_count,
            self.path_generation,
            self.path_in_flight,
            self.pending_paths_sample,
            self.uploads_in_flight_sample
        )
    }
}

impl UploadDebounceState {
    pub(crate) fn has_in_flight_upload_for_path(&self, relative_path: &str) -> bool {
        self.uploads_in_flight
            .lock()
            .expect("uploads_in_flight lock poisoned")
            .contains(relative_path)
    }

    pub(crate) fn debug_snapshot_for_path(
        &self,
        relative_path: &str,
        sample_limit: usize,
    ) -> UploadDebounceSnapshot {
        let sample_limit = sample_limit.max(1);
        let (pending_count, path_generation, pending_paths_sample) = {
            let pending = self
                .pending_generations
                .lock()
                .expect("pending upload generations lock poisoned");
            let mut pending_paths = pending.keys().cloned().collect::<Vec<_>>();
            pending_paths.sort();
            (
                pending.len(),
                pending.get(relative_path).copied(),
                pending_paths
                    .into_iter()
                    .take(sample_limit)
                    .collect::<Vec<_>>(),
            )
        };
        let (uploads_in_flight_count, path_in_flight, uploads_in_flight_sample) = {
            let uploads_in_flight = self
                .uploads_in_flight
                .lock()
                .expect("uploads_in_flight lock poisoned");
            let mut in_flight_paths = uploads_in_flight.iter().cloned().collect::<Vec<_>>();
            in_flight_paths.sort();
            (
                uploads_in_flight.len(),
                uploads_in_flight.contains(relative_path),
                in_flight_paths
                    .into_iter()
                    .take(sample_limit)
                    .collect::<Vec<_>>(),
            )
        };

        UploadDebounceSnapshot {
            pending_count,
            uploads_in_flight_count,
            path_generation,
            path_in_flight,
            pending_paths_sample,
            uploads_in_flight_sample,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalFileSnapshot {
    len: u64,
    modified: Option<SystemTime>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UploadAttemptOutcome {
    Settled,
    Retry,
}

pub(crate) fn schedule_debounced_close_upload(
    worker: Arc<UploadWorkerContext>,
    debounce: Arc<UploadDebounceState>,
    relative_path: String,
) {
    let generation = {
        let mut pending = debounce
            .pending_generations
            .lock()
            .expect("pending upload generations lock poisoned");
        let entry = pending.entry(relative_path.clone()).or_insert(0);
        *entry += 1;
        *entry
    };
    let snapshot = debounce.debug_snapshot_for_path(&relative_path, 8);

    tracing::info!(
        "close-completion: scheduled upload for {} after {:?} quiet period (generation {}, {})",
        relative_path,
        CLOSE_UPLOAD_QUIET_PERIOD,
        generation,
        snapshot.to_log_string()
    );

    spawn_debounced_close_upload(
        worker,
        debounce,
        relative_path,
        generation,
        CLOSE_UPLOAD_QUIET_PERIOD,
    );
}

fn spawn_debounced_close_upload(
    worker: Arc<UploadWorkerContext>,
    debounce: Arc<UploadDebounceState>,
    relative_path: String,
    generation: u64,
    delay: Duration,
) {
    std::thread::spawn(move || {
        std::thread::sleep(delay);

        let is_latest = {
            let pending = debounce
                .pending_generations
                .lock()
                .expect("pending upload generations lock poisoned");
            pending.get(&relative_path).copied() == Some(generation)
        };
        if !is_latest {
            let snapshot = debounce.debug_snapshot_for_path(&relative_path, 8);
            tracing::info!(
                "close-completion: skipping stale upload worker for {} generation {} ({})",
                relative_path,
                generation,
                snapshot.to_log_string()
            );
            return;
        }

        {
            let mut uploads_in_flight = debounce
                .uploads_in_flight
                .lock()
                .expect("uploads_in_flight lock poisoned");
            if !uploads_in_flight.insert(relative_path.clone()) {
                drop(uploads_in_flight);
                let snapshot = debounce.debug_snapshot_for_path(&relative_path, 8);
                tracing::info!(
                    "close-completion: upload already in flight for {} generation {} ({})",
                    relative_path,
                    generation,
                    snapshot.to_log_string()
                );
                return;
            }
        }

        let outcome = process_debounced_close_upload(worker.as_ref(), &relative_path);

        debounce
            .uploads_in_flight
            .lock()
            .expect("uploads_in_flight lock poisoned")
            .remove(&relative_path);

        let latest_generation = {
            let pending = debounce
                .pending_generations
                .lock()
                .expect("pending upload generations lock poisoned");
            pending.get(&relative_path).copied()
        };

        match (outcome, latest_generation) {
            (_, Some(latest)) if latest != generation => {}
            (UploadAttemptOutcome::Retry, Some(latest)) => {
                let snapshot = debounce.debug_snapshot_for_path(&relative_path, 8);
                tracing::info!(
                    "close-completion: retrying upload for {} generation {} after {:?} ({})",
                    relative_path,
                    latest,
                    CLOSE_UPLOAD_RETRY_DELAY,
                    snapshot.to_log_string()
                );
                spawn_debounced_close_upload(
                    worker,
                    debounce,
                    relative_path,
                    latest,
                    CLOSE_UPLOAD_RETRY_DELAY,
                );
            }
            (UploadAttemptOutcome::Settled, Some(latest)) if latest == generation => {
                debounce
                    .pending_generations
                    .lock()
                    .expect("pending upload generations lock poisoned")
                    .remove(&relative_path);
            }
            _ => {}
        }
    });
}

fn process_debounced_close_upload(
    worker: &UploadWorkerContext,
    relative_path: &str,
) -> UploadAttemptOutcome {
    let full_path = worker.sync_root.join(relative_path);

    tracing::info!(
        "close-completion: checking upload for {} state_before={}",
        relative_path,
        describe_path_state(&full_path)
    );

    let metadata = match std::fs::metadata(&full_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(
                "close-completion: path disappeared before upload check, skipping {}",
                relative_path
            );
            return UploadAttemptOutcome::Settled;
        }
        Err(err) => {
            tracing::info!(
                "close-completion: metadata error for {}: {}",
                full_path.display(),
                err
            );
            return UploadAttemptOutcome::Retry;
        }
    };

    if metadata.is_dir() {
        tracing::info!(
            "close-completion: {} is a directory, uploading directory metadata",
            relative_path
        );
        let mut cursor = std::io::Cursor::new(b"<DIR>".to_vec());
        return match worker.uploader.upload_reader(
            relative_path,
            &mut cursor,
            b"<DIR>".len() as u64,
        ) {
            Ok(_) => {
                tracing::info!("cfapi uploaded directory: path={}", relative_path);
                UploadAttemptOutcome::Settled
            }
            Err(err) => {
                tracing::info!(
                    "cfapi upload error (dir): path={} error={:#}",
                    relative_path,
                    err
                );
                UploadAttemptOutcome::Retry
            }
        };
    }

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&full_path)
    {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(
                "close-completion: file disappeared before open, skipping {}",
                relative_path
            );
            return UploadAttemptOutcome::Settled;
        }
        Err(err) => {
            tracing::info!(
                "cfapi close-completion open error: path={} error={}",
                full_path.display(),
                err
            );
            return UploadAttemptOutcome::Retry;
        }
    };

    match cf_get_placeholder_standard_info(&file) {
        Ok(placeholder_info) if placeholder_info.ModifiedDataSize == 0 => {
            tracing::info!(
                "close-completion: skipping upload for {} because ModifiedDataSize is zero state={}",
                relative_path,
                describe_path_state(&full_path)
            );
            return UploadAttemptOutcome::Settled;
        }
        Ok(_) => {}
        Err(err) => {
            tracing::info!(
                "close-completion: placeholder info unavailable for {}, treating as modified: {}",
                relative_path,
                err
            );
        }
    }

    let snapshot_before = match capture_file_snapshot(&file) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            tracing::info!(
                "close-completion: failed to snapshot {} before upload: {}",
                relative_path,
                err
            );
            return UploadAttemptOutcome::Retry;
        }
    };

    let mut upload_usn = match prepare_file_for_upload(&file, relative_path) {
        Ok(usn) => usn,
        Err(err) => {
            tracing::info!(
                "close-completion: failed to prepare {} for upload: {:#}",
                relative_path,
                err
            );
            return UploadAttemptOutcome::Retry;
        }
    };
    tracing::info!(
        "close-completion: prepared {} for upload snapshot_before={:?} upload_usn={} state={}",
        relative_path,
        snapshot_before,
        upload_usn,
        describe_path_state(&full_path)
    );
    reconcile_ancestor_directory_sync_states(&worker.sync_root, relative_path);

    if let Err(err) = upload_file_on_close(worker, relative_path, snapshot_before.len, file) {
        tracing::info!(
            "cfapi upload error: path={} bytes={} error={:#}",
            relative_path,
            snapshot_before.len,
            err
        );
        return UploadAttemptOutcome::Retry;
    }

    let snapshot_after = match capture_path_snapshot(&full_path) {
        Ok(snapshot) => snapshot,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(
                "close-completion: {} was removed after upload; waiting for follow-up event",
                relative_path
            );
            return UploadAttemptOutcome::Settled;
        }
        Err(err) => {
            tracing::info!(
                "close-completion: failed to snapshot {} after upload: {}",
                relative_path,
                err
            );
            return UploadAttemptOutcome::Retry;
        }
    };

    if snapshot_after != snapshot_before {
        tracing::info!(
            "close-completion: {} changed during upload, scheduling retry snapshot_before={:?} snapshot_after={:?} state={}",
            relative_path,
            snapshot_before,
            snapshot_after,
            describe_path_state(&full_path)
        );
        return UploadAttemptOutcome::Retry;
    }
    tracing::info!(
        "close-completion: upload finished for {} snapshot_after={:?} upload_usn={} state_before_in_sync={}",
        relative_path,
        snapshot_after,
        upload_usn,
        describe_path_state(&full_path)
    );

    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&full_path)
    {
        Ok(file_for_sync) => {
            if let Err(err) =
                ensure_placeholder_then_set_in_sync(&file_for_sync, relative_path, &mut upload_usn)
            {
                tracing::info!(
                    "close-completion: failed to mark {} in sync after upload: {:#}",
                    relative_path,
                    err
                );
                return UploadAttemptOutcome::Retry;
            }
        }
        Err(err) => {
            tracing::info!(
                "close-completion: failed to reopen {} for in-sync update: {}",
                relative_path,
                err
            );
            return UploadAttemptOutcome::Retry;
        }
    }

    reconcile_ancestor_directory_sync_states(&worker.sync_root, relative_path);
    if let Err(err) = record_local_file_hash(&worker.sync_root, relative_path) {
        tracing::info!(
            "close-completion: failed to record in-sync local file hash for {}: {:#}",
            relative_path,
            err
        );
    }
    tracing::info!(
        "cfapi uploaded local file: path={} bytes={} final_state={}",
        relative_path,
        snapshot_before.len,
        describe_path_state(&full_path)
    );
    UploadAttemptOutcome::Settled
}

fn prepare_file_for_upload(file: &std::fs::File, relative_path: &str) -> Result<i64> {
    cf_ensure_placeholder_identity(file, relative_path)?;
    cf_set_not_in_sync(file)
}

fn ensure_placeholder_then_set_in_sync(
    file: &std::fs::File,
    relative_path: &str,
    upload_usn: &mut i64,
) -> Result<()> {
    cf_ensure_placeholder_identity(file, relative_path)?;
    cf_set_in_sync_with_usn(file, upload_usn)
}

fn capture_file_snapshot(file: &std::fs::File) -> Result<LocalFileSnapshot> {
    let metadata = file.metadata()?;
    Ok(LocalFileSnapshot {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

fn capture_path_snapshot(path: &Path) -> std::io::Result<LocalFileSnapshot> {
    let metadata = std::fs::metadata(path)?;
    Ok(LocalFileSnapshot {
        len: metadata.len(),
        modified: metadata.modified().ok(),
    })
}

fn upload_file_on_close(
    worker: &UploadWorkerContext,
    relative_path: &str,
    metadata_len: u64,
    file: std::fs::File,
) -> Result<()> {
    tracing::info!(
        "close-completion: uploading {} ({} bytes)",
        relative_path,
        metadata_len
    );

    let mut reader = file;
    let remote_version = worker
        .uploader
        .upload_reader(relative_path, &mut reader, metadata_len)?;
    if let Some(version) = remote_version {
        worker.runtime.set_remote_version(relative_path, version);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::path::Path;
    use std::sync::Mutex as StdMutex;
    use std::time::UNIX_EPOCH;

    #[derive(Default)]
    struct RecordingUploader {
        uploads: StdMutex<Vec<(String, Vec<u8>, u64)>>,
        fail: bool,
    }

    impl Uploader for RecordingUploader {
        fn upload_reader(
            &self,
            path: &str,
            reader: &mut dyn std::io::Read,
            length: u64,
        ) -> Result<Option<String>> {
            if self.fail {
                return Err(anyhow!("simulated upload failure"));
            }
            let mut payload = Vec::new();
            reader.read_to_end(&mut payload)?;
            self.uploads
                .lock()
                .expect("upload record lock poisoned")
                .push((path.to_string(), payload, length));
            Ok(Some(format!("version:size={length}")))
        }
    }

    fn make_test_file(payload: &[u8]) -> (std::path::PathBuf, std::fs::File) {
        let path = std::env::temp_dir().join(format!(
            "ironmesh-cfapi-close-upload-test-{}-{}.bin",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time should be after epoch")
                .as_nanos()
        ));
        std::fs::write(&path, payload).expect("failed to write temp test file");
        let file = std::fs::File::open(&path).expect("failed to reopen temp test file");
        (path, file)
    }

    fn test_upload_worker_context(uploader: Arc<dyn Uploader>) -> UploadWorkerContext {
        UploadWorkerContext {
            sync_root: Path::new("C:/ironmesh-test").to_path_buf(),
            runtime: Arc::new(CfapiRuntime::default()),
            uploader,
        }
    }

    #[test]
    fn upload_file_on_close_updates_runtime_after_successful_upload() {
        let uploader = Arc::new(RecordingUploader::default());
        let worker = test_upload_worker_context(uploader.clone());
        let payload = b"cfapi-upload-payload";
        let (path, file) = make_test_file(payload);

        upload_file_on_close(&worker, "docs/photo.jpg", payload.len() as u64, file)
            .expect("upload should succeed");

        let uploads = uploader
            .uploads
            .lock()
            .expect("upload record lock poisoned");
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].0, "docs/photo.jpg");
        assert_eq!(uploads[0].1, payload);
        assert_eq!(uploads[0].2, payload.len() as u64);
        drop(uploads);

        let hydrated = worker
            .runtime
            .handle_fetch_data("docs/photo.jpg", &crate::runtime::DemoHydrator)
            .expect("remote version should still be updated after upload");
        let hydrated_text = String::from_utf8(hydrated).expect("demo hydrator emits utf8 payload");
        assert!(hydrated_text.contains(&format!("version:size={}", payload.len())));

        let _ = std::fs::remove_file(path);
    }
}
