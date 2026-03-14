use crate::cfapi::{
    cf_convert_to_placeholder, cf_get_placeholder_standard_info, cf_set_in_sync_with_usn,
    cf_set_not_in_sync,
};
use crate::runtime::{CfapiRuntime, Uploader};
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

    eprintln!(
        "close-completion: scheduled upload for {} after {:?} quiet period (generation {})",
        relative_path, CLOSE_UPLOAD_QUIET_PERIOD, generation
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
            return;
        }

        {
            let mut uploads_in_flight = debounce
                .uploads_in_flight
                .lock()
                .expect("uploads_in_flight lock poisoned");
            if !uploads_in_flight.insert(relative_path.clone()) {
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

    eprintln!("close-completion: checking upload for {}", relative_path);

    let metadata = match std::fs::metadata(&full_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "close-completion: path disappeared before upload check, skipping {}",
                relative_path
            );
            return UploadAttemptOutcome::Settled;
        }
        Err(err) => {
            eprintln!(
                "close-completion: metadata error for {}: {}",
                full_path.display(),
                err
            );
            return UploadAttemptOutcome::Retry;
        }
    };

    if metadata.is_dir() {
        eprintln!(
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
                eprintln!("cfapi uploaded directory: path={}", relative_path);
                UploadAttemptOutcome::Settled
            }
            Err(err) => {
                eprintln!(
                    "cfapi upload error (dir): path={} error={:#}",
                    relative_path, err
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
            eprintln!(
                "close-completion: file disappeared before open, skipping {}",
                relative_path
            );
            return UploadAttemptOutcome::Settled;
        }
        Err(err) => {
            eprintln!(
                "cfapi close-completion open error: path={} error={}",
                full_path.display(),
                err
            );
            return UploadAttemptOutcome::Retry;
        }
    };

    match cf_get_placeholder_standard_info(&file) {
        Ok(placeholder_info) if placeholder_info.ModifiedDataSize == 0 => {
            eprintln!(
                "close-completion: skipping upload for {} because ModifiedDataSize is zero",
                relative_path
            );
            return UploadAttemptOutcome::Settled;
        }
        Ok(_) => {}
        Err(err) => {
            eprintln!(
                "close-completion: placeholder info unavailable for {}, treating as modified: {}",
                relative_path, err
            );
        }
    }

    let snapshot_before = match capture_file_snapshot(&file) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            eprintln!(
                "close-completion: failed to snapshot {} before upload: {}",
                relative_path, err
            );
            return UploadAttemptOutcome::Retry;
        }
    };

    let mut upload_usn = match prepare_file_for_upload(&file) {
        Ok(usn) => usn,
        Err(err) => {
            eprintln!(
                "close-completion: failed to prepare {} for upload: {:#}",
                relative_path, err
            );
            return UploadAttemptOutcome::Retry;
        }
    };

    if let Err(err) = upload_file_on_close(worker, relative_path, snapshot_before.len, file) {
        eprintln!(
            "cfapi upload error: path={} bytes={} error={:#}",
            relative_path, snapshot_before.len, err
        );
        return UploadAttemptOutcome::Retry;
    }

    let snapshot_after = match capture_path_snapshot(&full_path) {
        Ok(snapshot) => snapshot,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            eprintln!(
                "close-completion: {} was removed after upload; waiting for follow-up event",
                relative_path
            );
            return UploadAttemptOutcome::Settled;
        }
        Err(err) => {
            eprintln!(
                "close-completion: failed to snapshot {} after upload: {}",
                relative_path, err
            );
            return UploadAttemptOutcome::Retry;
        }
    };

    if snapshot_after != snapshot_before {
        eprintln!(
            "close-completion: {} changed during upload, scheduling retry",
            relative_path
        );
        return UploadAttemptOutcome::Retry;
    }

    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&full_path)
    {
        Ok(file_for_sync) => {
            if let Err(err) = ensure_placeholder_then_set_in_sync(&file_for_sync, &mut upload_usn) {
                eprintln!(
                    "close-completion: failed to mark {} in sync after upload: {:#}",
                    relative_path, err
                );
                return UploadAttemptOutcome::Retry;
            }
        }
        Err(err) => {
            eprintln!(
                "close-completion: failed to reopen {} for in-sync update: {}",
                relative_path, err
            );
            return UploadAttemptOutcome::Retry;
        }
    }

    eprintln!(
        "cfapi uploaded local file: path={} bytes={}",
        relative_path, snapshot_before.len
    );
    UploadAttemptOutcome::Settled
}

fn prepare_file_for_upload(file: &std::fs::File) -> Result<i64> {
    if cf_get_placeholder_standard_info(file).is_err() {
        cf_convert_to_placeholder(file)?;
    }
    cf_set_not_in_sync(file)
}

fn ensure_placeholder_then_set_in_sync(file: &std::fs::File, upload_usn: &mut i64) -> Result<()> {
    if cf_get_placeholder_standard_info(file).is_err() {
        cf_convert_to_placeholder(file)?;
    }
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
    eprintln!(
        "close-completion: uploading {} ({} bytes)",
        relative_path, metadata_len
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
