use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::{
    ChunkRef, CurrentState, MetadataStore, TOMBSTONE_MANIFEST_HASH, chunk_path_for_hash, hash_hex,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use tokio::fs;
#[cfg(test)]
use tokio::sync::Semaphore;

const DATA_SCRUB_ISSUE_SAMPLE_LIMIT: usize = 128;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DataScrubIssueKind {
    ManifestMissing,
    ManifestUnreadable,
    ManifestInvalid,
    ManifestHashMismatch,
    ManifestKeyMismatch,
    ManifestSizeMismatch,
    ReplicaIncomplete,
    ChunkMissing,
    ChunkUnreadable,
    ChunkSizeMismatch,
    ChunkHashMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataScrubIssue {
    pub kind: DataScrubIssueKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifest_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunk_hash: Option<String>,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DataScrubReport {
    pub current_keys_scanned: usize,
    pub version_indexes_scanned: usize,
    pub version_records_scanned: usize,
    pub manifests_scanned: usize,
    pub chunks_scanned: usize,
    pub bytes_scanned: u64,
    pub issue_count: usize,
    pub sampled_issue_count: usize,
    pub issue_sample_truncated: bool,
    #[serde(default)]
    pub issues: Vec<DataScrubIssue>,
}

#[derive(Clone)]
pub(crate) struct DataScrubber {
    pub(super) current_state: CurrentState,
    pub(super) manifests_dir: PathBuf,
    pub(super) chunks_dir: PathBuf,
    pub(super) metadata_store: Arc<dyn MetadataStore>,
    #[cfg(test)]
    pub(super) run_test_hook: Option<DataScrubRunTestHook>,
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct DataScrubRunTestHook {
    started: Arc<Semaphore>,
    release: Arc<Semaphore>,
}

#[cfg(test)]
impl DataScrubRunTestHook {
    pub(crate) fn new() -> Self {
        Self {
            started: Arc::new(Semaphore::new(0)),
            release: Arc::new(Semaphore::new(0)),
        }
    }

    async fn block_run(&self) {
        self.started.add_permits(1);
        let permit = self
            .release
            .acquire()
            .await
            .expect("data scrub test hook should remain open");
        permit.forget();
    }

    pub(crate) async fn wait_until_started(&self) {
        let permit = self
            .started
            .acquire()
            .await
            .expect("data scrub test hook should remain open");
        permit.forget();
    }

    pub(crate) fn release_run(&self) {
        self.release.add_permits(1);
    }
}

#[derive(Debug, Clone)]
struct DataScrubReference {
    key: Option<String>,
    object_id: Option<String>,
    version_id: Option<String>,
}

impl DataScrubReference {
    fn subject(&self) -> Option<String> {
        let key = self.key.as_ref()?;
        if let Some(version_id) = &self.version_id {
            return Some(format!("{key}@{version_id}"));
        }
        Some(key.clone())
    }
}

#[derive(Debug, Default)]
pub(crate) struct DataScrubRunOutput {
    pub(crate) report: DataScrubReport,
    pub(crate) repair_subjects: BTreeSet<String>,
    pub(crate) degraded_subjects: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct VerifiedChunkState {
    actual_size_bytes: Option<u64>,
    actual_hash: Option<String>,
    read_error: Option<String>,
    missing: bool,
}

impl DataScrubber {
    pub(super) fn new(
        current_state: CurrentState,
        manifests_dir: PathBuf,
        chunks_dir: PathBuf,
        metadata_store: Arc<dyn MetadataStore>,
    ) -> Self {
        Self {
            current_state,
            manifests_dir,
            chunks_dir,
            metadata_store,
            #[cfg(test)]
            run_test_hook: None,
        }
    }

    #[cfg(test)]
    pub(super) fn with_run_test_hook(mut self, hook: Option<DataScrubRunTestHook>) -> Self {
        self.run_test_hook = hook;
        self
    }

    #[cfg(test)]
    pub(crate) async fn run(&self) -> Result<DataScrubReport> {
        Ok(self.run_internal(None).await?.report)
    }

    pub(crate) async fn run_with_repair_subjects(&self) -> Result<DataScrubRunOutput> {
        self.run_internal(None).await
    }

    pub(crate) async fn run_for_subjects(
        &self,
        subject_filter: &BTreeSet<String>,
    ) -> Result<DataScrubReport> {
        Ok(self.run_internal(Some(subject_filter)).await?.report)
    }

    async fn run_internal(
        &self,
        subject_filter: Option<&BTreeSet<String>>,
    ) -> Result<DataScrubRunOutput> {
        #[cfg(test)]
        if let Some(run_test_hook) = &self.run_test_hook {
            run_test_hook.block_run().await;
        }

        let mut output = DataScrubRunOutput {
            report: DataScrubReport::default(),
            repair_subjects: BTreeSet::new(),
            degraded_subjects: BTreeSet::new(),
        };
        if subject_filter.is_none() {
            output.report.current_keys_scanned = self.current_state.objects.len();
        }
        let mut manifest_references = HashMap::<String, Vec<DataScrubReference>>::new();
        let mut reverse_current_keys = HashMap::<String, String>::new();
        for (key, object_id) in &self.current_state.object_ids {
            reverse_current_keys.insert(object_id.clone(), key.clone());
        }

        let mut current_keys: Vec<_> = self.current_state.objects.keys().cloned().collect();
        current_keys.sort();
        for key in current_keys {
            if let Some(subject_filter) = subject_filter
                && !subject_filter.contains(&key)
            {
                continue;
            }
            let Some(manifest_hash) = self.current_state.objects.get(&key) else {
                continue;
            };
            if manifest_hash == TOMBSTONE_MANIFEST_HASH {
                continue;
            }
            if subject_filter.is_some() {
                output.report.current_keys_scanned =
                    output.report.current_keys_scanned.saturating_add(1);
            }
            manifest_references
                .entry(manifest_hash.clone())
                .or_default()
                .push(DataScrubReference {
                    key: Some(key.clone()),
                    object_id: self.current_state.object_ids.get(&key).cloned(),
                    version_id: None,
                });
        }

        let mut version_indexes = self.metadata_store.load_all_version_indexes().await?;
        version_indexes.sort_by(|a, b| a.object_id.cmp(&b.object_id));
        if subject_filter.is_none() {
            output.report.version_indexes_scanned = version_indexes.len();
        }

        for index in version_indexes {
            let mut records: Vec<_> = index.versions.values().cloned().collect();
            records.sort_by(|a, b| {
                a.created_at_unix
                    .cmp(&b.created_at_unix)
                    .then_with(|| a.version_id.cmp(&b.version_id))
            });
            if subject_filter.is_none() {
                output.report.version_records_scanned = output
                    .report
                    .version_records_scanned
                    .saturating_add(records.len());
            }
            let mut scanned_index = false;
            for record in records {
                if record.manifest_hash == TOMBSTONE_MANIFEST_HASH {
                    continue;
                }
                let key = record
                    .logical_path
                    .clone()
                    .or_else(|| reverse_current_keys.get(&index.object_id).cloned());
                if let Some(subject_filter) = subject_filter {
                    let Some(key) = key.as_deref() else {
                        continue;
                    };
                    let subject = format!("{key}@{}", record.version_id);
                    if !subject_filter.contains(&subject) {
                        continue;
                    }
                    scanned_index = true;
                    output.report.version_records_scanned =
                        output.report.version_records_scanned.saturating_add(1);
                }
                manifest_references
                    .entry(record.manifest_hash.clone())
                    .or_default()
                    .push(DataScrubReference {
                        key,
                        object_id: Some(index.object_id.clone()),
                        version_id: Some(record.version_id.clone()),
                    });
            }
            if subject_filter.is_some() && scanned_index {
                output.report.version_indexes_scanned =
                    output.report.version_indexes_scanned.saturating_add(1);
            }
        }

        let mut manifest_hashes: Vec<_> = manifest_references.keys().cloned().collect();
        manifest_hashes.sort();
        let mut verified_chunks = HashMap::<String, VerifiedChunkState>::new();
        let locally_owned_manifests = self
            .metadata_store
            .list_locally_owned_manifests()
            .await?
            .into_iter()
            .collect::<HashSet<_>>();

        for manifest_hash in manifest_hashes {
            output.report.manifests_scanned = output.report.manifests_scanned.saturating_add(1);
            let contexts = manifest_references
                .get(&manifest_hash)
                .cloned()
                .unwrap_or_default();
            self.verify_manifest(
                &manifest_hash,
                &contexts,
                locally_owned_manifests.contains(&manifest_hash),
                &mut verified_chunks,
                &mut output,
            )
            .await;
        }

        output.report.sampled_issue_count = output.report.issues.len();
        output.report.issue_sample_truncated =
            output.report.issue_count > output.report.issues.len();
        Ok(output)
    }

    async fn verify_manifest(
        &self,
        manifest_hash: &str,
        contexts: &[DataScrubReference],
        manifest_locally_owned: bool,
        verified_chunks: &mut HashMap<String, VerifiedChunkState>,
        output: &mut DataScrubRunOutput,
    ) {
        let manifest_path = self.manifests_dir.join(format!("{manifest_hash}.json"));
        let payload = match self.read_with_bounded_retry(&manifest_path).await {
            Ok(payload) => payload,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                self.push_issue(
                    output,
                    contexts,
                    DataScrubIssueKind::ManifestMissing,
                    Some(manifest_hash.to_string()),
                    None,
                    format!("manifest missing at {}", manifest_path.display()),
                );
                return;
            }
            Err(err) => {
                self.push_issue(
                    output,
                    contexts,
                    DataScrubIssueKind::ManifestUnreadable,
                    Some(manifest_hash.to_string()),
                    None,
                    format!("failed reading manifest {}: {err}", manifest_path.display()),
                );
                return;
            }
        };

        let computed_manifest_hash = hash_hex(&payload);
        if computed_manifest_hash != manifest_hash {
            self.push_issue(
                output,
                contexts,
                DataScrubIssueKind::ManifestHashMismatch,
                Some(manifest_hash.to_string()),
                None,
                format!(
                    "manifest hash mismatch expected={manifest_hash} actual={computed_manifest_hash}"
                ),
            );
        }

        let manifest = match serde_json::from_slice::<super::ObjectManifest>(&payload) {
            Ok(manifest) => manifest,
            Err(err) => {
                self.push_issue(
                    output,
                    contexts,
                    DataScrubIssueKind::ManifestInvalid,
                    Some(manifest_hash.to_string()),
                    None,
                    format!("invalid manifest payload: {err}"),
                );
                return;
            }
        };

        let expected_keys = contexts
            .iter()
            .filter_map(|context| context.key.as_deref())
            .collect::<BTreeSet<_>>();
        if !expected_keys.is_empty() && !expected_keys.contains(manifest.key.as_str()) {
            self.push_issue(
                output,
                contexts,
                DataScrubIssueKind::ManifestKeyMismatch,
                Some(manifest_hash.to_string()),
                None,
                format!(
                    "manifest key '{}' did not match referenced logical path(s): {}",
                    manifest.key,
                    expected_keys.into_iter().collect::<Vec<_>>().join(", ")
                ),
            );
        }

        let declared_total = manifest
            .chunks
            .iter()
            .fold(0usize, |acc, chunk| acc.saturating_add(chunk.size_bytes));
        if declared_total != manifest.total_size_bytes {
            self.push_issue(
                output,
                contexts,
                DataScrubIssueKind::ManifestSizeMismatch,
                Some(manifest_hash.to_string()),
                None,
                format!(
                    "manifest total_size_bytes mismatch expected={} summed_chunks={declared_total}",
                    manifest.total_size_bytes
                ),
            );
        }

        for chunk in &manifest.chunks {
            let verified_state = if let Some(existing) = verified_chunks.get(&chunk.hash) {
                existing.clone()
            } else {
                let verified = self.verify_chunk(chunk, &mut output.report).await;
                verified_chunks.insert(chunk.hash.clone(), verified.clone());
                verified
            };

            if verified_state.missing {
                let issue_kind = if manifest_locally_owned {
                    DataScrubIssueKind::ChunkMissing
                } else {
                    DataScrubIssueKind::ReplicaIncomplete
                };
                let detail = if manifest_locally_owned {
                    format!("chunk {} is missing from local storage", chunk.hash)
                } else {
                    format!(
                        "replica is incomplete locally: chunk {} is referenced by metadata manifest {manifest_hash} but is not present in local storage",
                        chunk.hash
                    )
                };
                self.push_issue(
                    output,
                    contexts,
                    issue_kind,
                    Some(manifest_hash.to_string()),
                    Some(chunk.hash.clone()),
                    detail,
                );
                continue;
            }

            if let Some(read_error) = &verified_state.read_error {
                self.push_issue(
                    output,
                    contexts,
                    DataScrubIssueKind::ChunkUnreadable,
                    Some(manifest_hash.to_string()),
                    Some(chunk.hash.clone()),
                    read_error.clone(),
                );
                continue;
            }

            if verified_state.actual_size_bytes != Some(chunk.size_bytes as u64) {
                self.push_issue(
                    output,
                    contexts,
                    DataScrubIssueKind::ChunkSizeMismatch,
                    Some(manifest_hash.to_string()),
                    Some(chunk.hash.clone()),
                    format!(
                        "chunk size mismatch expected={} actual={}",
                        chunk.size_bytes,
                        verified_state.actual_size_bytes.unwrap_or_default()
                    ),
                );
                continue;
            }

            if verified_state.actual_hash.as_deref() != Some(chunk.hash.as_str()) {
                self.push_issue(
                    output,
                    contexts,
                    DataScrubIssueKind::ChunkHashMismatch,
                    Some(manifest_hash.to_string()),
                    Some(chunk.hash.clone()),
                    format!(
                        "chunk hash mismatch expected={} actual={}",
                        chunk.hash,
                        verified_state.actual_hash.as_deref().unwrap_or("<missing>")
                    ),
                );
            }
        }
    }

    async fn read_with_bounded_retry(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        match fs::read(path).await {
            Ok(payload) => Ok(payload),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(err),
            Err(_) => fs::read(path).await,
        }
    }

    async fn verify_chunk(
        &self,
        chunk: &ChunkRef,
        report: &mut DataScrubReport,
    ) -> VerifiedChunkState {
        report.chunks_scanned = report.chunks_scanned.saturating_add(1);
        let chunk_path = match chunk_path_for_hash(&self.chunks_dir, &chunk.hash) {
            Ok(p) => p,
            Err(err) => {
                return VerifiedChunkState {
                    actual_size_bytes: None,
                    actual_hash: None,
                    read_error: Some(format!("invalid chunk hash {}: {err}", chunk.hash)),
                    missing: false,
                };
            }
        };
        match self.read_with_bounded_retry(&chunk_path).await {
            Ok(payload) => {
                report.bytes_scanned = report.bytes_scanned.saturating_add(payload.len() as u64);
                VerifiedChunkState {
                    actual_size_bytes: Some(payload.len() as u64),
                    actual_hash: Some(hash_hex(&payload)),
                    read_error: None,
                    missing: false,
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => VerifiedChunkState {
                actual_size_bytes: None,
                actual_hash: None,
                read_error: None,
                missing: true,
            },
            Err(err) => VerifiedChunkState {
                actual_size_bytes: None,
                actual_hash: None,
                read_error: Some(format!("failed reading chunk {}: {err}", chunk.hash)),
                missing: false,
            },
        }
    }

    fn push_issue(
        &self,
        output: &mut DataScrubRunOutput,
        contexts: &[DataScrubReference],
        kind: DataScrubIssueKind,
        manifest_hash: Option<String>,
        chunk_hash: Option<String>,
        detail: String,
    ) {
        if data_scrub_issue_requires_auto_repair(&kind) {
            output
                .repair_subjects
                .extend(data_scrub_repair_subjects_for_contexts(contexts));
            output
                .degraded_subjects
                .extend(data_scrub_all_subjects_for_contexts(contexts));
        }

        let report = &mut output.report;
        report.issue_count = report.issue_count.saturating_add(1);
        if report.issues.len() >= DATA_SCRUB_ISSUE_SAMPLE_LIMIT {
            return;
        }

        let context = contexts.first();
        report.issues.push(DataScrubIssue {
            kind,
            key: context.and_then(|context| context.key.clone()),
            object_id: context.and_then(|context| context.object_id.clone()),
            version_id: context.and_then(|context| context.version_id.clone()),
            manifest_hash,
            chunk_hash,
            detail,
        });
    }
}

fn data_scrub_issue_requires_auto_repair(kind: &DataScrubIssueKind) -> bool {
    !matches!(kind, DataScrubIssueKind::ManifestKeyMismatch)
}

fn data_scrub_repair_subjects_for_contexts(contexts: &[DataScrubReference]) -> BTreeSet<String> {
    let mut subjects = BTreeSet::new();
    let versioned_base_keys = contexts
        .iter()
        .filter(|context| context.version_id.is_some())
        .filter_map(|context| context.key.clone())
        .collect::<HashSet<_>>();

    for context in contexts {
        match (&context.key, &context.version_id) {
            (Some(key), Some(version_id)) => {
                subjects.insert(format!("{key}@{version_id}"));
            }
            (Some(key), None) if !versioned_base_keys.contains(key) => {
                subjects.insert(key.clone());
            }
            _ => {}
        }
    }

    subjects
}

fn data_scrub_all_subjects_for_contexts(contexts: &[DataScrubReference]) -> BTreeSet<String> {
    contexts
        .iter()
        .filter_map(DataScrubReference::subject)
        .collect()
}
