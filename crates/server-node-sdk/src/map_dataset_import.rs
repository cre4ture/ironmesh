use super::*;
use bytes::BytesMut;
use reqwest::Url;

const MAP_IMPORT_PATH: &str = "state/map_dataset_import.json";
const MAP_IMPORT_STORAGE_ROOT: &str = "sys/maps";
const MAP_IMPORT_MIN_PART_SIZE_BYTES: u64 = 256 * 1024 * 1024;
const MAP_IMPORT_MAX_PART_SIZE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const MAP_IMPORT_INGEST_CHUNK_BYTES: usize = 8 * 1024 * 1024;
const MAP_IMPORT_CHECKPOINT_BYTES: u64 = 64 * 1024 * 1024;
const MAP_IMPORT_RETRY_MAX_DELAY_SECS: u64 = 60;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AdminMapDatasetImportState {
    Running,
    Failed,
    Completed,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AdminMapDatasetImportStatusResponse {
    pub(crate) active_job: Option<AdminMapDatasetImportJobView>,
    pub(crate) can_start_new: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AdminMapDatasetImportJobView {
    pub(crate) job_id: String,
    pub(crate) state: AdminMapDatasetImportState,
    pub(crate) dataset_filename: String,
    pub(crate) source_display: String,
    pub(crate) logical_key: String,
    pub(crate) manifest_key: String,
    pub(crate) part_size_bytes: u64,
    pub(crate) total_size_bytes: u64,
    pub(crate) total_parts: usize,
    pub(crate) completed_parts: usize,
    pub(crate) completed_bytes: u64,
    pub(crate) current_part_index: Option<usize>,
    pub(crate) current_part_id: Option<String>,
    pub(crate) current_part_key: Option<String>,
    pub(crate) current_part_size_bytes: Option<u64>,
    pub(crate) current_part_completed_bytes: u64,
    pub(crate) manifest_uploaded: bool,
    pub(crate) retry_count: u32,
    pub(crate) next_retry_at_unix: Option<u64>,
    pub(crate) last_error: Option<String>,
    pub(crate) started_at_unix: u64,
    pub(crate) updated_at_unix: u64,
    pub(crate) finished_at_unix: Option<u64>,
    pub(crate) progress_percent: f64,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct StartAdminMapDatasetImportRequest {
    source: String,
    part_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StartAdminMapDatasetImportResponse {
    pub(crate) started: bool,
    pub(crate) status: AdminMapDatasetImportStatusResponse,
}

#[derive(Debug)]
pub(crate) struct MapDatasetImportRuntime {
    pub(crate) path: PathBuf,
    job: Option<MapDatasetImportJob>,
    worker_running: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MapDatasetImportStateFile {
    #[serde(default)]
    job: Option<MapDatasetImportJob>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct MapDatasetImportJob {
    job_id: String,
    state: AdminMapDatasetImportState,
    source_url: String,
    dataset_filename: String,
    logical_key: String,
    manifest_key: String,
    part_size_bytes: u64,
    total_size_bytes: u64,
    total_parts: usize,
    completed_parts: usize,
    completed_bytes: u64,
    current_part_index: usize,
    current_part_downloaded_bytes: u64,
    #[serde(default)]
    current_part_chunk_refs: Vec<UploadChunkRef>,
    manifest_uploaded: bool,
    retry_count: u32,
    next_retry_at_unix: Option<u64>,
    last_error: Option<String>,
    started_at_unix: u64,
    updated_at_unix: u64,
    finished_at_unix: Option<u64>,
}

#[derive(Debug, Clone)]
struct MapDatasetProbe {
    source_url: String,
    dataset_filename: String,
    total_size_bytes: u64,
}

#[derive(Debug, Clone)]
struct MapDatasetPartSpec {
    index: usize,
    part_id: String,
    key: String,
    offset_bytes: u64,
    size_bytes: u64,
}

#[derive(Debug)]
enum ImportAdvanceError {
    Fatal(String),
    Transient(String),
}

#[derive(Debug, Serialize)]
struct SplitFileManifestDocument {
    manifest_version: u32,
    #[serde(rename = "type")]
    manifest_type: String,
    logical_format: String,
    logical_key: String,
    manifest_key: String,
    storage_root: String,
    logical_size_bytes: u64,
    last_part_size_bytes: u64,
    parts_count: usize,
    parts: Vec<SplitFileManifestPartDocument>,
}

#[derive(Debug, Serialize)]
struct SplitFileManifestPartDocument {
    part_id: String,
    key: String,
    offset_bytes: u64,
    size_bytes: u64,
}

impl MapDatasetImportRuntime {
    pub(crate) fn empty(path: PathBuf) -> Self {
        Self {
            path,
            job: None,
            worker_running: false,
        }
    }

    fn status_view(&self) -> AdminMapDatasetImportStatusResponse {
        AdminMapDatasetImportStatusResponse {
            active_job: self.job.as_ref().map(MapDatasetImportJob::view),
            can_start_new: !self.worker_running
                && !matches!(
                    self.job.as_ref().map(|job| job.state),
                    Some(AdminMapDatasetImportState::Running)
                ),
        }
    }
}

impl MapDatasetImportJob {
    fn view(&self) -> AdminMapDatasetImportJobView {
        let current_part = current_part_spec(self).ok().flatten();
        let downloaded_bytes = self
            .completed_bytes
            .saturating_add(self.current_part_downloaded_bytes)
            .min(self.total_size_bytes);
        let progress_percent = if self.total_size_bytes == 0 {
            0.0
        } else {
            (downloaded_bytes as f64 / self.total_size_bytes as f64) * 100.0
        };

        AdminMapDatasetImportJobView {
            job_id: self.job_id.clone(),
            state: self.state,
            dataset_filename: self.dataset_filename.clone(),
            source_display: source_display_url(&self.source_url),
            logical_key: self.logical_key.clone(),
            manifest_key: self.manifest_key.clone(),
            part_size_bytes: self.part_size_bytes,
            total_size_bytes: self.total_size_bytes,
            total_parts: self.total_parts,
            completed_parts: self.completed_parts,
            completed_bytes: self.completed_bytes,
            current_part_index: current_part.as_ref().map(|part| part.index),
            current_part_id: current_part.as_ref().map(|part| part.part_id.clone()),
            current_part_key: current_part.as_ref().map(|part| part.key.clone()),
            current_part_size_bytes: current_part.as_ref().map(|part| part.size_bytes),
            current_part_completed_bytes: self.current_part_downloaded_bytes,
            manifest_uploaded: self.manifest_uploaded,
            retry_count: self.retry_count,
            next_retry_at_unix: self.next_retry_at_unix,
            last_error: self.last_error.clone(),
            started_at_unix: self.started_at_unix,
            updated_at_unix: self.updated_at_unix,
            finished_at_unix: self.finished_at_unix,
            progress_percent,
        }
    }
}

pub(crate) async fn load_runtime(data_dir: &FsPath) -> Result<MapDatasetImportRuntime> {
    let path = data_dir.join(MAP_IMPORT_PATH);
    if !tokio::fs::try_exists(&path).await? {
        return Ok(MapDatasetImportRuntime::empty(path));
    }

    let payload = tokio::fs::read(&path)
        .await
        .with_context(|| format!("failed reading {}", path.display()))?;
    let parsed = serde_json::from_slice::<MapDatasetImportStateFile>(&payload)
        .with_context(|| format!("failed parsing {}", path.display()))?;
    Ok(MapDatasetImportRuntime {
        path,
        job: parsed.job,
        worker_running: false,
    })
}

pub(crate) async fn spawn_resume_if_needed(state: ServerState) {
    spawn_worker_if_needed(&state).await;
}

pub(crate) async fn admin_status(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let action = "auth/maps/import/status";
    if let Err(status) =
        authorize_admin_request(&state, &headers, action, true, true, json!({})).await
    {
        return status.into_response();
    }

    let status = {
        let runtime = state.storage.map_dataset_import.lock().await;
        runtime.status_view()
    };
    (StatusCode::OK, Json(status)).into_response()
}

pub(crate) async fn start_admin_import(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<StartAdminMapDatasetImportRequest>,
) -> impl IntoResponse {
    let action = "auth/maps/import/run";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({
            "part_size_bytes": request.part_size_bytes,
        }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let start_result = match start_import_job(&state, request).await {
        Ok(result) => result,
        Err(status) => return status.into_response(),
    };

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        if start_result.started {
            "started"
        } else {
            "already_running"
        },
        json!({
            "started": start_result.started,
            "active_job": start_result.status.active_job.as_ref().map(|job| json!({
                "job_id": job.job_id,
                "logical_key": job.logical_key,
                "manifest_key": job.manifest_key,
                "part_size_bytes": job.part_size_bytes,
                "total_size_bytes": job.total_size_bytes,
            })),
        }),
    )
    .await;

    (StatusCode::ACCEPTED, Json(start_result)).into_response()
}

async fn start_import_job(
    state: &ServerState,
    request: StartAdminMapDatasetImportRequest,
) -> std::result::Result<StartAdminMapDatasetImportResponse, StatusCode> {
    let source_url = match extract_source_url(&request.source) {
        Ok(url) => url,
        Err(_) => return Err(StatusCode::BAD_REQUEST),
    };
    if request.part_size_bytes < MAP_IMPORT_MIN_PART_SIZE_BYTES
        || request.part_size_bytes > MAP_IMPORT_MAX_PART_SIZE_BYTES
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    {
        let runtime = state.storage.map_dataset_import.lock().await;
        if !runtime.status_view().can_start_new {
            return Ok(StartAdminMapDatasetImportResponse {
                started: false,
                status: runtime.status_view(),
            });
        }
    }

    let http = build_map_import_http_client().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let probe = probe_download_source(&http, &source_url)
        .await
        .map_err(import_error_status)?;
    let now = unix_ts();
    let dataset_filename = probe.dataset_filename.clone();
    let job = MapDatasetImportJob {
        job_id: Uuid::now_v7().to_string(),
        state: AdminMapDatasetImportState::Running,
        source_url: probe.source_url,
        dataset_filename: dataset_filename.clone(),
        logical_key: format!("{MAP_IMPORT_STORAGE_ROOT}/{dataset_filename}"),
        manifest_key: format!(
            "{MAP_IMPORT_STORAGE_ROOT}/{}.manifest.json",
            dataset_filename
        ),
        part_size_bytes: request.part_size_bytes,
        total_size_bytes: probe.total_size_bytes,
        total_parts: part_count_for_size(probe.total_size_bytes, request.part_size_bytes)
            .map_err(|_| StatusCode::BAD_REQUEST)?,
        completed_parts: 0,
        completed_bytes: 0,
        current_part_index: 0,
        current_part_downloaded_bytes: 0,
        current_part_chunk_refs: Vec::new(),
        manifest_uploaded: false,
        retry_count: 0,
        next_retry_at_unix: None,
        last_error: None,
        started_at_unix: now,
        updated_at_unix: now,
        finished_at_unix: None,
    };

    let status = {
        let mut runtime = state.storage.map_dataset_import.lock().await;
        // A second request may have completed its range probe while this request
        // was probing. Keep the persisted job and single worker authoritative.
        if !runtime.status_view().can_start_new {
            return Ok(StartAdminMapDatasetImportResponse {
                started: false,
                status: runtime.status_view(),
            });
        }
        runtime.job = Some(job);
        runtime.status_view()
    };
    persist_runtime(state)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    spawn_worker_if_needed(state).await;

    Ok(StartAdminMapDatasetImportResponse {
        started: true,
        status,
    })
}

async fn spawn_worker_if_needed(state: &ServerState) {
    let should_spawn = {
        let mut runtime = state.storage.map_dataset_import.lock().await;
        if runtime.worker_running {
            false
        } else if matches!(
            runtime.job.as_ref().map(|job| job.state),
            Some(AdminMapDatasetImportState::Running)
        ) {
            runtime.worker_running = true;
            true
        } else {
            false
        }
    };

    if !should_spawn {
        return;
    }

    let state = state.clone();
    tokio::spawn(async move {
        run_worker(state.clone()).await;
        let mut runtime = state.storage.map_dataset_import.lock().await;
        runtime.worker_running = false;
    });
}

async fn run_worker(state: ServerState) {
    let http = match build_map_import_http_client() {
        Ok(client) => client,
        Err(err) => {
            let _ = fail_job(&state, err.to_string()).await;
            return;
        }
    };

    loop {
        let job = {
            let runtime = state.storage.map_dataset_import.lock().await;
            match runtime.job.clone() {
                Some(job) if job.state == AdminMapDatasetImportState::Running => job,
                _ => return,
            }
        };

        let outcome = if job.completed_parts >= job.total_parts {
            if job.manifest_uploaded {
                complete_job(&state).await
            } else {
                finalize_manifest(&state, &job).await
            }
        } else {
            advance_part(&state, &http, &job).await
        };

        match outcome {
            Ok(()) => continue,
            Err(ImportAdvanceError::Fatal(err)) => {
                let _ = fail_job(&state, err).await;
                return;
            }
            Err(ImportAdvanceError::Transient(err)) => {
                let retry_delay = transient_retry_delay_secs(&job);
                let _ = note_transient_failure(&state, err, retry_delay).await;
                tokio::time::sleep(Duration::from_secs(retry_delay)).await;
            }
        }
    }
}

async fn advance_part(
    state: &ServerState,
    http: &reqwest::Client,
    job: &MapDatasetImportJob,
) -> std::result::Result<(), ImportAdvanceError> {
    let part = current_part_spec(job)?
        .ok_or_else(|| ImportAdvanceError::Fatal("missing current import part".to_string()))?;

    if job.current_part_downloaded_bytes > part.size_bytes {
        return Err(ImportAdvanceError::Fatal(format!(
            "current part progress exceeds declared part size for {}",
            part.key
        )));
    }

    if job.current_part_downloaded_bytes < part.size_bytes {
        download_part_bytes(state, http, job, &part).await?;
    }

    let refreshed_job = {
        let runtime = state.storage.map_dataset_import.lock().await;
        runtime.job.clone().ok_or_else(|| {
            ImportAdvanceError::Fatal("import job disappeared during processing".to_string())
        })?
    };
    let refreshed_part = current_part_spec(&refreshed_job)?
        .ok_or_else(|| ImportAdvanceError::Fatal("current part vanished".to_string()))?;

    if refreshed_job.current_part_downloaded_bytes < refreshed_part.size_bytes {
        return Ok(());
    }

    finalize_part_object(state, &refreshed_job, &refreshed_part).await
}

async fn download_part_bytes(
    state: &ServerState,
    http: &reqwest::Client,
    job: &MapDatasetImportJob,
    part: &MapDatasetPartSpec,
) -> std::result::Result<(), ImportAdvanceError> {
    let absolute_start = part
        .offset_bytes
        .saturating_add(job.current_part_downloaded_bytes);
    let absolute_end = part
        .offset_bytes
        .saturating_add(part.size_bytes)
        .saturating_sub(1);
    let range_header = format!("bytes={absolute_start}-{absolute_end}");
    let response = http
        .get(job.source_url.clone())
        .header(reqwest::header::RANGE, range_header)
        .send()
        .await
        .map_err(|err| ImportAdvanceError::Transient(err.to_string()))?;
    if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        return Err(classify_http_status(
            response.status(),
            format!(
                "range download for {} returned unexpected status {}",
                part.key,
                response.status()
            ),
        ));
    }
    validate_content_range(
        response.headers(),
        absolute_start,
        absolute_end,
        job.total_size_bytes,
        &part.key,
    )?;

    let mut downloaded_bytes = job.current_part_downloaded_bytes;
    let mut chunk_refs = job.current_part_chunk_refs.clone();
    let mut buffer = BytesMut::new();
    let mut checkpoint_bytes = 0u64;

    let mut response = response;
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|err| ImportAdvanceError::Transient(err.to_string()))?
    {
        buffer.extend_from_slice(chunk.as_ref());
        while buffer.len() >= MAP_IMPORT_INGEST_CHUNK_BYTES {
            let ingest = buffer.split_to(MAP_IMPORT_INGEST_CHUNK_BYTES).freeze();
            let chunk_ref = ingest_import_chunk(state, ingest.as_ref()).await?;
            downloaded_bytes = downloaded_bytes.saturating_add(chunk_ref.size_bytes as u64);
            chunk_refs.push(chunk_ref);
            checkpoint_bytes = checkpoint_bytes.saturating_add(ingest.len() as u64);
            if checkpoint_bytes >= MAP_IMPORT_CHECKPOINT_BYTES {
                update_running_part_checkpoint(
                    state,
                    job.job_id.as_str(),
                    downloaded_bytes,
                    &chunk_refs,
                    None,
                    None,
                    true,
                )
                .await
                .map_err(|err| ImportAdvanceError::Fatal(err.to_string()))?;
                checkpoint_bytes = 0;
            }
        }
    }

    if !buffer.is_empty() {
        let tail = buffer.split().freeze();
        let chunk_ref = ingest_import_chunk(state, tail.as_ref()).await?;
        downloaded_bytes = downloaded_bytes.saturating_add(chunk_ref.size_bytes as u64);
        chunk_refs.push(chunk_ref);
    }

    update_running_part_checkpoint(
        state,
        job.job_id.as_str(),
        downloaded_bytes,
        &chunk_refs,
        None,
        None,
        true,
    )
    .await
    .map_err(|err| ImportAdvanceError::Fatal(err.to_string()))?;

    if downloaded_bytes > part.size_bytes {
        return Err(ImportAdvanceError::Fatal(format!(
            "downloaded {} bytes for {}, expected at most {}",
            downloaded_bytes, part.key, part.size_bytes
        )));
    }
    if downloaded_bytes < part.size_bytes {
        return Err(ImportAdvanceError::Transient(format!(
            "download for {} ended after {} of {} bytes; retrying remaining range",
            part.key, downloaded_bytes, part.size_bytes
        )));
    }

    Ok(())
}

async fn finalize_part_object(
    state: &ServerState,
    job: &MapDatasetImportJob,
    part: &MapDatasetPartSpec,
) -> std::result::Result<(), ImportAdvanceError> {
    let current_chunk_bytes = chunk_refs_size_bytes(&job.current_part_chunk_refs);
    if current_chunk_bytes != part.size_bytes {
        return Err(ImportAdvanceError::Fatal(format!(
            "part {} has {} bytes across chunk refs but expected {}",
            part.key, current_chunk_bytes, part.size_bytes
        )));
    }

    let put_result = {
        let mut store = lock_store(state, "map_dataset_import.finalize_part").await;
        store
            .put_object_from_chunks(
                &part.key,
                part.size_bytes as usize,
                &job.current_part_chunk_refs,
                PutOptions {
                    parent_version_ids: Vec::new(),
                    state: VersionConsistencyState::Confirmed,
                    inherit_preferred_parent: true,
                    create_snapshot: true,
                    explicit_version_id: None,
                },
            )
            .await
            .map_err(|err| ImportAdvanceError::Fatal(err.to_string()))?
    };

    register_put_outcome(state, &part.key, &put_result.version_id).await;
    let next_completed_parts = job.completed_parts.saturating_add(1);
    let next_completed_bytes = job.completed_bytes.saturating_add(part.size_bytes);
    let next_part_index = next_completed_parts;

    {
        let mut runtime = state.storage.map_dataset_import.lock().await;
        let Some(active_job) = runtime.job.as_mut() else {
            return Err(ImportAdvanceError::Fatal(
                "import job vanished during part finalization".to_string(),
            ));
        };
        if active_job.job_id != job.job_id {
            return Err(ImportAdvanceError::Fatal(
                "import job changed during part finalization".to_string(),
            ));
        }
        active_job.completed_parts = next_completed_parts;
        active_job.completed_bytes = next_completed_bytes;
        active_job.current_part_index = next_part_index;
        active_job.current_part_downloaded_bytes = 0;
        active_job.current_part_chunk_refs.clear();
        active_job.retry_count = 0;
        active_job.next_retry_at_unix = None;
        active_job.last_error = None;
        active_job.updated_at_unix = unix_ts();
    }
    persist_runtime(state)
        .await
        .map_err(|err| ImportAdvanceError::Fatal(err.to_string()))?;
    Ok(())
}

async fn finalize_manifest(
    state: &ServerState,
    job: &MapDatasetImportJob,
) -> std::result::Result<(), ImportAdvanceError> {
    let manifest_bytes = build_split_manifest_bytes(job)
        .map_err(|err| ImportAdvanceError::Fatal(err.to_string()))?;
    let put_result = {
        let mut store = lock_store(state, "map_dataset_import.finalize_manifest").await;
        store
            .put_object_versioned(
                &job.manifest_key,
                Bytes::from(manifest_bytes),
                PutOptions {
                    parent_version_ids: Vec::new(),
                    state: VersionConsistencyState::Confirmed,
                    inherit_preferred_parent: true,
                    create_snapshot: true,
                    explicit_version_id: None,
                },
            )
            .await
            .map_err(|err| ImportAdvanceError::Fatal(err.to_string()))?
    };

    register_put_outcome(state, &job.manifest_key, &put_result.version_id).await;
    invalidate_cached_mbtiles_source(state, &job.manifest_key).await;

    {
        let mut runtime = state.storage.map_dataset_import.lock().await;
        let Some(active_job) = runtime.job.as_mut() else {
            return Err(ImportAdvanceError::Fatal(
                "import job vanished during manifest finalization".to_string(),
            ));
        };
        if active_job.job_id != job.job_id {
            return Err(ImportAdvanceError::Fatal(
                "import job changed during manifest finalization".to_string(),
            ));
        }
        active_job.manifest_uploaded = true;
        active_job.updated_at_unix = unix_ts();
    }
    persist_runtime(state)
        .await
        .map_err(|err| ImportAdvanceError::Fatal(err.to_string()))?;
    complete_job(state).await
}

async fn complete_job(state: &ServerState) -> std::result::Result<(), ImportAdvanceError> {
    {
        let mut runtime = state.storage.map_dataset_import.lock().await;
        let Some(job) = runtime.job.as_mut() else {
            return Err(ImportAdvanceError::Fatal(
                "import job disappeared before completion".to_string(),
            ));
        };
        job.state = AdminMapDatasetImportState::Completed;
        job.retry_count = 0;
        job.next_retry_at_unix = None;
        job.last_error = None;
        job.updated_at_unix = unix_ts();
        job.finished_at_unix = Some(job.updated_at_unix);
    }
    persist_runtime(state)
        .await
        .map_err(|err| ImportAdvanceError::Fatal(err.to_string()))?;
    Ok(())
}

async fn fail_job(state: &ServerState, error: String) -> Result<()> {
    {
        let mut runtime = state.storage.map_dataset_import.lock().await;
        if let Some(job) = runtime.job.as_mut() {
            job.state = AdminMapDatasetImportState::Failed;
            job.last_error = Some(error);
            job.next_retry_at_unix = None;
            job.updated_at_unix = unix_ts();
            job.finished_at_unix = Some(job.updated_at_unix);
        }
    }
    persist_runtime(state).await
}

async fn note_transient_failure(
    state: &ServerState,
    error: String,
    retry_delay_secs: u64,
) -> Result<()> {
    {
        let mut runtime = state.storage.map_dataset_import.lock().await;
        if let Some(job) = runtime.job.as_mut() {
            job.retry_count = job.retry_count.saturating_add(1);
            job.last_error = Some(error);
            job.next_retry_at_unix = Some(unix_ts().saturating_add(retry_delay_secs));
            job.updated_at_unix = unix_ts();
        }
    }
    persist_runtime(state).await
}

async fn update_running_part_checkpoint(
    state: &ServerState,
    job_id: &str,
    downloaded_bytes: u64,
    chunk_refs: &[UploadChunkRef],
    retry_count: Option<u32>,
    last_error: Option<Option<String>>,
    force_persist: bool,
) -> Result<()> {
    {
        let mut runtime = state.storage.map_dataset_import.lock().await;
        let Some(job) = runtime.job.as_mut() else {
            bail!("import job disappeared while updating checkpoint");
        };
        if job.job_id != job_id {
            bail!("import job changed while updating checkpoint");
        }
        job.current_part_downloaded_bytes = downloaded_bytes;
        job.current_part_chunk_refs = chunk_refs.to_vec();
        if let Some(retry_count) = retry_count {
            job.retry_count = retry_count;
        }
        if let Some(last_error) = last_error {
            job.last_error = last_error;
        }
        job.next_retry_at_unix = None;
        job.updated_at_unix = unix_ts();
    }

    if force_persist {
        persist_runtime(state).await?;
    }
    Ok(())
}

async fn persist_runtime(state: &ServerState) -> Result<()> {
    let (path, job) = {
        let runtime = state.storage.map_dataset_import.lock().await;
        (runtime.path.clone(), runtime.job.clone())
    };
    let payload = serde_json::to_vec_pretty(&MapDatasetImportStateFile { job })
        .context("failed encoding map dataset import state")?;
    write_json_atomic(&path, &payload).await
}

async fn ingest_import_chunk(
    state: &ServerState,
    payload: &[u8],
) -> std::result::Result<UploadChunkRef, ImportAdvanceError> {
    let (hash, _) = state
        .storage
        .upload_chunk_ingestor
        .ingest_chunk_auto(payload)
        .await
        .map_err(|err| ImportAdvanceError::Fatal(err.to_string()))?;
    Ok(UploadChunkRef {
        hash,
        size_bytes: payload.len(),
    })
}

async fn register_put_outcome(state: &ServerState, key: &str, version_id: &str) {
    publish_namespace_change(state);

    let mut cluster = state.cluster.lock().await;
    cluster.note_replica(key, state.node_id);
    cluster.note_replica(format!("{key}@{version_id}"), state.node_id);
    drop(cluster);

    if let Err(err) = persist_cluster_replicas_state(state).await {
        warn!(
            error = %err,
            key,
            version_id,
            "failed to persist cluster replicas after map dataset import put"
        );
    }

    if should_trigger_autonomous_post_write_replication(
        state.autonomous_replication_on_put_enabled,
        false,
    ) {
        enqueue_autonomous_post_write_replication(
            state,
            autonomous_post_write_replication_subjects(key, version_id),
        )
        .await;
    }
}

async fn invalidate_cached_mbtiles_source(state: &ServerState, manifest_key: &str) {
    let mut sources = state.storage.mbtiles_sources.write().await;
    sources.remove(manifest_key);
}

fn build_map_import_http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .build()
        .context("failed building map dataset import HTTP client")
}

async fn probe_download_source(
    http: &reqwest::Client,
    source_url: &str,
) -> std::result::Result<MapDatasetProbe, ImportAdvanceError> {
    let parsed = Url::parse(source_url)
        .map_err(|err| ImportAdvanceError::Fatal(format!("invalid source URL: {err}")))?;
    let response = http
        .get(parsed.clone())
        .header(reqwest::header::RANGE, "bytes=0-0")
        .send()
        .await
        .map_err(|err| ImportAdvanceError::Transient(err.to_string()))?;

    if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        return Err(classify_http_status(
            response.status(),
            format!(
                "source {} does not support resumable range requests",
                source_display_url(parsed.as_str())
            ),
        ));
    }

    let content_range = response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ImportAdvanceError::Fatal("range probe response was missing Content-Range".to_string())
        })?;
    let (start, end, total_size_bytes) = parse_content_range(content_range).ok_or_else(|| {
        ImportAdvanceError::Fatal(format!("invalid Content-Range header: {content_range}"))
    })?;
    if start != 0 || end != 0 || total_size_bytes == 0 {
        return Err(ImportAdvanceError::Fatal(format!(
            "range probe returned unexpected Content-Range: {content_range}"
        )));
    }

    let final_url = response.url().clone();
    let dataset_filename = dataset_filename_from_url(&final_url)?;
    Ok(MapDatasetProbe {
        // Keep the stable user-provided URL. Redirect targets may be short-lived
        // signed CDN URLs and must be re-resolved after a restart.
        source_url: source_url.to_string(),
        dataset_filename,
        total_size_bytes,
    })
}

fn dataset_filename_from_url(url: &Url) -> std::result::Result<String, ImportAdvanceError> {
    let Some(filename) = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
    else {
        return Err(ImportAdvanceError::Fatal(format!(
            "source URL {} does not contain a dataset filename",
            source_display_url(url.as_str())
        )));
    };
    if !filename.ends_with(".mbtiles") {
        return Err(ImportAdvanceError::Fatal(format!(
            "source dataset filename {filename} must end with .mbtiles"
        )));
    }
    Ok(filename.to_string())
}

fn extract_source_url(raw: &str) -> std::result::Result<String, String> {
    raw.split_whitespace()
        .map(|token| token.trim_matches(|ch| ch == '"' || ch == '\''))
        .find(|token| token.starts_with("https://") || token.starts_with("http://"))
        .map(ToString::to_string)
        .ok_or_else(|| "expected an http(s) URL or pasted wget command".to_string())
}

fn source_display_url(raw: &str) -> String {
    let Ok(url) = Url::parse(raw) else {
        return raw.to_string();
    };
    let host = url.host_str().unwrap_or("unknown-host");
    let file_name = url
        .path_segments()
        .and_then(|mut segments| segments.next_back())
        .filter(|segment| !segment.is_empty())
        .unwrap_or("download");
    format!("{}://{host}/.../{file_name}", url.scheme())
}

fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let payload = value.strip_prefix("bytes ")?;
    let (range, total) = payload.split_once('/')?;
    let (start, end) = range.split_once('-')?;
    let start = start.parse().ok()?;
    let end = end.parse().ok()?;
    let total = total.parse().ok()?;
    Some((start, end, total))
}

fn validate_content_range(
    headers: &HeaderMap,
    expected_start: u64,
    expected_end: u64,
    expected_total: u64,
    part_key: &str,
) -> std::result::Result<(), ImportAdvanceError> {
    let content_range = headers
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| {
            ImportAdvanceError::Fatal(format!(
                "range download for {part_key} was missing Content-Range"
            ))
        })?;
    let (start, end, total) = parse_content_range(content_range).ok_or_else(|| {
        ImportAdvanceError::Fatal(format!(
            "range download for {part_key} had invalid Content-Range: {content_range}"
        ))
    })?;
    if start != expected_start || end != expected_end || total != expected_total {
        return Err(ImportAdvanceError::Fatal(format!(
            "range download for {part_key} returned {content_range}, expected bytes {expected_start}-{expected_end}/{expected_total}"
        )));
    }
    Ok(())
}

fn classify_http_status(status: reqwest::StatusCode, message: String) -> ImportAdvanceError {
    if status == reqwest::StatusCode::UNAUTHORIZED
        || status == reqwest::StatusCode::FORBIDDEN
        || status == reqwest::StatusCode::NOT_FOUND
        || status == reqwest::StatusCode::BAD_REQUEST
    {
        ImportAdvanceError::Fatal(message)
    } else {
        ImportAdvanceError::Transient(message)
    }
}

fn import_error_status(error: ImportAdvanceError) -> StatusCode {
    match error {
        ImportAdvanceError::Fatal(_) => StatusCode::BAD_REQUEST,
        ImportAdvanceError::Transient(_) => StatusCode::BAD_GATEWAY,
    }
}

fn transient_retry_delay_secs(job: &MapDatasetImportJob) -> u64 {
    let exponent = job.retry_count.min(6);
    let base = 2u64.saturating_pow(exponent);
    base.clamp(2, MAP_IMPORT_RETRY_MAX_DELAY_SECS)
}

fn current_part_spec(
    job: &MapDatasetImportJob,
) -> std::result::Result<Option<MapDatasetPartSpec>, ImportAdvanceError> {
    if job.current_part_index >= job.total_parts {
        return Ok(None);
    }
    part_spec(
        &job.dataset_filename,
        &job.job_id,
        job.total_size_bytes,
        job.part_size_bytes,
        job.total_parts,
        job.current_part_index,
    )
    .map(Some)
    .map_err(|err| ImportAdvanceError::Fatal(err.to_string()))
}

fn part_spec(
    dataset_filename: &str,
    job_id: &str,
    total_size_bytes: u64,
    part_size_bytes: u64,
    total_parts: usize,
    index: usize,
) -> Result<MapDatasetPartSpec> {
    let width = split_suffix_width(total_parts);
    let offset_bytes = (index as u64)
        .checked_mul(part_size_bytes)
        .ok_or_else(|| anyhow!("part offset overflow"))?;
    let remaining = total_size_bytes
        .checked_sub(offset_bytes)
        .ok_or_else(|| anyhow!("part offset exceeds total size"))?;
    let size_bytes = remaining.min(part_size_bytes);
    Ok(MapDatasetPartSpec {
        index,
        part_id: split_suffix(index, width),
        key: format!(
            "{MAP_IMPORT_STORAGE_ROOT}/{dataset_filename}.import-{job_id}-part-{}",
            split_suffix(index, width)
        ),
        offset_bytes,
        size_bytes,
    })
}

fn build_split_manifest_bytes(job: &MapDatasetImportJob) -> Result<Vec<u8>> {
    let mut parts = Vec::with_capacity(job.total_parts);
    for index in 0..job.total_parts {
        let part = part_spec(
            &job.dataset_filename,
            &job.job_id,
            job.total_size_bytes,
            job.part_size_bytes,
            job.total_parts,
            index,
        )?;
        parts.push(SplitFileManifestPartDocument {
            part_id: part.part_id,
            key: part.key,
            offset_bytes: part.offset_bytes,
            size_bytes: part.size_bytes,
        });
    }
    let last_part_size_bytes = parts.last().map(|part| part.size_bytes).unwrap_or(0);
    serde_json::to_vec_pretty(&SplitFileManifestDocument {
        manifest_version: 1,
        manifest_type: "split_file_manifest".to_string(),
        logical_format: "mbtiles".to_string(),
        logical_key: job.logical_key.clone(),
        manifest_key: job.manifest_key.clone(),
        storage_root: MAP_IMPORT_STORAGE_ROOT.to_string(),
        logical_size_bytes: job.total_size_bytes,
        last_part_size_bytes,
        parts_count: parts.len(),
        parts,
    })
    .context("failed serializing split manifest JSON")
}

fn part_count_for_size(total_size_bytes: u64, part_size_bytes: u64) -> Result<usize> {
    if part_size_bytes == 0 {
        bail!("part size must be greater than zero");
    }
    let part_count =
        total_size_bytes.saturating_add(part_size_bytes.saturating_sub(1)) / part_size_bytes;
    usize::try_from(part_count).context("part count overflow")
}

fn split_suffix_width(total_parts: usize) -> usize {
    let mut width = 2usize;
    let mut capacity = 26usize.saturating_mul(26);
    while total_parts > capacity {
        width = width.saturating_add(1);
        capacity = capacity.saturating_mul(26);
    }
    width
}

fn split_suffix(mut index: usize, width: usize) -> String {
    let mut chars = vec!['a'; width];
    for slot in (0..width).rev() {
        chars[slot] = char::from(b'a'.saturating_add((index % 26) as u8));
        index /= 26;
    }
    chars.into_iter().collect()
}

fn chunk_refs_size_bytes(chunk_refs: &[UploadChunkRef]) -> u64 {
    chunk_refs.iter().fold(0u64, |acc, chunk| {
        acc.saturating_add(chunk.size_bytes as u64)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_url_from_wget_command() {
        let url = extract_source_url(
            "wget -c https://data.maptiler.com/download/token/maptiler-satellite-2017-11-02-planet.mbtiles",
        )
        .expect("url should parse");
        assert_eq!(
            url,
            "https://data.maptiler.com/download/token/maptiler-satellite-2017-11-02-planet.mbtiles"
        );
    }

    #[test]
    fn split_suffix_grows_beyond_two_letters() {
        assert_eq!(split_suffix(0, split_suffix_width(10)), "aa");
        assert_eq!(split_suffix(25, split_suffix_width(26)), "az");
        assert_eq!(split_suffix(26, split_suffix_width(27)), "ba");
        assert_eq!(
            split_suffix(26 * 26, split_suffix_width(26 * 26 + 1)),
            "baa"
        );
    }

    #[test]
    fn parses_content_range() {
        assert_eq!(
            parse_content_range("bytes 1024-2047/4096"),
            Some((1024, 2047, 4096))
        );
        assert_eq!(parse_content_range("bytes */4096"), None);
    }

    #[test]
    fn manifest_builder_uses_variable_part_size() {
        let job = MapDatasetImportJob {
            job_id: "job".to_string(),
            state: AdminMapDatasetImportState::Running,
            source_url: "https://example.invalid/file.mbtiles".to_string(),
            dataset_filename: "file.mbtiles".to_string(),
            logical_key: "sys/maps/file.mbtiles".to_string(),
            manifest_key: "sys/maps/file.mbtiles.manifest.json".to_string(),
            part_size_bytes: 1024,
            total_size_bytes: 2500,
            total_parts: 3,
            completed_parts: 0,
            completed_bytes: 0,
            current_part_index: 0,
            current_part_downloaded_bytes: 0,
            current_part_chunk_refs: Vec::new(),
            manifest_uploaded: false,
            retry_count: 0,
            next_retry_at_unix: None,
            last_error: None,
            started_at_unix: 1,
            updated_at_unix: 1,
            finished_at_unix: None,
        };

        let payload = build_split_manifest_bytes(&job).expect("manifest should build");
        let json: serde_json::Value =
            serde_json::from_slice(&payload).expect("manifest should decode");
        assert_eq!(json["parts_count"], 3);
        assert_eq!(json["last_part_size_bytes"], 452);
        assert_eq!(
            json["parts"][1]["key"],
            "sys/maps/file.mbtiles.import-job-part-ab"
        );
    }
}
