use super::*;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::path::Path;
use std::process::Stdio;
use tokio::fs;
use tokio::process::Command;
use tokio::time::timeout;

const NATURAL_EARTH_PHYSICAL_10M_URL: &str =
    "https://naciscdn.org/naturalearth/10m/physical/10m_physical.zip";
const NATURAL_EARTH_IMPORT_MAX_DOWNLOAD_BYTES: usize = 128 * 1024 * 1024;
const NATURAL_EARTH_IMPORT_MAX_ARTIFACT_BYTES: usize = 512 * 1024 * 1024;
const NATURAL_EARTH_IMPORT_PART_BYTES: usize = 256 * 1024 * 1024;
const NATURAL_EARTH_COMMAND_TIMEOUT_SECS: u64 = 20 * 60;
const NATURAL_EARTH_COMMAND_OUTPUT_LIMIT: usize = 32 * 1024;
const WEB_MERCATOR_WORLD_METERS: &str = "20037508.342789244";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NaturalEarthImportState {
    Running,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NaturalEarthImportJobView {
    pub(crate) id: String,
    pub(crate) state: NaturalEarthImportState,
    pub(crate) phase: String,
    pub(crate) source_url: String,
    pub(crate) logical_key: String,
    pub(crate) manifest_key: String,
    pub(crate) logical_size_bytes: u64,
    pub(crate) error: Option<String>,
    pub(crate) started_at_unix: u64,
    pub(crate) updated_at_unix: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NaturalEarthImportStatusResponse {
    pub(crate) active_job: Option<NaturalEarthImportJobView>,
    pub(crate) can_start_new: bool,
}

#[derive(Debug, Default)]
pub(crate) struct NaturalEarthImportRuntime {
    job: Option<NaturalEarthImportJobView>,
}

#[derive(Debug, Serialize)]
struct SplitFileManifestDocument {
    manifest_version: u32,
    #[serde(rename = "type")]
    manifest_type: &'static str,
    logical_format: &'static str,
    logical_key: String,
    manifest_key: String,
    storage_root: &'static str,
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

pub(crate) async fn is_running(state: &ServerState) -> bool {
    let runtime = state.storage.natural_earth_import.lock().await;
    matches!(
        runtime.job.as_ref().map(|job| &job.state),
        Some(NaturalEarthImportState::Running)
    )
}

pub(crate) async fn admin_status(State(state): State<ServerState>, headers: HeaderMap) -> Response {
    if let Err(status) = authorize_admin_request(
        &state,
        &headers,
        "auth/maps/import/natural-earth/status",
        true,
        true,
        json!({}),
    )
    .await
    {
        return status.into_response();
    }
    let runtime = state.storage.natural_earth_import.lock().await;
    Json(NaturalEarthImportStatusResponse {
        active_job: runtime.job.clone(),
        can_start_new: !matches!(
            runtime.job.as_ref().map(|job| &job.state),
            Some(NaturalEarthImportState::Running)
        ),
    })
    .into_response()
}

pub(crate) async fn start_admin_import(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> Response {
    let action = "auth/maps/import/natural-earth/run";
    let authz = match authorize_admin_request(&state, &headers, action, true, true, json!({})).await
    {
        Ok(authz) => authz,
        Err(status) => return status.into_response(),
    };

    let response = match start_import(&state).await {
        Ok(job) => (StatusCode::ACCEPTED, Json(job)).into_response(),
        Err((status, error)) => {
            (status, Json(json!({ "error": error.to_string() }))).into_response()
        }
    };
    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        if response.status().is_success() {
            "started"
        } else {
            "error"
        },
        json!({ "status": response.status().as_u16() }),
    )
    .await;
    response
}

async fn start_import(
    state: &ServerState,
) -> std::result::Result<NaturalEarthImportJobView, (StatusCode, anyhow::Error)> {
    if map_dataset_import::has_running_job(state).await {
        return Err((
            StatusCode::CONFLICT,
            anyhow!("another map dataset import is already running"),
        ));
    }
    let configuration = map_config::load_current_configuration(state)
        .await
        .map_err(|error| (StatusCode::BAD_GATEWAY, error))?;
    let target = map_config::resolve_import_target(
        &configuration.configuration,
        "natural-earth-globe",
        map_config::MapVariantAssetKind::Raster,
    )
    .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let now = unix_ts();
    let job = NaturalEarthImportJobView {
        id: Uuid::now_v7().to_string(),
        state: NaturalEarthImportState::Running,
        phase: "Waiting for the Natural Earth conversion worker".to_string(),
        source_url: NATURAL_EARTH_PHYSICAL_10M_URL.to_string(),
        logical_key: target.logical_key,
        manifest_key: target.manifest_key,
        logical_size_bytes: 0,
        error: None,
        started_at_unix: now,
        updated_at_unix: now,
    };
    {
        let mut runtime = state.storage.natural_earth_import.lock().await;
        if matches!(
            runtime.job.as_ref().map(|existing| &existing.state),
            Some(NaturalEarthImportState::Running)
        ) {
            return Err((
                StatusCode::CONFLICT,
                anyhow!("a Natural Earth conversion is already running"),
            ));
        }
        runtime.job = Some(job.clone());
    }
    let worker_state = state.clone();
    let worker_job = job.clone();
    tokio::spawn(async move {
        let result = run_import(&worker_state, &worker_job).await;
        match result {
            Ok(size) => {
                finish_job(
                    &worker_state,
                    NaturalEarthImportState::Ready,
                    "Ready",
                    size,
                    None,
                )
                .await
            }
            Err(error) => {
                warn!(natural_earth_import_id = %worker_job.id, error = %error, "Natural Earth map import failed");
                finish_job(
                    &worker_state,
                    NaturalEarthImportState::Failed,
                    "Failed",
                    0,
                    Some(error.to_string()),
                )
                .await;
            }
        }
    });
    Ok(job)
}

async fn run_import(state: &ServerState, job: &NaturalEarthImportJobView) -> Result<u64> {
    update_phase(state, "Checking GDAL and unzip dependencies").await;
    ensure_import_commands_available().await?;
    let staging_dir = state
        .data_dir
        .join("state")
        .join("natural-earth-imports")
        .join(&job.id);
    fs::create_dir_all(&staging_dir).await.with_context(|| {
        format!(
            "failed creating Natural Earth staging directory {}",
            staging_dir.display()
        )
    })?;

    let result = async {
        let archive_path = staging_dir.join("natural-earth-physical.zip");
        update_phase(state, "Downloading Natural Earth physical data").await;
        download_natural_earth_archive(&archive_path).await?;
        let extracted_dir = staging_dir.join("source");
        fs::create_dir_all(&extracted_dir).await?;
        update_phase(state, "Extracting Natural Earth source layers").await;
        run_command(
            "unzip",
            [
                "-q".into(),
                archive_path.as_os_str().to_owned(),
                "-d".into(),
                extracted_dir.as_os_str().to_owned(),
            ],
            &staging_dir,
        )
        .await?;
        let ocean = find_layer(&extracted_dir, "ne_10m_ocean.shp")?;
        let land = find_layer(&extracted_dir, "ne_10m_land.shp")?;
        let lakes = find_layer(&extracted_dir, "ne_10m_lakes.shp")?;
        let rivers = find_layer(&extracted_dir, "ne_10m_rivers_lake_centerlines.shp")?;
        let coastline = find_layer(&extracted_dir, "ne_10m_coastline.shp")?;
        let source_raster = staging_dir.join("natural-earth-physical-wgs84.tif");
        let mercator_raster = staging_dir.join("natural-earth-physical-mercator.tif");
        let artifact_path = staging_dir.join("natural-earth-globe.mbtiles");
        update_phase(state, "Rendering the physical world map").await;
        rasterize_physical_map(
            &ocean,
            &land,
            &lakes,
            &rivers,
            &coastline,
            &source_raster,
            &staging_dir,
        )
        .await?;
        update_phase(state, "Generating Web Mercator MBTiles").await;
        project_and_create_mbtiles(
            &source_raster,
            &mercator_raster,
            &artifact_path,
            &staging_dir,
        )
        .await?;
        validate_generated_mbtiles(&artifact_path).await?;
        update_phase(state, "Publishing the map artifact").await;
        publish_generated_mbtiles(state, job, &artifact_path).await
    }
    .await;
    if let Err(error) = fs::remove_dir_all(&staging_dir).await {
        warn!(path = %staging_dir.display(), error = %error, "failed cleaning Natural Earth import staging directory");
    }
    result
}

async fn update_phase(state: &ServerState, phase: &str) {
    let mut runtime = state.storage.natural_earth_import.lock().await;
    if let Some(job) = runtime.job.as_mut() {
        if matches!(job.state, NaturalEarthImportState::Running) {
            job.phase = phase.to_string();
            job.updated_at_unix = unix_ts();
        }
    }
}

async fn finish_job(
    state: &ServerState,
    import_state: NaturalEarthImportState,
    phase: &str,
    logical_size_bytes: u64,
    error: Option<String>,
) {
    let mut runtime = state.storage.natural_earth_import.lock().await;
    if let Some(job) = runtime.job.as_mut() {
        job.state = import_state;
        job.phase = phase.to_string();
        job.logical_size_bytes = logical_size_bytes;
        job.error = error;
        job.updated_at_unix = unix_ts();
    }
}

async fn ensure_import_commands_available() -> Result<()> {
    for command in [
        "unzip",
        "gdal_rasterize",
        "gdalwarp",
        "gdal_translate",
        "gdaladdo",
    ] {
        match timeout(
            Duration::from_secs(10),
            Command::new(command)
                .arg("--version")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .status(),
        )
        .await
        {
            Ok(Ok(status)) if status.success() => {}
            Ok(Ok(status)) => bail!("required map import command {command} exited with {status}"),
            Ok(Err(error)) if error.kind() == io::ErrorKind::NotFound => {
                bail!("required map import command {command} is not installed or not on PATH")
            }
            Ok(Err(error)) => {
                bail!("failed starting required map import command {command}: {error}")
            }
            Err(_) => bail!("timed out checking required map import command {command}"),
        }
    }
    Ok(())
}

async fn download_natural_earth_archive(destination: &Path) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10 * 60))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .context("failed building Natural Earth download client")?;
    let mut response = client
        .get(NATURAL_EARTH_PHYSICAL_10M_URL)
        .send()
        .await
        .context("failed downloading the Natural Earth physical archive")?
        .error_for_status()
        .context("Natural Earth physical archive request was rejected")?;
    if response
        .content_length()
        .is_some_and(|size| size > NATURAL_EARTH_IMPORT_MAX_DOWNLOAD_BYTES as u64)
    {
        bail!("Natural Earth physical archive exceeds the configured download size limit")
    }
    let mut payload = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(NATURAL_EARTH_IMPORT_MAX_DOWNLOAD_BYTES as u64) as usize,
    );
    while let Some(chunk) = response
        .chunk()
        .await
        .context("failed reading Natural Earth physical archive response")?
    {
        let next_size = payload
            .len()
            .checked_add(chunk.len())
            .context("Natural Earth physical archive size overflow")?;
        if next_size > NATURAL_EARTH_IMPORT_MAX_DOWNLOAD_BYTES {
            bail!("Natural Earth physical archive exceeds the configured download size limit")
        }
        payload.extend_from_slice(&chunk);
    }
    fs::write(destination, payload).await.with_context(|| {
        format!(
            "failed writing Natural Earth archive {}",
            destination.display()
        )
    })
}

async fn rasterize_physical_map(
    ocean: &Path,
    land: &Path,
    lakes: &Path,
    rivers: &Path,
    coastline: &Path,
    destination: &Path,
    working_dir: &Path,
) -> Result<()> {
    run_command(
        "gdal_rasterize",
        rasterize_create_arguments(ocean, destination, [199, 224, 239, 255]),
        working_dir,
    )
    .await?;
    for (layer, color) in [
        (land, [225, 232, 205, 255]),
        (lakes, [171, 211, 233, 255]),
        (rivers, [104, 170, 214, 255]),
        (coastline, [94, 117, 122, 255]),
    ] {
        run_command(
            "gdal_rasterize",
            rasterize_overlay_arguments(layer, destination, color),
            working_dir,
        )
        .await?;
    }
    Ok(())
}

fn rasterize_create_arguments(
    source: &Path,
    destination: &Path,
    color: [u8; 4],
) -> Vec<std::ffi::OsString> {
    let mut args = vec![
        "-of".into(),
        "GTiff".into(),
        "-te".into(),
        "-180".into(),
        "-90".into(),
        "180".into(),
        "90".into(),
        "-ts".into(),
        "4096".into(),
        "2048".into(),
        "-a_srs".into(),
        "EPSG:4326".into(),
        "-ot".into(),
        "Byte".into(),
    ];
    append_raster_color_arguments(&mut args, color, false);
    args.push(source.as_os_str().to_owned());
    args.push(destination.as_os_str().to_owned());
    args
}

fn rasterize_overlay_arguments(
    source: &Path,
    destination: &Path,
    color: [u8; 4],
) -> Vec<std::ffi::OsString> {
    let mut args = Vec::new();
    append_raster_color_arguments(&mut args, color, true);
    args.push(source.as_os_str().to_owned());
    args.push(destination.as_os_str().to_owned());
    args
}

fn append_raster_color_arguments(
    args: &mut Vec<std::ffi::OsString>,
    color: [u8; 4],
    include_bands: bool,
) {
    for band in 1..=4 {
        if include_bands {
            args.push("-b".into());
            args.push(band.to_string().into());
        }
        args.push("-burn".into());
        args.push(color[(band - 1) as usize].to_string().into());
    }
}

async fn project_and_create_mbtiles(
    source: &Path,
    mercator: &Path,
    artifact: &Path,
    working_dir: &Path,
) -> Result<()> {
    run_command(
        "gdalwarp",
        vec![
            "-overwrite".into(),
            "-t_srs".into(),
            "EPSG:3857".into(),
            "-te".into(),
            format!("-{WEB_MERCATOR_WORLD_METERS}").into(),
            format!("-{WEB_MERCATOR_WORLD_METERS}").into(),
            WEB_MERCATOR_WORLD_METERS.into(),
            WEB_MERCATOR_WORLD_METERS.into(),
            "-ts".into(),
            "8192".into(),
            "8192".into(),
            "-r".into(),
            "near".into(),
            source.as_os_str().to_owned(),
            mercator.as_os_str().to_owned(),
        ],
        working_dir,
    )
    .await?;
    run_command(
        "gdal_translate",
        vec![
            "-of".into(),
            "MBTILES".into(),
            "-b".into(),
            "1".into(),
            "-b".into(),
            "2".into(),
            "-b".into(),
            "3".into(),
            "-b".into(),
            "4".into(),
            "-colorinterp".into(),
            "red,green,blue,alpha".into(),
            "-co".into(),
            "NAME=Natural Earth Globe".into(),
            "-co".into(),
            "DESCRIPTION=Natural Earth Physical 10m".into(),
            "-co".into(),
            "TYPE=baselayer".into(),
            "-co".into(),
            "TILE_FORMAT=PNG".into(),
            "-co".into(),
            "ZOOM_LEVEL_STRATEGY=UPPER".into(),
            mercator.as_os_str().to_owned(),
            artifact.as_os_str().to_owned(),
        ],
        working_dir,
    )
    .await?;
    run_command(
        "gdaladdo",
        vec![
            "-r".into(),
            "average".into(),
            artifact.as_os_str().to_owned(),
            "2".into(),
            "4".into(),
            "8".into(),
            "16".into(),
            "32".into(),
        ],
        working_dir,
    )
    .await
}

async fn run_command(
    program: &str,
    args: impl IntoIterator<Item = std::ffi::OsString>,
    working_dir: &Path,
) -> Result<()> {
    let output = timeout(
        Duration::from_secs(NATURAL_EARTH_COMMAND_TIMEOUT_SECS),
        Command::new(program)
            .args(args)
            .current_dir(working_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .with_context(|| format!("{program} timed out"))?
    .with_context(|| format!("failed starting {program}"))?;
    if output.status.success() {
        return Ok(());
    }
    bail!(
        "{program} failed with {}:{}{}",
        output.status,
        truncate_command_output(&output.stderr),
        truncate_command_output(&output.stdout),
    )
}

fn truncate_command_output(output: &[u8]) -> String {
    let clipped = &output[..output.len().min(NATURAL_EARTH_COMMAND_OUTPUT_LIMIT)];
    let text = String::from_utf8_lossy(clipped).trim().to_string();
    if text.is_empty() {
        String::new()
    } else {
        format!(" {text}")
    }
}

fn find_layer(root: &Path, target_file_name: &str) -> Result<PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        for entry in std::fs::read_dir(&directory).with_context(|| {
            format!(
                "failed reading extracted Natural Earth directory {}",
                directory.display()
            )
        })? {
            let entry = entry?;
            let path = entry.path();
            if entry.file_type()?.is_dir() {
                stack.push(path);
            } else if entry
                .file_name()
                .to_string_lossy()
                .eq_ignore_ascii_case(target_file_name)
            {
                return Ok(path);
            }
        }
    }
    bail!("Natural Earth archive does not contain required layer {target_file_name}")
}

async fn validate_generated_mbtiles(path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .context("failed opening generated MBTiles artifact")?;
        let tiles: i64 = connection
            .query_row("select count(*) from tiles", [], |row| row.get(0))
            .context("generated MBTiles artifact has no readable tiles table")?;
        if tiles == 0 {
            bail!("generated MBTiles artifact contains no tiles")
        }
        let format: Option<String> = connection
            .query_row(
                "select value from metadata where name = 'format' limit 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("generated MBTiles artifact has no readable metadata table")?;
        if !matches!(format.as_deref(), Some(value) if value.eq_ignore_ascii_case("png")) {
            bail!("generated MBTiles artifact must declare PNG tiles")
        }
        Ok(())
    })
    .await
    .context("generated MBTiles validation task failed")?
}

async fn publish_generated_mbtiles(
    state: &ServerState,
    job: &NaturalEarthImportJobView,
    artifact_path: &Path,
) -> Result<u64> {
    let payload = fs::read(artifact_path).await.with_context(|| {
        format!(
            "failed reading generated MBTiles {}",
            artifact_path.display()
        )
    })?;
    if payload.is_empty() || payload.len() > NATURAL_EARTH_IMPORT_MAX_ARTIFACT_BYTES {
        bail!("generated MBTiles artifact is empty or exceeds the configured artifact size limit")
    }
    let mut parts = Vec::new();
    let mut offset = 0_u64;
    for (index, part_payload) in payload.chunks(NATURAL_EARTH_IMPORT_PART_BYTES).enumerate() {
        let size_bytes =
            u64::try_from(part_payload.len()).context("map artifact part size overflow")?;
        let key = format!(
            "{}.natural-earth-{}-part-{}",
            job.logical_key,
            job.id,
            split_part_id(index)?
        );
        put_system_object(state, &key, Bytes::copy_from_slice(part_payload)).await?;
        parts.push(SplitFileManifestPartDocument {
            part_id: split_part_id(index)?,
            key,
            offset_bytes: offset,
            size_bytes,
        });
        offset = offset
            .checked_add(size_bytes)
            .context("map artifact size overflow")?;
    }
    let manifest = SplitFileManifestDocument {
        manifest_version: 1,
        manifest_type: "split_file_manifest",
        logical_format: "mbtiles",
        logical_key: job.logical_key.clone(),
        manifest_key: job.manifest_key.clone(),
        storage_root: "sys/maps",
        logical_size_bytes: offset,
        last_part_size_bytes: parts.last().map(|part| part.size_bytes).unwrap_or_default(),
        parts_count: parts.len(),
        parts,
    };
    put_system_object(
        state,
        &job.manifest_key,
        Bytes::from(
            serde_json::to_vec_pretty(&manifest)
                .context("failed serializing map artifact manifest")?,
        ),
    )
    .await?;
    map_dataset_import::invalidate_cached_mbtiles_source(state, &job.manifest_key).await;
    Ok(offset)
}

async fn put_system_object(state: &ServerState, key: &str, payload: Bytes) -> Result<()> {
    let outcome = {
        let mut store = lock_store(state, "natural_earth_import.put").await;
        store
            .put_object_versioned(key, payload, PutOptions::default())
            .await
            .with_context(|| format!("failed storing Natural Earth map object {key}"))?
    };
    map_dataset_import::register_put_outcome(state, key, &outcome.version_id).await;
    Ok(())
}

fn split_part_id(index: usize) -> Result<String> {
    let first = u8::try_from(index / 26).context("too many Natural Earth map parts")?;
    let second = u8::try_from(index % 26).context("Natural Earth map part index overflow")?;
    if first >= 26 {
        bail!("too many Natural Earth map parts")
    }
    Ok(format!(
        "{}{}",
        char::from(b'a' + first),
        char::from(b'a' + second)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_part_ids_are_stable() {
        assert_eq!(split_part_id(0).unwrap(), "aa");
        assert_eq!(split_part_id(25).unwrap(), "az");
        assert_eq!(split_part_id(26).unwrap(), "ba");
    }
}
