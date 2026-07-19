use super::*;
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use std::path::Path;
use std::process::Stdio;
use tokio::fs;
use tokio::process::Command;
use tokio::time::timeout;

const NATURAL_EARTH_PHYSICAL_10M_URL: &str =
    "https://naciscdn.org/naturalearth/10m/physical/10m_physical.zip";
const NATURAL_EARTH_COUNTRIES_10M_URL: &str =
    "https://naciscdn.org/naturalearth/10m/cultural/ne_10m_admin_0_countries.zip";
const NATURAL_EARTH_POPULATED_PLACES_10M_URL: &str =
    "https://naciscdn.org/naturalearth/10m/cultural/ne_10m_populated_places.zip";
const NATURAL_EARTH_BOUNDARIES_10M_URL: &str =
    "https://naciscdn.org/naturalearth/10m/cultural/ne_10m_admin_0_boundary_lines_land.zip";
const NATURAL_EARTH_IMPORT_MAX_DOWNLOAD_BYTES: usize = 128 * 1024 * 1024;
const NATURAL_EARTH_IMPORT_MAX_ARTIFACT_BYTES: usize = 512 * 1024 * 1024;
const NATURAL_EARTH_IMPORT_PART_BYTES: usize = 256 * 1024 * 1024;
const NATURAL_EARTH_COMMAND_TIMEOUT_SECS: u64 = 20 * 60;
const NATURAL_EARTH_COMMAND_OUTPUT_LIMIT: usize = 8 * 1024;
const NATURAL_EARTH_COMMAND_LOG_OUTPUT_LIMIT: usize = 2 * 1024;
const NATURAL_EARTH_IMPORT_LOG_MAX_ENTRIES: usize = 64;
const WEB_MERCATOR_WORLD_METERS: &str = "20037508.342789244";
const REQUIRED_MAP_IMPORT_COMMANDS: [(&str, &str); 5] = [
    ("unzip", "-v"),
    ("gdal_rasterize", "--version"),
    ("gdalwarp", "--version"),
    ("gdal_translate", "--version"),
    ("gdaladdo", "--version"),
];
const REQUIRED_LABEL_IMPORT_COMMANDS: [(&str, &str); 1] = [("ogr2ogr", "--version")];

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NaturalEarthImportProfile {
    #[default]
    Physical,
    PhysicalWithLabels,
}

#[derive(Debug, Deserialize)]
pub(crate) struct StartNaturalEarthImportRequest {
    #[serde(default)]
    profile: NaturalEarthImportProfile,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NaturalEarthImportState {
    Running,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NaturalEarthImportLogEntry {
    pub(crate) timestamp_unix: u64,
    pub(crate) message: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NaturalEarthImportArtifactView {
    pub(crate) variant_id: String,
    pub(crate) asset: map_config::MapVariantAssetKind,
    pub(crate) logical_key: String,
    pub(crate) manifest_key: String,
    pub(crate) logical_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct NaturalEarthImportJobView {
    pub(crate) id: String,
    pub(crate) state: NaturalEarthImportState,
    pub(crate) profile: NaturalEarthImportProfile,
    pub(crate) phase: String,
    pub(crate) source_url: String,
    pub(crate) logical_key: String,
    pub(crate) manifest_key: String,
    pub(crate) logical_size_bytes: u64,
    pub(crate) artifacts: Vec<NaturalEarthImportArtifactView>,
    pub(crate) error: Option<String>,
    pub(crate) log_entries: Vec<NaturalEarthImportLogEntry>,
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

struct PhysicalMapLayers<'a> {
    ocean: &'a Path,
    land: &'a Path,
    lakes: &'a Path,
    rivers: &'a Path,
    coastline: &'a Path,
}

struct NaturalEarthLabelLayers<'a> {
    countries: &'a Path,
    populated_places: &'a Path,
    boundaries: &'a Path,
}

struct NaturalEarthSourceArchive {
    url: &'static str,
    archive_name: &'static str,
    description: &'static str,
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
    request: Option<Json<StartNaturalEarthImportRequest>>,
) -> Response {
    let action = "auth/maps/import/natural-earth/run";
    let profile = request
        .map(|Json(request)| request.profile)
        .unwrap_or_default();
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({ "profile": profile }),
    )
    .await
    {
        Ok(authz) => authz,
        Err(status) => return status.into_response(),
    };

    let response = match start_import(&state, profile).await {
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
    profile: NaturalEarthImportProfile,
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
    let base_variant_id = match profile {
        NaturalEarthImportProfile::Physical => "natural-earth-globe",
        NaturalEarthImportProfile::PhysicalWithLabels => "natural-earth-labels",
    };
    let target = map_config::resolve_import_target(
        &configuration.configuration,
        base_variant_id,
        map_config::MapVariantAssetKind::Raster,
    )
    .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let mut artifacts = vec![NaturalEarthImportArtifactView {
        variant_id: target.variant_id.clone(),
        asset: target.asset,
        logical_key: target.logical_key.clone(),
        manifest_key: target.manifest_key.clone(),
        logical_size_bytes: 0,
    }];
    if profile == NaturalEarthImportProfile::PhysicalWithLabels {
        let label_target = map_config::resolve_import_target(
            &configuration.configuration,
            "natural-earth-labels",
            map_config::MapVariantAssetKind::Vector,
        )
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
        artifacts.push(NaturalEarthImportArtifactView {
            variant_id: label_target.variant_id,
            asset: label_target.asset,
            logical_key: label_target.logical_key,
            manifest_key: label_target.manifest_key,
            logical_size_bytes: 0,
        });
    }
    let now = unix_ts();
    let job = NaturalEarthImportJobView {
        id: Uuid::now_v7().to_string(),
        state: NaturalEarthImportState::Running,
        profile,
        phase: "Waiting for the Natural Earth conversion worker".to_string(),
        source_url: NATURAL_EARTH_PHYSICAL_10M_URL.to_string(),
        logical_key: target.logical_key,
        manifest_key: target.manifest_key,
        logical_size_bytes: 0,
        artifacts,
        error: None,
        log_entries: vec![NaturalEarthImportLogEntry {
            timestamp_unix: now,
            message: "Import job accepted; waiting for the conversion worker".to_string(),
        }],
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
    ensure_import_commands_available(state, job.profile).await?;
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
        let extracted_dir = staging_dir.join("source");
        fs::create_dir_all(&extracted_dir).await?;
        download_and_extract_natural_earth_archive(
            state,
            NaturalEarthSourceArchive {
                url: NATURAL_EARTH_PHYSICAL_10M_URL,
                archive_name: "natural-earth-physical.zip",
                description: "Natural Earth physical archive",
            },
            &extracted_dir,
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
            state,
            PhysicalMapLayers {
                ocean: &ocean,
                land: &land,
                lakes: &lakes,
                rivers: &rivers,
                coastline: &coastline,
            },
            &source_raster,
            &staging_dir,
        )
        .await?;
        update_phase(state, "Generating Web Mercator MBTiles").await;
        project_and_create_mbtiles(
            state,
            &source_raster,
            &mercator_raster,
            &artifact_path,
            &staging_dir,
        )
        .await?;
        update_phase(state, "Validating generated MBTiles").await;
        validate_generated_mbtiles(state, &artifact_path).await?;

        let label_artifact_path = if job.profile == NaturalEarthImportProfile::PhysicalWithLabels {
            let labels_source_dir = staging_dir.join("labels-source");
            fs::create_dir_all(&labels_source_dir).await?;
            for archive in [
                NaturalEarthSourceArchive {
                    url: NATURAL_EARTH_COUNTRIES_10M_URL,
                    archive_name: "natural-earth-countries.zip",
                    description: "Natural Earth countries archive",
                },
                NaturalEarthSourceArchive {
                    url: NATURAL_EARTH_POPULATED_PLACES_10M_URL,
                    archive_name: "natural-earth-populated-places.zip",
                    description: "Natural Earth populated places archive",
                },
                NaturalEarthSourceArchive {
                    url: NATURAL_EARTH_BOUNDARIES_10M_URL,
                    archive_name: "natural-earth-boundaries.zip",
                    description: "Natural Earth country boundaries archive",
                },
            ] {
                download_and_extract_natural_earth_archive(
                    state,
                    archive,
                    &labels_source_dir,
                    &staging_dir,
                )
                .await?;
            }
            let countries = find_layer(&labels_source_dir, "ne_10m_admin_0_countries.shp")?;
            let populated_places = find_layer(&labels_source_dir, "ne_10m_populated_places.shp")?;
            let boundaries =
                find_layer(&labels_source_dir, "ne_10m_admin_0_boundary_lines_land.shp")?;
            let label_geopackage = staging_dir.join("natural-earth-labels.gpkg");
            let label_mbtiles = staging_dir.join("natural-earth-labels.mbtiles");
            update_phase(state, "Preparing Natural Earth country and place labels").await;
            create_natural_earth_label_overlay(
                state,
                NaturalEarthLabelLayers {
                    countries: &countries,
                    populated_places: &populated_places,
                    boundaries: &boundaries,
                },
                &label_geopackage,
                &label_mbtiles,
                &staging_dir,
            )
            .await?;
            update_phase(state, "Validating generated label overlay").await;
            validate_generated_label_mbtiles(state, &label_mbtiles).await?;
            Some(label_mbtiles)
        } else {
            None
        };

        update_phase(state, "Publishing generated map artifact").await;
        let base_artifact = required_job_artifact(job, map_config::MapVariantAssetKind::Raster)?;
        let base_size =
            publish_generated_mbtiles(state, job, base_artifact, &artifact_path).await?;
        record_published_artifact(state, &base_artifact.manifest_key, base_size).await;

        let label_size = if let Some(label_artifact_path) = label_artifact_path {
            update_phase(state, "Publishing generated label overlay").await;
            let label_artifact =
                required_job_artifact(job, map_config::MapVariantAssetKind::Vector)?;
            let size =
                publish_generated_mbtiles(state, job, label_artifact, &label_artifact_path).await?;
            record_published_artifact(state, &label_artifact.manifest_key, size).await;
            size
        } else {
            0
        };
        base_size
            .checked_add(label_size)
            .context("published Natural Earth artifact size overflow")
    }
    .await;
    if let Err(error) = fs::remove_dir_all(&staging_dir).await {
        warn!(path = %staging_dir.display(), error = %error, "failed cleaning Natural Earth import staging directory");
    }
    result
}

async fn update_phase(state: &ServerState, phase: &str) {
    let mut runtime = state.storage.natural_earth_import.lock().await;
    if let Some(job) = runtime.job.as_mut()
        && matches!(job.state, NaturalEarthImportState::Running)
    {
        job.phase = phase.to_string();
        job.updated_at_unix = unix_ts();
        append_job_log(job, format!("Phase: {phase}"));
    }
}

async fn append_import_log(state: &ServerState, message: impl Into<String>) {
    let mut runtime = state.storage.natural_earth_import.lock().await;
    if let Some(job) = runtime.job.as_mut() {
        append_job_log(job, message);
        job.updated_at_unix = unix_ts();
    }
}

fn append_job_log(job: &mut NaturalEarthImportJobView, message: impl Into<String>) {
    if job.log_entries.len() == NATURAL_EARTH_IMPORT_LOG_MAX_ENTRIES {
        job.log_entries.remove(0);
    }
    job.log_entries.push(NaturalEarthImportLogEntry {
        timestamp_unix: unix_ts(),
        message: message.into(),
    });
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
        job.phase = phase.to_string();
        if !matches!(import_state, NaturalEarthImportState::Failed) || logical_size_bytes > 0 {
            job.logical_size_bytes = logical_size_bytes;
        }
        job.error = error;
        job.updated_at_unix = unix_ts();
        let completion_log = match &import_state {
            NaturalEarthImportState::Ready => Some("Import completed successfully".to_string()),
            NaturalEarthImportState::Failed => Some(format!(
                "Import failed: {}",
                job.error.as_deref().unwrap_or("unknown error")
            )),
            NaturalEarthImportState::Running => None,
        };
        job.state = import_state;
        if let Some(completion_log) = completion_log {
            append_job_log(job, completion_log);
        }
    }
}

async fn ensure_import_commands_available(
    state: &ServerState,
    profile: NaturalEarthImportProfile,
) -> Result<()> {
    for (command, version_argument) in required_import_commands(profile) {
        let arguments = vec![version_argument.into()];
        let command_display = format_command(command, &arguments);
        append_import_log(
            state,
            format!("Checking required command: {command_display}"),
        )
        .await;
        match timeout(
            Duration::from_secs(10),
            Command::new(command)
                .args(&arguments)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true)
                .output(),
        )
        .await
        {
            Ok(Ok(output)) if output.status.success() => {
                append_import_log(
                    state,
                    format!("Required command is available: {command_display}"),
                )
                .await;
            }
            Ok(Ok(output)) => {
                let error = command_failure_message(&command_display, &output);
                append_import_log(state, format!("Required command check failed: {error}")).await;
                bail!("required map import command {error}")
            }
            Ok(Err(error)) if error.kind() == io::ErrorKind::NotFound => {
                let error = format!("`{command_display}` is not installed or not on PATH");
                append_import_log(state, format!("Required command check failed: {error}")).await;
                bail!("required map import command {error}")
            }
            Ok(Err(error)) => {
                let error = format!("could not start `{command_display}`: {error}");
                append_import_log(state, format!("Required command check failed: {error}")).await;
                bail!("failed starting required map import command {error}")
            }
            Err(_) => {
                let error = format!("`{command_display}` timed out after 10 seconds");
                append_import_log(state, format!("Required command check failed: {error}")).await;
                bail!("required map import command {error}")
            }
        }
    }
    Ok(())
}

fn required_import_commands(
    profile: NaturalEarthImportProfile,
) -> Vec<(&'static str, &'static str)> {
    let mut commands = REQUIRED_MAP_IMPORT_COMMANDS.to_vec();
    if profile == NaturalEarthImportProfile::PhysicalWithLabels {
        commands.extend(REQUIRED_LABEL_IMPORT_COMMANDS);
    }
    commands
}

async fn download_and_extract_natural_earth_archive(
    state: &ServerState,
    archive: NaturalEarthSourceArchive,
    destination_dir: &Path,
    working_dir: &Path,
) -> Result<()> {
    let destination = working_dir.join(archive.archive_name);
    update_phase(state, &format!("Downloading {}", archive.description)).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10 * 60))
        .redirect(reqwest::redirect::Policy::limited(3))
        .build()
        .context("failed building Natural Earth download client")?;
    let mut response = client
        .get(archive.url)
        .send()
        .await
        .with_context(|| format!("failed downloading the {}", archive.description))?
        .error_for_status()
        .with_context(|| format!("{} request was rejected", archive.description))?;
    if response
        .content_length()
        .is_some_and(|size| size > NATURAL_EARTH_IMPORT_MAX_DOWNLOAD_BYTES as u64)
    {
        bail!(
            "{} exceeds the configured download size limit",
            archive.description
        )
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
            .with_context(|| format!("{} size overflow", archive.description))?;
        if next_size > NATURAL_EARTH_IMPORT_MAX_DOWNLOAD_BYTES {
            bail!(
                "{} exceeds the configured download size limit",
                archive.description
            )
        }
        payload.extend_from_slice(&chunk);
    }
    let downloaded_bytes = payload.len();
    fs::write(&destination, payload).await.with_context(|| {
        format!(
            "failed writing {} {}",
            archive.description,
            destination.display()
        )
    })?;
    append_import_log(
        state,
        format!(
            "Downloaded {} ({downloaded_bytes} bytes)",
            archive.description
        ),
    )
    .await;
    update_phase(state, &format!("Extracting {}", archive.description)).await;
    run_command(
        state,
        "unzip",
        [
            "-q".into(),
            destination.as_os_str().to_owned(),
            "-d".into(),
            destination_dir.as_os_str().to_owned(),
        ],
        working_dir,
    )
    .await
}

async fn rasterize_physical_map(
    state: &ServerState,
    layers: PhysicalMapLayers<'_>,
    destination: &Path,
    working_dir: &Path,
) -> Result<()> {
    run_command(
        state,
        "gdal_rasterize",
        rasterize_create_arguments(layers.ocean, destination, [199, 224, 239, 255]),
        working_dir,
    )
    .await?;
    for (layer, color) in [
        (layers.land, [225, 232, 205, 255]),
        (layers.lakes, [171, 211, 233, 255]),
        (layers.rivers, [104, 170, 214, 255]),
        (layers.coastline, [94, 117, 122, 255]),
    ] {
        run_command(
            state,
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
    state: &ServerState,
    source: &Path,
    mercator: &Path,
    artifact: &Path,
    working_dir: &Path,
) -> Result<()> {
    run_command(
        state,
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
        state,
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
        state,
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

async fn create_natural_earth_label_overlay(
    state: &ServerState,
    layers: NaturalEarthLabelLayers<'_>,
    geopackage: &Path,
    artifact: &Path,
    working_dir: &Path,
) -> Result<()> {
    run_command(
        state,
        "ogr2ogr",
        country_label_geopackage_arguments(layers.countries, geopackage),
        working_dir,
    )
    .await?;
    run_command(
        state,
        "ogr2ogr",
        populated_place_label_geopackage_arguments(layers.populated_places, geopackage),
        working_dir,
    )
    .await?;
    run_command(
        state,
        "ogr2ogr",
        boundary_geopackage_arguments(layers.boundaries, geopackage),
        working_dir,
    )
    .await?;
    run_command(
        state,
        "ogr2ogr",
        vector_mbtiles_arguments(geopackage, artifact),
        working_dir,
    )
    .await
}

fn country_label_geopackage_arguments(
    source: &Path,
    destination: &Path,
) -> Vec<std::ffi::OsString> {
    vec![
        "-f".into(),
        "GPKG".into(),
        "-nln".into(),
        "ne_places".into(),
        "-nlt".into(),
        "POINT".into(),
        "-dialect".into(),
        "SQLite".into(),
        "-sql".into(),
        "SELECT 'country' AS class, NAME AS name, NAME AS name_en, ST_PointOnSurface(geometry) AS geometry FROM ne_10m_admin_0_countries".into(),
        destination.as_os_str().to_owned(),
        source.as_os_str().to_owned(),
    ]
}

fn populated_place_label_geopackage_arguments(
    source: &Path,
    destination: &Path,
) -> Vec<std::ffi::OsString> {
    vec![
        "-update".into(),
        "-append".into(),
        "-nln".into(),
        "ne_places".into(),
        "-nlt".into(),
        "POINT".into(),
        "-dialect".into(),
        "SQLite".into(),
        "-sql".into(),
        "SELECT CASE WHEN SCALERANK <= 3 THEN 'city' WHEN SCALERANK <= 6 THEN 'town' ELSE 'village' END AS class, NAME AS name, COALESCE(NAMEASCII, NAME) AS name_en, geometry FROM ne_10m_populated_places".into(),
        destination.as_os_str().to_owned(),
        source.as_os_str().to_owned(),
    ]
}

fn boundary_geopackage_arguments(source: &Path, destination: &Path) -> Vec<std::ffi::OsString> {
    vec![
        "-update".into(),
        "-append".into(),
        "-nln".into(),
        "ne_boundaries".into(),
        destination.as_os_str().to_owned(),
        source.as_os_str().to_owned(),
    ]
}

fn vector_mbtiles_arguments(source: &Path, destination: &Path) -> Vec<std::ffi::OsString> {
    vec![
        "-f".into(),
        "MBTILES".into(),
        "-dsco".into(),
        "NAME=Natural Earth labels".into(),
        "-dsco".into(),
        "DESCRIPTION=Natural Earth countries, populated places, and borders".into(),
        "-dsco".into(),
        "TYPE=overlay".into(),
        "-dsco".into(),
        "MINZOOM=0".into(),
        "-dsco".into(),
        "MAXZOOM=8".into(),
        destination.as_os_str().to_owned(),
        source.as_os_str().to_owned(),
    ]
}

async fn run_command(
    state: &ServerState,
    program: &str,
    args: impl IntoIterator<Item = std::ffi::OsString>,
    working_dir: &Path,
) -> Result<()> {
    let args = args.into_iter().collect::<Vec<_>>();
    let command_display = format_command(program, &args);
    append_import_log(state, format!("Running command: {command_display}")).await;
    let output = match timeout(
        Duration::from_secs(NATURAL_EARTH_COMMAND_TIMEOUT_SECS),
        Command::new(program)
            .args(&args)
            .current_dir(working_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => {
            let error = format!("`{command_display}` could not be started: {error}");
            append_import_log(state, format!("Command failed: {error}")).await;
            bail!("map conversion command {error}")
        }
        Err(_) => {
            let error = format!(
                "`{command_display}` timed out after {NATURAL_EARTH_COMMAND_TIMEOUT_SECS} seconds"
            );
            append_import_log(state, format!("Command failed: {error}")).await;
            bail!("map conversion command {error}")
        }
    };
    if output.status.success() {
        let output_details =
            command_output_details(&output, NATURAL_EARTH_COMMAND_LOG_OUTPUT_LIMIT);
        let message = if output_details.is_empty() {
            format!("Command completed successfully: {command_display}")
        } else {
            format!("Command completed successfully: {command_display}\n{output_details}")
        };
        append_import_log(state, message).await;
        return Ok(());
    }
    let error = command_failure_message(&command_display, &output);
    append_import_log(state, format!("Command failed: {error}")).await;
    bail!("map conversion command {error}")
}

fn format_command(program: &str, args: &[std::ffi::OsString]) -> String {
    std::iter::once(program.to_string())
        .chain(
            args.iter()
                .map(|arg| quote_command_argument(&arg.to_string_lossy())),
        )
        .collect::<Vec<_>>()
        .join(" ")
}

fn quote_command_argument(argument: &str) -> String {
    if argument
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-._/=:".contains(character))
    {
        argument.to_string()
    } else {
        format!("'{}'", argument.replace('\'', "'\\''"))
    }
}

fn command_failure_message(command_display: &str, output: &std::process::Output) -> String {
    let details = command_output_details(output, NATURAL_EARTH_COMMAND_OUTPUT_LIMIT);
    if details.is_empty() {
        format!("`{command_display}` exited with {}", output.status)
    } else {
        format!(
            "`{command_display}` exited with {}:\n{details}",
            output.status
        )
    }
}

fn command_output_details(output: &std::process::Output, limit: usize) -> String {
    let mut sections = Vec::new();
    if let Some(stderr) = truncate_command_output(&output.stderr, limit) {
        sections.push(format!("stderr:\n{stderr}"));
    }
    if let Some(stdout) = truncate_command_output(&output.stdout, limit) {
        sections.push(format!("stdout:\n{stdout}"));
    }
    sections.join("\n")
}

fn truncate_command_output(output: &[u8], limit: usize) -> Option<String> {
    let clipped = &output[..output.len().min(limit)];
    let text = String::from_utf8_lossy(clipped).trim().to_string();
    if text.is_empty() {
        None
    } else {
        let truncated = output.len() > clipped.len();
        Some(if truncated {
            format!("{text}\n… output truncated")
        } else {
            text
        })
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

async fn validate_generated_mbtiles(state: &ServerState, path: &Path) -> Result<()> {
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
    .context("generated MBTiles validation task failed")??;
    append_import_log(state, "Generated MBTiles validation completed successfully").await;
    Ok(())
}

async fn validate_generated_label_mbtiles(state: &ServerState, path: &Path) -> Result<()> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let connection = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .context("failed opening generated Natural Earth label MBTiles artifact")?;
        let tiles: i64 = connection
            .query_row("select count(*) from tiles", [], |row| row.get(0))
            .context("generated Natural Earth label artifact has no readable tiles table")?;
        if tiles == 0 {
            bail!("generated Natural Earth label artifact contains no tiles")
        }
        let format: Option<String> = connection
            .query_row(
                "select value from metadata where name = 'format' limit 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("generated Natural Earth label artifact has no readable metadata table")?;
        if !matches!(format.as_deref(), Some(value) if value.eq_ignore_ascii_case("pbf")) {
            bail!("generated Natural Earth label artifact must declare PBF vector tiles")
        }
        let metadata_json: Option<String> = connection
            .query_row(
                "select value from metadata where name = 'json' limit 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .context("generated Natural Earth label artifact has no vector metadata")?;
        validate_natural_earth_label_metadata(metadata_json.as_deref())
    })
    .await
    .context("generated Natural Earth label validation task failed")??;
    append_import_log(
        state,
        "Generated Natural Earth label overlay validation completed successfully",
    )
    .await;
    Ok(())
}

fn validate_natural_earth_label_metadata(metadata_json: Option<&str>) -> Result<()> {
    let metadata_json =
        metadata_json.context("generated Natural Earth label artifact has no json metadata")?;
    let metadata: serde_json::Value = serde_json::from_str(metadata_json)
        .context("generated Natural Earth label metadata is invalid JSON")?;
    let vector_layers = metadata
        .get("vector_layers")
        .and_then(serde_json::Value::as_array)
        .context("generated Natural Earth label metadata has no vector_layers array")?;
    let layer_names = vector_layers
        .iter()
        .filter_map(|layer| layer.get("id").and_then(serde_json::Value::as_str))
        .collect::<std::collections::HashSet<_>>();
    let missing_layers = ["ne_places", "ne_boundaries"]
        .into_iter()
        .filter(|layer| !layer_names.contains(layer))
        .collect::<Vec<_>>();
    if !missing_layers.is_empty() {
        bail!(
            "generated Natural Earth label artifact is missing required vector layer(s): {}",
            missing_layers.join(", ")
        )
    }
    Ok(())
}

fn required_job_artifact(
    job: &NaturalEarthImportJobView,
    asset: map_config::MapVariantAssetKind,
) -> Result<&NaturalEarthImportArtifactView> {
    job.artifacts
        .iter()
        .find(|artifact| artifact.asset == asset)
        .with_context(|| format!("Natural Earth import job has no configured {asset:?} artifact"))
}

async fn record_published_artifact(
    state: &ServerState,
    manifest_key: &str,
    logical_size_bytes: u64,
) {
    let mut runtime = state.storage.natural_earth_import.lock().await;
    if let Some(job) = runtime.job.as_mut()
        && matches!(job.state, NaturalEarthImportState::Running)
    {
        if let Some(artifact) = job
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.manifest_key == manifest_key)
        {
            artifact.logical_size_bytes = logical_size_bytes;
        }
        job.logical_size_bytes = job.artifacts.iter().fold(0_u64, |total, artifact| {
            total.saturating_add(artifact.logical_size_bytes)
        });
        job.updated_at_unix = unix_ts();
    }
}

async fn publish_generated_mbtiles(
    state: &ServerState,
    job: &NaturalEarthImportJobView,
    artifact: &NaturalEarthImportArtifactView,
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
            artifact.logical_key,
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
    let parts_count = parts.len();
    let manifest = SplitFileManifestDocument {
        manifest_version: 1,
        manifest_type: "split_file_manifest",
        logical_format: "mbtiles",
        logical_key: artifact.logical_key.clone(),
        manifest_key: artifact.manifest_key.clone(),
        storage_root: "sys/maps",
        logical_size_bytes: offset,
        last_part_size_bytes: parts.last().map(|part| part.size_bytes).unwrap_or_default(),
        parts_count,
        parts,
    };
    put_system_object(
        state,
        &artifact.manifest_key,
        Bytes::from(
            serde_json::to_vec_pretty(&manifest)
                .context("failed serializing map artifact manifest")?,
        ),
    )
    .await?;
    map_dataset_import::invalidate_cached_mbtiles_source(state, &artifact.manifest_key).await;
    append_import_log(
        state,
        format!("Published {parts_count} map artifact part(s) and manifest"),
    )
    .await;
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

    #[test]
    fn command_probes_use_unzip_version_flag() {
        assert_eq!(
            REQUIRED_MAP_IMPORT_COMMANDS
                .iter()
                .find(|(command, _)| *command == "unzip"),
            Some(&("unzip", "-v"))
        );
    }

    #[test]
    fn command_display_names_the_exact_command() {
        assert_eq!(format_command("unzip", &["-v".into()]), "unzip -v");
    }

    #[test]
    fn labels_profile_requires_ogr2ogr_but_the_raster_only_profile_does_not() {
        assert!(
            !required_import_commands(NaturalEarthImportProfile::Physical)
                .iter()
                .any(|(command, _)| *command == "ogr2ogr")
        );
        assert!(
            required_import_commands(NaturalEarthImportProfile::PhysicalWithLabels)
                .iter()
                .any(|(command, argument)| *command == "ogr2ogr" && *argument == "--version")
        );
    }

    #[test]
    fn label_conversion_uses_the_viewer_source_layer_contract() {
        let countries = Path::new("/tmp/ne_10m_admin_0_countries.shp");
        let places = Path::new("/tmp/ne_10m_populated_places.shp");
        let boundaries = Path::new("/tmp/ne_10m_admin_0_boundary_lines_land.shp");
        let geopackage = Path::new("/tmp/natural-earth-labels.gpkg");
        let artifact = Path::new("/tmp/natural-earth-labels.mbtiles");

        let country_arguments = country_label_geopackage_arguments(countries, geopackage);
        let place_arguments = populated_place_label_geopackage_arguments(places, geopackage);
        let boundary_arguments = boundary_geopackage_arguments(boundaries, geopackage);
        let mbtiles_command =
            format_command("ogr2ogr", &vector_mbtiles_arguments(geopackage, artifact));

        let country_sql = country_arguments[9].to_string_lossy();
        let place_sql = place_arguments[9].to_string_lossy();
        assert!(country_sql.contains("'country' AS class"));
        assert!(country_sql.contains("ST_PointOnSurface(geometry)"));
        assert!(place_sql.contains("'city'"));
        assert!(place_sql.contains("'town'"));
        assert!(place_sql.contains("'village'"));
        assert_eq!(boundary_arguments[3].to_string_lossy(), "ne_boundaries");
        assert!(mbtiles_command.contains("-f MBTILES"));
        assert!(mbtiles_command.contains("MINZOOM=0"));
        assert!(mbtiles_command.contains("MAXZOOM=8"));
    }

    #[test]
    fn label_metadata_requires_places_and_boundaries_layers() {
        assert!(
            validate_natural_earth_label_metadata(Some(
                r#"{"vector_layers":[{"id":"ne_places"},{"id":"ne_boundaries"}]}"#
            ))
            .is_ok()
        );
        assert!(
            validate_natural_earth_label_metadata(Some(
                r#"{"vector_layers":[{"id":"ne_places"}]}"#
            ))
            .is_err()
        );
    }
}
