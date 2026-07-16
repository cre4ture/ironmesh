use super::*;
use std::fs;

const HARDWARE_HEALTH_REFRESH_INTERVAL_SECS: u64 = 5 * 60;
const HARDWARE_HEALTH_STATE_FILE: &str = "health/hardware-health-state.json";
const HARDWARE_HEALTH_LOG_SCAN_LIMIT: usize = 250;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HardwareHealthCurrentResponse {
    report: Option<HardwareHealthReport>,
    collecting: bool,
    last_attempt_unix: Option<u64>,
    last_success_unix: Option<u64>,
    last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct HardwareHealthReport {
    reporting_node_id: NodeId,
    generated_at_unix: u64,
    ironmesh_version: String,
    ironmesh_revision: String,
    hardware_profile_id: String,
    inventory: HardwareInventory,
    node_lifecycle: HardwareNodeLifecycle,
    collectors: Vec<HardwareHealthCollectorStatus>,
    findings: Vec<HardwareHealthFinding>,
    health_notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct HardwareInventory {
    host_os: String,
    architecture: String,
    kernel_version: Option<String>,
    system: HardwareSystemInfo,
    cpu_packages: Vec<HardwareCpuPackage>,
    memory: HardwareMemoryInfo,
    storage_devices: Vec<HardwareStorageDevice>,
    network_interfaces: Vec<HardwareNetworkInterface>,
}

#[derive(Debug, Clone, Serialize)]
struct HardwareSystemInfo {
    vendor: Option<String>,
    product_name: Option<String>,
    product_version: Option<String>,
    board_vendor: Option<String>,
    board_name: Option<String>,
    board_version: Option<String>,
    bios_vendor: Option<String>,
    bios_version: Option<String>,
    bios_date: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct HardwareCpuPackage {
    component_ref: String,
    component_instance_id: String,
    lifecycle: HardwareComponentLifecycle,
    vendor_id: Option<String>,
    model_name: Option<String>,
    family: Option<String>,
    model: Option<String>,
    stepping: Option<String>,
    microcode: Option<String>,
    nominal_frequency_mhz: Option<u64>,
    logical_cpu_count: u32,
    physical_core_count: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
struct HardwareMemoryInfo {
    installed_bytes: u64,
    page_size_bytes: Option<u64>,
    details_complete: bool,
}

#[derive(Debug, Clone, Serialize)]
struct HardwareStorageDevice {
    component_ref: String,
    component_instance_id: String,
    lifecycle: HardwareComponentLifecycle,
    block_device_name: String,
    vendor: Option<String>,
    model: Option<String>,
    firmware_version: Option<String>,
    capacity_bytes: Option<u64>,
    interface_type: String,
    bus_type: Option<String>,
    is_rotational: Option<bool>,
    logical_sector_size_bytes: Option<u64>,
    physical_sector_size_bytes: Option<u64>,
    pci_slot: Option<String>,
    driver: Option<String>,
    smart: Option<HardwareStorageSmartInfo>,
}

#[derive(Debug, Clone, Serialize)]
struct HardwareStorageSmartInfo {
    smart_available: bool,
    smart_passed: Option<bool>,
    temperature_celsius: Option<f32>,
    power_on_hours: Option<u64>,
    power_cycle_count: Option<u64>,
    unsafe_shutdown_count: Option<u64>,
    percentage_used: Option<u64>,
    available_spare_percent: Option<u64>,
    available_spare_threshold_percent: Option<u64>,
    data_units_read: Option<u64>,
    data_units_written: Option<u64>,
    media_errors: Option<u64>,
    error_log_entries: Option<u64>,
    reallocated_sector_count: Option<u64>,
    pending_sector_count: Option<u64>,
    offline_uncorrectable_sector_count: Option<u64>,
    crc_error_count: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
struct HardwareNetworkInterface {
    component_ref: String,
    component_instance_id: String,
    lifecycle: HardwareComponentLifecycle,
    interface_name: String,
    oper_state: Option<String>,
    carrier: Option<bool>,
    speed_mbps: Option<u64>,
    driver: Option<String>,
    pci_slot: Option<String>,
    vendor_id: Option<String>,
    device_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct HardwareNodeLifecycle {
    node_first_seen_at_unix: u64,
    inventory_last_changed_at_unix: u64,
    boot_id: Option<String>,
    booted_at_unix: Option<u64>,
    uptime_seconds: Option<u64>,
    cumulative_observed_uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
struct HardwareComponentLifecycle {
    first_seen_at_unix: u64,
    last_seen_at_unix: u64,
    sighting_count: u64,
}

#[derive(Debug, Clone, Serialize)]
struct HardwareHealthCollectorStatus {
    collector_id: String,
    label: String,
    state: String,
    available: bool,
    last_collected_at_unix: Option<u64>,
    last_error_code: Option<String>,
    detail: String,
}

#[derive(Debug, Clone, Serialize)]
struct HardwareHealthFinding {
    source: String,
    category: String,
    finding_code: String,
    severity: String,
    component_ref: Option<String>,
    component_instance_id: Option<String>,
    first_seen_at_unix: u64,
    last_seen_at_unix: u64,
    occurrence_count: u64,
    summary: String,
    evidence: serde_json::Value,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct HardwareHealthRuntime {
    report: Option<HardwareHealthReport>,
    collecting: bool,
    last_attempt_unix: Option<u64>,
    last_success_unix: Option<u64>,
    last_error: Option<String>,
    state_path: PathBuf,
    persisted: PersistedHardwareHealthState,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedHardwareHealthState {
    node_first_seen_at_unix: Option<u64>,
    inventory_last_changed_at_unix: Option<u64>,
    last_hardware_profile_id: Option<String>,
    cumulative_observed_uptime_seconds: u64,
    last_boot_id: Option<String>,
    last_observed_uptime_seconds: u64,
    components: HashMap<String, PersistedComponentLifecycle>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedComponentLifecycle {
    first_seen_at_unix: u64,
    last_seen_at_unix: u64,
    sighting_count: u64,
}

#[derive(Debug)]
struct CollectedHardwareHealth {
    generated_at_unix: u64,
    inventory: HardwareInventory,
    collectors: Vec<HardwareHealthCollectorStatus>,
    findings: Vec<HardwareHealthFinding>,
    boot_id: Option<String>,
    uptime_seconds: Option<u64>,
}

#[derive(Debug)]
struct SmartctlSnapshot {
    smart: HardwareStorageSmartInfo,
    findings: Vec<HardwareHealthFinding>,
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct CpuPackageSeed {
    component_ref: String,
    stable_material: String,
    vendor_id: Option<String>,
    model_name: Option<String>,
    family: Option<String>,
    model: Option<String>,
    stepping: Option<String>,
    microcode: Option<String>,
    nominal_frequency_mhz: Option<u64>,
    logical_cpu_count: u32,
    physical_core_count: Option<u32>,
}

impl HardwareHealthRuntime {
    pub(crate) fn load(data_dir: &FsPath) -> Self {
        let state_path = data_dir.join(HARDWARE_HEALTH_STATE_FILE);
        let persisted = match fs::read_to_string(&state_path) {
            Ok(raw) => match serde_json::from_str::<PersistedHardwareHealthState>(&raw) {
                Ok(parsed) => parsed,
                Err(err) => {
                    warn!(
                        error = %err,
                        path = %state_path.display(),
                        "failed to parse persisted hardware-health state; starting fresh"
                    );
                    PersistedHardwareHealthState::default()
                }
            },
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                PersistedHardwareHealthState::default()
            }
            Err(err) => {
                warn!(
                    error = %err,
                    path = %state_path.display(),
                    "failed to load persisted hardware-health state; starting fresh"
                );
                PersistedHardwareHealthState::default()
            }
        };

        Self {
            state_path,
            persisted,
            ..Self::default()
        }
    }
}

pub(crate) fn spawn_hardware_health_sampler(state: ServerState) {
    tokio::spawn(async move {
        refresh_hardware_health_once(&state).await;

        let mut ticker =
            tokio::time::interval(Duration::from_secs(HARDWARE_HEALTH_REFRESH_INTERVAL_SECS));
        loop {
            ticker.tick().await;
            refresh_hardware_health_once(&state).await;
        }
    });
}

pub(crate) async fn hardware_health_current(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let action = "auth/hardware/health/get";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        true,
        true,
        json!({ "node_id": state.node_id }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let runtime = state.hardware_health_runtime.lock().await;
    let response = HardwareHealthCurrentResponse {
        report: runtime.report.clone(),
        collecting: runtime.collecting,
        last_attempt_unix: runtime.last_attempt_unix,
        last_success_unix: runtime.last_success_unix,
        last_error: runtime.last_error.clone(),
    };
    let finding_count = response
        .report
        .as_ref()
        .map(|report| report.findings.len())
        .unwrap_or(0);
    let storage_count = response
        .report
        .as_ref()
        .map(|report| report.inventory.storage_devices.len())
        .unwrap_or(0);
    drop(runtime);

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "finding_count": finding_count,
            "storage_devices": storage_count,
        }),
    )
    .await;

    (StatusCode::OK, Json(response)).into_response()
}

async fn refresh_hardware_health_once(state: &ServerState) {
    {
        let mut runtime = state.hardware_health_runtime.lock().await;
        runtime.collecting = true;
        runtime.last_attempt_unix = Some(unix_ts());
    }

    match collect_hardware_health(state).await {
        Ok(collected) => {
            let (payload, state_path, persisted_bytes) = {
                let mut runtime = state.hardware_health_runtime.lock().await;
                let report = finalize_hardware_health_report(state, &mut runtime, collected);
                runtime.collecting = false;
                runtime.last_success_unix = Some(report.generated_at_unix);
                runtime.last_error = None;
                runtime.report = Some(report.clone());
                let persisted_bytes = serde_json::to_vec_pretty(&runtime.persisted)
                    .context("failed to serialize persisted hardware-health state");
                (report, runtime.state_path.clone(), persisted_bytes)
            };

            match persisted_bytes {
                Ok(bytes) => {
                    if let Err(err) = write_json_atomic(&state_path, &bytes).await {
                        let mut runtime = state.hardware_health_runtime.lock().await;
                        runtime.last_error = Some(sanitize_error_code(&err.to_string()));
                        warn!(error = %err, "failed to persist hardware-health state");
                    } else {
                        let _ = payload;
                    }
                }
                Err(err) => {
                    let mut runtime = state.hardware_health_runtime.lock().await;
                    runtime.last_error = Some(sanitize_error_code(&err.to_string()));
                    warn!(error = %err, "failed to serialize hardware-health state");
                }
            }
        }
        Err(err) => {
            let mut runtime = state.hardware_health_runtime.lock().await;
            runtime.collecting = false;
            runtime.last_error = Some(sanitize_error_code(&err.to_string()));
            warn!(error = %err, "failed to collect hardware-health report");
        }
    }
}

fn finalize_hardware_health_report(
    state: &ServerState,
    runtime: &mut HardwareHealthRuntime,
    collected: CollectedHardwareHealth,
) -> HardwareHealthReport {
    let node_first_seen_at_unix = runtime
        .persisted
        .node_first_seen_at_unix
        .get_or_insert(collected.generated_at_unix)
        .to_owned();
    update_persisted_uptime(
        &mut runtime.persisted,
        collected.boot_id.as_deref(),
        collected.uptime_seconds,
    );
    let hardware_profile_id = hardware_profile_id(&collected.inventory);
    let inventory_last_changed_at_unix = match runtime.persisted.last_hardware_profile_id.as_deref()
    {
        Some(current) if current == hardware_profile_id => runtime
            .persisted
            .inventory_last_changed_at_unix
            .unwrap_or(collected.generated_at_unix),
        _ => {
            runtime.persisted.last_hardware_profile_id = Some(hardware_profile_id.clone());
            runtime.persisted.inventory_last_changed_at_unix = Some(collected.generated_at_unix);
            collected.generated_at_unix
        }
    };

    let inventory = apply_component_lifecycle(
        collected.inventory,
        &mut runtime.persisted,
        collected.generated_at_unix,
    );

    let node_lifecycle = HardwareNodeLifecycle {
        node_first_seen_at_unix,
        inventory_last_changed_at_unix,
        boot_id: collected.boot_id,
        booted_at_unix: collected
            .uptime_seconds
            .map(|uptime_seconds| collected.generated_at_unix.saturating_sub(uptime_seconds)),
        uptime_seconds: collected.uptime_seconds,
        cumulative_observed_uptime_seconds: runtime.persisted.cumulative_observed_uptime_seconds,
    };
    let mut findings = collected.findings;
    findings.sort_by(|left, right| {
        severity_rank(&left.severity)
            .cmp(&severity_rank(&right.severity))
            .then_with(|| right.last_seen_at_unix.cmp(&left.last_seen_at_unix))
            .then_with(|| left.finding_code.cmp(&right.finding_code))
    });
    let health_notes = build_health_notes(&inventory, &node_lifecycle, &findings);

    HardwareHealthReport {
        reporting_node_id: state.node_id,
        generated_at_unix: collected.generated_at_unix,
        ironmesh_version: BUILD_VERSION.to_string(),
        ironmesh_revision: BUILD_REVISION.to_string(),
        hardware_profile_id,
        inventory,
        node_lifecycle,
        collectors: collected.collectors,
        findings,
        health_notes,
    }
}

fn apply_component_lifecycle(
    mut inventory: HardwareInventory,
    persisted: &mut PersistedHardwareHealthState,
    generated_at_unix: u64,
) -> HardwareInventory {
    for cpu in &mut inventory.cpu_packages {
        cpu.lifecycle =
            resolve_component_lifecycle(persisted, &cpu.component_instance_id, generated_at_unix);
    }
    for device in &mut inventory.storage_devices {
        device.lifecycle = resolve_component_lifecycle(
            persisted,
            &device.component_instance_id,
            generated_at_unix,
        );
    }
    for iface in &mut inventory.network_interfaces {
        iface.lifecycle =
            resolve_component_lifecycle(persisted, &iface.component_instance_id, generated_at_unix);
    }
    inventory
}

fn resolve_component_lifecycle(
    persisted: &mut PersistedHardwareHealthState,
    component_instance_id: &str,
    generated_at_unix: u64,
) -> HardwareComponentLifecycle {
    let entry = persisted
        .components
        .entry(component_instance_id.to_string())
        .or_insert_with(|| PersistedComponentLifecycle {
            first_seen_at_unix: generated_at_unix,
            last_seen_at_unix: generated_at_unix,
            sighting_count: 0,
        });
    entry.last_seen_at_unix = generated_at_unix;
    entry.sighting_count = entry.sighting_count.saturating_add(1);
    HardwareComponentLifecycle {
        first_seen_at_unix: entry.first_seen_at_unix,
        last_seen_at_unix: entry.last_seen_at_unix,
        sighting_count: entry.sighting_count,
    }
}

fn update_persisted_uptime(
    persisted: &mut PersistedHardwareHealthState,
    boot_id: Option<&str>,
    uptime_seconds: Option<u64>,
) {
    let Some(uptime_seconds) = uptime_seconds else {
        return;
    };

    match (&persisted.last_boot_id, boot_id) {
        (Some(previous), Some(current)) if previous == current => {
            let delta = uptime_seconds.saturating_sub(persisted.last_observed_uptime_seconds);
            persisted.cumulative_observed_uptime_seconds = persisted
                .cumulative_observed_uptime_seconds
                .saturating_add(delta);
        }
        (_, Some(current)) => {
            persisted.last_boot_id = Some(current.to_string());
            persisted.cumulative_observed_uptime_seconds = persisted
                .cumulative_observed_uptime_seconds
                .saturating_add(uptime_seconds);
        }
        _ => {
            persisted.cumulative_observed_uptime_seconds = persisted
                .cumulative_observed_uptime_seconds
                .saturating_add(uptime_seconds);
        }
    }
    persisted.last_observed_uptime_seconds = uptime_seconds;
}

async fn collect_hardware_health(state: &ServerState) -> Result<CollectedHardwareHealth> {
    let generated_at_unix = unix_ts();
    let mut collectors = Vec::new();
    let mut findings = collect_runtime_findings(state, generated_at_unix).await;

    let inventory_collection = collect_inventory_linux(state, generated_at_unix).await;
    let (mut inventory, inventory_collector, mut storage_smart_targets) = match inventory_collection
    {
        Ok(result) => result,
        Err(err) => {
            let fallback = empty_inventory();
            (
                fallback,
                HardwareHealthCollectorStatus {
                    collector_id: "linux_inventory".to_string(),
                    label: "Linux inventory".to_string(),
                    state: "unavailable".to_string(),
                    available: false,
                    last_collected_at_unix: Some(generated_at_unix),
                    last_error_code: Some(sanitize_error_code(&err.to_string())),
                    detail: "Failed to collect Linux hardware inventory.".to_string(),
                },
                Vec::new(),
            )
        }
    };
    collectors.push(inventory_collector);

    let (smart_collector, smart_findings) = enrich_storage_with_smartctl(
        &mut inventory.storage_devices,
        &mut storage_smart_targets,
        generated_at_unix,
    )
    .await;
    collectors.push(smart_collector);
    findings.extend(smart_findings);

    let temp_findings = temperature_findings_from_runtime(state, generated_at_unix);
    findings.extend(temp_findings);

    findings.sort_by(|left, right| {
        severity_rank(&left.severity)
            .cmp(&severity_rank(&right.severity))
            .then_with(|| right.last_seen_at_unix.cmp(&left.last_seen_at_unix))
            .then_with(|| left.finding_code.cmp(&right.finding_code))
    });

    Ok(CollectedHardwareHealth {
        generated_at_unix,
        inventory,
        collectors,
        findings,
        boot_id: current_boot_id(),
        uptime_seconds: current_uptime_seconds(),
    })
}

async fn collect_runtime_findings(
    state: &ServerState,
    generated_at_unix: u64,
) -> Vec<HardwareHealthFinding> {
    let mut findings = Vec::new();

    if let Ok(Some(latest_scrub)) = latest_data_scrub_run_record(state).await {
        findings.extend(scrub_findings(&latest_scrub));
    }
    if let Ok(Some(latest_repair)) = latest_repair_run_record(state).await
        && let Some(finding) = repair_finding(&latest_repair)
    {
        findings.push(finding);
    }

    findings.extend(log_pattern_findings(
        state.log_buffer.recent(HARDWARE_HEALTH_LOG_SCAN_LIMIT),
        generated_at_unix,
    ));

    let storage_stats_runtime = state.storage.storage_stats_runtime.lock().await.clone();
    if storage_stats_runtime.last_error.is_some() {
        findings.push(HardwareHealthFinding {
            source: "ironmesh_runtime".to_string(),
            category: "collector".to_string(),
            finding_code: "storage_stats_collector_failed".to_string(),
            severity: "warn".to_string(),
            component_ref: Some("storage_stats".to_string()),
            component_instance_id: None,
            first_seen_at_unix: storage_stats_runtime
                .last_attempt_unix
                .unwrap_or(generated_at_unix),
            last_seen_at_unix: storage_stats_runtime
                .last_attempt_unix
                .unwrap_or(generated_at_unix),
            occurrence_count: 1,
            summary: "The storage stats collector reported a recent failure.".to_string(),
            evidence: json!({
                "last_attempt_unix": storage_stats_runtime.last_attempt_unix,
                "last_success_unix": storage_stats_runtime.last_success_unix,
                "last_error_code": storage_stats_runtime.last_error.as_deref().map(sanitize_error_code),
            }),
        });
    }

    findings
}

fn scrub_findings(latest_scrub: &DataScrubRunRecord) -> Vec<HardwareHealthFinding> {
    if latest_scrub.status == DataScrubRunStatus::Clean || latest_scrub.summary.issue_count == 0 {
        return Vec::new();
    }

    let mut counts = BTreeMap::<String, u64>::new();
    for issue in &latest_scrub.summary.issues {
        *counts.entry(scrub_issue_code(&issue.kind)).or_default() += 1;
    }

    counts
        .into_iter()
        .map(|(issue_kind, count)| HardwareHealthFinding {
            source: "ironmesh_scrub".to_string(),
            category: "data_integrity".to_string(),
            finding_code: issue_kind.clone(),
            severity: scrub_issue_severity(issue_kind.as_str()).to_string(),
            component_ref: Some("local_store".to_string()),
            component_instance_id: None,
            first_seen_at_unix: latest_scrub.started_at_unix,
            last_seen_at_unix: latest_scrub.finished_at_unix,
            occurrence_count: count,
            summary: format!(
                "The latest retained data scrub reported {count} {issue_kind} issue{} on this node.",
                if count == 1 { "" } else { "s" }
            ),
            evidence: json!({
                "reporting_node_id": latest_scrub.reporting_node_id,
                "run_id": latest_scrub.run_id,
                "status": latest_scrub.status,
                "issue_count": latest_scrub.summary.issue_count,
                "sampled_issue_count": latest_scrub.summary.sampled_issue_count,
                "manifests_scanned": latest_scrub.summary.manifests_scanned,
                "chunks_scanned": latest_scrub.summary.chunks_scanned,
                "bytes_scanned": latest_scrub.summary.bytes_scanned,
                "issue_kind_count": count,
            }),
        })
        .collect()
}

fn repair_finding(latest_repair: &RepairRunRecord) -> Option<HardwareHealthFinding> {
    let summary = latest_repair.summary.as_ref()?;
    if summary.failed_transfers == 0 && summary.failed_nodes.unwrap_or(0) == 0 {
        return None;
    }

    Some(HardwareHealthFinding {
        source: "ironmesh_repair".to_string(),
        category: "replication".to_string(),
        finding_code: "repair_failures".to_string(),
        severity: if summary.failed_transfers > 0 || summary.failed_nodes.unwrap_or(0) > 0 {
            "warn".to_string()
        } else {
            "info".to_string()
        },
        component_ref: Some("replication_runtime".to_string()),
        component_instance_id: None,
        first_seen_at_unix: latest_repair.started_at_unix,
        last_seen_at_unix: latest_repair.finished_at_unix,
        occurrence_count: summary.failed_transfers.max(1) as u64,
        summary: format!(
            "The latest retained repair run finished with {} failed transfer{} across {} failed node{}.",
            summary.failed_transfers,
            if summary.failed_transfers == 1 {
                ""
            } else {
                "s"
            },
            summary.failed_nodes.unwrap_or(0),
            if summary.failed_nodes.unwrap_or(0) == 1 {
                ""
            } else {
                "s"
            },
        ),
        evidence: json!({
            "run_id": latest_repair.run_id,
            "status": latest_repair.status,
            "attempted_transfers": summary.attempted_transfers,
            "successful_transfers": summary.successful_transfers,
            "failed_transfers": summary.failed_transfers,
            "skipped_items": summary.skipped_items,
            "failed_nodes": summary.failed_nodes,
            "nodes_contacted": summary.nodes_contacted,
            "last_error_code": summary.last_error.as_deref().map(sanitize_error_code),
        }),
    })
}

fn log_pattern_findings(
    entries: Vec<LogBufferEntry>,
    generated_at_unix: u64,
) -> Vec<HardwareHealthFinding> {
    let patterns = [
        (
            "storage_io_errors",
            "storage",
            "warn",
            &[
                "input/output error",
                "i/o error",
                "blk_update_request",
                "buffer i/o error",
            ][..],
        ),
        (
            "sqlite_corruption",
            "storage",
            "critical",
            &[
                "database disk image is malformed",
                "file is not a database",
                "sqlite corruption",
            ][..],
        ),
        (
            "disk_full",
            "capacity",
            "warn",
            &["no space left on device"][..],
        ),
        (
            "read_only_filesystem",
            "storage",
            "warn",
            &["read-only file system"][..],
        ),
        (
            "device_resets",
            "storage",
            "warn",
            &["reset controller", "device reset", "link is down"][..],
        ),
    ];

    let mut findings = Vec::new();
    for (code, category, severity, needles) in patterns {
        let mut count = 0_u64;
        let mut first_seen = None;
        let mut last_seen = None;

        for entry in &entries {
            let line = entry.line.to_ascii_lowercase();
            if needles.iter().any(|needle| line.contains(needle)) {
                count += 1;
                first_seen = Some(
                    first_seen
                        .unwrap_or(entry.captured_at_unix)
                        .min(entry.captured_at_unix),
                );
                last_seen = Some(
                    last_seen
                        .unwrap_or(entry.captured_at_unix)
                        .max(entry.captured_at_unix),
                );
            }
        }

        if count == 0 {
            continue;
        }

        findings.push(HardwareHealthFinding {
            source: "ironmesh_logs".to_string(),
            category: category.to_string(),
            finding_code: code.to_string(),
            severity: severity.to_string(),
            component_ref: None,
            component_instance_id: None,
            first_seen_at_unix: first_seen.unwrap_or(generated_at_unix),
            last_seen_at_unix: last_seen.unwrap_or(generated_at_unix),
            occurrence_count: count,
            summary: format!(
                "Recent IronMesh runtime logs matched the {code} pattern {count} time{}.",
                if count == 1 { "" } else { "s" }
            ),
            evidence: json!({
                "sample_size": entries.len(),
                "matched_lines": count,
            }),
        });
    }
    findings
}

fn temperature_findings_from_runtime(
    state: &ServerState,
    generated_at_unix: u64,
) -> Vec<HardwareHealthFinding> {
    let runtime = match state.process_stats_runtime.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };

    runtime
        .latest_temperature_components
        .iter()
        .filter_map(|component| {
            let temp = component.temperature_celsius?;
            let critical = component.critical_celsius;
            let max = component.max_celsius;
            let severity = match (critical, max) {
                (Some(critical), _) if temp >= critical => Some("critical"),
                (Some(critical), _) if temp >= critical - 5.0 => Some("warn"),
                (_, Some(max)) if temp >= max => Some("warn"),
                _ if temp >= 85.0 => Some("warn"),
                _ => None,
            }?;

            Some(HardwareHealthFinding {
                source: "host_temperature".to_string(),
                category: "thermal".to_string(),
                finding_code: "component_temperature_high".to_string(),
                severity: severity.to_string(),
                component_ref: Some(component.label.clone()),
                component_instance_id: None,
                first_seen_at_unix: generated_at_unix,
                last_seen_at_unix: generated_at_unix,
                occurrence_count: 1,
                summary: format!(
                    "{} is currently reporting {:.1}C, which is above the configured warning threshold.",
                    component.label, temp
                ),
                evidence: json!({
                    "temperature_celsius": temp,
                    "max_celsius": max,
                    "critical_celsius": critical,
                }),
            })
        })
        .collect()
}

async fn collect_inventory_linux(
    _state: &ServerState,
    generated_at_unix: u64,
) -> Result<(
    HardwareInventory,
    HardwareHealthCollectorStatus,
    Vec<(usize, String)>,
)> {
    #[cfg(target_os = "linux")]
    {
        let system = collect_system_info_linux();
        let cpu_packages = collect_cpu_packages_linux();
        let memory = collect_memory_info_linux();
        let (storage_devices, storage_targets) = collect_storage_devices_linux();
        let network_interfaces = collect_network_interfaces_linux();
        let inventory = HardwareInventory {
            host_os: "linux".to_string(),
            architecture: std::env::consts::ARCH.to_string(),
            kernel_version: read_trimmed_file("/proc/sys/kernel/osrelease"),
            system,
            cpu_packages,
            memory,
            storage_devices,
            network_interfaces,
        };
        let collector = HardwareHealthCollectorStatus {
            collector_id: "linux_inventory".to_string(),
            label: "Linux inventory".to_string(),
            state: "ready".to_string(),
            available: true,
            last_collected_at_unix: Some(generated_at_unix),
            last_error_code: None,
            detail: "Collected board, CPU, memory, storage, and NIC inventory from Linux sysfs and procfs."
                .to_string(),
        };
        Ok((inventory, collector, storage_targets))
    }

    #[cfg(not(target_os = "linux"))]
    {
        let inventory = empty_inventory();
        let collector = HardwareHealthCollectorStatus {
            collector_id: "linux_inventory".to_string(),
            label: "Linux inventory".to_string(),
            state: "unavailable".to_string(),
            available: false,
            last_collected_at_unix: Some(generated_at_unix),
            last_error_code: Some("unsupported_os".to_string()),
            detail: "Exact hardware inventory is currently implemented for Linux hosts only."
                .to_string(),
        };
        Ok((inventory, collector, Vec::new()))
    }
}

async fn enrich_storage_with_smartctl(
    storage_devices: &mut [HardwareStorageDevice],
    storage_targets: &mut [(usize, String)],
    generated_at_unix: u64,
) -> (HardwareHealthCollectorStatus, Vec<HardwareHealthFinding>) {
    if storage_targets.is_empty() {
        return (
            HardwareHealthCollectorStatus {
                collector_id: "smartctl".to_string(),
                label: "SMART / NVMe".to_string(),
                state: "unavailable".to_string(),
                available: false,
                last_collected_at_unix: Some(generated_at_unix),
                last_error_code: Some("no_supported_block_devices".to_string()),
                detail: "No physical block devices were available for SMART enrichment."
                    .to_string(),
            },
            Vec::new(),
        );
    }

    let mut findings = Vec::new();
    let mut successful_devices = 0_usize;
    let mut last_error_code = None;

    for (index, device_path) in storage_targets.iter() {
        match run_smartctl_snapshot(device_path, &storage_devices[*index], generated_at_unix).await
        {
            Ok(Some(snapshot)) => {
                storage_devices[*index].smart = Some(snapshot.smart);
                findings.extend(snapshot.findings);
                successful_devices += 1;
            }
            Ok(None) => {}
            Err(err) => {
                last_error_code = Some(sanitize_error_code(&err.to_string()));
            }
        }
    }

    let state = if successful_devices == storage_targets.len() {
        "ready"
    } else if successful_devices > 0 {
        "degraded"
    } else {
        "unavailable"
    };

    (
        HardwareHealthCollectorStatus {
            collector_id: "smartctl".to_string(),
            label: "SMART / NVMe".to_string(),
            state: state.to_string(),
            available: successful_devices > 0,
            last_collected_at_unix: Some(generated_at_unix),
            last_error_code,
            detail: if successful_devices > 0 {
                format!(
                    "Collected SMART or NVMe lifecycle data from {successful_devices} of {} storage device{}.",
                    storage_targets.len(),
                    if storage_targets.len() == 1 { "" } else { "s" }
                )
            } else {
                "SMART enrichment is unavailable on this node.".to_string()
            },
        },
        findings,
    )
}

async fn run_smartctl_snapshot(
    device_path: &str,
    device: &HardwareStorageDevice,
    generated_at_unix: u64,
) -> Result<Option<SmartctlSnapshot>> {
    let output = match tokio::process::Command::new("smartctl")
        .arg("--json")
        .arg("-a")
        .arg(device_path)
        .output()
        .await
    {
        Ok(output) => output,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("failed running smartctl for {device_path}"));
        }
    };

    if output.stdout.is_empty() {
        return Ok(None);
    }
    let value: serde_json::Value = serde_json::from_slice(&output.stdout)
        .with_context(|| format!("failed parsing smartctl json for {device_path}"))?;

    let smart_passed = value
        .pointer("/smart_status/passed")
        .and_then(serde_json::Value::as_bool);
    let temperature_celsius = smart_temperature_celsius(&value);
    let power_on_hours = value
        .pointer("/power_on_time/hours")
        .and_then(serde_json::Value::as_u64);
    let power_cycle_count = value
        .get("power_cycle_count")
        .and_then(serde_json::Value::as_u64)
        .or_else(|| smart_attribute_value(&value, "Power_Cycle_Count"));
    let unsafe_shutdown_count = value
        .pointer("/nvme_smart_health_information_log/unsafe_shutdowns")
        .and_then(serde_json::Value::as_u64);
    let percentage_used = value
        .pointer("/nvme_smart_health_information_log/percentage_used")
        .and_then(serde_json::Value::as_u64);
    let available_spare_percent = value
        .pointer("/nvme_smart_health_information_log/available_spare")
        .and_then(serde_json::Value::as_u64);
    let available_spare_threshold_percent = value
        .pointer("/nvme_smart_health_information_log/available_spare_threshold")
        .and_then(serde_json::Value::as_u64);
    let data_units_read = value
        .pointer("/nvme_smart_health_information_log/data_units_read")
        .and_then(serde_json::Value::as_u64);
    let data_units_written = value
        .pointer("/nvme_smart_health_information_log/data_units_written")
        .and_then(serde_json::Value::as_u64);
    let media_errors = value
        .pointer("/nvme_smart_health_information_log/media_errors")
        .and_then(serde_json::Value::as_u64);
    let error_log_entries = value
        .pointer("/nvme_smart_health_information_log/num_err_log_entries")
        .and_then(serde_json::Value::as_u64);
    let reallocated_sector_count = smart_attribute_value(&value, "Reallocated_Sector_Ct");
    let pending_sector_count = smart_attribute_value(&value, "Current_Pending_Sector");
    let offline_uncorrectable_sector_count = smart_attribute_value(&value, "Offline_Uncorrectable");
    let crc_error_count = smart_attribute_value(&value, "UDMA_CRC_Error_Count");

    let smart = HardwareStorageSmartInfo {
        smart_available: true,
        smart_passed,
        temperature_celsius,
        power_on_hours,
        power_cycle_count,
        unsafe_shutdown_count,
        percentage_used,
        available_spare_percent,
        available_spare_threshold_percent,
        data_units_read,
        data_units_written,
        media_errors,
        error_log_entries,
        reallocated_sector_count,
        pending_sector_count,
        offline_uncorrectable_sector_count,
        crc_error_count,
    };

    let mut findings = Vec::new();
    if smart_passed == Some(false) {
        findings.push(storage_finding(
            device,
            generated_at_unix,
            "smart_overall_failed",
            "critical",
            "smart",
            "SMART reports that this storage device is failing.",
            json!({
                "device_path": device_path,
                "smart_passed": smart_passed,
            }),
        ));
    }
    if reallocated_sector_count.unwrap_or(0) > 0 {
        findings.push(storage_finding(
            device,
            generated_at_unix,
            "reallocated_sectors_present",
            "warn",
            "smart",
            "The storage device reports reallocated sectors.",
            json!({ "reallocated_sector_count": reallocated_sector_count }),
        ));
    }
    if pending_sector_count.unwrap_or(0) > 0 {
        findings.push(storage_finding(
            device,
            generated_at_unix,
            "pending_sectors_present",
            "warn",
            "smart",
            "The storage device reports pending sectors.",
            json!({ "pending_sector_count": pending_sector_count }),
        ));
    }
    if offline_uncorrectable_sector_count.unwrap_or(0) > 0 {
        findings.push(storage_finding(
            device,
            generated_at_unix,
            "uncorrectable_sectors_present",
            "critical",
            "smart",
            "The storage device reports offline uncorrectable sectors.",
            json!({ "offline_uncorrectable_sector_count": offline_uncorrectable_sector_count }),
        ));
    }
    if media_errors.unwrap_or(0) > 0 {
        findings.push(storage_finding(
            device,
            generated_at_unix,
            "nvme_media_errors_present",
            "warn",
            "smart",
            "The NVMe device reports media errors.",
            json!({ "media_errors": media_errors, "error_log_entries": error_log_entries }),
        ));
    }
    if let (Some(spare), Some(threshold)) =
        (available_spare_percent, available_spare_threshold_percent)
        && spare <= threshold
    {
        findings.push(storage_finding(
            device,
            generated_at_unix,
            "nvme_spare_below_threshold",
            "critical",
            "smart",
            "The NVMe available spare value is below its threshold.",
            json!({
                "available_spare_percent": spare,
                "available_spare_threshold_percent": threshold,
            }),
        ));
    }
    if percentage_used.unwrap_or(0) >= 90 {
        findings.push(storage_finding(
            device,
            generated_at_unix,
            "device_wear_high",
            if percentage_used.unwrap_or(0) >= 100 {
                "critical"
            } else {
                "warn"
            },
            "smart",
            "The storage device reports a high wear percentage.",
            json!({ "percentage_used": percentage_used }),
        ));
    }

    Ok(Some(SmartctlSnapshot { smart, findings }))
}

fn storage_finding(
    device: &HardwareStorageDevice,
    generated_at_unix: u64,
    finding_code: &str,
    severity: &str,
    source: &str,
    summary: &str,
    evidence: serde_json::Value,
) -> HardwareHealthFinding {
    HardwareHealthFinding {
        source: source.to_string(),
        category: "storage".to_string(),
        finding_code: finding_code.to_string(),
        severity: severity.to_string(),
        component_ref: Some(device.component_ref.clone()),
        component_instance_id: Some(device.component_instance_id.clone()),
        first_seen_at_unix: generated_at_unix,
        last_seen_at_unix: generated_at_unix,
        occurrence_count: 1,
        summary: summary.to_string(),
        evidence,
    }
}

fn empty_inventory() -> HardwareInventory {
    HardwareInventory {
        host_os: std::env::consts::OS.to_string(),
        architecture: std::env::consts::ARCH.to_string(),
        kernel_version: None,
        system: HardwareSystemInfo {
            vendor: None,
            product_name: None,
            product_version: None,
            board_vendor: None,
            board_name: None,
            board_version: None,
            bios_vendor: None,
            bios_version: None,
            bios_date: None,
        },
        cpu_packages: Vec::new(),
        memory: HardwareMemoryInfo {
            installed_bytes: 0,
            page_size_bytes: None,
            details_complete: false,
        },
        storage_devices: Vec::new(),
        network_interfaces: Vec::new(),
    }
}

#[cfg(target_os = "linux")]
fn collect_system_info_linux() -> HardwareSystemInfo {
    HardwareSystemInfo {
        vendor: read_trimmed_file("/sys/class/dmi/id/sys_vendor"),
        product_name: read_trimmed_file("/sys/class/dmi/id/product_name"),
        product_version: read_trimmed_file("/sys/class/dmi/id/product_version"),
        board_vendor: read_trimmed_file("/sys/class/dmi/id/board_vendor"),
        board_name: read_trimmed_file("/sys/class/dmi/id/board_name"),
        board_version: read_trimmed_file("/sys/class/dmi/id/board_version"),
        bios_vendor: read_trimmed_file("/sys/class/dmi/id/bios_vendor"),
        bios_version: read_trimmed_file("/sys/class/dmi/id/bios_version"),
        bios_date: read_trimmed_file("/sys/class/dmi/id/bios_date"),
    }
}

#[cfg(target_os = "linux")]
fn collect_cpu_packages_linux() -> Vec<HardwareCpuPackage> {
    let Some(raw) = read_trimmed_file("/proc/cpuinfo") else {
        return Vec::new();
    };

    let mut packages = BTreeMap::<String, CpuPackageSeed>::new();
    for block in raw.split("\n\n") {
        let mut fields = HashMap::<&str, &str>::new();
        for line in block.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            fields.insert(key.trim(), value.trim());
        }
        if fields.is_empty() {
            continue;
        }

        let package_key = fields
            .get("physical id")
            .copied()
            .unwrap_or("0")
            .to_string();
        let component_ref = format!("cpu:{package_key}");
        let stable_material = format!(
            "{}|{}|{}|{}",
            package_key,
            fields.get("vendor_id").copied().unwrap_or_default(),
            fields.get("model name").copied().unwrap_or_default(),
            fields.get("microcode").copied().unwrap_or_default(),
        );

        let seed = packages
            .entry(package_key)
            .or_insert_with(|| CpuPackageSeed {
                component_ref,
                stable_material,
                vendor_id: fields.get("vendor_id").map(|value| (*value).to_string()),
                model_name: fields.get("model name").map(|value| (*value).to_string()),
                family: fields.get("cpu family").map(|value| (*value).to_string()),
                model: fields.get("model").map(|value| (*value).to_string()),
                stepping: fields.get("stepping").map(|value| (*value).to_string()),
                microcode: fields.get("microcode").map(|value| (*value).to_string()),
                nominal_frequency_mhz: fields
                    .get("cpu MHz")
                    .and_then(|value| value.parse::<f64>().ok())
                    .map(|value| value.round() as u64),
                logical_cpu_count: 0,
                physical_core_count: fields
                    .get("cpu cores")
                    .and_then(|value| value.parse::<u32>().ok()),
            });
        seed.logical_cpu_count = seed.logical_cpu_count.saturating_add(1);
    }

    packages
        .into_values()
        .map(|seed| HardwareCpuPackage {
            component_ref: seed.component_ref,
            component_instance_id: stable_hash_id("cpu", &[seed.stable_material.as_str()]),
            lifecycle: HardwareComponentLifecycle {
                first_seen_at_unix: 0,
                last_seen_at_unix: 0,
                sighting_count: 0,
            },
            vendor_id: seed.vendor_id,
            model_name: seed.model_name,
            family: seed.family,
            model: seed.model,
            stepping: seed.stepping,
            microcode: seed.microcode,
            nominal_frequency_mhz: seed.nominal_frequency_mhz,
            logical_cpu_count: seed.logical_cpu_count,
            physical_core_count: seed.physical_core_count,
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn collect_memory_info_linux() -> HardwareMemoryInfo {
    let mut system = sysinfo::System::new_all();
    system.refresh_memory();
    HardwareMemoryInfo {
        installed_bytes: system.total_memory(),
        page_size_bytes: None,
        details_complete: false,
    }
}

#[cfg(target_os = "linux")]
fn collect_storage_devices_linux() -> (Vec<HardwareStorageDevice>, Vec<(usize, String)>) {
    let mut devices = Vec::new();
    let mut smart_targets = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/block") else {
        return (devices, smart_targets);
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if should_skip_block_device(&name) {
            continue;
        }

        let sys_path = entry.path();
        let device_path = format!("/dev/{name}");
        let canonical = fs::canonicalize(&sys_path).ok();
        let pci_slot = canonical.as_ref().and_then(|path| extract_pci_slot(path));
        let driver = read_symlink_file_name(sys_path.join("device/driver"));
        let vendor = read_trimmed_file(sys_path.join("device/vendor"));
        let model = read_trimmed_file(sys_path.join("device/model"))
            .or_else(|| read_trimmed_file(sys_path.join("device/device/model")));
        let firmware_version = read_trimmed_file(sys_path.join("device/rev"))
            .or_else(|| read_trimmed_file(sys_path.join("device/firmware_rev")));
        let capacity_bytes = read_trimmed_file(sys_path.join("size"))
            .and_then(|raw| raw.parse::<u64>().ok())
            .map(|sectors| sectors.saturating_mul(512));
        let logical_sector_size_bytes =
            read_trimmed_file(sys_path.join("queue/logical_block_size"))
                .and_then(|raw| raw.parse::<u64>().ok());
        let physical_sector_size_bytes =
            read_trimmed_file(sys_path.join("queue/physical_block_size"))
                .and_then(|raw| raw.parse::<u64>().ok());
        let is_rotational = read_trimmed_file(sys_path.join("queue/rotational")).and_then(|raw| {
            match raw.as_str() {
                "0" => Some(false),
                "1" => Some(true),
                _ => None,
            }
        });
        let interface_type = if name.starts_with("nvme") {
            "nvme".to_string()
        } else if is_rotational == Some(true) {
            "rotational_block".to_string()
        } else {
            "solid_state_block".to_string()
        };
        let bus_type = canonical
            .as_ref()
            .map(|path| path.display().to_string())
            .map(|path| {
                if path.contains("/nvme/") {
                    "nvme".to_string()
                } else if path.contains("/ata") {
                    "ata".to_string()
                } else if path.contains("/usb") {
                    "usb".to_string()
                } else if path.contains("/virtio") {
                    "virtio".to_string()
                } else if path.contains("/pci") {
                    "pci".to_string()
                } else {
                    "unknown".to_string()
                }
            });
        let serial_material = read_trimmed_file(sys_path.join("device/serial"))
            .or_else(|| read_nearby_serial(&sys_path));
        let stable_material = format!(
            "{}|{}|{}|{}|{}",
            name,
            vendor.clone().unwrap_or_default(),
            model.clone().unwrap_or_default(),
            firmware_version.clone().unwrap_or_default(),
            serial_material.unwrap_or_default(),
        );

        let index = devices.len();
        devices.push(HardwareStorageDevice {
            component_ref: format!("disk:{name}"),
            component_instance_id: stable_hash_id("storage", &[stable_material.as_str()]),
            lifecycle: HardwareComponentLifecycle {
                first_seen_at_unix: 0,
                last_seen_at_unix: 0,
                sighting_count: 0,
            },
            block_device_name: name.clone(),
            vendor,
            model,
            firmware_version,
            capacity_bytes,
            interface_type,
            bus_type,
            is_rotational,
            logical_sector_size_bytes,
            physical_sector_size_bytes,
            pci_slot,
            driver,
            smart: None,
        });
        smart_targets.push((index, device_path));
    }

    devices.sort_by(|left, right| left.block_device_name.cmp(&right.block_device_name));
    (devices, smart_targets)
}

#[cfg(target_os = "linux")]
fn collect_network_interfaces_linux() -> Vec<HardwareNetworkInterface> {
    let Ok(entries) = fs::read_dir("/sys/class/net") else {
        return Vec::new();
    };
    let mut interfaces = Vec::new();

    for entry in entries.flatten() {
        let interface_name = entry.file_name().to_string_lossy().into_owned();
        if interface_name == "lo" {
            continue;
        }
        let sys_path = entry.path();
        let device_link = sys_path.join("device");
        let canonical = fs::canonicalize(&device_link).ok();
        let pci_slot = canonical.as_ref().and_then(|path| extract_pci_slot(path));
        let stable_material = format!(
            "{}|{}|{}|{}",
            interface_name,
            pci_slot.clone().unwrap_or_default(),
            read_trimmed_file(device_link.join("vendor")).unwrap_or_default(),
            read_trimmed_file(device_link.join("device")).unwrap_or_default(),
        );

        interfaces.push(HardwareNetworkInterface {
            component_ref: format!("net:{interface_name}"),
            component_instance_id: stable_hash_id("net", &[stable_material.as_str()]),
            lifecycle: HardwareComponentLifecycle {
                first_seen_at_unix: 0,
                last_seen_at_unix: 0,
                sighting_count: 0,
            },
            interface_name: interface_name.clone(),
            oper_state: read_trimmed_file(sys_path.join("operstate")),
            carrier: read_trimmed_file(sys_path.join("carrier")).and_then(|raw| {
                match raw.as_str() {
                    "0" => Some(false),
                    "1" => Some(true),
                    _ => None,
                }
            }),
            speed_mbps: read_trimmed_file(sys_path.join("speed"))
                .and_then(|raw| raw.parse::<u64>().ok()),
            driver: read_symlink_file_name(device_link.join("driver")),
            pci_slot,
            vendor_id: read_trimmed_file(device_link.join("vendor")),
            device_id: read_trimmed_file(device_link.join("device")),
        });
    }

    interfaces.sort_by(|left, right| left.interface_name.cmp(&right.interface_name));
    interfaces
}

fn hardware_profile_id(inventory: &HardwareInventory) -> String {
    let value = json!({
        "host_os": inventory.host_os,
        "architecture": inventory.architecture,
        "kernel_version": inventory.kernel_version,
        "system": {
            "vendor": inventory.system.vendor,
            "product_name": inventory.system.product_name,
            "product_version": inventory.system.product_version,
            "board_vendor": inventory.system.board_vendor,
            "board_name": inventory.system.board_name,
            "board_version": inventory.system.board_version,
            "bios_vendor": inventory.system.bios_vendor,
            "bios_version": inventory.system.bios_version,
            "bios_date": inventory.system.bios_date,
        },
        "cpus": inventory.cpu_packages.iter().map(|cpu| json!({
            "vendor_id": cpu.vendor_id,
            "model_name": cpu.model_name,
            "family": cpu.family,
            "model": cpu.model,
            "stepping": cpu.stepping,
            "microcode": cpu.microcode,
            "nominal_frequency_mhz": cpu.nominal_frequency_mhz,
            "logical_cpu_count": cpu.logical_cpu_count,
            "physical_core_count": cpu.physical_core_count,
        })).collect::<Vec<_>>(),
        "memory": {
            "installed_bytes": inventory.memory.installed_bytes,
            "details_complete": inventory.memory.details_complete,
        },
        "storage_devices": inventory.storage_devices.iter().map(|device| json!({
            "block_device_name": device.block_device_name,
            "vendor": device.vendor,
            "model": device.model,
            "firmware_version": device.firmware_version,
            "capacity_bytes": device.capacity_bytes,
            "interface_type": device.interface_type,
            "bus_type": device.bus_type,
            "is_rotational": device.is_rotational,
            "logical_sector_size_bytes": device.logical_sector_size_bytes,
            "physical_sector_size_bytes": device.physical_sector_size_bytes,
            "pci_slot": device.pci_slot,
            "driver": device.driver,
        })).collect::<Vec<_>>(),
        "network_interfaces": inventory.network_interfaces.iter().map(|iface| json!({
            "interface_name": iface.interface_name,
            "speed_mbps": iface.speed_mbps,
            "driver": iface.driver,
            "pci_slot": iface.pci_slot,
            "vendor_id": iface.vendor_id,
            "device_id": iface.device_id,
        })).collect::<Vec<_>>(),
    });
    let payload = value.to_string();
    stable_hash_id("profile", &[payload.as_str()])
}

fn build_health_notes(
    inventory: &HardwareInventory,
    lifecycle: &HardwareNodeLifecycle,
    findings: &[HardwareHealthFinding],
) -> Vec<String> {
    let mut notes = Vec::new();
    notes.push(format!(
        "The current hardware inventory reports {} storage device{}, {} CPU package{}, and {} network interface{}.",
        inventory.storage_devices.len(),
        if inventory.storage_devices.len() == 1 { "" } else { "s" },
        inventory.cpu_packages.len(),
        if inventory.cpu_packages.len() == 1 { "" } else { "s" },
        inventory.network_interfaces.len(),
        if inventory.network_interfaces.len() == 1 { "" } else { "s" },
    ));

    if let Some(uptime_seconds) = lifecycle.uptime_seconds {
        notes.push(format!(
            "This node has been observed since {} and the current boot has been up for {} seconds.",
            lifecycle.node_first_seen_at_unix, uptime_seconds
        ));
    }

    if lifecycle.inventory_last_changed_at_unix == lifecycle.node_first_seen_at_unix {
        notes.push(
            "The hardware inventory has remained stable since the node was first observed."
                .to_string(),
        );
    } else {
        notes.push(format!(
            "The normalized hardware inventory most recently changed at {}.",
            lifecycle.inventory_last_changed_at_unix
        ));
    }

    for finding in findings.iter().take(5) {
        notes.push(finding.summary.clone());
    }

    if notes.is_empty() {
        notes.push("No hardware health notes are available yet.".to_string());
    }
    notes
}

fn scrub_issue_severity(issue_kind: &str) -> &'static str {
    match issue_kind {
        "chunk_hash_mismatch" | "manifest_hash_mismatch" | "manifest_invalid" => "critical",
        "chunk_unreadable" | "manifest_unreadable" | "chunk_missing" | "manifest_missing" => "warn",
        _ => "info",
    }
}

fn scrub_issue_code<T: Serialize>(issue_kind: &T) -> String {
    serde_json::to_value(issue_kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown_issue".to_string())
}

fn severity_rank(severity: &str) -> u8 {
    match severity {
        "critical" => 0,
        "warn" => 1,
        _ => 2,
    }
}

fn sanitize_error_code(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if lower.contains("not found") || lower.contains("no such file") {
        "not_found".to_string()
    } else if lower.contains("permission denied") {
        "permission_denied".to_string()
    } else if lower.contains("timed out") || lower.contains("timeout") {
        "timeout".to_string()
    } else if lower.contains("input/output error") || lower.contains("i/o error") {
        "io_error".to_string()
    } else if lower.contains("parse") || lower.contains("json") {
        "parse_error".to_string()
    } else if lower.contains("unsupported") {
        "unsupported".to_string()
    } else if lower.contains("connection refused") {
        "connection_refused".to_string()
    } else {
        "unknown".to_string()
    }
}

fn stable_hash_id(namespace: &str, parts: &[&str]) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(namespace.as_bytes());
    hasher.update(&[0xff]);
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update(&[0x00]);
    }
    hasher.finalize().to_hex().to_string()
}

#[cfg(target_os = "linux")]
fn read_nearby_serial(sys_block_path: &FsPath) -> Option<String> {
    let canonical = fs::canonicalize(sys_block_path).ok()?;
    for ancestor in canonical.ancestors().take(6) {
        let serial_path = ancestor.join("serial");
        if let Some(serial) = read_trimmed_file(&serial_path) {
            return Some(serial);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_symlink_file_name(path: impl AsRef<FsPath>) -> Option<String> {
    fs::read_link(path).ok().and_then(|path| {
        path.file_name()
            .map(|value| value.to_string_lossy().into_owned())
    })
}

#[cfg(target_os = "linux")]
fn read_trimmed_file(path: impl AsRef<FsPath>) -> Option<String> {
    let raw = fs::read_to_string(path).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(target_os = "linux")]
fn extract_pci_slot(path: &FsPath) -> Option<String> {
    path.components().find_map(|component| {
        let value = component.as_os_str().to_string_lossy();
        let bytes = value.as_bytes();
        if bytes.len() == 12 && bytes[4] == b':' && bytes[7] == b':' && bytes[10] == b'.' {
            Some(value.to_string())
        } else {
            None
        }
    })
}

#[cfg(target_os = "linux")]
fn should_skip_block_device(name: &str) -> bool {
    matches!(
        name,
        value
            if value.starts_with("loop")
                || value.starts_with("ram")
                || value.starts_with("zram")
                || value.starts_with("fd")
                || value.starts_with("dm-")
                || value.starts_with("md")
    )
}

fn current_boot_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        read_trimmed_file("/proc/sys/kernel/random/boot_id")
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn current_uptime_seconds() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        read_trimmed_file("/proc/uptime")
            .and_then(|raw| raw.split_whitespace().next().map(str::to_string))
            .and_then(|raw| raw.parse::<f64>().ok())
            .map(|value| value.floor() as u64)
    }

    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

fn smart_attribute_value(value: &serde_json::Value, attribute_name: &str) -> Option<u64> {
    let table = value.pointer("/ata_smart_attributes/table")?.as_array()?;
    for entry in table {
        if entry.get("name").and_then(serde_json::Value::as_str) == Some(attribute_name) {
            if let Some(raw) = entry
                .pointer("/raw/value")
                .and_then(serde_json::Value::as_u64)
            {
                return Some(raw);
            }
            if let Some(raw) = entry
                .pointer("/raw/string")
                .and_then(serde_json::Value::as_str)
            {
                let digits = raw
                    .chars()
                    .take_while(|char| char.is_ascii_digit())
                    .collect::<String>();
                if let Ok(parsed) = digits.parse::<u64>() {
                    return Some(parsed);
                }
            }
        }
    }
    None
}

fn smart_temperature_celsius(value: &serde_json::Value) -> Option<f32> {
    if let Some(current) = value
        .pointer("/temperature/current")
        .and_then(serde_json::Value::as_f64)
    {
        return Some(current as f32);
    }
    if let Some(current) = value
        .pointer("/nvme_smart_health_information_log/temperature")
        .and_then(serde_json::Value::as_f64)
    {
        return Some(if current > 200.0 {
            (current - 273.15) as f32
        } else {
            current as f32
        });
    }
    smart_attribute_value(value, "Temperature_Celsius").map(|value| value as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_error_code_classifies_common_errors() {
        assert_eq!(
            sanitize_error_code("permission denied opening file"),
            "permission_denied"
        );
        assert_eq!(sanitize_error_code("request timed out"), "timeout");
        assert_eq!(sanitize_error_code("database parse failed"), "parse_error");
    }

    #[test]
    fn update_persisted_uptime_accumulates_per_boot() {
        let mut persisted = PersistedHardwareHealthState::default();
        update_persisted_uptime(&mut persisted, Some("boot-a"), Some(10));
        update_persisted_uptime(&mut persisted, Some("boot-a"), Some(15));
        update_persisted_uptime(&mut persisted, Some("boot-b"), Some(4));
        assert_eq!(persisted.cumulative_observed_uptime_seconds, 19);
        assert_eq!(persisted.last_boot_id.as_deref(), Some("boot-b"));
        assert_eq!(persisted.last_observed_uptime_seconds, 4);
    }

    #[test]
    fn smart_temperature_handles_kelvin_and_celsius_layouts() {
        assert_eq!(
            smart_temperature_celsius(&json!({ "temperature": { "current": 41.0 } })),
            Some(41.0)
        );
        assert_eq!(
            smart_temperature_celsius(
                &json!({ "nvme_smart_health_information_log": { "temperature": 300.15 } })
            )
            .map(|value| value.round() as i32),
            Some(27)
        );
    }
}
