use super::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::fs;

type HmacSha256 = Hmac<Sha256>;

const RELIABILITY_TELEMETRY_STATE_FILE: &str = "telemetry/reliability-telemetry-state.json";
const TELEMETRY_SCHEMA_VERSION: u32 = 1;
const TELEMETRY_HMAC_DOMAIN: &[u8] = b"ironmesh-telemetry-v1";

/// The reduced, pseudonymized payload that would be sent to the central fleet
/// reliability collector (see `docs/server-node-hardware-reliability-telemetry-strategy.md`,
/// Section 7). This slice does not implement outbound sending; it only builds and exposes
/// exactly this payload via a preview endpoint.
///
/// Every field here is an explicit allow-listed projection of `hardware_health::HardwareHealthReport`.
/// There is deliberately no `#[serde(flatten)]` or raw passthrough of any node-local struct, so
/// that fields added to `hardware_health.rs` in the future do not silently leak into this payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReliabilityTelemetryPayload {
    schema_version: u32,
    telemetry_subject_id: String,
    generated_at_unix: u64,
    ironmesh_version: String,
    hardware_profile_id: String,
    // `country_code` is intentionally not a field here: per doc Section 4.2 it is derived
    // server-side (central collector) from the TCP source IP of the ingest request, and is
    // never computed or sent by the node itself.
    node_lifecycle: TelemetryNodeLifecycle,
    storage_devices: Vec<TelemetryStorageDevice>,
    memory_ecc: TelemetryMemoryEcc,
    reliability_findings_summary: Vec<TelemetryFindingSummary>,
    collectors: Vec<TelemetryCollectorStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TelemetryNodeLifecycle {
    uptime_seconds: Option<u64>,
    cumulative_observed_uptime_seconds: u64,
    // `boot_count_observed` from the doc Section 7 sketch is deliberately omitted: the node
    // currently only tracks a single `boot_id` string per current boot
    // (`hardware_health::HardwareNodeLifecycle::boot_id`), not a persisted count of distinct
    // boots observed over time. Deriving a real count would require a new persisted counter
    // incremented on `boot_id` change - out of scope for this slice, left for a follow-up.
}

/// Allow-listed projection of `hardware_health::HardwareStorageDevice`. Deliberately excludes
/// `component_ref` (human-readable device path alias), `block_device_name`, `vendor`, `model`,
/// `firmware_version`, `pci_slot`, `driver`, and raw serial material - none of those are copied
/// here, by construction, per doc Section 2.6.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TelemetryStorageDevice {
    component_instance_id: String,
    is_rotational: Option<bool>,
    interface_type: String,
    smart: Option<TelemetryStorageSmart>,
}

/// Allow-listed projection of `hardware_health::HardwareStorageSmartInfo` - only the five SMART
/// fields sketched in doc Section 7, not the full SMART struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TelemetryStorageSmart {
    smart_passed: Option<bool>,
    power_on_hours: Option<u64>,
    reallocated_sector_count: Option<u64>,
    media_errors: Option<u64>,
    percentage_used: Option<u64>,
}

/// The node does not collect real EDAC/ECC data yet. This is always emitted with
/// `available: false` for now; real EDAC collection (reading
/// `/sys/devices/system/edac/mc/mc*/{ce_count,ue_count}`) is a separate follow-up slice
/// (doc Section 2.4), not attempted here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TelemetryMemoryEcc {
    available: bool,
    correctable_error_count: Option<u64>,
    uncorrectable_error_count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TelemetryFindingSummary {
    finding_code: String,
    occurrence_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TelemetryCollectorStatus {
    collector_id: String,
    available: bool,
}

/// Pure converter: derives the reduced, pseudonymized telemetry payload from the existing
/// node-local `hardware_health_report`. Per doc "Open Questions" recommendation, this stays a
/// one-way projection of the existing report rather than a second independent collector, so the
/// node-local and centrally-sent views cannot drift apart.
pub(crate) fn build_reliability_telemetry_payload(
    report: &hardware_health::HardwareHealthReport,
    telemetry_subject_id: String,
    generated_at_unix: u64,
) -> ReliabilityTelemetryPayload {
    let storage_devices = report
        .inventory
        .storage_devices
        .iter()
        .map(|device| TelemetryStorageDevice {
            component_instance_id: device.component_instance_id.clone(),
            is_rotational: device.is_rotational,
            interface_type: device.interface_type.clone(),
            smart: device.smart.as_ref().map(|smart| TelemetryStorageSmart {
                smart_passed: smart.smart_passed,
                power_on_hours: smart.power_on_hours,
                reallocated_sector_count: smart.reallocated_sector_count,
                media_errors: smart.media_errors,
                percentage_used: smart.percentage_used,
            }),
        })
        .collect();

    let mut finding_counts: BTreeMap<String, u64> = BTreeMap::new();
    for finding in &report.findings {
        *finding_counts
            .entry(finding.finding_code.clone())
            .or_default() += finding.occurrence_count;
    }
    let reliability_findings_summary = finding_counts
        .into_iter()
        .map(|(finding_code, occurrence_count)| TelemetryFindingSummary {
            finding_code,
            occurrence_count,
        })
        .collect();

    let mut collectors: Vec<TelemetryCollectorStatus> = report
        .collectors
        .iter()
        .map(|collector| TelemetryCollectorStatus {
            collector_id: collector.collector_id.clone(),
            available: collector.available,
        })
        .collect();
    // EDAC is not implemented as a `hardware_health` collector at all yet, so it never shows
    // up in `report.collectors`. Report it explicitly as a known-but-unavailable collector
    // (rather than omitting it) so the central collector can distinguish "not yet supported"
    // from "silently missing", consistent with the tolerance-first convention in doc Section 7.
    collectors.push(TelemetryCollectorStatus {
        collector_id: "edac".to_string(),
        available: false,
    });

    ReliabilityTelemetryPayload {
        schema_version: TELEMETRY_SCHEMA_VERSION,
        telemetry_subject_id,
        generated_at_unix,
        ironmesh_version: report.ironmesh_version.clone(),
        hardware_profile_id: report.hardware_profile_id.clone(),
        node_lifecycle: TelemetryNodeLifecycle {
            uptime_seconds: report.node_lifecycle.uptime_seconds,
            cumulative_observed_uptime_seconds: report
                .node_lifecycle
                .cumulative_observed_uptime_seconds,
        },
        storage_devices,
        memory_ecc: TelemetryMemoryEcc {
            available: false,
            correctable_error_count: None,
            uncorrectable_error_count: None,
        },
        reliability_findings_summary,
        collectors,
    }
}

fn compute_telemetry_subject_id(local_random_salt: &[u8], node_id: NodeId) -> String {
    let mut mac =
        HmacSha256::new_from_slice(local_random_salt).expect("HMAC accepts arbitrary key sizes");
    mac.update(TELEMETRY_HMAC_DOMAIN);
    mac.update(node_id.as_bytes());
    hex_encode(&mac.finalize().into_bytes())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}

/// env var opt-out toggle, in the exact style already used for
/// `IRONMESH_AUTONOMOUS_HEARTBEAT_ENABLED` and specified verbatim in doc Section 3.1. This does
/// not reuse the crate's `env_flag_or` helper: that helper treats any non-truthy value
/// (including unset) as `false`-leaning, whereas this toggle must default to *enabled* unless
/// explicitly disabled with `"0"`/`"false"`/`"no"` - a different (inverted-default) semantic.
fn reliability_telemetry_env_enabled() -> bool {
    parse_reliability_telemetry_env_flag(
        std::env::var("IRONMESH_RELIABILITY_TELEMETRY_ENABLED").ok(),
    )
}

/// Pulled out from `reliability_telemetry_env_enabled` so tests can exercise the parsing rules
/// directly instead of mutating the real process environment (this crate denies `unsafe_code`,
/// and `std::env::set_var`/`remove_var` are `unsafe` as of the 2024 edition).
fn parse_reliability_telemetry_env_flag(value: Option<String>) -> bool {
    value
        .map(|v| !matches!(v.as_str(), "0" | "false" | "no"))
        .unwrap_or(true)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PersistedReliabilityTelemetryState {
    /// Base64-encoded local random salt used to derive `telemetry_subject_id`
    /// (doc Section 4.1). Generated once, the first time it's needed, and never transmitted or
    /// exposed via any API response.
    local_random_salt_b64: Option<String>,
    /// `None` means "no override yet - use the env var default". `Some(_)` means an operator
    /// has explicitly set the toggle via the admin API/UI, which takes precedence over the env
    /// var going forward.
    enabled_override: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ReliabilityTelemetryRuntime {
    state_path: PathBuf,
    persisted: PersistedReliabilityTelemetryState,
}

impl ReliabilityTelemetryRuntime {
    /// Mirrors `hardware_health::HardwareHealthRuntime::load`'s load-with-graceful-fallback
    /// idiom: a missing or unparseable state file starts fresh rather than failing startup.
    pub(crate) fn load(data_dir: &FsPath) -> Self {
        let state_path = data_dir.join(RELIABILITY_TELEMETRY_STATE_FILE);
        let persisted = match fs::read_to_string(&state_path) {
            Ok(raw) => match serde_json::from_str::<PersistedReliabilityTelemetryState>(&raw) {
                Ok(parsed) => parsed,
                Err(err) => {
                    warn!(
                        error = %err,
                        path = %state_path.display(),
                        "failed to parse persisted reliability-telemetry state; starting fresh"
                    );
                    PersistedReliabilityTelemetryState::default()
                }
            },
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                PersistedReliabilityTelemetryState::default()
            }
            Err(err) => {
                warn!(
                    error = %err,
                    path = %state_path.display(),
                    "failed to load persisted reliability-telemetry state; starting fresh"
                );
                PersistedReliabilityTelemetryState::default()
            }
        };

        Self {
            state_path,
            persisted,
        }
    }

    /// Effective enabled state: the persisted admin override if set, else the env var default.
    pub(crate) fn effective_enabled(&self) -> bool {
        self.persisted
            .enabled_override
            .unwrap_or_else(reliability_telemetry_env_enabled)
    }

    pub(crate) fn enabled_source(&self) -> &'static str {
        if self.persisted.enabled_override.is_some() {
            "override"
        } else {
            "env"
        }
    }

    /// Persists (or sets to `None`, reverting to the env var default) an explicit admin
    /// override for the enabled toggle.
    pub(crate) async fn set_enabled_override(&mut self, enabled: Option<bool>) -> Result<()> {
        self.persisted.enabled_override = enabled;
        self.persist().await
    }

    /// Derives the stable `telemetry_subject_id` for this node, generating and persisting the
    /// local random salt on first use if one does not exist yet.
    pub(crate) async fn telemetry_subject_id(&mut self, node_id: NodeId) -> Result<String> {
        let salt = self.ensure_salt().await?;
        Ok(compute_telemetry_subject_id(&salt, node_id))
    }

    async fn ensure_salt(&mut self) -> Result<Vec<u8>> {
        if let Some(existing) = self.persisted.local_random_salt_b64.as_deref()
            && let Ok(bytes) = BASE64_STANDARD.decode(existing)
        {
            return Ok(bytes);
        }

        let mut salt = vec![0_u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);
        self.persisted.local_random_salt_b64 = Some(BASE64_STANDARD.encode(&salt));
        self.persist().await?;
        Ok(salt)
    }

    async fn persist(&self) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(&self.persisted)
            .context("failed to serialize persisted reliability-telemetry state")?;
        write_json_atomic(&self.state_path, &bytes).await
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct TelemetrySettingsResponse {
    enabled: bool,
    telemetry_subject_id: String,
    source: &'static str,
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct UpdateTelemetrySettingsRequest {
    enabled: bool,
}

pub(crate) async fn telemetry_settings_get(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let action = "auth/telemetry/settings/get";
    let authz = match authorize_admin_request(&state, &headers, action, true, true, json!({})).await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let mut runtime = state.reliability_telemetry_runtime.lock().await;
    let enabled = runtime.effective_enabled();
    let source = runtime.enabled_source();
    let telemetry_subject_id = match runtime.telemetry_subject_id(state.node_id).await {
        Ok(id) => id,
        Err(err) => {
            warn!(error = %err, "failed to derive telemetry subject id");
            drop(runtime);
            append_admin_audit(&state, action, &authz, true, true, true, "error", json!({})).await;
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    drop(runtime);

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({ "enabled": enabled, "source": source }),
    )
    .await;

    (
        StatusCode::OK,
        Json(TelemetrySettingsResponse {
            enabled,
            telemetry_subject_id,
            source,
        }),
    )
        .into_response()
}

pub(crate) async fn telemetry_settings_put(
    State(state): State<ServerState>,
    headers: HeaderMap,
    Json(request): Json<UpdateTelemetrySettingsRequest>,
) -> impl IntoResponse {
    let action = "auth/telemetry/settings/update";
    let authz = match authorize_admin_request(
        &state,
        &headers,
        action,
        false,
        true,
        json!({ "enabled": request.enabled }),
    )
    .await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let mut runtime = state.reliability_telemetry_runtime.lock().await;
    if let Err(err) = runtime.set_enabled_override(Some(request.enabled)).await {
        warn!(error = %err, "failed to persist reliability telemetry settings");
        drop(runtime);
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            false,
            true,
            "error",
            json!({}),
        )
        .await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let enabled = runtime.effective_enabled();
    let source = runtime.enabled_source();
    let telemetry_subject_id = match runtime.telemetry_subject_id(state.node_id).await {
        Ok(id) => id,
        Err(err) => {
            warn!(error = %err, "failed to derive telemetry subject id");
            drop(runtime);
            append_admin_audit(
                &state,
                action,
                &authz,
                true,
                false,
                true,
                "error",
                json!({}),
            )
            .await;
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    drop(runtime);

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        false,
        true,
        "success",
        json!({ "enabled": enabled, "source": source }),
    )
    .await;

    (
        StatusCode::OK,
        Json(TelemetrySettingsResponse {
            enabled,
            telemetry_subject_id,
            source,
        }),
    )
        .into_response()
}

pub(crate) async fn telemetry_preview_get(
    State(state): State<ServerState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let action = "auth/telemetry/preview/get";
    let authz = match authorize_admin_request(&state, &headers, action, true, true, json!({})).await
    {
        Ok(request) => request,
        Err(status) => return status.into_response(),
    };

    let report = {
        let hw_runtime = state.hardware_health_runtime.lock().await;
        hw_runtime.report.clone()
    };
    let Some(report) = report else {
        append_admin_audit(
            &state,
            action,
            &authz,
            true,
            true,
            true,
            "no_report_yet",
            json!({}),
        )
        .await;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({
                "error": "the hardware health report has not been collected yet; retry shortly",
            })),
        )
            .into_response();
    };

    let mut runtime = state.reliability_telemetry_runtime.lock().await;
    let telemetry_subject_id = match runtime.telemetry_subject_id(state.node_id).await {
        Ok(id) => id,
        Err(err) => {
            warn!(error = %err, "failed to derive telemetry subject id");
            drop(runtime);
            append_admin_audit(&state, action, &authz, true, true, true, "error", json!({})).await;
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    drop(runtime);

    let payload = build_reliability_telemetry_payload(&report, telemetry_subject_id, unix_ts());

    append_admin_audit(
        &state,
        action,
        &authz,
        true,
        true,
        true,
        "success",
        json!({
            "storage_devices": payload.storage_devices.len(),
            "reliability_findings_summary": payload.reliability_findings_summary.len(),
        }),
    )
    .await;

    (StatusCode::OK, Json(payload)).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn telemetry_subject_id_is_deterministic_for_the_same_salt_and_node_id() {
        let node_id = NodeId::from_u128(42);
        let salt = b"fixed-salt-for-test".to_vec();

        let first = compute_telemetry_subject_id(&salt, node_id);
        let second = compute_telemetry_subject_id(&salt, node_id);
        assert_eq!(first, second);
        assert_eq!(
            first.len(),
            64,
            "hex-encoded SHA-256 HMAC should be 64 chars"
        );
    }

    #[test]
    fn telemetry_subject_id_differs_for_different_salts() {
        let node_id = NodeId::from_u128(42);
        let a = compute_telemetry_subject_id(b"salt-a", node_id);
        let b = compute_telemetry_subject_id(b"salt-b", node_id);
        assert_ne!(a, b);
    }

    #[test]
    fn telemetry_subject_id_differs_for_different_node_ids() {
        let salt = b"same-salt".to_vec();
        let a = compute_telemetry_subject_id(&salt, NodeId::from_u128(1));
        let b = compute_telemetry_subject_id(&salt, NodeId::from_u128(2));
        assert_ne!(a, b);
    }

    #[test]
    fn env_enabled_defaults_to_true_when_unset() {
        assert!(parse_reliability_telemetry_env_flag(None));
    }

    #[test]
    fn env_enabled_treats_falsey_strings_as_disabled() {
        for value in ["0", "false", "no"] {
            assert!(
                !parse_reliability_telemetry_env_flag(Some(value.to_string())),
                "expected {value} to disable telemetry"
            );
        }
    }

    #[test]
    fn env_enabled_treats_other_strings_as_enabled() {
        assert!(parse_reliability_telemetry_env_flag(Some("1".to_string())));
        assert!(parse_reliability_telemetry_env_flag(Some(
            "anything-else".to_string()
        )));
    }

    #[tokio::test]
    async fn persisted_state_round_trips_through_load_and_save() {
        let tmp = std::env::temp_dir().join(format!(
            "ironmesh-reliability-telemetry-test-{}",
            Uuid::new_v4()
        ));
        tokio::fs::create_dir_all(&tmp).await.unwrap();

        let mut runtime = ReliabilityTelemetryRuntime::load(&tmp);
        assert!(runtime.persisted.local_random_salt_b64.is_none());
        assert_eq!(runtime.enabled_source(), "env");

        let node_id = NodeId::from_u128(7);
        let subject_id_first = runtime.telemetry_subject_id(node_id).await.unwrap();
        runtime.set_enabled_override(Some(false)).await.unwrap();

        // Reload from disk and confirm both the salt (and thus subject id) and the override
        // survive a restart.
        let mut reloaded = ReliabilityTelemetryRuntime::load(&tmp);
        assert_eq!(reloaded.enabled_source(), "override");
        assert!(!reloaded.effective_enabled());
        let subject_id_second = reloaded.telemetry_subject_id(node_id).await.unwrap();
        assert_eq!(subject_id_first, subject_id_second);

        let _ = tokio::fs::remove_dir_all(&tmp).await;
    }

    #[test]
    fn converter_produces_only_allow_listed_storage_fields_and_aggregates_findings() {
        let report = hardware_health::test_support::sample_report_for_telemetry_tests();

        let payload = build_reliability_telemetry_payload(
            &report,
            "test-subject-id".to_string(),
            1_700_000_000,
        );

        assert_eq!(payload.schema_version, 1);
        assert_eq!(payload.telemetry_subject_id, "test-subject-id");
        assert_eq!(payload.generated_at_unix, 1_700_000_000);

        assert_eq!(payload.storage_devices.len(), 1);
        let device = &payload.storage_devices[0];
        assert_eq!(device.interface_type, "nvme");
        assert_eq!(device.is_rotational, Some(false));
        let smart = device.smart.as_ref().expect("smart data expected");
        assert_eq!(smart.power_on_hours, Some(1234));
        assert_eq!(smart.reallocated_sector_count, Some(0));

        // Data-minimization: serialize and confirm no disallowed keys or raw identifiers leak
        // through, since a future field added to HardwareStorageDevice must not silently widen
        // the payload.
        let serialized = serde_json::to_value(&payload).unwrap();
        let device_json = &serialized["storage_devices"][0];
        let mut keys: Vec<&str> = device_json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            vec![
                "component_instance_id",
                "interface_type",
                "is_rotational",
                "smart",
            ]
        );
        assert!(serialized.to_string().contains("component_instance_id"));
        assert!(!serialized.to_string().contains("component_ref"));
        assert!(!serialized.to_string().contains("block_device_name"));
        assert!(!serialized.to_string().contains("serial"));

        // Findings from two different sightings of the same finding_code must be summed, not
        // duplicated as separate entries.
        assert_eq!(payload.reliability_findings_summary.len(), 2);
        let chunk_mismatch = payload
            .reliability_findings_summary
            .iter()
            .find(|entry| entry.finding_code == "chunk_hash_mismatch")
            .expect("expected chunk_hash_mismatch summary entry");
        assert_eq!(chunk_mismatch.occurrence_count, 5);

        assert!(!payload.memory_ecc.available);
        assert!(
            payload
                .collectors
                .iter()
                .any(|collector| collector.collector_id == "edac" && !collector.available)
        );
    }
}
