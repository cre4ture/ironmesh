use super::*;
use std::collections::BTreeSet;
use storage::{ReplicationExportBundle, TOMBSTONE_MANIFEST_HASH};

const REPAIR_PROGRESS_CHUNK_LOG_INTERVAL: usize = 128;
const MAX_REPAIR_REPORT_LOG_ENTRIES: usize = 2_048;
const MAX_REPAIR_REPORT_SKIPPED_DETAILS: usize = 2_048;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReplicationRepairReport {
    pub(crate) attempted_transfers: usize,
    pub(crate) successful_transfers: usize,
    pub(crate) failed_transfers: usize,
    pub(crate) skipped_items: usize,
    pub(crate) skipped_backoff: usize,
    pub(crate) skipped_max_retries: usize,
    #[serde(default)]
    pub(crate) skipped_details: Vec<ReplicationRepairSkippedItem>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub(crate) detailed_log: Vec<ReplicationRepairLogEntry>,
    pub(crate) last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReplicationRepairLogEntry {
    pub(crate) captured_at_unix: u64,
    pub(crate) report_node_id: NodeId,
    pub(crate) event: String,
    pub(crate) detail: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) subject: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) version_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) source_node_id: Option<NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) target_node_id: Option<NodeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) context: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReplicationRepairSkipReason {
    InvalidSubject,
    SourceNodeUnavailable,
    BundleUnavailable,
    BackoffActive,
    MaxRetriesExhausted,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReplicationRepairSkippedItem {
    pub(crate) report_node_id: NodeId,
    pub(crate) subject: String,
    pub(crate) key: Option<String>,
    pub(crate) version_id: Option<String>,
    pub(crate) source_node_id: Option<NodeId>,
    pub(crate) target_node_id: Option<NodeId>,
    pub(crate) reason: ReplicationRepairSkipReason,
    pub(crate) detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ReplicationRepairScope {
    #[default]
    Local,
    Cluster,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClusterReplicationRepairNodeReport {
    pub(crate) node_id: NodeId,
    pub(crate) attempted_transfers: usize,
    pub(crate) successful_transfers: usize,
    pub(crate) failed_transfers: usize,
    pub(crate) skipped_items: usize,
    pub(crate) skipped_backoff: usize,
    pub(crate) skipped_max_retries: usize,
    pub(crate) skipped_details: Vec<ReplicationRepairSkippedItem>,
    pub(crate) last_error: Option<String>,
    pub(crate) request_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClusterReplicationRepairReport {
    #[serde(flatten)]
    pub(crate) totals: ReplicationRepairReport,
    pub(crate) scope: ReplicationRepairScope,
    pub(crate) nodes_contacted: usize,
    pub(crate) failed_nodes: usize,
    pub(crate) node_reports: Vec<ClusterReplicationRepairNodeReport>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReplicationRepairQuery {
    batch_size: Option<usize>,
    scope: Option<ReplicationRepairScope>,
}

async fn execute_replication_repair_with_trigger(
    State(state): State<ServerState>,
    Query(query): Query<ReplicationRepairQuery>,
    trigger: RepairRunTrigger,
    force_local_scope: bool,
) -> impl IntoResponse {
    let batch_override = query.batch_size.filter(|v| *v > 0);
    let scope = if force_local_scope {
        ReplicationRepairScope::Local
    } else {
        query.scope.unwrap_or_default()
    };

    match scope {
        ReplicationRepairScope::Local => {
            let report =
                execute_tracked_local_replication_repair(&state, batch_override, trigger, None)
                    .await;
            (StatusCode::OK, Json(report)).into_response()
        }
        ReplicationRepairScope::Cluster => {
            let report =
                execute_tracked_cluster_replication_repair(&state, batch_override, trigger, None)
                    .await;
            (StatusCode::OK, Json(report)).into_response()
        }
    }
}

pub(crate) async fn execute_replication_repair_public(
    State(state): State<ServerState>,
    headers: HeaderMap,
    query: Query<ReplicationRepairQuery>,
) -> impl IntoResponse {
    if let Err(status) = authorize_admin_request(
        &state,
        &headers,
        "replication_repair",
        false,
        true,
        json!({}),
    )
    .await
    {
        return status.into_response();
    }
    execute_replication_repair_with_trigger(
        State(state),
        query,
        RepairRunTrigger::ManualRequest,
        false,
    )
    .await
    .into_response()
}

pub(crate) async fn execute_replication_repair_peer(
    state: State<ServerState>,
    query: Query<ReplicationRepairQuery>,
) -> impl IntoResponse {
    execute_replication_repair_with_trigger(
        state,
        query,
        RepairRunTrigger::PeerClusterRequest,
        false,
    )
    .await
}

pub(crate) async fn execute_replication_repair_inner(
    state: &ServerState,
    batch_size_override: Option<usize>,
) -> ReplicationRepairReport {
    execute_replication_repair_inner_with_context(state, batch_size_override, None).await
}

pub(crate) async fn execute_replication_repair_inner_with_context(
    state: &ServerState,
    batch_size_override: Option<usize>,
    run_id: Option<&str>,
) -> ReplicationRepairReport {
    sync_availability_views_once(state).await;
    let keys = planning_replication_subjects(state).await;

    let (plan, nodes) = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();
        (cluster.replication_plan(&keys), cluster.list_nodes())
    };

    execute_replication_repair_plan(state, plan, nodes, batch_size_override, false, run_id).await
}

#[allow(dead_code)]
pub(crate) async fn execute_planned_targeted_replication_repair_inner(
    state: &ServerState,
    subjects: Vec<String>,
    batch_size_override: Option<usize>,
) -> (ReplicationPlan, ReplicationRepairReport) {
    execute_planned_targeted_replication_repair_inner_with_context(
        state,
        subjects,
        batch_size_override,
        None,
    )
    .await
}

pub(crate) async fn execute_planned_targeted_replication_repair_inner_with_context(
    state: &ServerState,
    subjects: Vec<String>,
    batch_size_override: Option<usize>,
    run_id: Option<&str>,
) -> (ReplicationPlan, ReplicationRepairReport) {
    let mut subjects = subjects
        .into_iter()
        .filter(|subject| !subject.trim().is_empty())
        .collect::<Vec<_>>();
    subjects.sort();
    subjects.dedup();

    sync_availability_views_once(state).await;

    let (plan, nodes) = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();
        (cluster.replication_plan(&subjects), cluster.list_nodes())
    };
    let batch_size_override = batch_size_override.or_else(|| {
        Some(
            plan.items
                .iter()
                .map(|item| item.missing_nodes.len())
                .sum::<usize>()
                .max(1),
        )
    });
    let report = execute_replication_repair_plan(
        state,
        plan.clone(),
        nodes,
        batch_size_override,
        false,
        run_id,
    )
    .await;

    (plan, report)
}

#[allow(dead_code)]
pub(crate) async fn execute_targeted_replication_repair_inner(
    state: &ServerState,
    subjects: Vec<String>,
    batch_size_override: Option<usize>,
) -> ReplicationRepairReport {
    execute_targeted_replication_repair_inner_with_context(
        state,
        subjects,
        batch_size_override,
        None,
    )
    .await
}

pub(crate) async fn execute_targeted_replication_repair_inner_with_context(
    state: &ServerState,
    mut subjects: Vec<String>,
    batch_size_override: Option<usize>,
    run_id: Option<&str>,
) -> ReplicationRepairReport {
    let mut attempted_transfers = 0usize;
    let mut successful_transfers = 0usize;
    let mut failed_transfers = 0usize;
    let mut skipped_items = 0usize;
    let mut skipped_backoff = 0usize;
    let mut skipped_max_retries = 0usize;
    let mut skipped_details = Vec::new();
    let mut detailed_log = Vec::new();
    let mut last_error = None;
    let mut repair_state_dirty = false;
    let mut local_availability_refresh_needed = false;

    let max_attempts = state.repair_config.max_retries;
    let backoff_secs = state.repair_config.backoff_secs;
    let max_transfers = batch_size_override.unwrap_or(subjects.len().max(1));
    let now = unix_ts();

    subjects.sort_by(|a, b| {
        let a_versioned = parse_replication_subject(a)
            .and_then(|(_, version_id)| version_id)
            .is_some();
        let b_versioned = parse_replication_subject(b)
            .and_then(|(_, version_id)| version_id)
            .is_some();
        b_versioned.cmp(&a_versioned).then_with(|| a.cmp(b))
    });
    subjects.dedup();

    let repair_run_id = run_id.unwrap_or("untracked");
    info!(
        repair_run_id,
        subject_count = subjects.len(),
        max_transfers,
        max_retries = max_attempts,
        backoff_secs,
        "targeted scrub repair run started"
    );
    push_repair_log_entry(
        &mut detailed_log,
        state.node_id,
        "targeted_repair_started",
        "starting targeted scrub repair run",
        None,
        None,
        None,
        None,
        Some(state.node_id),
        Some(serde_json::json!({
            "subject_count": subjects.len(),
            "max_transfers": max_transfers,
            "max_retries": max_attempts,
            "backoff_secs": backoff_secs,
        })),
    );

    for subject in subjects {
        if attempted_transfers >= max_transfers {
            push_repair_log_entry(
                &mut detailed_log,
                state.node_id,
                "batch_limit_reached",
                "stopping targeted scrub repair because the transfer batch limit was reached",
                Some(subject.clone()),
                None,
                None,
                None,
                Some(state.node_id),
                Some(serde_json::json!({
                    "attempted_transfers": attempted_transfers,
                    "max_transfers": max_transfers,
                })),
            );
            break;
        }

        let Some((key, version_id)) = parse_replication_subject(&subject) else {
            skipped_items += 1;
            push_repair_log_entry(
                &mut detailed_log,
                state.node_id,
                "subject_skipped",
                "replication subject could not be parsed into key and version components",
                Some(subject.clone()),
                None,
                None,
                None,
                Some(state.node_id),
                Some(serde_json::json!({
                    "reason": "invalid_subject",
                })),
            );
            push_repair_skipped_detail(
                &mut skipped_details,
                state.node_id,
                subject.clone(),
                None,
                None,
                None,
                Some(state.node_id),
                ReplicationRepairSkipReason::InvalidSubject,
                "replication subject could not be parsed into key and version components",
            );
            continue;
        };

        push_repair_log_entry(
            &mut detailed_log,
            state.node_id,
            "subject_selected",
            "evaluating targeted scrub repair subject",
            Some(subject.clone()),
            Some(key.clone()),
            version_id.clone(),
            None,
            Some(state.node_id),
            None,
        );

        let source_node = {
            let mut cluster = state.cluster.lock().await;
            cluster.update_health_and_detect_offline_transition();
            cluster
                .available_nodes_for_subject(&subject)
                .into_iter()
                .find(|node| node.node_id != state.node_id)
        };

        let Some(source_node) = source_node else {
            skipped_items += 1;
            push_repair_log_entry(
                &mut detailed_log,
                state.node_id,
                "subject_skipped",
                "targeted scrub repair could not find a healthy online source node",
                Some(subject.clone()),
                Some(key.clone()),
                version_id.clone(),
                None,
                Some(state.node_id),
                Some(serde_json::json!({
                    "reason": "source_node_unavailable",
                })),
            );
            push_repair_skipped_detail(
                &mut skipped_details,
                state.node_id,
                subject.clone(),
                Some(key.clone()),
                version_id.clone(),
                None,
                Some(state.node_id),
                ReplicationRepairSkipReason::SourceNodeUnavailable,
                "targeted scrub repair could not find a healthy online source node",
            );
            continue;
        };

        let transfer_key = format!("{subject}|{}", state.node_id);
        {
            let repair_state = state.maintenance.repair_state.lock().await;
            if let Some(previous) = repair_state.attempts.get(&transfer_key) {
                if previous.attempts > max_attempts {
                    skipped_max_retries += 1;
                    push_repair_log_entry(
                        &mut detailed_log,
                        state.node_id,
                        "subject_skipped",
                        format!(
                            "transfer skipped after {} failed attempts (max_retries={max_attempts})",
                            previous.attempts
                        ),
                        Some(subject.clone()),
                        Some(key.clone()),
                        version_id.clone(),
                        Some(source_node.node_id),
                        Some(state.node_id),
                        Some(serde_json::json!({
                            "reason": "max_retries_exhausted",
                            "failed_attempts": previous.attempts,
                            "max_retries": max_attempts,
                            "last_failure_unix": previous.last_failure_unix,
                        })),
                    );
                    push_repair_skipped_detail(
                        &mut skipped_details,
                        state.node_id,
                        subject.clone(),
                        Some(key.clone()),
                        version_id.clone(),
                        Some(source_node.node_id),
                        Some(state.node_id),
                        ReplicationRepairSkipReason::MaxRetriesExhausted,
                        format!(
                            "transfer skipped after {} failed attempts (max_retries={max_attempts})",
                            previous.attempts
                        ),
                    );
                    continue;
                }

                let elapsed = now.saturating_sub(previous.last_failure_unix);
                let required_backoff =
                    jittered_backoff_secs(backoff_secs, &transfer_key, previous.attempts);
                if elapsed < required_backoff {
                    skipped_backoff += 1;
                    push_repair_log_entry(
                        &mut detailed_log,
                        state.node_id,
                        "subject_skipped",
                        format!(
                            "retry backoff active for another {}s after {} failed attempts",
                            required_backoff.saturating_sub(elapsed),
                            previous.attempts
                        ),
                        Some(subject.clone()),
                        Some(key.clone()),
                        version_id.clone(),
                        Some(source_node.node_id),
                        Some(state.node_id),
                        Some(serde_json::json!({
                            "reason": "backoff_active",
                            "failed_attempts": previous.attempts,
                            "last_failure_unix": previous.last_failure_unix,
                            "elapsed_since_failure_secs": elapsed,
                            "required_backoff_secs": required_backoff,
                        })),
                    );
                    push_repair_skipped_detail(
                        &mut skipped_details,
                        state.node_id,
                        subject.clone(),
                        Some(key.clone()),
                        version_id.clone(),
                        Some(source_node.node_id),
                        Some(state.node_id),
                        ReplicationRepairSkipReason::BackoffActive,
                        format!(
                            "retry backoff active for another {}s after {} failed attempts",
                            required_backoff.saturating_sub(elapsed),
                            previous.attempts
                        ),
                    );
                    continue;
                }
            }
        }

        await_repair_busy_threshold(state).await;
        attempted_transfers += 1;
        info!(
            repair_run_id,
            subject = %subject,
            key = %key,
            version_id = ?version_id,
            source_node_id = %source_node.node_id,
            target_node_id = %state.node_id,
            attempted_transfers,
            "targeted scrub repair starting local pull"
        );
        push_repair_log_entry(
            &mut detailed_log,
            state.node_id,
            "local_pull_started",
            "starting targeted scrub repair local pull",
            Some(subject.clone()),
            Some(key.clone()),
            version_id.clone(),
            Some(source_node.node_id),
            Some(state.node_id),
            Some(serde_json::json!({
                "attempted_transfers": attempted_transfers,
            })),
        );

        match pull_bundle_from_source(
            &source_node,
            &key,
            version_id.as_deref(),
            state,
            run_id,
            &mut detailed_log,
        )
        .await
        {
            Ok(imported_version_id) => {
                push_repair_log_entry(
                    &mut detailed_log,
                    state.node_id,
                    "local_verify_started",
                    "starting targeted scrub repair post-pull verification",
                    Some(subject.clone()),
                    Some(key.clone()),
                    version_id.clone(),
                    Some(source_node.node_id),
                    Some(state.node_id),
                    Some(serde_json::json!({
                        "imported_version_id": imported_version_id,
                    })),
                );
                match verify_local_repair_subject(state, &subject).await {
                    Ok(()) => {
                        successful_transfers += 1;
                        publish_namespace_change(state);

                        let mut repair_state = state.maintenance.repair_state.lock().await;
                        repair_state.attempts.remove(&transfer_key);
                        drop(repair_state);
                        repair_state_dirty = true;
                        local_availability_refresh_needed = true;

                        info!(
                            repair_run_id,
                            subject = %subject,
                            key = %key,
                            version_id = ?version_id,
                            source_node_id = %source_node.node_id,
                            target_node_id = %state.node_id,
                            imported_version_id = %imported_version_id,
                            "targeted scrub repair completed local pull"
                        );
                        push_repair_log_entry(
                            &mut detailed_log,
                            state.node_id,
                            "local_pull_completed",
                            "targeted scrub repair local pull and verification completed",
                            Some(subject.clone()),
                            Some(key.clone()),
                            version_id.clone(),
                            Some(source_node.node_id),
                            Some(state.node_id),
                            Some(serde_json::json!({
                                "imported_version_id": imported_version_id,
                            })),
                        );
                    }
                    Err(err) => {
                        let error_text = format!("{err:#}");
                        failed_transfers += 1;
                        last_error = Some(error_text.clone());
                        warn!(
                            repair_run_id,
                            subject = %subject,
                            key = %key,
                            version_id = ?version_id,
                            source_node_id = %source_node.node_id,
                            target_node_id = %state.node_id,
                            error = %error_text,
                            "targeted scrub repair verification failed"
                        );
                        push_repair_log_entry(
                            &mut detailed_log,
                            state.node_id,
                            "local_verify_failed",
                            "targeted scrub repair verification failed after local pull",
                            Some(subject.clone()),
                            Some(key.clone()),
                            version_id.clone(),
                            Some(source_node.node_id),
                            Some(state.node_id),
                            Some(serde_json::json!({
                                "imported_version_id": imported_version_id,
                                "error": error_text,
                            })),
                        );

                        let mut repair_state = state.maintenance.repair_state.lock().await;
                        let entry = repair_state.attempts.entry(transfer_key).or_insert(
                            RepairAttemptEntry {
                                attempts: 0,
                                last_failure_unix: now,
                            },
                        );
                        entry.attempts = entry.attempts.saturating_add(1);
                        entry.last_failure_unix = now;
                        drop(repair_state);
                        repair_state_dirty = true;
                    }
                }
            }
            Err(err) => {
                let error_text = format!("{err:#}");
                failed_transfers += 1;
                last_error = Some(error_text.clone());
                warn!(
                    repair_run_id,
                    subject = %subject,
                    key = %key,
                    version_id = ?version_id,
                    source_node_id = %source_node.node_id,
                    target_node_id = %state.node_id,
                    error = %error_text,
                    "targeted scrub repair local pull failed"
                );
                push_repair_log_entry(
                    &mut detailed_log,
                    state.node_id,
                    "local_pull_failed",
                    "targeted scrub repair local pull failed",
                    Some(subject.clone()),
                    Some(key.clone()),
                    version_id.clone(),
                    Some(source_node.node_id),
                    Some(state.node_id),
                    Some(serde_json::json!({
                        "error": error_text,
                    })),
                );

                let mut repair_state = state.maintenance.repair_state.lock().await;
                let entry =
                    repair_state
                        .attempts
                        .entry(transfer_key)
                        .or_insert(RepairAttemptEntry {
                            attempts: 0,
                            last_failure_unix: now,
                        });
                entry.attempts = entry.attempts.saturating_add(1);
                entry.last_failure_unix = now;
                drop(repair_state);
                repair_state_dirty = true;
            }
        }
    }

    if local_availability_refresh_needed {
        refresh_local_availability_view_once(state).await;
        push_repair_log_entry(
            &mut detailed_log,
            state.node_id,
            "local_availability_refreshed",
            "refreshed local availability view after targeted scrub repair",
            None,
            None,
            None,
            None,
            Some(state.node_id),
            None,
        );
    }

    if repair_state_dirty {
        match persist_repair_state(state).await {
            Ok(()) => {
                push_repair_log_entry(
                    &mut detailed_log,
                    state.node_id,
                    "repair_attempt_state_persisted",
                    "persisted targeted scrub repair attempt state",
                    None,
                    None,
                    None,
                    None,
                    Some(state.node_id),
                    None,
                );
            }
            Err(err) => {
                warn!(
                    repair_run_id,
                    error = %err,
                    "failed persisting repair attempts after targeted scrub repair"
                );
                push_repair_log_entry(
                    &mut detailed_log,
                    state.node_id,
                    "repair_attempt_state_persist_failed",
                    "failed persisting targeted scrub repair attempt state",
                    None,
                    None,
                    None,
                    None,
                    Some(state.node_id),
                    Some(serde_json::json!({
                        "error": err.to_string(),
                    })),
                );
            }
        }
    }

    info!(
        repair_run_id,
        attempted_transfers,
        successful_transfers,
        failed_transfers,
        skipped_items,
        skipped_backoff,
        skipped_max_retries,
        "targeted scrub repair local phase finished"
    );
    push_repair_log_entry(
        &mut detailed_log,
        state.node_id,
        "targeted_repair_finished",
        "finished targeted scrub repair run",
        None,
        None,
        None,
        None,
        Some(state.node_id),
        Some(serde_json::json!({
            "attempted_transfers": attempted_transfers,
            "successful_transfers": successful_transfers,
            "failed_transfers": failed_transfers,
            "skipped_items": skipped_items,
            "skipped_backoff": skipped_backoff,
            "skipped_max_retries": skipped_max_retries,
        })),
    );

    ReplicationRepairReport {
        attempted_transfers,
        successful_transfers,
        failed_transfers,
        skipped_items,
        skipped_backoff,
        skipped_max_retries,
        skipped_details,
        detailed_log,
        last_error,
    }
}

async fn execute_replication_repair_plan(
    state: &ServerState,
    plan: ReplicationPlan,
    nodes: Vec<NodeDescriptor>,
    batch_size_override: Option<usize>,
    verify_local_pulls: bool,
    run_id: Option<&str>,
) -> ReplicationRepairReport {
    let node_by_id: HashMap<NodeId, NodeDescriptor> =
        nodes.into_iter().map(|node| (node.node_id, node)).collect();

    let plan_generated_at_unix = plan.generated_at_unix;
    let plan_under_replicated = plan.under_replicated;
    let plan_over_replicated = plan.over_replicated;
    let plan_cleanup_deferred_items = plan.cleanup_deferred_items;
    let plan_cleanup_deferred_extra_nodes = plan.cleanup_deferred_extra_nodes;
    let mut attempted_transfers = 0usize;
    let mut successful_transfers = 0usize;
    let mut failed_transfers = 0usize;
    let mut skipped_items = 0usize;
    let mut skipped_backoff = 0usize;
    let mut skipped_max_retries = 0usize;
    let mut skipped_details = Vec::new();
    let mut detailed_log = Vec::new();
    let mut last_error = None;
    let mut replicas_state_dirty = false;
    let mut repair_state_dirty = false;

    let max_attempts = state.repair_config.max_retries;
    let backoff_secs = state.repair_config.backoff_secs;
    let max_transfers = batch_size_override.unwrap_or(state.repair_config.batch_size);
    let now = unix_ts();
    let repair_run_id = run_id.unwrap_or("untracked");

    let mut plan_items = plan.items;
    let plan_item_count = plan_items.len();
    plan_items.sort_by(|a, b| {
        let a_versioned = parse_replication_subject(&a.key)
            .and_then(|(_, version_id)| version_id)
            .is_some();
        let b_versioned = parse_replication_subject(&b.key)
            .and_then(|(_, version_id)| version_id)
            .is_some();
        b_versioned
            .cmp(&a_versioned)
            .then_with(|| a.key.cmp(&b.key))
    });

    info!(
        repair_run_id,
        plan_item_count,
        plan_generated_at_unix,
        under_replicated = plan_under_replicated,
        over_replicated = plan_over_replicated,
        cleanup_deferred_items = plan_cleanup_deferred_items,
        cleanup_deferred_extra_nodes = plan_cleanup_deferred_extra_nodes,
        max_transfers,
        max_retries = max_attempts,
        backoff_secs,
        verify_local_pulls,
        "replication repair run started"
    );
    push_repair_log_entry(
        &mut detailed_log,
        state.node_id,
        "repair_run_started",
        "starting replication repair run",
        None,
        None,
        None,
        None,
        Some(state.node_id),
        Some(serde_json::json!({
            "plan_item_count": plan_item_count,
            "plan_generated_at_unix": plan_generated_at_unix,
            "under_replicated": plan_under_replicated,
            "over_replicated": plan_over_replicated,
            "cleanup_deferred_items": plan_cleanup_deferred_items,
            "cleanup_deferred_extra_nodes": plan_cleanup_deferred_extra_nodes,
            "max_transfers": max_transfers,
            "max_retries": max_attempts,
            "backoff_secs": backoff_secs,
            "verify_local_pulls": verify_local_pulls,
        })),
    );

    for item in plan_items {
        if attempted_transfers >= max_transfers {
            push_repair_log_entry(
                &mut detailed_log,
                state.node_id,
                "batch_limit_reached",
                "stopping replication repair because the transfer batch limit was reached",
                Some(item.key.clone()),
                None,
                None,
                None,
                None,
                Some(serde_json::json!({
                    "attempted_transfers": attempted_transfers,
                    "max_transfers": max_transfers,
                })),
            );
            break;
        }

        let Some((key, version_id)) = parse_replication_subject(&item.key) else {
            skipped_items += 1;
            push_repair_log_entry(
                &mut detailed_log,
                state.node_id,
                "subject_skipped",
                "replication subject could not be parsed into key and version components",
                Some(item.key.clone()),
                None,
                None,
                None,
                None,
                Some(serde_json::json!({
                    "reason": "invalid_subject",
                })),
            );
            push_repair_skipped_detail(
                &mut skipped_details,
                state.node_id,
                item.key.clone(),
                None,
                None,
                None,
                None,
                ReplicationRepairSkipReason::InvalidSubject,
                "replication subject could not be parsed into key and version components",
            );
            continue;
        };

        if item.missing_nodes.is_empty() {
            // Nothing under-replicated here, only extra/deferred replicas, which
            // extra-node cleanup (a separate endpoint) handles, not this pass.
            // Skip before export_replication_bundle() so over-replicated-only
            // items don't pay for a manifest export/parse they never use.
            continue;
        }

        let local_missing = item.missing_nodes.contains(&state.node_id);
        let remote_target_count = item
            .missing_nodes
            .iter()
            .filter(|node_id| **node_id != state.node_id)
            .count();
        let mut repair_source_node_id = None;

        info!(
            repair_run_id,
            subject = %item.key,
            key = %key,
            version_id = ?version_id,
            local_missing,
            remote_target_count,
            current_replica_count = item.current_nodes.len(),
            attempted_transfers,
            max_transfers,
            "replication repair processing subject"
        );
        push_repair_log_entry(
            &mut detailed_log,
            state.node_id,
            "subject_evaluated",
            "processing replication repair subject",
            Some(item.key.clone()),
            Some(key.clone()),
            version_id.clone(),
            None,
            None,
            Some(serde_json::json!({
                "local_missing": local_missing,
                "remote_target_count": remote_target_count,
                "current_nodes": item.current_nodes,
                "missing_nodes": item.missing_nodes,
                "extra_nodes": item.extra_nodes,
                "current_replica_count": item.current_nodes.len(),
                "cleanup_option": item.cleanup_option,
                "deferred_extra_nodes": item.deferred_extra_nodes,
                "attempted_transfers": attempted_transfers,
                "max_transfers": max_transfers,
            })),
        );

        let mut bundle = {
            let store = read_store(state, "replication_repair.export_bundle").await;

            match store
                .export_replication_bundle(&key, version_id.as_deref(), ObjectReadMode::Preferred)
                .await
            {
                Ok(Some(bundle)) => Some(bundle),
                _ => None,
            }
        };

        if bundle.is_some() && local_missing {
            // The local store already has this version but the cluster replica map doesn't know
            // about it (e.g. the version was received through a path that bypassed note_replica,
            // or it's a non-head version that list_replication_subjects doesn't surface). Register
            // it now so future repair plans stop treating this node as missing.
            info!(
                repair_run_id,
                subject = %item.key,
                key = %key,
                version_id = ?version_id,
                "replication repair found local replica not reflected in cluster state; registering"
            );
            push_repair_log_entry(
                &mut detailed_log,
                state.node_id,
                "local_replica_registered",
                "local replica was present but not reflected in cluster state; registering",
                Some(item.key.clone()),
                Some(key.clone()),
                version_id.clone(),
                None,
                Some(state.node_id),
                None,
            );
            let mut cluster = state.cluster.lock().await;
            cluster.note_replica(&key, state.node_id);
            if let Some(vid) = &version_id {
                cluster.note_replica(format!("{key}@{vid}"), state.node_id);
            }
            drop(cluster);
            replicas_state_dirty = true;
        }

        if bundle.is_none() && local_missing {
            let Some(source_node) = item
                .current_nodes
                .iter()
                .filter(|node_id| **node_id != state.node_id)
                .find_map(|node_id| node_by_id.get(node_id))
            else {
                skipped_items += 1;
                push_repair_log_entry(
                    &mut detailed_log,
                    state.node_id,
                    "subject_skipped",
                    "local node is missing the subject and no online source node was available",
                    Some(item.key.clone()),
                    Some(key.clone()),
                    version_id.clone(),
                    None,
                    Some(state.node_id),
                    Some(serde_json::json!({
                        "reason": "source_node_unavailable",
                        "local_missing": true,
                    })),
                );
                push_repair_skipped_detail(
                    &mut skipped_details,
                    state.node_id,
                    item.key.clone(),
                    Some(key.clone()),
                    version_id.clone(),
                    None,
                    Some(state.node_id),
                    ReplicationRepairSkipReason::SourceNodeUnavailable,
                    "local node is missing the subject and no online source node was available",
                );
                continue;
            };

            repair_source_node_id = Some(source_node.node_id);

            let transfer_key = format!("{}|{}", item.key, state.node_id);

            {
                let repair_state = state.maintenance.repair_state.lock().await;
                if let Some(previous) = repair_state.attempts.get(&transfer_key) {
                    if previous.attempts > max_attempts {
                        skipped_max_retries += 1;
                        push_repair_log_entry(
                            &mut detailed_log,
                            state.node_id,
                            "subject_skipped",
                            format!(
                                "transfer skipped after {} failed attempts (max_retries={max_attempts})",
                                previous.attempts
                            ),
                            Some(item.key.clone()),
                            Some(key.clone()),
                            version_id.clone(),
                            Some(source_node.node_id),
                            Some(state.node_id),
                            Some(serde_json::json!({
                                "reason": "max_retries_exhausted",
                                "failed_attempts": previous.attempts,
                                "max_retries": max_attempts,
                                "last_failure_unix": previous.last_failure_unix,
                            })),
                        );
                        push_repair_skipped_detail(
                            &mut skipped_details,
                            state.node_id,
                            item.key.clone(),
                            Some(key.clone()),
                            version_id.clone(),
                            Some(source_node.node_id),
                            Some(state.node_id),
                            ReplicationRepairSkipReason::MaxRetriesExhausted,
                            format!(
                                "transfer skipped after {} failed attempts (max_retries={max_attempts})",
                                previous.attempts
                            ),
                        );
                        continue;
                    }

                    let elapsed = now.saturating_sub(previous.last_failure_unix);
                    let required_backoff =
                        jittered_backoff_secs(backoff_secs, &transfer_key, previous.attempts);
                    if elapsed < required_backoff {
                        skipped_backoff += 1;
                        push_repair_log_entry(
                            &mut detailed_log,
                            state.node_id,
                            "subject_skipped",
                            format!(
                                "retry backoff active for another {}s after {} failed attempts",
                                required_backoff.saturating_sub(elapsed),
                                previous.attempts
                            ),
                            Some(item.key.clone()),
                            Some(key.clone()),
                            version_id.clone(),
                            Some(source_node.node_id),
                            Some(state.node_id),
                            Some(serde_json::json!({
                                "reason": "backoff_active",
                                "failed_attempts": previous.attempts,
                                "last_failure_unix": previous.last_failure_unix,
                                "elapsed_since_failure_secs": elapsed,
                                "required_backoff_secs": required_backoff,
                            })),
                        );
                        push_repair_skipped_detail(
                            &mut skipped_details,
                            state.node_id,
                            item.key.clone(),
                            Some(key.clone()),
                            version_id.clone(),
                            Some(source_node.node_id),
                            Some(state.node_id),
                            ReplicationRepairSkipReason::BackoffActive,
                            format!(
                                "retry backoff active for another {}s after {} failed attempts",
                                required_backoff.saturating_sub(elapsed),
                                previous.attempts
                            ),
                        );
                        continue;
                    }
                }
            }

            await_repair_busy_threshold(state).await;
            attempted_transfers += 1;

            info!(
                repair_run_id,
                subject = %item.key,
                key = %key,
                version_id = ?version_id,
                source_node_id = %source_node.node_id,
                target_node_id = %state.node_id,
                attempted_transfers,
                "replication repair starting local pull"
            );
            push_repair_log_entry(
                &mut detailed_log,
                state.node_id,
                "local_pull_started",
                "starting replication repair local pull",
                Some(item.key.clone()),
                Some(key.clone()),
                version_id.clone(),
                Some(source_node.node_id),
                Some(state.node_id),
                Some(serde_json::json!({
                    "attempted_transfers": attempted_transfers,
                })),
            );

            match pull_bundle_from_source(
                source_node,
                &key,
                version_id.as_deref(),
                state,
                run_id,
                &mut detailed_log,
            )
            .await
            {
                Ok(imported_version_id) => {
                    if verify_local_pulls
                        && let Err(err) = verify_local_repair_subject(state, &item.key).await
                    {
                        let error_text = format!("{err:#}");
                        failed_transfers += 1;
                        last_error = Some(error_text.clone());
                        warn!(
                            repair_run_id,
                            subject = %item.key,
                            key = %key,
                            version_id = ?version_id,
                            source_node_id = %source_node.node_id,
                            target_node_id = %state.node_id,
                            error = %error_text,
                            "replication repair local pull verification failed"
                        );
                        push_repair_log_entry(
                            &mut detailed_log,
                            state.node_id,
                            "local_verify_failed",
                            "replication repair local pull verification failed",
                            Some(item.key.clone()),
                            Some(key.clone()),
                            version_id.clone(),
                            Some(source_node.node_id),
                            Some(state.node_id),
                            Some(serde_json::json!({
                                "imported_version_id": imported_version_id,
                                "error": error_text,
                            })),
                        );

                        let mut repair_state = state.maintenance.repair_state.lock().await;
                        let entry = repair_state.attempts.entry(transfer_key).or_insert(
                            RepairAttemptEntry {
                                attempts: 0,
                                last_failure_unix: now,
                            },
                        );
                        entry.attempts = entry.attempts.saturating_add(1);
                        entry.last_failure_unix = now;
                        drop(repair_state);
                        repair_state_dirty = true;
                        continue;
                    }

                    successful_transfers += 1;
                    info!(
                        repair_run_id,
                        subject = %item.key,
                        key = %key,
                        version_id = ?version_id,
                        source_node_id = %source_node.node_id,
                        target_node_id = %state.node_id,
                        imported_version_id = %imported_version_id,
                        "replication repair completed local pull"
                    );
                    push_repair_log_entry(
                        &mut detailed_log,
                        state.node_id,
                        "local_pull_completed",
                        "replication repair local pull completed",
                        Some(item.key.clone()),
                        Some(key.clone()),
                        version_id.clone(),
                        Some(source_node.node_id),
                        Some(state.node_id),
                        Some(serde_json::json!({
                            "imported_version_id": imported_version_id,
                        })),
                    );
                    publish_namespace_change(state);

                    let mut cluster = state.cluster.lock().await;
                    cluster.note_replica(&key, state.node_id);
                    cluster.note_replica(format!("{key}@{imported_version_id}"), state.node_id);
                    drop(cluster);
                    replicas_state_dirty = true;

                    let mut repair_state = state.maintenance.repair_state.lock().await;
                    repair_state.attempts.remove(&transfer_key);
                    drop(repair_state);
                    repair_state_dirty = true;

                    bundle = {
                        let store = read_store(state, "replication_repair.reload_bundle").await;
                        store
                            .export_replication_bundle(
                                &key,
                                version_id.as_deref(),
                                ObjectReadMode::Preferred,
                            )
                            .await
                            .ok()
                            .flatten()
                    };
                }
                Err(err) => {
                    let error_text = format!("{err:#}");
                    failed_transfers += 1;
                    last_error = Some(error_text.clone());
                    warn!(
                        repair_run_id,
                        subject = %item.key,
                        key = %key,
                        version_id = ?version_id,
                        source_node_id = %source_node.node_id,
                        target_node_id = %state.node_id,
                        error = %error_text,
                        "replication repair local pull failed"
                    );
                    push_repair_log_entry(
                        &mut detailed_log,
                        state.node_id,
                        "local_pull_failed",
                        "replication repair local pull failed",
                        Some(item.key.clone()),
                        Some(key.clone()),
                        version_id.clone(),
                        Some(source_node.node_id),
                        Some(state.node_id),
                        Some(serde_json::json!({
                            "error": error_text,
                        })),
                    );

                    let mut repair_state = state.maintenance.repair_state.lock().await;
                    let entry =
                        repair_state
                            .attempts
                            .entry(transfer_key)
                            .or_insert(RepairAttemptEntry {
                                attempts: 0,
                                last_failure_unix: now,
                            });
                    entry.attempts = entry.attempts.saturating_add(1);
                    entry.last_failure_unix = now;
                    drop(repair_state);
                    repair_state_dirty = true;
                }
            }
        }

        let Some(bundle) = bundle else {
            skipped_items += 1;
            push_repair_log_entry(
                &mut detailed_log,
                state.node_id,
                "subject_skipped",
                if local_missing {
                    "replication bundle remained unavailable after attempting local repair import"
                } else {
                    "replication bundle was not available on the reporting node"
                },
                Some(item.key.clone()),
                Some(key.clone()),
                version_id.clone(),
                repair_source_node_id,
                local_missing.then_some(state.node_id),
                Some(serde_json::json!({
                    "reason": "bundle_unavailable",
                    "local_missing": local_missing,
                })),
            );
            push_repair_skipped_detail(
                &mut skipped_details,
                state.node_id,
                item.key.clone(),
                Some(key.clone()),
                version_id.clone(),
                repair_source_node_id,
                local_missing.then_some(state.node_id),
                ReplicationRepairSkipReason::BundleUnavailable,
                if local_missing {
                    "replication bundle remained unavailable after attempting local repair import"
                } else {
                    "replication bundle was not available on the reporting node"
                },
            );
            continue;
        };

        for target in item.missing_nodes {
            if attempted_transfers >= max_transfers {
                push_repair_log_entry(
                    &mut detailed_log,
                    state.node_id,
                    "batch_limit_reached",
                    "stopping subject target pushes because the transfer batch limit was reached",
                    Some(item.key.clone()),
                    Some(key.clone()),
                    version_id.clone(),
                    Some(state.node_id),
                    Some(target),
                    Some(serde_json::json!({
                        "attempted_transfers": attempted_transfers,
                        "max_transfers": max_transfers,
                    })),
                );
                break;
            }

            let Some(node) = node_by_id.get(&target) else {
                failed_transfers += 1;
                push_repair_log_entry(
                    &mut detailed_log,
                    state.node_id,
                    "target_push_failed",
                    "replication repair could not resolve the target node descriptor",
                    Some(item.key.clone()),
                    Some(key.clone()),
                    version_id.clone(),
                    Some(state.node_id),
                    Some(target),
                    Some(serde_json::json!({
                        "error": "target node descriptor missing",
                    })),
                );
                continue;
            };

            if target == state.node_id {
                continue;
            }

            let transfer_key = format!("{}|{}", item.key, target);

            {
                let repair_state = state.maintenance.repair_state.lock().await;
                if let Some(previous) = repair_state.attempts.get(&transfer_key) {
                    if previous.attempts > max_attempts {
                        skipped_max_retries += 1;
                        push_repair_log_entry(
                            &mut detailed_log,
                            state.node_id,
                            "subject_skipped",
                            format!(
                                "transfer skipped after {} failed attempts (max_retries={max_attempts})",
                                previous.attempts
                            ),
                            Some(item.key.clone()),
                            Some(key.clone()),
                            version_id.clone(),
                            Some(state.node_id),
                            Some(target),
                            Some(serde_json::json!({
                                "reason": "max_retries_exhausted",
                                "failed_attempts": previous.attempts,
                                "max_retries": max_attempts,
                                "last_failure_unix": previous.last_failure_unix,
                            })),
                        );
                        push_repair_skipped_detail(
                            &mut skipped_details,
                            state.node_id,
                            item.key.clone(),
                            Some(key.clone()),
                            version_id.clone(),
                            Some(state.node_id),
                            Some(target),
                            ReplicationRepairSkipReason::MaxRetriesExhausted,
                            format!(
                                "transfer skipped after {} failed attempts (max_retries={max_attempts})",
                                previous.attempts
                            ),
                        );
                        continue;
                    }

                    let elapsed = now.saturating_sub(previous.last_failure_unix);
                    let required_backoff =
                        jittered_backoff_secs(backoff_secs, &transfer_key, previous.attempts);
                    if elapsed < required_backoff {
                        skipped_backoff += 1;
                        push_repair_log_entry(
                            &mut detailed_log,
                            state.node_id,
                            "subject_skipped",
                            format!(
                                "retry backoff active for another {}s after {} failed attempts",
                                required_backoff.saturating_sub(elapsed),
                                previous.attempts
                            ),
                            Some(item.key.clone()),
                            Some(key.clone()),
                            version_id.clone(),
                            Some(state.node_id),
                            Some(target),
                            Some(serde_json::json!({
                                "reason": "backoff_active",
                                "failed_attempts": previous.attempts,
                                "last_failure_unix": previous.last_failure_unix,
                                "elapsed_since_failure_secs": elapsed,
                                "required_backoff_secs": required_backoff,
                            })),
                        );
                        push_repair_skipped_detail(
                            &mut skipped_details,
                            state.node_id,
                            item.key.clone(),
                            Some(key.clone()),
                            version_id.clone(),
                            Some(state.node_id),
                            Some(target),
                            ReplicationRepairSkipReason::BackoffActive,
                            format!(
                                "retry backoff active for another {}s after {} failed attempts",
                                required_backoff.saturating_sub(elapsed),
                                previous.attempts
                            ),
                        );
                        continue;
                    }
                }
            }

            await_repair_busy_threshold(state).await;

            attempted_transfers += 1;
            info!(
                repair_run_id,
                subject = %item.key,
                key = %key,
                version_id = ?version_id,
                source_node_id = %state.node_id,
                target_node_id = %target,
                chunk_count = bundle.manifest.chunks.len(),
                total_size_bytes = bundle.manifest.total_size_bytes,
                attempted_transfers,
                "replication repair starting target push"
            );
            push_repair_log_entry(
                &mut detailed_log,
                state.node_id,
                "target_push_started",
                "starting replication repair target push",
                Some(item.key.clone()),
                Some(key.clone()),
                version_id.clone(),
                Some(state.node_id),
                Some(target),
                Some(serde_json::json!({
                    "attempted_transfers": attempted_transfers,
                    "chunk_count": bundle.manifest.chunks.len(),
                    "total_size_bytes": bundle.manifest.total_size_bytes,
                    "manifest_hash": bundle.manifest_hash,
                    "bundle_version_id": bundle.version_id,
                })),
            );
            let transfer_result =
                replicate_bundle_to_target(node, &bundle, state, run_id, &mut detailed_log).await;

            match transfer_result {
                Ok(remote_version_id) => {
                    successful_transfers += 1;
                    info!(
                        repair_run_id,
                        subject = %item.key,
                        key = %key,
                        version_id = ?version_id,
                        source_node_id = %state.node_id,
                        target_node_id = %target,
                        remote_version_id = %remote_version_id,
                        "replication repair completed target push"
                    );
                    push_repair_log_entry(
                        &mut detailed_log,
                        state.node_id,
                        "target_push_completed",
                        "replication repair target push completed",
                        Some(item.key.clone()),
                        Some(key.clone()),
                        version_id.clone(),
                        Some(state.node_id),
                        Some(target),
                        Some(serde_json::json!({
                            "remote_version_id": remote_version_id,
                        })),
                    );

                    let mut cluster = state.cluster.lock().await;
                    cluster.note_replica(&item.key, target);
                    if let Some(version_id) = &bundle.version_id {
                        cluster.note_replica(format!("{key}@{version_id}"), target);
                    } else {
                        cluster.note_replica(&key, target);
                    }
                    cluster.note_replica(format!("{key}@{remote_version_id}"), target);
                    drop(cluster);
                    replicas_state_dirty = true;

                    let mut repair_state = state.maintenance.repair_state.lock().await;
                    repair_state.attempts.remove(&transfer_key);
                    drop(repair_state);
                    repair_state_dirty = true;
                }
                Err(err) => {
                    let error_text = format!("{err:#}");
                    failed_transfers += 1;
                    last_error = Some(error_text.clone());
                    warn!(
                        repair_run_id,
                        subject = %item.key,
                        key = %key,
                        version_id = ?version_id,
                        source_node_id = %state.node_id,
                        target_node_id = %target,
                        error = %error_text,
                        "replication repair target push failed"
                    );
                    push_repair_log_entry(
                        &mut detailed_log,
                        state.node_id,
                        "target_push_failed",
                        "replication repair target push failed",
                        Some(item.key.clone()),
                        Some(key.clone()),
                        version_id.clone(),
                        Some(state.node_id),
                        Some(target),
                        Some(serde_json::json!({
                            "error": error_text,
                        })),
                    );

                    let mut repair_state = state.maintenance.repair_state.lock().await;
                    let entry =
                        repair_state
                            .attempts
                            .entry(transfer_key)
                            .or_insert(RepairAttemptEntry {
                                attempts: 0,
                                last_failure_unix: now,
                            });
                    entry.attempts = entry.attempts.saturating_add(1);
                    entry.last_failure_unix = now;
                    drop(repair_state);
                    repair_state_dirty = true;
                }
            }
        }
    }

    if replicas_state_dirty {
        match persist_cluster_replicas_state(state).await {
            Ok(()) => {
                push_repair_log_entry(
                    &mut detailed_log,
                    state.node_id,
                    "replica_state_persisted",
                    "persisted cluster replica state after repair run",
                    None,
                    None,
                    None,
                    None,
                    Some(state.node_id),
                    None,
                );
            }
            Err(err) => {
                warn!(
                    repair_run_id,
                    error = %err,
                    "failed to persist cluster replicas after repair run"
                );
                push_repair_log_entry(
                    &mut detailed_log,
                    state.node_id,
                    "replica_state_persist_failed",
                    "failed to persist cluster replica state after repair run",
                    None,
                    None,
                    None,
                    None,
                    Some(state.node_id),
                    Some(serde_json::json!({
                        "error": err.to_string(),
                    })),
                );
            }
        }
    }

    if repair_state_dirty {
        match persist_repair_state(state).await {
            Ok(()) => {
                push_repair_log_entry(
                    &mut detailed_log,
                    state.node_id,
                    "repair_attempt_state_persisted",
                    "persisted repair attempt state after repair run",
                    None,
                    None,
                    None,
                    None,
                    Some(state.node_id),
                    None,
                );
            }
            Err(err) => {
                warn!(
                    repair_run_id,
                    error = %err,
                    "failed persisting repair attempts after repair run"
                );
                push_repair_log_entry(
                    &mut detailed_log,
                    state.node_id,
                    "repair_attempt_state_persist_failed",
                    "failed to persist repair attempt state after repair run",
                    None,
                    None,
                    None,
                    None,
                    Some(state.node_id),
                    Some(serde_json::json!({
                        "error": err.to_string(),
                    })),
                );
            }
        }
    }

    info!(
        repair_run_id,
        attempted_transfers,
        successful_transfers,
        failed_transfers,
        skipped_items,
        skipped_backoff,
        skipped_max_retries,
        "replication repair local phase finished"
    );
    push_repair_log_entry(
        &mut detailed_log,
        state.node_id,
        "repair_run_finished",
        "finished replication repair run",
        None,
        None,
        None,
        None,
        Some(state.node_id),
        Some(serde_json::json!({
            "attempted_transfers": attempted_transfers,
            "successful_transfers": successful_transfers,
            "failed_transfers": failed_transfers,
            "skipped_items": skipped_items,
            "skipped_backoff": skipped_backoff,
            "skipped_max_retries": skipped_max_retries,
        })),
    );

    ReplicationRepairReport {
        attempted_transfers,
        successful_transfers,
        failed_transfers,
        skipped_items,
        skipped_backoff,
        skipped_max_retries,
        skipped_details,
        detailed_log,
        last_error,
    }
}

#[allow(dead_code)]
pub(crate) async fn execute_cluster_replication_repair_inner(
    state: &ServerState,
    batch_size_override: Option<usize>,
) -> ClusterReplicationRepairReport {
    execute_cluster_replication_repair_inner_with_context(state, batch_size_override, None).await
}

pub(crate) async fn execute_cluster_replication_repair_inner_with_context(
    state: &ServerState,
    batch_size_override: Option<usize>,
    run_id: Option<&str>,
) -> ClusterReplicationRepairReport {
    let mut node_reports = Vec::new();
    let mut totals = ReplicationRepairReport {
        attempted_transfers: 0,
        successful_transfers: 0,
        failed_transfers: 0,
        skipped_items: 0,
        skipped_backoff: 0,
        skipped_max_retries: 0,
        skipped_details: Vec::new(),
        detailed_log: Vec::new(),
        last_error: None,
    };
    let mut failed_nodes = 0usize;
    let repair_run_id = run_id.unwrap_or("untracked");

    info!(
        repair_run_id,
        batch_size_override = ?batch_size_override,
        "cluster replication repair starting local phase"
    );
    push_repair_log_entry(
        &mut totals.detailed_log,
        state.node_id,
        "cluster_repair_started",
        "starting cluster replication repair run",
        None,
        None,
        None,
        None,
        Some(state.node_id),
        Some(serde_json::json!({
            "batch_size_override": batch_size_override,
        })),
    );

    let local_report =
        execute_replication_repair_inner_with_context(state, batch_size_override, run_id).await;
    info!(
        repair_run_id,
        attempted_transfers = local_report.attempted_transfers,
        successful_transfers = local_report.successful_transfers,
        failed_transfers = local_report.failed_transfers,
        skipped_items = local_report.skipped_items,
        skipped_backoff = local_report.skipped_backoff,
        skipped_max_retries = local_report.skipped_max_retries,
        "cluster replication repair finished local phase"
    );
    accumulate_repair_report(&mut totals, &local_report);
    node_reports.push(ClusterReplicationRepairNodeReport {
        node_id: state.node_id,
        attempted_transfers: local_report.attempted_transfers,
        successful_transfers: local_report.successful_transfers,
        failed_transfers: local_report.failed_transfers,
        skipped_items: local_report.skipped_items,
        skipped_backoff: local_report.skipped_backoff,
        skipped_max_retries: local_report.skipped_max_retries,
        skipped_details: local_report.skipped_details.clone(),
        last_error: local_report.last_error.clone(),
        request_error: None,
    });

    let peers = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();
        cluster
            .list_nodes()
            .into_iter()
            .filter(|node| {
                node.node_id != state.node_id && node.status == cluster::NodeStatus::Online
            })
            .collect::<Vec<_>>()
    };

    for peer in peers {
        let path =
            build_replication_repair_path(batch_size_override, ReplicationRepairScope::Local);
        info!(
            repair_run_id,
            peer_node_id = %peer.node_id,
            path = %path,
            "cluster replication repair starting peer local phase request"
        );
        push_repair_log_entry(
            &mut totals.detailed_log,
            state.node_id,
            "peer_local_phase_request_started",
            "starting cluster repair peer local phase request",
            None,
            None,
            None,
            Some(state.node_id),
            Some(peer.node_id),
            Some(serde_json::json!({
                "path": path,
            })),
        );
        match execute_peer_request(
            state,
            &peer,
            reqwest::Method::POST,
            &path,
            Vec::new(),
            Vec::new(),
        )
        .await
        {
            Ok(response) if response.is_success() => {
                match response.json::<ReplicationRepairReport>() {
                    Ok(report) => {
                        info!(
                            repair_run_id,
                            peer_node_id = %peer.node_id,
                            attempted_transfers = report.attempted_transfers,
                            successful_transfers = report.successful_transfers,
                            failed_transfers = report.failed_transfers,
                            skipped_items = report.skipped_items,
                            skipped_backoff = report.skipped_backoff,
                            skipped_max_retries = report.skipped_max_retries,
                            "cluster replication repair finished peer local phase request"
                        );
                        push_repair_log_entry(
                            &mut totals.detailed_log,
                            state.node_id,
                            "peer_local_phase_request_completed",
                            "cluster repair peer local phase request completed",
                            None,
                            None,
                            None,
                            Some(state.node_id),
                            Some(peer.node_id),
                            Some(serde_json::json!({
                                "attempted_transfers": report.attempted_transfers,
                                "successful_transfers": report.successful_transfers,
                                "failed_transfers": report.failed_transfers,
                                "skipped_items": report.skipped_items,
                                "skipped_backoff": report.skipped_backoff,
                                "skipped_max_retries": report.skipped_max_retries,
                            })),
                        );
                        accumulate_repair_report(&mut totals, &report);
                        node_reports.push(ClusterReplicationRepairNodeReport {
                            node_id: peer.node_id,
                            attempted_transfers: report.attempted_transfers,
                            successful_transfers: report.successful_transfers,
                            failed_transfers: report.failed_transfers,
                            skipped_items: report.skipped_items,
                            skipped_backoff: report.skipped_backoff,
                            skipped_max_retries: report.skipped_max_retries,
                            skipped_details: report.skipped_details.clone(),
                            last_error: report.last_error.clone(),
                            request_error: None,
                        });
                    }
                    Err(err) => {
                        failed_nodes += 1;
                        let error = format!("failed decoding peer repair report: {err}");
                        warn!(
                            repair_run_id,
                            peer_node_id = %peer.node_id,
                            error = %error,
                            "cluster replication repair peer local phase decode failed"
                        );
                        push_repair_log_entry(
                            &mut totals.detailed_log,
                            state.node_id,
                            "peer_local_phase_request_failed",
                            "failed decoding cluster repair peer local phase response",
                            None,
                            None,
                            None,
                            Some(state.node_id),
                            Some(peer.node_id),
                            Some(serde_json::json!({
                                "error": error,
                            })),
                        );
                        totals.last_error = Some(error.clone());
                        node_reports.push(ClusterReplicationRepairNodeReport {
                            node_id: peer.node_id,
                            attempted_transfers: 0,
                            successful_transfers: 0,
                            failed_transfers: 0,
                            skipped_items: 0,
                            skipped_backoff: 0,
                            skipped_max_retries: 0,
                            skipped_details: Vec::new(),
                            last_error: None,
                            request_error: Some(error),
                        });
                    }
                }
            }
            Ok(response) => {
                failed_nodes += 1;
                let error = format!("peer repair request returned HTTP {}", response.status);
                warn!(
                    repair_run_id,
                    peer_node_id = %peer.node_id,
                    status = response.status,
                    "cluster replication repair peer local phase returned non-success status"
                );
                push_repair_log_entry(
                    &mut totals.detailed_log,
                    state.node_id,
                    "peer_local_phase_request_failed",
                    "cluster repair peer local phase request returned non-success status",
                    None,
                    None,
                    None,
                    Some(state.node_id),
                    Some(peer.node_id),
                    Some(serde_json::json!({
                        "error": error,
                        "status": response.status,
                    })),
                );
                totals.last_error = Some(error.clone());
                node_reports.push(ClusterReplicationRepairNodeReport {
                    node_id: peer.node_id,
                    attempted_transfers: 0,
                    successful_transfers: 0,
                    failed_transfers: 0,
                    skipped_items: 0,
                    skipped_backoff: 0,
                    skipped_max_retries: 0,
                    skipped_details: Vec::new(),
                    last_error: None,
                    request_error: Some(error),
                });
            }
            Err(err) => {
                failed_nodes += 1;
                let error = format!("peer repair request failed: {err:#}");
                warn!(
                    repair_run_id,
                    peer_node_id = %peer.node_id,
                    error = %error,
                    "cluster replication repair peer local phase request failed"
                );
                push_repair_log_entry(
                    &mut totals.detailed_log,
                    state.node_id,
                    "peer_local_phase_request_failed",
                    "cluster repair peer local phase request failed",
                    None,
                    None,
                    None,
                    Some(state.node_id),
                    Some(peer.node_id),
                    Some(serde_json::json!({
                        "error": error,
                    })),
                );
                totals.last_error = Some(error.clone());
                node_reports.push(ClusterReplicationRepairNodeReport {
                    node_id: peer.node_id,
                    attempted_transfers: 0,
                    successful_transfers: 0,
                    failed_transfers: 0,
                    skipped_items: 0,
                    skipped_backoff: 0,
                    skipped_max_retries: 0,
                    skipped_details: Vec::new(),
                    last_error: None,
                    request_error: Some(error),
                });
            }
        }
    }

    push_repair_log_entry(
        &mut totals.detailed_log,
        state.node_id,
        "cluster_repair_finished",
        "finished cluster replication repair run",
        None,
        None,
        None,
        None,
        Some(state.node_id),
        Some(serde_json::json!({
            "nodes_contacted": node_reports.len(),
            "failed_nodes": failed_nodes,
            "attempted_transfers": totals.attempted_transfers,
            "successful_transfers": totals.successful_transfers,
            "failed_transfers": totals.failed_transfers,
            "skipped_items": totals.skipped_items,
            "skipped_backoff": totals.skipped_backoff,
            "skipped_max_retries": totals.skipped_max_retries,
        })),
    );

    ClusterReplicationRepairReport {
        totals,
        scope: ReplicationRepairScope::Cluster,
        nodes_contacted: node_reports.len(),
        failed_nodes,
        node_reports,
    }
}

fn accumulate_repair_report(
    totals: &mut ReplicationRepairReport,
    report: &ReplicationRepairReport,
) {
    totals.attempted_transfers = totals
        .attempted_transfers
        .saturating_add(report.attempted_transfers);
    totals.successful_transfers = totals
        .successful_transfers
        .saturating_add(report.successful_transfers);
    totals.failed_transfers = totals
        .failed_transfers
        .saturating_add(report.failed_transfers);
    totals.skipped_items = totals.skipped_items.saturating_add(report.skipped_items);
    totals.skipped_backoff = totals
        .skipped_backoff
        .saturating_add(report.skipped_backoff);
    totals.skipped_max_retries = totals
        .skipped_max_retries
        .saturating_add(report.skipped_max_retries);
    let skipped_detail_capacity =
        MAX_REPAIR_REPORT_SKIPPED_DETAILS.saturating_sub(totals.skipped_details.len());
    totals.skipped_details.extend(
        report
            .skipped_details
            .iter()
            .take(skipped_detail_capacity)
            .cloned(),
    );
    let detailed_log_capacity =
        MAX_REPAIR_REPORT_LOG_ENTRIES.saturating_sub(totals.detailed_log.len());
    totals.detailed_log.extend(
        report
            .detailed_log
            .iter()
            .take(detailed_log_capacity)
            .cloned(),
    );
    if report.last_error.is_some() {
        totals.last_error = report.last_error.clone();
    }
}

#[allow(clippy::too_many_arguments)]
fn push_repair_log_entry(
    detailed_log: &mut Vec<ReplicationRepairLogEntry>,
    report_node_id: NodeId,
    event: impl Into<String>,
    detail: impl Into<String>,
    subject: Option<String>,
    key: Option<String>,
    version_id: Option<String>,
    source_node_id: Option<NodeId>,
    target_node_id: Option<NodeId>,
    context: Option<serde_json::Value>,
) {
    let entry = ReplicationRepairLogEntry {
        captured_at_unix: unix_ts(),
        report_node_id,
        event: event.into(),
        detail: detail.into(),
        subject,
        key,
        version_id,
        source_node_id,
        target_node_id,
        context,
    };
    append_active_repair_log_entry(&entry);
    if detailed_log.len() >= MAX_REPAIR_REPORT_LOG_ENTRIES {
        return;
    }
    detailed_log.push(entry);
}

#[allow(clippy::too_many_arguments)]
fn push_repair_skipped_detail(
    skipped_details: &mut Vec<ReplicationRepairSkippedItem>,
    report_node_id: NodeId,
    subject: String,
    key: Option<String>,
    version_id: Option<String>,
    source_node_id: Option<NodeId>,
    target_node_id: Option<NodeId>,
    reason: ReplicationRepairSkipReason,
    detail: impl Into<String>,
) {
    if skipped_details.len() >= MAX_REPAIR_REPORT_SKIPPED_DETAILS {
        return;
    }
    skipped_details.push(ReplicationRepairSkippedItem {
        report_node_id,
        subject,
        key,
        version_id,
        source_node_id,
        target_node_id,
        reason,
        detail: detail.into(),
    });
}

fn build_replication_repair_path(
    batch_size_override: Option<usize>,
    scope: ReplicationRepairScope,
) -> String {
    let mut query = Vec::new();
    if let Some(batch_size) = batch_size_override {
        query.push(format!("batch_size={batch_size}"));
    }
    query.push(format!(
        "scope={}",
        match scope {
            ReplicationRepairScope::Local => "local",
            ReplicationRepairScope::Cluster => "cluster",
        }
    ));

    format!("/cluster/replication/repair?{}", query.join("&"))
}

fn should_log_repair_chunk_progress(chunk_index: usize, chunk_count: usize) -> bool {
    chunk_count <= 4
        || chunk_index == 1
        || chunk_index == chunk_count
        || chunk_index.is_multiple_of(REPAIR_PROGRESS_CHUNK_LOG_INTERVAL)
}

async fn pull_bundle_from_source(
    source_node: &NodeDescriptor,
    key: &str,
    version_id: Option<&str>,
    state: &ServerState,
    run_id: Option<&str>,
    detailed_log: &mut Vec<ReplicationRepairLogEntry>,
) -> Result<String> {
    let transfer_started = Instant::now();
    let export_path = build_replication_export_path(key, version_id);
    let repair_run_id = run_id.unwrap_or("untracked");
    let subject = match version_id {
        Some(version_id) => format!("{key}@{version_id}"),
        None => key.to_string(),
    };
    info!(
        repair_run_id,
        source_node_id = %source_node.node_id,
        key = %key,
        version_id = ?version_id,
        path = %export_path,
        "replication repair pull export request starting"
    );
    push_repair_log_entry(
        detailed_log,
        state.node_id,
        "pull_export_request_started",
        "requesting replica export bundle from source node",
        Some(subject.clone()),
        Some(key.to_string()),
        version_id.map(str::to_string),
        Some(source_node.node_id),
        Some(state.node_id),
        Some(serde_json::json!({
            "path": export_path,
        })),
    );
    let bundle = execute_peer_request(
        state,
        source_node,
        reqwest::Method::GET,
        &export_path,
        Vec::new(),
        Vec::new(),
    )
    .await?
    .json::<ReplicationExportBundle>()?;
    let chunk_count = bundle.manifest.chunks.len();

    info!(
        repair_run_id,
        source_node_id = %source_node.node_id,
        key = %bundle.key,
        version_id = ?bundle.version_id,
        manifest_hash = %bundle.manifest_hash,
        chunk_count,
        total_size_bytes = bundle.manifest.total_size_bytes,
        "replication repair pull export ready"
    );
    push_repair_log_entry(
        detailed_log,
        state.node_id,
        "pull_export_ready",
        "received replica export bundle from source node",
        Some(subject.clone()),
        Some(bundle.key.clone()),
        bundle.version_id.clone(),
        Some(source_node.node_id),
        Some(state.node_id),
        Some(serde_json::json!({
            "manifest_hash": bundle.manifest_hash.clone(),
            "chunk_count": chunk_count,
            "total_size_bytes": bundle.manifest.total_size_bytes,
            "tombstone": bundle.manifest_hash == TOMBSTONE_MANIFEST_HASH,
        })),
    );

    if bundle.manifest_hash != TOMBSTONE_MANIFEST_HASH {
        for (chunk_offset, chunk) in bundle.manifest.chunks.iter().enumerate() {
            let chunk_index = chunk_offset + 1;
            if should_log_repair_chunk_progress(chunk_index, chunk_count) {
                info!(
                    repair_run_id,
                    source_node_id = %source_node.node_id,
                    key = %bundle.key,
                    version_id = ?bundle.version_id,
                    chunk_index,
                    chunk_count,
                    chunk_hash = %chunk.hash,
                    "replication repair pull chunk progress"
                );
                push_repair_log_entry(
                    detailed_log,
                    state.node_id,
                    "pull_chunk_progress",
                    "downloading replica chunk from source node",
                    Some(subject.clone()),
                    Some(bundle.key.clone()),
                    bundle.version_id.clone(),
                    Some(source_node.node_id),
                    Some(state.node_id),
                    Some(serde_json::json!({
                        "chunk_index": chunk_index,
                        "chunk_count": chunk_count,
                        "chunk_hash": chunk.hash.clone(),
                    })),
                );
            }
            let payload = execute_peer_request(
                state,
                source_node,
                reqwest::Method::GET,
                &format!("/cluster/v2/replication/chunk/{}", chunk.hash),
                Vec::new(),
                Vec::new(),
            )
            .await?
            .body;

            let store = lock_store(state, "replication_pull.ingest_chunk").await;
            store.ingest_chunk(&chunk.hash, payload.as_ref()).await?;
        }
    }

    info!(
        repair_run_id,
        source_node_id = %source_node.node_id,
        key = %bundle.key,
        version_id = ?bundle.version_id,
        manifest_hash = %bundle.manifest_hash,
        "replication repair pull importing manifest"
    );
    push_repair_log_entry(
        detailed_log,
        state.node_id,
        "pull_manifest_import_started",
        "importing pulled replica manifest locally",
        Some(subject.clone()),
        Some(bundle.key.clone()),
        bundle.version_id.clone(),
        Some(source_node.node_id),
        Some(state.node_id),
        Some(serde_json::json!({
            "manifest_hash": bundle.manifest_hash.clone(),
        })),
    );
    let mut store = lock_store(state, "replication_pull.import_manifest").await;
    let imported_version_id = store.import_replication_bundle(&bundle).await?;
    info!(
        repair_run_id,
        source_node_id = %source_node.node_id,
        key = %bundle.key,
        version_id = ?bundle.version_id,
        imported_version_id = %imported_version_id,
        chunk_count,
        elapsed_ms = transfer_started.elapsed().as_millis(),
        "replication repair pull completed"
    );
    push_repair_log_entry(
        detailed_log,
        state.node_id,
        "pull_completed",
        "finished pulling replica bundle from source node",
        Some(subject),
        Some(bundle.key),
        bundle.version_id,
        Some(source_node.node_id),
        Some(state.node_id),
        Some(serde_json::json!({
            "imported_version_id": imported_version_id.clone(),
            "chunk_count": chunk_count,
            "elapsed_ms": transfer_started.elapsed().as_millis(),
        })),
    );
    Ok(imported_version_id)
}

async fn verify_local_repair_subject(state: &ServerState, subject: &str) -> Result<()> {
    let scrubber = {
        let store = read_store(state, "replication_repair.verify_subject").await;
        store.data_scrubber().await?
    };
    let subjects = BTreeSet::from([subject.to_string()]);
    let report = scrubber.run_for_subjects(&subjects).await?;
    if report.current_keys_scanned == 0 && report.version_records_scanned == 0 {
        bail!("post-repair verification did not resolve subject={subject}");
    }
    if report.issue_count == 0 {
        return Ok(());
    }

    let first_issue = report
        .issues
        .first()
        .map(|issue| format!("{:?}: {}", issue.kind, issue.detail))
        .unwrap_or_else(|| format!("{} issue(s) without sampled details", report.issue_count));
    bail!(
        "post-repair scrub verification found {} issue(s) for subject={subject}: {first_issue}",
        report.issue_count
    );
}

async fn replicate_bundle_to_target(
    target_node: &NodeDescriptor,
    bundle: &ReplicationExportBundle,
    state: &ServerState,
    run_id: Option<&str>,
    detailed_log: &mut Vec<ReplicationRepairLogEntry>,
) -> Result<String> {
    let transfer_started = Instant::now();
    let chunk_count = bundle.manifest.chunks.len();
    let repair_run_id = run_id.unwrap_or("untracked");
    let subject = match bundle.version_id.as_deref() {
        Some(version_id) => format!("{}@{version_id}", bundle.key),
        None => bundle.key.clone(),
    };
    info!(
        repair_run_id,
        target_node_id = %target_node.node_id,
        key = %bundle.key,
        version_id = ?bundle.version_id,
        manifest_hash = %bundle.manifest_hash,
        chunk_count,
        total_size_bytes = bundle.manifest.total_size_bytes,
        tombstone = bundle.manifest_hash == TOMBSTONE_MANIFEST_HASH,
        "replication repair target push starting"
    );
    push_repair_log_entry(
        detailed_log,
        state.node_id,
        "target_transfer_started",
        "starting replica transfer to target node",
        Some(subject.clone()),
        Some(bundle.key.clone()),
        bundle.version_id.clone(),
        Some(state.node_id),
        Some(target_node.node_id),
        Some(serde_json::json!({
            "manifest_hash": bundle.manifest_hash.clone(),
            "chunk_count": chunk_count,
            "total_size_bytes": bundle.manifest.total_size_bytes,
            "tombstone": bundle.manifest_hash == TOMBSTONE_MANIFEST_HASH,
        })),
    );

    if bundle.manifest_hash != TOMBSTONE_MANIFEST_HASH {
        for (chunk_offset, chunk) in bundle.manifest.chunks.iter().enumerate() {
            let chunk_index = chunk_offset + 1;
            if should_log_repair_chunk_progress(chunk_index, chunk_count) {
                info!(
                    repair_run_id,
                    target_node_id = %target_node.node_id,
                    key = %bundle.key,
                    version_id = ?bundle.version_id,
                    chunk_index,
                    chunk_count,
                    chunk_hash = %chunk.hash,
                    "replication repair target push chunk progress"
                );
                push_repair_log_entry(
                    detailed_log,
                    state.node_id,
                    "target_push_chunk_progress",
                    "uploading replica chunk to target node",
                    Some(subject.clone()),
                    Some(bundle.key.clone()),
                    bundle.version_id.clone(),
                    Some(state.node_id),
                    Some(target_node.node_id),
                    Some(serde_json::json!({
                        "chunk_index": chunk_index,
                        "chunk_count": chunk_count,
                        "chunk_hash": chunk.hash.clone(),
                    })),
                );
            }
            let payload = {
                let guard = read_store(state, "replication_push.read_chunk").await;
                guard
                    .read_chunk_payload(&chunk.hash)
                    .await?
                    .with_context(|| format!("missing local chunk {}", chunk.hash))?
            };

            let response = execute_peer_request(
                state,
                target_node,
                reqwest::Method::POST,
                &format!("/cluster/v2/replication/push/chunk/{}", chunk.hash),
                vec![RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/octet-stream".to_string(),
                }],
                payload.to_vec(),
            )
            .await
            .with_context(|| {
                format!(
                    "failed to push chunk hash={} key={} version_id={:?} to target={}",
                    chunk.hash, bundle.key, bundle.version_id, target_node.node_id
                )
            })?;
            if !response.is_success() {
                bail!(
                    "chunk replication target {} returned HTTP {}",
                    target_node.node_id,
                    response.status
                );
            }
        }
    }

    let bundle_path = build_replication_bundle_push_path();
    info!(
        repair_run_id,
        target_node_id = %target_node.node_id,
        key = %bundle.key,
        version_id = ?bundle.version_id,
        manifest_hash = %bundle.manifest_hash,
        path = %bundle_path,
        "replication repair target push bundle starting"
    );
    push_repair_log_entry(
        detailed_log,
        state.node_id,
        "target_bundle_push_started",
        "pushing replica bundle to target node",
        Some(subject.clone()),
        Some(bundle.key.clone()),
        bundle.version_id.clone(),
        Some(state.node_id),
        Some(target_node.node_id),
        Some(serde_json::json!({
            "manifest_hash": bundle.manifest_hash.clone(),
            "path": bundle_path.clone(),
        })),
    );
    let response = execute_peer_request(
        state,
        target_node,
        reqwest::Method::POST,
        &bundle_path,
        vec![RelayHttpHeader {
            name: "content-type".to_string(),
            value: "application/json".to_string(),
        }],
        serde_json::to_vec(bundle)?,
    )
    .await
    .with_context(|| {
        format!(
            "failed to push replica bundle key={} version_id={:?} manifest_hash={} to target={}",
            bundle.key, bundle.version_id, bundle.manifest_hash, target_node.node_id
        )
    })?;
    if !response.is_success() {
        bail!(
            "replication bundle target {} returned HTTP {}",
            target_node.node_id,
            response.status
        );
    }

    let report = response.json::<ReplicationBundlePushReport>()?;
    info!(
        repair_run_id,
        target_node_id = %target_node.node_id,
        key = %bundle.key,
        version_id = ?bundle.version_id,
        remote_version_id = %report.version_id,
        chunk_count,
        elapsed_ms = transfer_started.elapsed().as_millis(),
        "replication repair target push completed"
    );
    push_repair_log_entry(
        detailed_log,
        state.node_id,
        "target_transfer_completed",
        "finished replica transfer to target node",
        Some(subject),
        Some(bundle.key.clone()),
        bundle.version_id.clone(),
        Some(state.node_id),
        Some(target_node.node_id),
        Some(serde_json::json!({
            "remote_version_id": report.version_id.clone(),
            "chunk_count": chunk_count,
            "elapsed_ms": transfer_started.elapsed().as_millis(),
        })),
    );
    Ok(report.version_id)
}

pub(crate) fn build_replication_export_path(key: &str, version_id: Option<&str>) -> String {
    match version_id {
        Some(version_id) => format!(
            "/cluster/v2/replication/export?key={}&version_id={}",
            encode_query_value(key),
            encode_query_value(version_id)
        ),
        None => format!(
            "/cluster/v2/replication/export?key={}",
            encode_query_value(key)
        ),
    }
}

pub(crate) fn build_replication_bundle_push_path() -> String {
    "/cluster/v2/replication/push/bundle".to_string()
}

fn encode_query_value(value: &str) -> String {
    utf8_percent_encode(value, QUERY_COMPONENT_ENCODE_SET).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_report() -> ReplicationRepairReport {
        ReplicationRepairReport {
            attempted_transfers: 0,
            successful_transfers: 0,
            failed_transfers: 0,
            skipped_items: 0,
            skipped_backoff: 0,
            skipped_max_retries: 0,
            skipped_details: Vec::new(),
            detailed_log: Vec::new(),
            last_error: None,
        }
    }

    #[test]
    fn push_repair_log_entry_caps_retained_report_log() {
        let node_id = NodeId::new_v4();
        let mut detailed_log = Vec::new();

        for idx in 0..(MAX_REPAIR_REPORT_LOG_ENTRIES + 32) {
            push_repair_log_entry(
                &mut detailed_log,
                node_id,
                "log_entry",
                format!("detail-{idx}"),
                None,
                None,
                None,
                None,
                None,
                None,
            );
        }

        assert_eq!(detailed_log.len(), MAX_REPAIR_REPORT_LOG_ENTRIES);
        assert_eq!(
            detailed_log.first().map(|entry| entry.detail.as_str()),
            Some("detail-0")
        );
        let expected_last = format!("detail-{}", MAX_REPAIR_REPORT_LOG_ENTRIES - 1);
        assert_eq!(
            detailed_log.last().map(|entry| entry.detail.as_str()),
            Some(expected_last.as_str())
        );
    }

    #[test]
    fn accumulate_repair_report_caps_aggregate_log_and_skip_buffers() {
        let node_id = NodeId::new_v4();
        let oversized_report = ReplicationRepairReport {
            attempted_transfers: 1,
            successful_transfers: 2,
            failed_transfers: 3,
            skipped_items: 4,
            skipped_backoff: 5,
            skipped_max_retries: 6,
            skipped_details: (0..(MAX_REPAIR_REPORT_SKIPPED_DETAILS + 32))
                .map(|idx| ReplicationRepairSkippedItem {
                    report_node_id: node_id,
                    subject: format!("subject-{idx}"),
                    key: None,
                    version_id: None,
                    source_node_id: None,
                    target_node_id: None,
                    reason: ReplicationRepairSkipReason::InvalidSubject,
                    detail: format!("detail-{idx}"),
                })
                .collect(),
            detailed_log: (0..(MAX_REPAIR_REPORT_LOG_ENTRIES + 32))
                .map(|idx| ReplicationRepairLogEntry {
                    captured_at_unix: idx as u64,
                    report_node_id: node_id,
                    event: "event".to_string(),
                    detail: format!("detail-{idx}"),
                    subject: None,
                    key: None,
                    version_id: None,
                    source_node_id: None,
                    target_node_id: None,
                    context: None,
                })
                .collect(),
            last_error: Some("boom".to_string()),
        };

        let mut totals = empty_report();
        accumulate_repair_report(&mut totals, &oversized_report);
        accumulate_repair_report(&mut totals, &oversized_report);

        assert_eq!(totals.attempted_transfers, 2);
        assert_eq!(totals.successful_transfers, 4);
        assert_eq!(totals.failed_transfers, 6);
        assert_eq!(totals.skipped_items, 8);
        assert_eq!(totals.skipped_backoff, 10);
        assert_eq!(totals.skipped_max_retries, 12);
        assert_eq!(
            totals.skipped_details.len(),
            MAX_REPAIR_REPORT_SKIPPED_DETAILS
        );
        assert_eq!(totals.detailed_log.len(), MAX_REPAIR_REPORT_LOG_ENTRIES);
        assert_eq!(totals.last_error.as_deref(), Some("boom"));
    }
}
