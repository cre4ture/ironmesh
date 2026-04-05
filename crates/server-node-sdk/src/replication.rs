use super::*;
use bytes::BytesMut;
use storage::{ReplicationExportBundle, TOMBSTONE_MANIFEST_HASH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ReplicationRepairReport {
    pub(crate) attempted_transfers: usize,
    pub(crate) successful_transfers: usize,
    pub(crate) failed_transfers: usize,
    pub(crate) skipped_items: usize,
    pub(crate) skipped_backoff: usize,
    pub(crate) skipped_max_retries: usize,
    pub(crate) last_error: Option<String>,
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

pub(crate) async fn execute_replication_repair(
    State(state): State<ServerState>,
    Query(query): Query<ReplicationRepairQuery>,
) -> impl IntoResponse {
    let batch_override = query.batch_size.filter(|v| *v > 0);
    match query.scope.unwrap_or_default() {
        ReplicationRepairScope::Local => {
            let report = execute_replication_repair_inner(&state, batch_override).await;
            (StatusCode::OK, Json(report)).into_response()
        }
        ReplicationRepairScope::Cluster => {
            let report = execute_cluster_replication_repair_inner(&state, batch_override).await;
            (StatusCode::OK, Json(report)).into_response()
        }
    }
}

pub(crate) async fn execute_replication_repair_inner(
    state: &ServerState,
    batch_size_override: Option<usize>,
) -> ReplicationRepairReport {
    sync_availability_views_once(state).await;
    let keys = planning_replication_subjects(state).await;

    let (plan, nodes) = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();
        (cluster.replication_plan(&keys), cluster.list_nodes())
    };

    let node_by_id: HashMap<NodeId, NodeDescriptor> =
        nodes.into_iter().map(|node| (node.node_id, node)).collect();

    let mut attempted_transfers = 0usize;
    let mut successful_transfers = 0usize;
    let mut failed_transfers = 0usize;
    let mut skipped_items = 0usize;
    let mut skipped_backoff = 0usize;
    let mut skipped_max_retries = 0usize;
    let mut last_error = None;
    let mut replicas_state_dirty = false;
    let mut repair_state_dirty = false;

    let max_attempts = state.repair_config.max_retries;
    let backoff_secs = state.repair_config.backoff_secs;
    let max_transfers = batch_size_override.unwrap_or(state.repair_config.batch_size);
    let now = unix_ts();

    let mut plan_items = plan.items;
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

    for item in plan_items {
        if attempted_transfers >= max_transfers {
            break;
        }

        let Some((key, version_id)) = parse_replication_subject(&item.key) else {
            skipped_items += 1;
            continue;
        };

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

        if bundle.is_none() && item.missing_nodes.contains(&state.node_id) {
            let Some(source_node) = item
                .current_nodes
                .iter()
                .filter(|node_id| **node_id != state.node_id)
                .find_map(|node_id| node_by_id.get(node_id))
            else {
                skipped_items += 1;
                continue;
            };

            let transfer_key = format!("{}|{}", item.key, state.node_id);

            {
                let repair_state = state.repair_state.lock().await;
                if let Some(previous) = repair_state.attempts.get(&transfer_key) {
                    if previous.attempts > max_attempts {
                        skipped_max_retries += 1;
                        continue;
                    }

                    let elapsed = now.saturating_sub(previous.last_failure_unix);
                    let required_backoff =
                        jittered_backoff_secs(backoff_secs, &transfer_key, previous.attempts);
                    if elapsed < required_backoff {
                        skipped_backoff += 1;
                        continue;
                    }
                }
            }

            await_repair_busy_threshold(state).await;
            attempted_transfers += 1;

            match pull_bundle_from_source(source_node, &key, version_id.as_deref(), state).await {
                Ok(imported_version_id) => {
                    successful_transfers += 1;
                    publish_namespace_change(state);

                    let mut cluster = state.cluster.lock().await;
                    cluster.note_replica(&key, state.node_id);
                    cluster.note_replica(format!("{key}@{imported_version_id}"), state.node_id);
                    drop(cluster);
                    replicas_state_dirty = true;

                    let mut repair_state = state.repair_state.lock().await;
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
                    failed_transfers += 1;
                    last_error = Some(format!("{err:#}"));

                    let mut repair_state = state.repair_state.lock().await;
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
            continue;
        };

        for target in item.missing_nodes {
            if attempted_transfers >= max_transfers {
                break;
            }

            let Some(node) = node_by_id.get(&target) else {
                failed_transfers += 1;
                continue;
            };

            if target == state.node_id {
                continue;
            }

            let transfer_key = format!("{}|{}", item.key, target);

            {
                let repair_state = state.repair_state.lock().await;
                if let Some(previous) = repair_state.attempts.get(&transfer_key) {
                    if previous.attempts > max_attempts {
                        skipped_max_retries += 1;
                        continue;
                    }

                    let elapsed = now.saturating_sub(previous.last_failure_unix);
                    let required_backoff =
                        jittered_backoff_secs(backoff_secs, &transfer_key, previous.attempts);
                    if elapsed < required_backoff {
                        skipped_backoff += 1;
                        continue;
                    }
                }
            }

            await_repair_busy_threshold(state).await;

            attempted_transfers += 1;
            let transfer_result = replicate_bundle_to_target(node, &bundle, state).await;

            match transfer_result {
                Ok(remote_version_id) => {
                    successful_transfers += 1;

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

                    let mut repair_state = state.repair_state.lock().await;
                    repair_state.attempts.remove(&transfer_key);
                    drop(repair_state);
                    repair_state_dirty = true;
                }
                Err(err) => {
                    failed_transfers += 1;
                    last_error = Some(format!("{err:#}"));

                    let mut repair_state = state.repair_state.lock().await;
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

    if replicas_state_dirty && let Err(err) = persist_cluster_replicas_state(state).await {
        warn!(
            error = %err,
            "failed to persist cluster replicas after repair run"
        );
    }

    if repair_state_dirty && let Err(err) = persist_repair_state(state).await {
        warn!(error = %err, "failed persisting repair attempts after repair run");
    }

    ReplicationRepairReport {
        attempted_transfers,
        successful_transfers,
        failed_transfers,
        skipped_items,
        skipped_backoff,
        skipped_max_retries,
        last_error,
    }
}

async fn execute_cluster_replication_repair_inner(
    state: &ServerState,
    batch_size_override: Option<usize>,
) -> ClusterReplicationRepairReport {
    let mut node_reports = Vec::new();
    let mut totals = ReplicationRepairReport {
        attempted_transfers: 0,
        successful_transfers: 0,
        failed_transfers: 0,
        skipped_items: 0,
        skipped_backoff: 0,
        skipped_max_retries: 0,
        last_error: None,
    };
    let mut failed_nodes = 0usize;

    let local_report = execute_replication_repair_inner(state, batch_size_override).await;
    accumulate_repair_report(&mut totals, &local_report);
    node_reports.push(ClusterReplicationRepairNodeReport {
        node_id: state.node_id,
        attempted_transfers: local_report.attempted_transfers,
        successful_transfers: local_report.successful_transfers,
        failed_transfers: local_report.failed_transfers,
        skipped_items: local_report.skipped_items,
        skipped_backoff: local_report.skipped_backoff,
        skipped_max_retries: local_report.skipped_max_retries,
        last_error: local_report.last_error.clone(),
        request_error: None,
    });

    let peers = {
        let mut cluster = state.cluster.lock().await;
        cluster.update_health_and_detect_offline_transition();
        cluster
            .list_nodes()
            .into_iter()
            .filter(|node| node.node_id != state.node_id && node.status == cluster::NodeStatus::Online)
            .collect::<Vec<_>>()
    };

    for peer in peers {
        let path = build_replication_repair_path(batch_size_override, ReplicationRepairScope::Local);
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
            Ok(response) if response.is_success() => match response.json::<ReplicationRepairReport>() {
                Ok(report) => {
                    accumulate_repair_report(&mut totals, &report);
                    node_reports.push(ClusterReplicationRepairNodeReport {
                        node_id: peer.node_id,
                        attempted_transfers: report.attempted_transfers,
                        successful_transfers: report.successful_transfers,
                        failed_transfers: report.failed_transfers,
                        skipped_items: report.skipped_items,
                        skipped_backoff: report.skipped_backoff,
                        skipped_max_retries: report.skipped_max_retries,
                        last_error: report.last_error.clone(),
                        request_error: None,
                    });
                }
                Err(err) => {
                    failed_nodes += 1;
                    let error = format!("failed decoding peer repair report: {err}");
                    totals.last_error = Some(error.clone());
                    node_reports.push(ClusterReplicationRepairNodeReport {
                        node_id: peer.node_id,
                        attempted_transfers: 0,
                        successful_transfers: 0,
                        failed_transfers: 0,
                        skipped_items: 0,
                        skipped_backoff: 0,
                        skipped_max_retries: 0,
                        last_error: None,
                        request_error: Some(error),
                    });
                }
            },
            Ok(response) => {
                failed_nodes += 1;
                let error = format!(
                    "peer repair request returned HTTP {}",
                    response.status
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
                    last_error: None,
                    request_error: Some(error),
                });
            }
            Err(err) => {
                failed_nodes += 1;
                let error = format!("peer repair request failed: {err:#}");
                totals.last_error = Some(error.clone());
                node_reports.push(ClusterReplicationRepairNodeReport {
                    node_id: peer.node_id,
                    attempted_transfers: 0,
                    successful_transfers: 0,
                    failed_transfers: 0,
                    skipped_items: 0,
                    skipped_backoff: 0,
                    skipped_max_retries: 0,
                    last_error: None,
                    request_error: Some(error),
                });
            }
        }
    }

    ClusterReplicationRepairReport {
        totals,
        scope: ReplicationRepairScope::Cluster,
        nodes_contacted: node_reports.len(),
        failed_nodes,
        node_reports,
    }
}

fn accumulate_repair_report(totals: &mut ReplicationRepairReport, report: &ReplicationRepairReport) {
    totals.attempted_transfers =
        totals.attempted_transfers.saturating_add(report.attempted_transfers);
    totals.successful_transfers =
        totals.successful_transfers.saturating_add(report.successful_transfers);
    totals.failed_transfers = totals.failed_transfers.saturating_add(report.failed_transfers);
    totals.skipped_items = totals.skipped_items.saturating_add(report.skipped_items);
    totals.skipped_backoff = totals.skipped_backoff.saturating_add(report.skipped_backoff);
    totals.skipped_max_retries =
        totals.skipped_max_retries.saturating_add(report.skipped_max_retries);
    if report.last_error.is_some() {
        totals.last_error = report.last_error.clone();
    }
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

async fn pull_bundle_from_source(
    source_node: &NodeDescriptor,
    key: &str,
    version_id: Option<&str>,
    state: &ServerState,
) -> Result<String> {
    let export_path = build_replication_export_path(key, version_id);
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

    if bundle.manifest_hash != TOMBSTONE_MANIFEST_HASH {
        for chunk in &bundle.manifest.chunks {
            let payload = execute_peer_request(
                state,
                source_node,
                reqwest::Method::GET,
                &format!("/cluster/replication/chunk/{}", chunk.hash),
                Vec::new(),
                Vec::new(),
            )
            .await?
            .body;

            let store = lock_store(state, "replication_pull.ingest_chunk").await;
            store.ingest_chunk(&chunk.hash, payload.as_ref()).await?;
        }
    }

    let mut store = lock_store(state, "replication_pull.import_manifest").await;
    store
        .import_replica_manifest(
            &bundle.key,
            bundle.version_id.as_deref(),
            &bundle.parent_version_ids,
            bundle.state,
            &bundle.manifest_hash,
            &bundle.manifest_bytes,
        )
        .await
}

async fn replicate_bundle_to_target(
    target_node: &NodeDescriptor,
    bundle: &ReplicationExportBundle,
    state: &ServerState,
) -> Result<String> {
    if bundle.manifest_hash == TOMBSTONE_MANIFEST_HASH {
        let state_query = match bundle.state {
            VersionConsistencyState::Confirmed => "confirmed",
            VersionConsistencyState::Provisional => "provisional",
        };

        let delete_path = build_internal_replication_delete_path(
            &bundle.key,
            state_query,
            bundle.version_id.as_deref(),
        );
        let response = execute_peer_request(
            state,
            target_node,
            reqwest::Method::POST,
            &delete_path,
            Vec::new(),
            Vec::new(),
        )
        .await
        .with_context(|| {
            format!(
                "failed to push tombstone key={} version_id={:?} to target={}",
                bundle.key, bundle.version_id, target_node.node_id
            )
        })?;
        if !response.is_success() {
            bail!(
                "tombstone replication target {} returned HTTP {}",
                target_node.node_id,
                response.status
            );
        }

        return bundle
            .version_id
            .clone()
            .context("tombstone replication bundle missing version id");
    }

    if bundle.version_id.is_some() {
        for chunk in &bundle.manifest.chunks {
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
                &format!("/cluster/replication/push/chunk/{}", chunk.hash),
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
    } else {
        let mut assembled = BytesMut::with_capacity(bundle.manifest.total_size_bytes);

        for chunk in &bundle.manifest.chunks {
            let payload = {
                let guard = read_store(state, "replication_push.read_chunk_inline").await;
                guard
                    .read_chunk_payload(&chunk.hash)
                    .await?
                    .with_context(|| format!("missing local chunk {}", chunk.hash))?
            };

            assembled.extend_from_slice(&payload);
        }

        let state_query = match bundle.state {
            VersionConsistencyState::Confirmed => "confirmed",
            VersionConsistencyState::Provisional => "provisional",
        };

        let put_url = build_internal_replication_put_url(
            "",
            &bundle.key,
            state_query,
            bundle.version_id.as_deref(),
        );
        let response = execute_peer_request(
            state,
            target_node,
            reqwest::Method::PUT,
            &put_url,
            vec![RelayHttpHeader {
                name: "content-type".to_string(),
                value: "application/octet-stream".to_string(),
            }],
            assembled.freeze().to_vec(),
        )
        .await
        .with_context(|| {
            format!(
                "failed to push assembled object key={} version_id={:?} to target={}",
                bundle.key, bundle.version_id, target_node.node_id
            )
        })?;
        if !response.is_success() {
            bail!(
                "assembled object replication target {} returned HTTP {}",
                target_node.node_id,
                response.status
            );
        }
    }

    let parent_version_ids_json = if bundle.parent_version_ids.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&bundle.parent_version_ids)?)
    };
    let manifest_path = build_replication_manifest_push_path(
        &bundle.key,
        &bundle.manifest_hash,
        bundle.state.clone(),
        bundle.version_id.as_deref(),
        parent_version_ids_json.as_deref(),
    );
    let response = execute_peer_request(
        state,
        target_node,
        reqwest::Method::POST,
        &manifest_path,
        vec![RelayHttpHeader {
            name: "content-type".to_string(),
            value: "application/octet-stream".to_string(),
        }],
        bundle.manifest_bytes.clone(),
    )
    .await
    .with_context(|| {
        format!(
            "failed to push manifest key={} version_id={:?} manifest_hash={} to target={}",
            bundle.key, bundle.version_id, bundle.manifest_hash, target_node.node_id
        )
    })?;
    if !response.is_success() {
        bail!(
            "manifest replication target {} returned HTTP {}",
            target_node.node_id,
            response.status
        );
    }

    let report = response.json::<ReplicationManifestPushReport>()?;
    Ok(report.version_id)
}

pub(crate) fn build_internal_replication_put_url(
    target_base_url: &str,
    key: &str,
    state_query: &str,
    version_id: Option<&str>,
) -> String {
    let state_query = encode_query_value(state_query);
    match version_id {
        Some(version_id) => format!(
            "{target_base_url}/store/{key}?state={state_query}&version_id={}&internal_replication=true",
            encode_query_value(version_id)
        ),
        None => {
            format!("{target_base_url}/store/{key}?state={state_query}&internal_replication=true")
        }
    }
}

fn build_replication_export_path(key: &str, version_id: Option<&str>) -> String {
    match version_id {
        Some(version_id) => format!(
            "/cluster/replication/export?key={}&version_id={}",
            encode_query_value(key),
            encode_query_value(version_id)
        ),
        None => format!(
            "/cluster/replication/export?key={}",
            encode_query_value(key)
        ),
    }
}

fn build_internal_replication_delete_path(
    key: &str,
    state_query: &str,
    version_id: Option<&str>,
) -> String {
    let mut path = format!(
        "/store/delete?key={}&state={}&internal_replication=true",
        encode_query_value(key),
        encode_query_value(state_query)
    );
    if let Some(version_id) = version_id {
        path.push_str("&version_id=");
        path.push_str(&encode_query_value(version_id));
    }
    path
}

fn build_replication_manifest_push_path(
    key: &str,
    manifest_hash: &str,
    state: VersionConsistencyState,
    version_id: Option<&str>,
    parent_version_ids_json: Option<&str>,
) -> String {
    let mut path = format!(
        "/cluster/replication/push/manifest?key={}&manifest_hash={}&state={}",
        encode_query_value(key),
        encode_query_value(manifest_hash),
        encode_query_value(match state {
            VersionConsistencyState::Confirmed => "confirmed",
            VersionConsistencyState::Provisional => "provisional",
        })
    );
    let suffix = build_manifest_push_query_suffix(version_id, parent_version_ids_json);
    if !suffix.is_empty() {
        path.push('&');
        path.push_str(&suffix);
    }
    path
}

fn build_manifest_push_query_suffix(
    version_id: Option<&str>,
    parent_version_ids_json: Option<&str>,
) -> String {
    let mut segments = Vec::new();
    if let Some(version_id) = version_id {
        segments.push(format!("version_id={}", encode_query_value(version_id)));
    }
    if let Some(parent_version_ids_json) = parent_version_ids_json {
        segments.push(format!(
            "parent_version_ids_json={}",
            encode_query_value(parent_version_ids_json)
        ));
    }
    segments.join("&")
}

fn encode_query_value(value: &str) -> String {
    utf8_percent_encode(value, QUERY_COMPONENT_ENCODE_SET).to_string()
}
