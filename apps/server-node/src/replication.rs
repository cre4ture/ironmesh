use super::*;
use bytes::BytesMut;
use storage::ReplicationExportBundle;

#[derive(Debug, Serialize)]
pub(crate) struct ReplicationRepairReport {
    pub(crate) attempted_transfers: usize,
    pub(crate) successful_transfers: usize,
    pub(crate) failed_transfers: usize,
    pub(crate) skipped_items: usize,
    pub(crate) skipped_backoff: usize,
    pub(crate) skipped_max_retries: usize,
    pub(crate) last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReplicationRepairQuery {
    batch_size: Option<usize>,
}

pub(crate) async fn execute_replication_repair(
    State(state): State<ServerState>,
    Query(query): Query<ReplicationRepairQuery>,
) -> impl IntoResponse {
    let batch_override = query.batch_size.filter(|v| *v > 0);
    let report = execute_replication_repair_inner(&state, batch_override).await;

    (StatusCode::OK, Json(report))
}

pub(crate) async fn execute_replication_repair_inner(
    state: &ServerState,
    batch_size_override: Option<usize>,
) -> ReplicationRepairReport {
    let keys = {
        let store = state.store.lock().await;
        store
            .list_replication_subjects()
            .await
            .unwrap_or_else(|_| store.current_keys())
    };

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

    let http = reqwest::Client::new();

    for item in plan.items {
        if attempted_transfers >= max_transfers {
            break;
        }

        let Some((key, version_id)) = parse_replication_subject(&item.key) else {
            skipped_items += 1;
            continue;
        };

        let bundle = {
            let store = state.store.lock().await;

            match store
                .export_replication_bundle(&key, version_id.as_deref(), ObjectReadMode::Preferred)
                .await
            {
                Ok(Some(bundle)) => bundle,
                _ => {
                    skipped_items += 1;
                    continue;
                }
            }
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
            let transfer_result = replicate_bundle_to_target(
                &http,
                &node.public_url,
                &bundle,
                &state.store,
                internal_outbound_token(state).await,
                state.node_id,
            )
            .await;

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
                    last_error = Some(err.to_string());

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

async fn replicate_bundle_to_target(
    http: &reqwest::Client,
    target_base_url: &str,
    bundle: &ReplicationExportBundle,
    store: &Arc<Mutex<PersistentStore>>,
    internal_token: Option<String>,
    source_node_id: NodeId,
) -> Result<String> {
    let mut assembled = BytesMut::with_capacity(bundle.manifest.total_size_bytes);

    for chunk in &bundle.manifest.chunks {
        let payload = {
            let guard = store.lock().await;
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

    let put_url = build_internal_replication_put_url(target_base_url, &bundle.key, state_query);
    http.put(put_url)
        .body(assembled.freeze())
        .send()
        .await?
        .error_for_status()?;

    let manifest_url = format!("{target_base_url}/cluster/replication/push/manifest");
    let mut request = http
        .post(manifest_url)
        .query(&ReplicationManifestPushQuery {
            key: bundle.key.clone(),
            version_id: bundle.version_id.clone(),
            state: bundle.state.clone(),
            manifest_hash: bundle.manifest_hash.clone(),
        })
        .body(bundle.manifest_bytes.clone());

    if let Some(token) = internal_token {
        request = request.header("x-ironmesh-internal-token", token);
        request = request.header("x-ironmesh-node-id", source_node_id.to_string());
    }

    let response = request.send().await?.error_for_status()?;

    let report = response.json::<ReplicationManifestPushReport>().await?;
    Ok(report.version_id)
}

pub(crate) fn build_internal_replication_put_url(
    target_base_url: &str,
    key: &str,
    state_query: &str,
) -> String {
    format!("{target_base_url}/store/{key}?state={state_query}&internal_replication=true")
}
