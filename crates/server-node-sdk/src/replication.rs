use super::*;
use bytes::BytesMut;
use storage::{ReplicationExportBundle, TOMBSTONE_MANIFEST_HASH};

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

#[derive(Debug, Serialize)]
struct InternalReplicationDeleteQuery<'a> {
    key: &'a str,
    state: &'a str,
    version_id: Option<&'a str>,
    internal_replication: bool,
}

#[derive(Debug, Serialize)]
struct ReplicationExportRequestQuery<'a> {
    key: &'a str,
    version_id: Option<&'a str>,
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
    sync_replica_views_once(state).await;
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

    let http = state.internal_http.clone();

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
            let store = state.store.lock().await;

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

            match pull_bundle_from_source(&http, source_node, &key, version_id.as_deref(), state)
                .await
            {
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
                        let store = state.store.lock().await;
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
            let transfer_result =
                replicate_bundle_to_target(&http, node, &bundle, &state.store, state).await;

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

async fn pull_bundle_from_source(
    http: &reqwest::Client,
    source_node: &NodeDescriptor,
    key: &str,
    version_id: Option<&str>,
    state: &ServerState,
) -> Result<String> {
    let source_base_url = resolve_peer_base_url(state, source_node)?;
    let source_base_url = source_base_url.trim_end_matches('/');
    let export_url = format!("{source_base_url}/cluster/replication/export");
    let bundle = http
        .get(export_url)
        .query(&ReplicationExportRequestQuery { key, version_id })
        .send()
        .await?
        .error_for_status()?
        .json::<ReplicationExportBundle>()
        .await?;

    if bundle.manifest_hash != TOMBSTONE_MANIFEST_HASH {
        for chunk in &bundle.manifest.chunks {
            let chunk_url = format!("{source_base_url}/cluster/replication/chunk/{}", chunk.hash);
            let payload = http
                .get(chunk_url)
                .send()
                .await?
                .error_for_status()?
                .bytes()
                .await?;

            let store = state.store.lock().await;
            store.ingest_chunk(&chunk.hash, payload.as_ref()).await?;
        }
    }

    let mut store = state.store.lock().await;
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
    http: &reqwest::Client,
    target_node: &NodeDescriptor,
    bundle: &ReplicationExportBundle,
    store: &Arc<Mutex<PersistentStore>>,
    state: &ServerState,
) -> Result<String> {
    let target_base_url = resolve_peer_base_url(state, target_node)?;
    if bundle.manifest_hash == TOMBSTONE_MANIFEST_HASH {
        let state_query = match bundle.state {
            VersionConsistencyState::Confirmed => "confirmed",
            VersionConsistencyState::Provisional => "provisional",
        };

        let delete_url = format!("{target_base_url}/store/delete");
        http.post(delete_url)
            .query(&InternalReplicationDeleteQuery {
                key: &bundle.key,
                state: state_query,
                version_id: bundle.version_id.as_deref(),
                internal_replication: true,
            })
            .send()
            .await
            .with_context(|| {
                format!(
                    "failed to push tombstone key={} version_id={:?} to target={target_base_url}",
                    bundle.key, bundle.version_id
                )
            })?
            .error_for_status()?;

        return bundle
            .version_id
            .clone()
            .context("tombstone replication bundle missing version id");
    }

    if bundle.version_id.is_some() {
        for chunk in &bundle.manifest.chunks {
            let payload = {
                let guard = store.lock().await;
                guard
                    .read_chunk_payload(&chunk.hash)
                    .await?
                    .with_context(|| format!("missing local chunk {}", chunk.hash))?
            };

            let chunk_url = format!(
                "{target_base_url}/cluster/replication/push/chunk/{}",
                chunk.hash
            );
            http.post(chunk_url)
                .body(payload)
                .send()
                .await
                .with_context(|| {
                    format!(
                        "failed to push chunk hash={} key={} version_id={:?} to target={target_base_url}",
                        chunk.hash, bundle.key, bundle.version_id
                    )
                })?
                .error_for_status()?;
        }
    } else {
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

        let put_url = build_internal_replication_put_url(
            &target_base_url,
            &bundle.key,
            state_query,
            bundle.version_id.as_deref(),
        );
        http.put(put_url)
            .body(assembled.freeze())
            .send()
            .await
            .with_context(|| {
                format!(
                    "failed to push assembled object key={} version_id={:?} to target={target_base_url}",
                    bundle.key, bundle.version_id
                )
            })?
            .error_for_status()?;
    }

    let parent_version_ids_json = if bundle.parent_version_ids.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&bundle.parent_version_ids)?)
    };
    let manifest_url = format!("{target_base_url}/cluster/replication/push/manifest");
    let request = http
        .post(manifest_url)
        .query(&ReplicationManifestPushQuery {
            key: bundle.key.clone(),
            version_id: bundle.version_id.clone(),
            parent_version_ids_json,
            state: bundle.state.clone(),
            manifest_hash: bundle.manifest_hash.clone(),
        })
        .body(bundle.manifest_bytes.clone());

    let response = request
        .send()
        .await
        .with_context(|| {
            format!(
                "failed to push manifest key={} version_id={:?} manifest_hash={} to target={target_base_url}",
                bundle.key, bundle.version_id, bundle.manifest_hash
            )
        })?
        .error_for_status()?;

    let report = response.json::<ReplicationManifestPushReport>().await?;
    Ok(report.version_id)
}

pub(crate) fn build_internal_replication_put_url(
    target_base_url: &str,
    key: &str,
    state_query: &str,
    version_id: Option<&str>,
) -> String {
    match version_id {
        Some(version_id) => format!(
            "{target_base_url}/store/{key}?state={state_query}&version_id={version_id}&internal_replication=true"
        ),
        None => {
            format!("{target_base_url}/store/{key}?state={state_query}&internal_replication=true")
        }
    }
}
