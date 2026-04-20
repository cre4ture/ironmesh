use anyhow::{Context, Result};
use axum::Router;
use axum::body::{Body, to_bytes};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, Request, Uri};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use percent_encoding::percent_decode_str;
use std::borrow::Cow;
use tower::ServiceExt;

use crate::{
    BufferedTransportRequest, BufferedTransportResponse, InternalCaller,
    PUBLIC_API_V1_MEDIA_THUMBNAIL_ROUTE, PUBLIC_API_V1_PREFIX, ServerState,
    StoreIndexChangeWaitQuery, StoreIndexQuery, TransportHeader, build_internal_peer_api,
    cluster_status, commit_version, complete_upload_session_route, confirm_version,
    copy_object_path, delete_object, delete_object_by_query, delete_upload_session,
    enroll_client_device, execute_replication_cleanup, get_media_thumbnail,
    get_media_thumbnail_response, get_object, get_object_response, get_upload_session, head_object,
    health, latency_diagnostic, list_nodes, list_snapshots, list_store_index,
    list_store_index_response, list_tombstone_archives, list_versions, list_versions_response,
    placement_for_key, put_object, reconcile_from_node, redeem_client_bootstrap_claim,
    rename_object_path, replication, replication_plan, require_client_auth,
    require_client_or_admin_auth, require_internal_caller, restore_snapshot_path, run_cleanup,
    run_tombstone_archive_purge, run_tombstone_archive_restore, run_tombstone_compaction,
    start_upload_session, storage_stats_current, storage_stats_history,
    transport_headers_from_response, trigger_replication_audit, upload_session_chunk,
    wait_for_store_index_change,
};

#[derive(Clone)]
pub(super) enum TransportExecutionScope {
    Public,
    Internal(InternalCaller),
}

pub(super) fn strip_public_api_v1_prefix(path: &str) -> &str {
    if let Some(rest) = path.strip_prefix(PUBLIC_API_V1_PREFIX)
        && !rest.is_empty()
        && (rest.starts_with('/') || rest.starts_with('?'))
    {
        rest
    } else {
        path
    }
}

pub(super) fn normalize_public_api_v1_path_and_query(path_and_query: &str) -> Cow<'_, str> {
    let normalized = strip_public_api_v1_prefix(path_and_query);
    if normalized == path_and_query {
        Cow::Borrowed(path_and_query)
    } else {
        Cow::Owned(normalized.to_string())
    }
}

pub(super) async fn execute_buffered_transport_request(
    state: &ServerState,
    scope: &TransportExecutionScope,
    request: &BufferedTransportRequest,
) -> Result<BufferedTransportResponse> {
    if let Some(response) = try_execute_direct_transport_request(state, request).await? {
        return Ok(response);
    }

    execute_fallback_local_router_request(state, scope, request).await
}

async fn try_execute_direct_transport_request(
    state: &ServerState,
    request: &BufferedTransportRequest,
) -> Result<Option<BufferedTransportResponse>> {
    let method = request.method.trim();
    let raw_path = request.path.trim();
    let normalized_raw_path = normalize_public_api_v1_path_and_query(raw_path);
    let path_only = raw_path
        .split_once('?')
        .map(|(path, _)| path)
        .unwrap_or(raw_path);
    let path_only = strip_public_api_v1_prefix(path_only);
    let headers = header_map_from_transport_headers(&request.headers)?;

    let response = match (method, path_only) {
        ("GET", "/health") => Some(health(State(state.clone())).await.into_response()),
        ("GET", "/cluster/status") => {
            Some(cluster_status(State(state.clone())).await.into_response())
        }
        ("GET", "/cluster/nodes") => Some(list_nodes(State(state.clone())).await.into_response()),
        ("GET", "/diagnostics/latency") => {
            let query = parse_query::<crate::LatencyDiagnosticQuery>(raw_path).map_err(|err| {
                anyhow::anyhow!("failed parsing latency diagnostic query {raw_path}: {err}")
            })?;
            Some(latency_diagnostic(State(state.clone()), Query(query)).await)
        }
        ("GET", "/store/index") => {
            let query = parse_query::<StoreIndexQuery>(&normalized_raw_path).map_err(|err| {
                anyhow::anyhow!("failed parsing store index query {raw_path}: {err}")
            })?;
            Some(list_store_index_response(state, query, PUBLIC_API_V1_MEDIA_THUMBNAIL_ROUTE).await)
        }
        ("GET", "/store/index/changes/wait") => {
            let query =
                parse_query::<StoreIndexChangeWaitQuery>(&normalized_raw_path).map_err(|err| {
                    anyhow::anyhow!(
                        "failed parsing store index change wait query {raw_path}: {err}"
                    )
                })?;
            Some(
                wait_for_store_index_change(State(state.clone()), Query(query))
                    .await
                    .into_response(),
            )
        }
        ("GET", "/media/thumbnail") => {
            let query =
                parse_query::<crate::MediaThumbnailQuery>(&normalized_raw_path).map_err(|err| {
                    anyhow::anyhow!("failed parsing media thumbnail query {raw_path}: {err}")
                })?;
            Some(get_media_thumbnail_response(state, query).await)
        }
        ("GET", path) if path.starts_with("/store/uploads/") => {
            let upload_id = decode_route_tail(path, "/store/uploads/")?;
            Some(
                get_upload_session(State(state.clone()), headers.clone(), Path(upload_id))
                    .await
                    .into_response(),
            )
        }
        ("GET", path) if path.starts_with("/store/") => {
            let query = parse_query::<crate::ObjectGetQuery>(&normalized_raw_path)
                .map_err(|err| anyhow::anyhow!("failed parsing object query {raw_path}: {err}"))?;
            let key = decode_route_tail(path, "/store/")?;
            Some(get_object_response(state, &key, query, &headers, false).await)
        }
        ("HEAD", path) if path.starts_with("/store/") => {
            let query =
                parse_query::<crate::ObjectGetQuery>(&normalized_raw_path).map_err(|err| {
                    anyhow::anyhow!("failed parsing object HEAD query {raw_path}: {err}")
                })?;
            let key = decode_route_tail(path, "/store/")?;
            Some(get_object_response(state, &key, query, &headers, true).await)
        }
        ("GET", path) if path.starts_with("/versions/") => {
            let key = decode_route_tail(path, "/versions/")?;
            Some(list_versions_response(state, &key).await)
        }
        _ => None,
    };

    let Some(response) = response else {
        return Ok(None);
    };
    Ok(Some(
        buffered_response_from_axum_response(request.request_id.clone(), response).await?,
    ))
}

async fn execute_fallback_local_router_request(
    state: &ServerState,
    scope: &TransportExecutionScope,
    request: &BufferedTransportRequest,
) -> Result<BufferedTransportResponse> {
    let method = request
        .method
        .parse::<axum::http::Method>()
        .with_context(|| {
            format!(
                "invalid multiplexed transport fallback HTTP method {}",
                request.method
            )
        })?;
    let uri: Uri = request.path.parse().with_context(|| {
        format!(
            "invalid multiplexed transport fallback URI {}",
            request.path
        )
    })?;
    let mut builder = Request::builder().method(method).uri(uri);
    for header in &request.headers {
        if header.name.eq_ignore_ascii_case("host")
            || header.name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        builder = builder.header(&header.name, &header.value);
    }
    let mut outbound = builder
        .body(Body::from(request.body.clone()))
        .context("failed building fallback local multiplex transport request")?;
    if let TransportExecutionScope::Internal(caller) = scope {
        outbound.extensions_mut().insert(caller.clone());
    }

    let response = match scope {
        TransportExecutionScope::Public => build_public_transport_router(state.clone())
            .oneshot(outbound)
            .await
            .context("failed executing public fallback local multiplex transport request")?,
        TransportExecutionScope::Internal(_) => build_internal_transport_router(state.clone())
            .oneshot(outbound)
            .await
            .context("failed executing internal fallback local multiplex transport request")?,
    };
    buffered_response_from_axum_response(request.request_id.clone(), response).await
}

pub(super) fn parse_query<T>(path_and_query: &str) -> Result<T>
where
    T: serde::de::DeserializeOwned,
{
    let uri: Uri = path_and_query
        .parse()
        .with_context(|| format!("invalid transport request URI {path_and_query}"))?;
    Ok(Query::<T>::try_from_uri(&uri)?.0)
}

pub(super) fn decode_route_tail(path: &str, prefix: &str) -> Result<String> {
    let tail = path.strip_prefix(prefix).ok_or_else(|| {
        anyhow::anyhow!("transport request path {path} did not start with {prefix}")
    })?;
    percent_decode_str(tail)
        .decode_utf8()
        .map(|value| value.into_owned())
        .context("failed decoding percent-encoded transport path tail")
}

pub(super) fn header_map_from_transport_headers(headers: &[TransportHeader]) -> Result<HeaderMap> {
    let mut header_map = HeaderMap::new();
    for header in headers {
        let name = header
            .name
            .parse::<axum::http::HeaderName>()
            .with_context(|| format!("invalid transport header name {}", header.name))?;
        let value = HeaderValue::from_str(&header.value)
            .with_context(|| format!("invalid transport header value for {}", header.name))?;
        header_map.append(name, value);
    }
    Ok(header_map)
}

async fn buffered_response_from_axum_response(
    request_id: String,
    response: Response,
) -> Result<BufferedTransportResponse> {
    let (parts, body) = response.into_parts();
    let body = to_bytes(body, usize::MAX)
        .await
        .context("failed buffering transport service response body")?;
    Ok(BufferedTransportResponse {
        request_id,
        status: parts.status.as_u16(),
        headers: transport_headers_from_response(&parts.headers),
        body: body.to_vec(),
    })
}

fn build_public_transport_router(state: ServerState) -> Router {
    let public_client_api = Router::new()
        .route("/diagnostics/latency", get(latency_diagnostic))
        .route("/snapshots", get(list_snapshots))
        .route("/store/index", get(list_store_index))
        .route(
            "/store/index/changes/wait",
            get(wait_for_store_index_change),
        )
        .route("/store/uploads/start", post(start_upload_session))
        .route(
            "/store/uploads/{upload_id}",
            get(get_upload_session).delete(delete_upload_session),
        )
        .route(
            "/store/uploads/{upload_id}/chunk/{index}",
            put(upload_session_chunk),
        )
        .route(
            "/store/uploads/{upload_id}/complete",
            post(complete_upload_session_route),
        )
        .route("/media/thumbnail", get(get_media_thumbnail))
        .route("/store/delete", post(delete_object_by_query))
        .route("/store/rename", post(rename_object_path))
        .route("/store/copy", post(copy_object_path))
        .route("/store/restore", post(restore_snapshot_path))
        .route(
            "/store/{key}",
            put(put_object)
                .get(get_object)
                .head(head_object)
                .delete(delete_object),
        )
        .route("/versions/{key}", get(list_versions))
        .route(
            "/versions/{key}/confirm/{version_id}",
            post(confirm_version),
        )
        .route("/versions/{key}/commit/{version_id}", post(commit_version))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_client_auth,
        ));

    let public_cluster_info_api = Router::new()
        .route("/cluster/status", get(cluster_status))
        .route("/cluster/nodes", get(list_nodes))
        .route("/cluster/replication/plan", get(replication_plan))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_client_or_admin_auth,
        ));

    let public_api_v1 = Router::new()
        .route("/health", get(health))
        .route(
            "/auth/bootstrap-claims/redeem",
            post(redeem_client_bootstrap_claim),
        )
        .route("/auth/device/enroll", post(enroll_client_device))
        .route("/storage/stats/current", get(storage_stats_current))
        .route("/storage/stats/history", get(storage_stats_history))
        .route("/cluster/placement/{key}", get(placement_for_key))
        .route(
            "/cluster/replication/audit",
            post(trigger_replication_audit),
        )
        .route(
            "/cluster/replication/repair",
            post(replication::execute_replication_repair_public),
        )
        .route(
            "/cluster/replication/cleanup",
            post(execute_replication_cleanup),
        )
        .route("/cluster/reconcile/{node_id}", post(reconcile_from_node))
        .route("/maintenance/cleanup", post(run_cleanup))
        .route(
            "/maintenance/tombstones/compact",
            post(run_tombstone_compaction),
        )
        .route(
            "/maintenance/tombstones/archive",
            get(list_tombstone_archives),
        )
        .route(
            "/maintenance/tombstones/archive/restore",
            post(run_tombstone_archive_restore),
        )
        .route(
            "/maintenance/tombstones/archive/purge",
            post(run_tombstone_archive_purge),
        )
        .merge(public_cluster_info_api.clone())
        .merge(public_client_api.clone());

    let legacy_public_api = Router::new()
        .route("/health", get(health))
        .route(
            "/auth/bootstrap-claims/redeem",
            post(redeem_client_bootstrap_claim),
        )
        .route("/auth/device/enroll", post(enroll_client_device))
        .route("/storage/stats/current", get(storage_stats_current))
        .route("/storage/stats/history", get(storage_stats_history))
        .route("/cluster/placement/{key}", get(placement_for_key))
        .route(
            "/cluster/replication/audit",
            post(trigger_replication_audit),
        )
        .route(
            "/cluster/replication/repair",
            post(replication::execute_replication_repair_public),
        )
        .route(
            "/cluster/replication/cleanup",
            post(execute_replication_cleanup),
        )
        .route("/cluster/reconcile/{node_id}", post(reconcile_from_node))
        .route("/maintenance/cleanup", post(run_cleanup))
        .route(
            "/maintenance/tombstones/compact",
            post(run_tombstone_compaction),
        )
        .route(
            "/maintenance/tombstones/archive",
            get(list_tombstone_archives),
        )
        .route(
            "/maintenance/tombstones/archive/restore",
            post(run_tombstone_archive_restore),
        )
        .route(
            "/maintenance/tombstones/archive/purge",
            post(run_tombstone_archive_purge),
        )
        .merge(public_cluster_info_api)
        .merge(public_client_api);

    Router::new()
        .nest(PUBLIC_API_V1_PREFIX, public_api_v1)
        .merge(legacy_public_api)
        .with_state(state)
}

fn build_internal_transport_router(state: ServerState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/diagnostics/latency", get(latency_diagnostic))
        .route(
            "/auth/bootstrap-claims/redeem",
            post(redeem_client_bootstrap_claim),
        )
        .route("/auth/device/enroll", post(enroll_client_device))
        .route("/cluster/status", get(cluster_status))
        .route("/cluster/nodes", get(list_nodes))
        .route("/storage/stats/current", get(storage_stats_current))
        .route("/storage/stats/history", get(storage_stats_history))
        .route("/cluster/placement/{key}", get(placement_for_key))
        .route("/cluster/replication/plan", get(replication_plan))
        .route("/snapshots", get(list_snapshots))
        .route("/store/index", get(list_store_index))
        .route(
            "/store/index/changes/wait",
            get(wait_for_store_index_change),
        )
        .route("/store/uploads/start", post(start_upload_session))
        .route(
            "/store/uploads/{upload_id}",
            get(get_upload_session).delete(delete_upload_session),
        )
        .route(
            "/store/uploads/{upload_id}/chunk/{index}",
            put(upload_session_chunk),
        )
        .route(
            "/store/uploads/{upload_id}/complete",
            post(complete_upload_session_route),
        )
        .route("/media/thumbnail", get(get_media_thumbnail))
        .route("/store/delete", post(delete_object_by_query))
        .route("/store/rename", post(rename_object_path))
        .route("/store/copy", post(copy_object_path))
        .route("/store/restore", post(restore_snapshot_path))
        .route(
            "/store/{key}",
            put(put_object)
                .get(get_object)
                .head(head_object)
                .delete(delete_object),
        )
        .route("/versions/{key}", get(list_versions))
        .route(
            "/versions/{key}/confirm/{version_id}",
            post(confirm_version),
        )
        .route("/versions/{key}/commit/{version_id}", post(commit_version))
        .merge(build_internal_peer_api())
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(
            state,
            require_internal_caller,
        ))
}
