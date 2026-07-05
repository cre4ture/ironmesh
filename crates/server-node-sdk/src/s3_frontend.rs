use super::*;
use crate::storage::{ObjectVersionMetadataRecord, S3ObjectVersionRecord};
use axum::extract::{OriginalUri, Path, Query, State};
use axum::http::{HeaderName, Method, Uri};
use axum::routing::get;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;

const S3_XML_NAMESPACE: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
const S3_MAX_LIST_KEYS: usize = 1000;
const S3_LIST_DEFAULT_MAX_KEYS: usize = 1000;
const S3_UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone)]
struct S3RequestContext {
    request_id: String,
    access_key: S3AccessKeyRecord,
}

#[derive(Debug, Clone)]
struct ParsedS3Authorization {
    access_key_id: String,
    credential_scope: String,
    signed_headers: Vec<String>,
    signature_hex: String,
    date_scope: String,
    region: String,
    service: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct S3ListObjectsV2Query {
    #[serde(rename = "list-type")]
    list_type: Option<u8>,
    prefix: Option<String>,
    delimiter: Option<String>,
    #[serde(rename = "continuation-token")]
    continuation_token: Option<String>,
    #[serde(rename = "start-after")]
    start_after: Option<String>,
    #[serde(rename = "max-keys")]
    max_keys: Option<usize>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct S3ObjectQuery {
    #[serde(rename = "versionId")]
    version_id: Option<String>,
    #[serde(rename = "uploadId")]
    upload_id: Option<String>,
    #[serde(rename = "partNumber")]
    part_number: Option<u32>,
}

#[derive(Debug, Clone)]
struct S3ListContentEntry {
    key: String,
    etag: String,
    size_bytes: u64,
    modified_at_unix: u64,
}

pub(crate) fn build_listener_app() -> Router<ServerState> {
    Router::new()
        .route("/", get(list_buckets))
        .route(
            "/{bucket}",
            get(list_bucket_objects)
                .head(head_bucket)
                .post(s3_not_implemented_bucket_post)
                .put(s3_bucket_mutation_not_supported)
                .delete(s3_bucket_mutation_not_supported),
        )
        .route(
            "/{bucket}/{*key}",
            get(get_object)
                .head(head_object)
                .put(put_object)
                .delete(delete_object)
                .post(s3_not_implemented_object_post),
        )
}

async fn list_buckets(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let request = match authenticate_request(&state, &Method::GET, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if !request.access_key.allow_list {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to list buckets",
            uri.path(),
            &request.request_id,
        );
    }

    let buckets = visible_buckets(&state, &request.access_key).await;
    let mut xml =
        String::from(r#"<?xml version="1.0" encoding="UTF-8"?><ListAllMyBucketsResult xmlns=""#);
    xml.push('"');
    xml.push_str(S3_XML_NAMESPACE);
    xml.push_str(r#""><Owner><ID>"#);
    xml.push_str(&xml_escape(&state.cluster_id.to_string()));
    xml.push_str(r#"</ID><DisplayName>ironmesh</DisplayName></Owner><Buckets>"#);
    for bucket in buckets {
        xml.push_str("<Bucket><Name>");
        xml.push_str(&xml_escape(&bucket.bucket_name));
        xml.push_str("</Name><CreationDate>");
        xml.push_str(&xml_escape(&s3_timestamp(bucket.created_at_unix)));
        xml.push_str("</CreationDate></Bucket>");
    }
    xml.push_str("</Buckets></ListAllMyBucketsResult>");

    xml_response(StatusCode::OK, xml, &request.request_id)
}

async fn head_bucket(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(bucket_name): Path<String>,
) -> Response {
    let request = match authenticate_request(&state, &Method::HEAD, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if !request.access_key.allow_list {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to inspect buckets",
            uri.path(),
            &request.request_id,
        );
    }

    let bucket = match resolve_bucket(&state, &bucket_name).await {
        Some(bucket) => bucket,
        None => {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
                uri.path(),
                &request.request_id,
            );
        }
    };
    if !access_key_allows_bucket(&request.access_key, &bucket) {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to access this bucket",
            uri.path(),
            &request.request_id,
        );
    }

    let mut response = StatusCode::OK.into_response();
    append_request_id_header(&mut response, &request.request_id);
    response
}

async fn list_bucket_objects(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(bucket_name): Path<String>,
    Query(query): Query<S3ListObjectsV2Query>,
) -> Response {
    let request = match authenticate_request(&state, &Method::GET, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if !request.access_key.allow_list {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to list objects",
            uri.path(),
            &request.request_id,
        );
    }
    if query.list_type.is_some_and(|value| value != 2) {
        return s3_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "only list-type=2 is supported",
            uri.path(),
            &request.request_id,
        );
    }

    let bucket = match resolve_bucket(&state, &bucket_name).await {
        Some(bucket) => bucket,
        None => {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
                uri.path(),
                &request.request_id,
            );
        }
    };
    if !access_key_allows_bucket(&request.access_key, &bucket) {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to access this bucket",
            uri.path(),
            &request.request_id,
        );
    }

    let prefix = query.prefix.unwrap_or_default();
    let delimiter = query
        .delimiter
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("");
    let continuation_marker = match query
        .continuation_token
        .as_deref()
        .or(query.start_after.as_deref())
    {
        Some(value) if query.continuation_token.is_some() => match decode_continuation_token(value)
        {
            Ok(value) => Some(value),
            Err(()) => {
                return s3_error_response(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "the continuation token could not be decoded",
                    uri.path(),
                    &request.request_id,
                );
            }
        },
        Some(value) => Some(value.to_string()),
        None => None,
    };
    let max_keys = query
        .max_keys
        .unwrap_or(S3_LIST_DEFAULT_MAX_KEYS)
        .min(S3_MAX_LIST_KEYS);

    let inspector = {
        let store = read_store(&state, "s3.list.clone_inspector").await;
        store.store_index_inspector()
    };
    let object_hashes = inspector.current_object_hashes();
    let object_ids = inspector.current_object_ids();

    let mut relative_keys = object_hashes
        .iter()
        .filter(|(key, manifest_hash)| {
            manifest_hash.as_str() != TOMBSTONE_MANIFEST_HASH
                && key.starts_with(&bucket.root_prefix)
                && access_key_allows_storage_path(&request.access_key, key)
        })
        .filter_map(|(key, _)| {
            full_key_to_object_key(&bucket, key).map(|object_key| (object_key, key.clone()))
        })
        .filter(|(object_key, _)| object_key.starts_with(&prefix))
        .collect::<Vec<_>>();
    relative_keys.sort_by(|left, right| left.0.cmp(&right.0));

    let mut contents = Vec::new();
    let mut common_prefixes = Vec::new();
    let mut selected_hashes = HashMap::new();
    let mut selected_object_ids = HashMap::new();
    let mut results_count = 0usize;
    let mut last_processed_key = None::<String>;
    let mut index = 0usize;

    while index < relative_keys.len() && results_count < max_keys {
        let (object_key, full_key) = &relative_keys[index];
        if continuation_marker
            .as_deref()
            .is_some_and(|marker| object_key.as_str() <= marker)
        {
            index += 1;
            continue;
        }

        let remainder = object_key
            .strip_prefix(&prefix)
            .unwrap_or(object_key.as_str());
        if !delimiter.is_empty() && !remainder.is_empty() {
            if let Some(separator_index) = remainder.find(delimiter) {
                let common_prefix = format!(
                    "{prefix}{}",
                    &remainder[..separator_index + delimiter.len()]
                );
                common_prefixes.push(common_prefix.clone());
                results_count += 1;
                while index < relative_keys.len()
                    && relative_keys[index].0.starts_with(&common_prefix)
                {
                    last_processed_key = Some(relative_keys[index].0.clone());
                    index += 1;
                }
                continue;
            }
        }

        let manifest_hash = object_hashes.get(full_key).cloned().unwrap_or_default();
        selected_hashes.insert(full_key.clone(), manifest_hash);
        if let Some(object_id) = object_ids.get(full_key).cloned() {
            selected_object_ids.insert(full_key.clone(), object_id);
        }
        contents.push((object_key.clone(), full_key.clone()));
        last_processed_key = Some(object_key.clone());
        results_count += 1;
        index += 1;
    }

    let is_truncated = index < relative_keys.len();
    let next_continuation_token = if is_truncated {
        last_processed_key.as_deref().map(encode_continuation_token)
    } else {
        None
    };

    let (sizes, _) = match inspector
        .object_sizes_and_content_fingerprints_by_key(&selected_hashes)
        .await
    {
        Ok(values) => values,
        Err(err) => {
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("failed to inspect object sizes: {err:#}"),
                uri.path(),
                &request.request_id,
            );
        }
    };
    let modified = match inspector
        .object_modified_at_by_key(&selected_hashes, &selected_object_ids, None)
        .await
    {
        Ok(values) => values,
        Err(err) => {
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("failed to inspect object modification times: {err:#}"),
                uri.path(),
                &request.request_id,
            );
        }
    };

    let content_entries = contents
        .into_iter()
        .map(|(object_key, full_key)| S3ListContentEntry {
            key: object_key,
            etag: object_etag(
                selected_hashes
                    .get(&full_key)
                    .map(String::as_str)
                    .unwrap_or_default(),
            ),
            size_bytes: sizes.get(&full_key).copied().unwrap_or(0),
            modified_at_unix: modified.get(&full_key).copied().unwrap_or(0),
        })
        .collect::<Vec<_>>();

    let key_count = content_entries.len() + common_prefixes.len();
    let xml = render_list_objects_v2_result(
        &bucket,
        &prefix,
        delimiter,
        max_keys,
        continuation_marker.as_deref(),
        next_continuation_token.as_deref(),
        is_truncated,
        key_count,
        &content_entries,
        &common_prefixes,
    );

    xml_response(StatusCode::OK, xml, &request.request_id)
}

async fn get_object(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path((bucket_name, raw_key)): Path<(String, String)>,
    Query(query): Query<S3ObjectQuery>,
) -> Response {
    get_or_head_object_response(
        &state,
        &Method::GET,
        uri,
        headers,
        bucket_name,
        raw_key,
        query,
        false,
    )
    .await
}

async fn head_object(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path((bucket_name, raw_key)): Path<(String, String)>,
    Query(query): Query<S3ObjectQuery>,
) -> Response {
    get_or_head_object_response(
        &state,
        &Method::HEAD,
        uri,
        headers,
        bucket_name,
        raw_key,
        query,
        true,
    )
    .await
}

async fn put_object(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path((bucket_name, raw_key)): Path<(String, String)>,
    Query(query): Query<S3ObjectQuery>,
    payload: Bytes,
) -> Response {
    let request = match authenticate_request(&state, &Method::PUT, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if query.upload_id.is_some() || query.part_number.is_some() {
        return s3_error_response(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "multipart upload operations are not implemented yet",
            uri.path(),
            &request.request_id,
        );
    }
    if !request.access_key.allow_write {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to write objects",
            uri.path(),
            &request.request_id,
        );
    }

    let bucket = match resolve_bucket(&state, &bucket_name).await {
        Some(bucket) => bucket,
        None => {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
                uri.path(),
                &request.request_id,
            );
        }
    };
    if bucket.read_only {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the bucket mapping is read-only",
            uri.path(),
            &request.request_id,
        );
    }

    let object_key = raw_key.trim_start_matches('/').to_string();
    let full_key = format!("{}{}", bucket.root_prefix, object_key);
    if !access_key_allows_object(&request.access_key, &bucket, &full_key) {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to write this object path",
            uri.path(),
            &request.request_id,
        );
    }

    let metadata = object_metadata_from_headers(&headers);
    let total_size_bytes = u64::try_from(payload.len()).unwrap_or(u64::MAX);
    let actor = s3_actor_context(&request.access_key);
    let mut store = lock_store(&state, "s3.put_object.store").await;
    let outcome = match store
        .put_object_versioned(&full_key, payload, PutOptions::default())
        .await
    {
        Ok(outcome) => outcome,
        Err(err) => {
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("failed to store S3 object: {err:#}"),
                uri.path(),
                &request.request_id,
            );
        }
    };
    if let Err(err) = store
        .persist_object_version_metadata(&ObjectVersionMetadataRecord {
            version_id: outcome.version_id.clone(),
            content_type: metadata.content_type.clone(),
            content_encoding: metadata.content_encoding.clone(),
            content_language: metadata.content_language.clone(),
            cache_control: metadata.cache_control.clone(),
            content_disposition: metadata.content_disposition.clone(),
            user_metadata: metadata.user_metadata.clone(),
            checksum_sha256: metadata.checksum_sha256.clone(),
            checksum_crc32c: metadata.checksum_crc32c.clone(),
            updated_at_unix: unix_ts(),
        })
        .await
    {
        return s3_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("failed to persist S3 object metadata: {err:#}"),
            uri.path(),
            &request.request_id,
        );
    }
    if let Err(err) = store
        .persist_s3_object_version(&S3ObjectVersionRecord {
            bucket_name: bucket.bucket_name.clone(),
            ironmesh_key: full_key.clone(),
            version_id: outcome.version_id.clone(),
            etag: object_etag(&outcome.manifest_hash),
            multipart_part_count: None,
            created_at_unix: unix_ts(),
        })
        .await
    {
        return s3_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("failed to persist S3 object version record: {err:#}"),
            uri.path(),
            &request.request_id,
        );
    }
    drop(store);

    publish_namespace_change(&state);
    spawn_media_metadata_warmup(
        state.clone(),
        full_key.clone(),
        outcome.manifest_hash.clone(),
    );

    let mut cluster = state.cluster.lock().await;
    cluster.note_replica(&full_key, state.node_id);
    cluster.note_replica(
        format!("{}@{}", full_key, outcome.version_id.as_str()),
        state.node_id,
    );
    drop(cluster);
    if let Err(err) = persist_cluster_replicas_state(&state).await {
        warn!(
            error = %err,
            key = %full_key,
            "failed persisting cluster replicas after S3 PUT"
        );
    }
    if should_trigger_autonomous_post_write_replication(
        state.autonomous_replication_on_put_enabled,
        false,
    ) {
        enqueue_autonomous_post_write_replication(
            &state,
            autonomous_post_write_replication_subjects(&full_key, outcome.version_id.as_str()),
        )
        .await;
    }
    record_data_change_event(
        &state,
        PendingDataChangeEvent {
            action: DataChangeAction::Upload,
            actor: Some(actor),
            path: full_key,
            from_path: None,
            to_path: None,
            recursive: false,
            affected_path_count: 1,
            total_size_bytes: Some(total_size_bytes),
            version_id: Some(outcome.version_id.clone()),
            snapshot_id: Some(outcome.snapshot_id.clone()),
            upload_mode: Some(DataChangeUploadMode::Direct),
        },
    )
    .await;

    let mut response = StatusCode::OK.into_response();
    append_request_id_header(&mut response, &request.request_id);
    append_etag_header(&mut response, &object_etag(&outcome.manifest_hash));
    append_version_id_header(&mut response, Some(&outcome.version_id));
    response
}

async fn delete_object(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path((bucket_name, raw_key)): Path<(String, String)>,
    Query(query): Query<S3ObjectQuery>,
) -> Response {
    let request = match authenticate_request(&state, &Method::DELETE, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if query.upload_id.is_some() || query.part_number.is_some() {
        return s3_error_response(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "multipart upload operations are not implemented yet",
            uri.path(),
            &request.request_id,
        );
    }
    if !request.access_key.allow_delete {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to delete objects",
            uri.path(),
            &request.request_id,
        );
    }

    let bucket = match resolve_bucket(&state, &bucket_name).await {
        Some(bucket) => bucket,
        None => {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
                uri.path(),
                &request.request_id,
            );
        }
    };
    if bucket.read_only {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the bucket mapping is read-only",
            uri.path(),
            &request.request_id,
        );
    }

    let object_key = raw_key.trim_start_matches('/').to_string();
    let full_key = format!("{}{}", bucket.root_prefix, object_key);
    if !access_key_allows_object(&request.access_key, &bucket, &full_key) {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to delete this object path",
            uri.path(),
            &request.request_id,
        );
    }

    let actor = s3_actor_context(&request.access_key);
    let mut store = lock_store(&state, "s3.delete_object.store").await;
    let version_id = match store
        .tombstone_object(&full_key, PutOptions::default())
        .await
    {
        Ok(version_id) => version_id,
        Err(err) => {
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("failed to delete S3 object: {err:#}"),
                uri.path(),
                &request.request_id,
            );
        }
    };
    let s3_object_version = S3ObjectVersionRecord {
        bucket_name: bucket.bucket_name.clone(),
        ironmesh_key: full_key.clone(),
        version_id: version_id.clone(),
        etag: object_etag(TOMBSTONE_MANIFEST_HASH),
        multipart_part_count: None,
        created_at_unix: unix_ts(),
    };
    if let Err(err) = store.persist_s3_object_version(&s3_object_version).await {
        return s3_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("failed to persist S3 tombstone version record: {err:#}"),
            uri.path(),
            &request.request_id,
        );
    }
    drop(store);

    publish_namespace_change(&state);
    let mut cluster = state.cluster.lock().await;
    cluster.note_replica(&full_key, state.node_id);
    cluster.note_replica(format!("{}@{}", full_key, version_id), state.node_id);
    drop(cluster);
    if let Err(err) = persist_cluster_replicas_state(&state).await {
        warn!(
            error = %err,
            key = %full_key,
            "failed persisting cluster replicas after S3 DELETE"
        );
    }
    if should_trigger_autonomous_post_write_replication(
        state.autonomous_replication_on_put_enabled,
        false,
    ) {
        enqueue_autonomous_post_write_replication(
            &state,
            autonomous_post_write_replication_subjects(&full_key, &version_id),
        )
        .await;
    }
    record_data_change_event(
        &state,
        PendingDataChangeEvent {
            action: DataChangeAction::Delete,
            actor: Some(actor),
            path: full_key,
            from_path: None,
            to_path: None,
            recursive: false,
            affected_path_count: 1,
            total_size_bytes: None,
            version_id: Some(version_id.clone()),
            snapshot_id: None,
            upload_mode: None,
        },
    )
    .await;

    let mut response = StatusCode::NO_CONTENT.into_response();
    append_request_id_header(&mut response, &request.request_id);
    append_version_id_header(&mut response, Some(&version_id));
    response
}

async fn get_or_head_object_response(
    state: &ServerState,
    method: &Method,
    uri: Uri,
    headers: HeaderMap,
    bucket_name: String,
    raw_key: String,
    query: S3ObjectQuery,
    head_only: bool,
) -> Response {
    let request = match authenticate_request(state, method, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if !request.access_key.allow_read {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to read objects",
            uri.path(),
            &request.request_id,
        );
    }
    if query.upload_id.is_some() || query.part_number.is_some() {
        return s3_error_response(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "multipart upload operations are not implemented yet",
            uri.path(),
            &request.request_id,
        );
    }

    let bucket = match resolve_bucket(state, &bucket_name).await {
        Some(bucket) => bucket,
        None => {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
                uri.path(),
                &request.request_id,
            );
        }
    };
    let object_key = raw_key.trim_start_matches('/').to_string();
    let full_key = format!("{}{}", bucket.root_prefix, object_key);
    if !access_key_allows_object(&request.access_key, &bucket, &full_key) {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to read this object path",
            uri.path(),
            &request.request_id,
        );
    }

    let resolved_version_id = match resolve_requested_version_id(
        state,
        &bucket,
        &full_key,
        query.version_id.as_deref(),
        uri.path(),
        &request.request_id,
    )
    .await
    {
        Ok(version_id) => version_id,
        Err(response) => return response,
    };
    let object_response = super::get_object_response(
        state,
        &full_key,
        ObjectGetQuery {
            snapshot: None,
            version: resolved_version_id.clone(),
            read_mode: None,
        },
        &headers,
        head_only,
    )
    .await;
    if !object_response.status().is_success() {
        let status = object_response.status();
        return match status {
            StatusCode::NOT_FOUND => s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                "the specified key does not exist",
                uri.path(),
                &request.request_id,
            ),
            StatusCode::RANGE_NOT_SATISFIABLE => {
                let mut response = object_response;
                append_request_id_header(&mut response, &request.request_id);
                response
            }
            StatusCode::CONFLICT => s3_error_response(
                StatusCode::CONFLICT,
                "InvalidObjectState",
                "the object could not be read because its storage state is inconsistent",
                uri.path(),
                &request.request_id,
            ),
            _ => s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "the object could not be read",
                uri.path(),
                &request.request_id,
            ),
        };
    }

    let metadata = match resolved_version_id.as_deref() {
        Some(version_id) => {
            let store = read_store(state, "s3.get_object.load_metadata").await;
            match store.load_object_version_metadata(version_id).await {
                Ok(record) => record,
                Err(err) => {
                    return s3_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("failed to load S3 object metadata: {err:#}"),
                        uri.path(),
                        &request.request_id,
                    );
                }
            }
        }
        None => None,
    };

    let mut response = object_response;
    append_request_id_header(&mut response, &request.request_id);
    append_version_id_header(&mut response, resolved_version_id.as_deref());
    append_object_metadata_headers(&mut response, metadata.as_ref());
    response
}

async fn s3_bucket_mutation_not_supported(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let method = headers
        .get("x-http-method-override")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| Method::from_bytes(value.as_bytes()).ok())
        .unwrap_or(Method::PUT);
    let request = match authenticate_request(&state, &method, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    s3_error_response(
        StatusCode::FORBIDDEN,
        "AccessDenied",
        "bucket creation and deletion are managed through the Ironmesh admin control plane",
        uri.path(),
        &request.request_id,
    )
}

async fn s3_not_implemented_bucket_post(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let request = match authenticate_request(&state, &Method::POST, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    s3_error_response(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        "bucket POST operations are not implemented yet",
        uri.path(),
        &request.request_id,
    )
}

async fn s3_not_implemented_object_post(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    let request = match authenticate_request(&state, &Method::POST, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    s3_error_response(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        "multipart upload operations are not implemented yet",
        uri.path(),
        &request.request_id,
    )
}

async fn authenticate_request(
    state: &ServerState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<S3RequestContext, Response> {
    if uri
        .query()
        .is_some_and(|query| query.contains("X-Amz-Signature="))
    {
        let request_id = new_s3_request_id();
        return Err(s3_error_response(
            StatusCode::NOT_IMPLEMENTED,
            "NotImplemented",
            "presigned S3 requests are not implemented yet",
            uri.path(),
            &request_id,
        ));
    }

    let request_id = new_s3_request_id();
    let authorization = match headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    {
        Some(value) => value,
        None => {
            return Err(s3_error_response(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "an AWS Signature Version 4 Authorization header is required",
                uri.path(),
                &request_id,
            ));
        }
    };
    let parsed = match parse_authorization_header(authorization) {
        Ok(parsed) => parsed,
        Err(message) => {
            return Err(s3_error_response(
                StatusCode::FORBIDDEN,
                "AuthorizationHeaderMalformed",
                &message,
                uri.path(),
                &request_id,
            ));
        }
    };
    if parsed.service != "s3" {
        return Err(s3_error_response(
            StatusCode::FORBIDDEN,
            "AuthorizationHeaderMalformed",
            "the authorization header must target the s3 service",
            uri.path(),
            &request_id,
        ));
    }

    let access_key = {
        let control_plane = state.s3.control_plane.lock().await;
        control_plane
            .access_keys
            .iter()
            .find(|access_key| {
                access_key.access_key_id == parsed.access_key_id
                    && access_key.revoked_at_unix.is_none()
            })
            .cloned()
    };
    let Some(access_key) = access_key else {
        return Err(s3_error_response(
            StatusCode::FORBIDDEN,
            "InvalidAccessKeyId",
            "the provided access key is not recognized",
            uri.path(),
            &request_id,
        ));
    };

    let expected_signature = match build_expected_signature(
        method,
        uri,
        headers,
        &parsed,
        &access_key.secret_material,
    ) {
        Ok(signature) => signature,
        Err(message) => {
            return Err(s3_error_response(
                StatusCode::FORBIDDEN,
                "SignatureDoesNotMatch",
                &message,
                uri.path(),
                &request_id,
            ));
        }
    };
    if !constant_time_eq(
        expected_signature.as_bytes(),
        parsed.signature_hex.to_ascii_lowercase().as_bytes(),
    ) {
        return Err(s3_error_response(
            StatusCode::FORBIDDEN,
            "SignatureDoesNotMatch",
            "the request signature we calculated does not match the provided signature",
            uri.path(),
            &request_id,
        ));
    }

    Ok(S3RequestContext {
        request_id,
        access_key,
    })
}

fn parse_authorization_header(value: &str) -> Result<ParsedS3Authorization, String> {
    let raw = value.trim();
    let Some(rest) = raw.strip_prefix("AWS4-HMAC-SHA256 ") else {
        return Err("only AWS4-HMAC-SHA256 authorization is supported".to_string());
    };

    let mut credential = None::<String>;
    let mut signed_headers = None::<Vec<String>>;
    let mut signature_hex = None::<String>;

    for part in rest.split(',') {
        let Some((name, value)) = part.trim().split_once('=') else {
            continue;
        };
        match name {
            "Credential" => credential = Some(value.trim().to_string()),
            "SignedHeaders" => {
                signed_headers = Some(
                    value
                        .split(';')
                        .map(|entry| entry.trim().to_ascii_lowercase())
                        .filter(|entry| !entry.is_empty())
                        .collect(),
                );
            }
            "Signature" => signature_hex = Some(value.trim().to_ascii_lowercase()),
            _ => {}
        }
    }

    let credential = credential.ok_or_else(|| "Credential is missing".to_string())?;
    let signed_headers = signed_headers.ok_or_else(|| "SignedHeaders is missing".to_string())?;
    let signature_hex = signature_hex.ok_or_else(|| "Signature is missing".to_string())?;
    let credential_parts = credential.split('/').collect::<Vec<_>>();
    if credential_parts.len() != 5 {
        return Err(
            "Credential scope must contain access key, date, region, service, and aws4_request"
                .to_string(),
        );
    }
    if credential_parts[4] != "aws4_request" {
        return Err("Credential scope must end with aws4_request".to_string());
    }

    Ok(ParsedS3Authorization {
        access_key_id: credential_parts[0].to_string(),
        credential_scope: credential_parts[1..].join("/"),
        signed_headers,
        signature_hex,
        date_scope: credential_parts[1].to_string(),
        region: credential_parts[2].to_string(),
        service: credential_parts[3].to_string(),
    })
}

fn build_expected_signature(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    parsed: &ParsedS3Authorization,
    secret_material: &str,
) -> Result<String, String> {
    let amz_date = headers
        .get("x-amz-date")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "x-amz-date is missing".to_string())?;
    let payload_hash = headers
        .get("x-amz-content-sha256")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "x-amz-content-sha256 is missing".to_string())?;
    let payload_hash = if payload_hash.eq_ignore_ascii_case(S3_UNSIGNED_PAYLOAD) {
        S3_UNSIGNED_PAYLOAD
    } else {
        payload_hash
    };

    let canonical_request =
        build_canonical_request(method, uri, headers, &parsed.signed_headers, payload_hash)?;
    let canonical_request_hash = hex_sha256(canonical_request.as_bytes());
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{}\n{canonical_request_hash}",
        parsed.credential_scope
    );
    let signing_key = derive_signing_key(
        secret_material,
        &parsed.date_scope,
        &parsed.region,
        &parsed.service,
    );
    Ok(hex_encode(&hmac_sha256(
        &signing_key,
        string_to_sign.as_bytes(),
    )))
}

fn build_canonical_request(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    signed_headers: &[String],
    payload_hash: &str,
) -> Result<String, String> {
    let canonical_uri = if uri.path().is_empty() {
        "/"
    } else {
        uri.path()
    };
    let canonical_query = canonical_query_string(uri);
    let canonical_headers = canonical_headers(headers, signed_headers)?;
    let signed_headers_value = signed_headers.join(";");
    Ok(format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.as_str(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers_value,
        payload_hash
    ))
}

fn canonical_query_string(uri: &Uri) -> String {
    let mut pairs = uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (name.to_string(), value.to_string())
        })
        .collect::<Vec<_>>();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn canonical_headers(headers: &HeaderMap, signed_headers: &[String]) -> Result<String, String> {
    let mut result = String::new();
    for header_name in signed_headers {
        let name = HeaderName::from_bytes(header_name.as_bytes())
            .map_err(|_| format!("signed header {header_name:?} is invalid"))?;
        let value = headers
            .get_all(name)
            .iter()
            .map(|value| {
                value
                    .to_str()
                    .map(normalize_header_value)
                    .map_err(|_| format!("header {header_name:?} is not valid UTF-8"))
            })
            .collect::<Result<Vec<_>, _>>()?
            .join(",");
        if value.is_empty() {
            return Err(format!("signed header {header_name:?} is missing"));
        }
        result.push_str(header_name);
        result.push(':');
        result.push_str(&value);
        result.push('\n');
    }
    Ok(result)
}

fn normalize_header_value(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn derive_signing_key(secret_material: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let secret_key = format!("AWS4{secret_material}");
    let date_key = hmac_sha256(secret_key.as_bytes(), date.as_bytes());
    let region_key = hmac_sha256(&date_key, region.as_bytes());
    let service_key = hmac_sha256(&region_key, service.as_bytes());
    hmac_sha256(&service_key, b"aws4_request").to_vec()
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary key sizes");
    mac.update(data);
    let bytes = mac.finalize().into_bytes();
    let mut output = [0_u8; 32];
    output.copy_from_slice(&bytes);
    output
}

fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex_encode(&hasher.finalize())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        result.push_str(&format!("{byte:02x}"));
    }
    result
}

async fn resolve_bucket(state: &ServerState, bucket_name: &str) -> Option<S3BucketRecord> {
    let control_plane = state.s3.control_plane.lock().await;
    control_plane
        .buckets
        .iter()
        .find(|bucket| bucket.bucket_name == bucket_name && bucket.deleted_at_unix.is_none())
        .cloned()
}

async fn visible_buckets(
    state: &ServerState,
    access_key: &S3AccessKeyRecord,
) -> Vec<S3BucketRecord> {
    let control_plane = state.s3.control_plane.lock().await;
    control_plane
        .buckets
        .iter()
        .filter(|bucket| bucket.deleted_at_unix.is_none())
        .filter(|bucket| access_key_allows_bucket(access_key, bucket))
        .cloned()
        .collect()
}

fn access_key_allows_bucket(access_key: &S3AccessKeyRecord, bucket: &S3BucketRecord) -> bool {
    let bucket_allowed =
        access_key.bucket_scope.is_empty() || access_key.bucket_scope.contains(&bucket.bucket_name);
    let prefix_allowed = access_key.prefix_scope.is_empty()
        || access_key.prefix_scope.iter().any(|scope| {
            bucket.root_prefix.starts_with(scope) || scope.starts_with(&bucket.root_prefix)
        });
    bucket_allowed && prefix_allowed
}

fn access_key_allows_storage_path(access_key: &S3AccessKeyRecord, full_key: &str) -> bool {
    access_key.prefix_scope.is_empty()
        || access_key
            .prefix_scope
            .iter()
            .any(|scope| full_key.starts_with(scope))
}

fn access_key_allows_object(
    access_key: &S3AccessKeyRecord,
    bucket: &S3BucketRecord,
    full_key: &str,
) -> bool {
    access_key_allows_bucket(access_key, bucket)
        && access_key_allows_storage_path(access_key, full_key)
}

fn full_key_to_object_key(bucket: &S3BucketRecord, full_key: &str) -> Option<String> {
    full_key
        .strip_prefix(&bucket.root_prefix)
        .map(ToString::to_string)
}

async fn resolve_requested_version_id(
    state: &ServerState,
    bucket: &S3BucketRecord,
    full_key: &str,
    requested_version_id: Option<&str>,
    request_path: &str,
    request_id: &str,
) -> Result<Option<String>, Response> {
    if let Some(version_id) = requested_version_id {
        let store = read_store(state, "s3.get_object.load_version_record").await;
        let version = match store
            .load_s3_object_version(&bucket.bucket_name, version_id)
            .await
        {
            Ok(record) => record,
            Err(err) => {
                return Err(s3_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("failed to load S3 object version record: {err:#}"),
                    request_path,
                    request_id,
                ));
            }
        };
        let Some(version) = version else {
            return Ok(None);
        };
        if version.ironmesh_key != full_key {
            return Ok(None);
        }
        return Ok(Some(version.version_id));
    }

    let store = read_store(state, "s3.get_object.list_versions").await;
    let versions = match store.list_versions(full_key).await {
        Ok(versions) => versions,
        Err(err) => {
            return Err(s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("failed to inspect object versions: {err:#}"),
                request_path,
                request_id,
            ));
        }
    };
    Ok(
        if bucket.versioning_status == S3BucketVersioningStatus::Enabled {
            versions.and_then(|graph| graph.preferred_head_version_id)
        } else {
            None
        },
    )
}

fn object_metadata_from_headers(headers: &HeaderMap) -> ObjectVersionMetadataRecord {
    let mut user_metadata = BTreeMap::new();
    for (name, value) in headers {
        let name = name.as_str();
        if let Some(metadata_key) = name.strip_prefix("x-amz-meta-") {
            if let Ok(value) = value.to_str() {
                user_metadata.insert(metadata_key.to_string(), value.to_string());
            }
        }
    }

    ObjectVersionMetadataRecord {
        version_id: String::new(),
        content_type: header_value(headers, header::CONTENT_TYPE),
        content_encoding: header_value(headers, header::CONTENT_ENCODING),
        content_language: header_value(headers, header::CONTENT_LANGUAGE),
        cache_control: header_value(headers, header::CACHE_CONTROL),
        content_disposition: header_value(headers, header::CONTENT_DISPOSITION),
        user_metadata,
        checksum_sha256: header_value_name(headers, "x-amz-checksum-sha256"),
        checksum_crc32c: header_value_name(headers, "x-amz-checksum-crc32c"),
        updated_at_unix: unix_ts(),
    }
}

fn header_value(headers: &HeaderMap, name: HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn header_value_name(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn append_object_metadata_headers(
    response: &mut Response,
    metadata: Option<&ObjectVersionMetadataRecord>,
) {
    let Some(metadata) = metadata else {
        return;
    };
    insert_optional_header(
        response,
        header::CONTENT_TYPE.as_str(),
        metadata.content_type.as_deref(),
    );
    insert_optional_header(
        response,
        header::CONTENT_ENCODING.as_str(),
        metadata.content_encoding.as_deref(),
    );
    insert_optional_header(
        response,
        header::CONTENT_LANGUAGE.as_str(),
        metadata.content_language.as_deref(),
    );
    insert_optional_header(
        response,
        header::CACHE_CONTROL.as_str(),
        metadata.cache_control.as_deref(),
    );
    insert_optional_header(
        response,
        header::CONTENT_DISPOSITION.as_str(),
        metadata.content_disposition.as_deref(),
    );
    insert_optional_header(
        response,
        "x-amz-checksum-sha256",
        metadata.checksum_sha256.as_deref(),
    );
    insert_optional_header(
        response,
        "x-amz-checksum-crc32c",
        metadata.checksum_crc32c.as_deref(),
    );
    for (key, value) in &metadata.user_metadata {
        insert_optional_header(
            response,
            &format!("x-amz-meta-{key}"),
            Some::<&str>(value.as_str()),
        );
    }
}

fn insert_optional_header(response: &mut Response, name: &str, value: Option<&str>) {
    let Some(value) = value else {
        return;
    };
    let Ok(header_name) = HeaderName::from_bytes(name.as_bytes()) else {
        return;
    };
    let Ok(header_value) = HeaderValue::from_str(value) else {
        return;
    };
    response.headers_mut().insert(header_name, header_value);
}

fn s3_actor_context(access_key: &S3AccessKeyRecord) -> DataChangeActorContext {
    DataChangeActorContext {
        actor_kind: DataChangeActorKind::Unknown,
        actor_id: Some(access_key.access_key_id.clone()),
        actor_label: access_key.description.clone(),
        actor_credential_fingerprint: None,
        actor_source_node: None,
    }
}

fn render_list_objects_v2_result(
    bucket: &S3BucketRecord,
    prefix: &str,
    delimiter: &str,
    max_keys: usize,
    continuation_token: Option<&str>,
    next_continuation_token: Option<&str>,
    is_truncated: bool,
    key_count: usize,
    contents: &[S3ListContentEntry],
    common_prefixes: &[String],
) -> String {
    let mut xml =
        String::from(r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns=""#);
    xml.push('"');
    xml.push_str(S3_XML_NAMESPACE);
    xml.push_str(r#""><Name>"#);
    xml.push_str(&xml_escape(&bucket.bucket_name));
    xml.push_str("</Name><Prefix>");
    xml.push_str(&xml_escape(prefix));
    xml.push_str("</Prefix><Delimiter>");
    xml.push_str(&xml_escape(delimiter));
    xml.push_str("</Delimiter><MaxKeys>");
    xml.push_str(&max_keys.to_string());
    xml.push_str("</MaxKeys><KeyCount>");
    xml.push_str(&key_count.to_string());
    xml.push_str("</KeyCount><IsTruncated>");
    xml.push_str(if is_truncated { "true" } else { "false" });
    xml.push_str("</IsTruncated>");
    if let Some(token) = continuation_token {
        xml.push_str("<ContinuationToken>");
        xml.push_str(&xml_escape(token));
        xml.push_str("</ContinuationToken>");
    }
    if let Some(token) = next_continuation_token {
        xml.push_str("<NextContinuationToken>");
        xml.push_str(&xml_escape(token));
        xml.push_str("</NextContinuationToken>");
    }
    for entry in contents {
        xml.push_str("<Contents><Key>");
        xml.push_str(&xml_escape(&entry.key));
        xml.push_str("</Key><LastModified>");
        xml.push_str(&xml_escape(&s3_timestamp(entry.modified_at_unix)));
        xml.push_str("</LastModified><ETag>");
        xml.push_str(&xml_escape(&entry.etag));
        xml.push_str("</ETag><Size>");
        xml.push_str(&entry.size_bytes.to_string());
        xml.push_str("</Size><StorageClass>STANDARD</StorageClass></Contents>");
    }
    for prefix in common_prefixes {
        xml.push_str("<CommonPrefixes><Prefix>");
        xml.push_str(&xml_escape(prefix));
        xml.push_str("</Prefix></CommonPrefixes>");
    }
    xml.push_str("</ListBucketResult>");
    xml
}

fn encode_continuation_token(value: &str) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(value.as_bytes())
}

fn decode_continuation_token(value: &str) -> Result<String, ()> {
    let decoded = BASE64_URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| ())?;
    String::from_utf8(decoded).map_err(|_| ())
}

fn new_s3_request_id() -> String {
    Uuid::now_v7().simple().to_string().to_ascii_uppercase()
}

fn append_request_id_header(response: &mut Response, request_id: &str) {
    if let Ok(value) = HeaderValue::from_str(request_id) {
        response.headers_mut().insert("x-amz-request-id", value);
    }
}

fn append_etag_header(response: &mut Response, etag: &str) {
    if let Ok(value) = HeaderValue::from_str(etag) {
        response.headers_mut().insert(header::ETAG, value);
    }
}

fn append_version_id_header(response: &mut Response, version_id: Option<&str>) {
    let Some(version_id) = version_id else {
        return;
    };
    if let Ok(value) = HeaderValue::from_str(version_id) {
        response.headers_mut().insert("x-amz-version-id", value);
    }
}

fn xml_response(status: StatusCode, body: String, request_id: &str) -> Response {
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml"),
    );
    append_request_id_header(&mut response, request_id);
    response
}

fn s3_error_response(
    status: StatusCode,
    code: &str,
    message: &str,
    resource: &str,
    request_id: &str,
) -> Response {
    let body = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>{}</Code><Message>{}</Message><Resource>{}</Resource><RequestId>{}</RequestId></Error>"#,
        xml_escape(code),
        xml_escape(message),
        xml_escape(resource),
        xml_escape(request_id),
    );
    xml_response(status, body, request_id)
}

fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn s3_timestamp(unix_ts: u64) -> String {
    OffsetDateTime::from_unix_timestamp(unix_ts as i64)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
