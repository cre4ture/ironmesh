use super::*;
use crate::storage::{ObjectVersionInspection, ObjectVersionMetadataRecord, S3ObjectVersionRecord};
use axum::body::Body;
use axum::extract::{DefaultBodyLimit, OriginalUri, Path, Query, State};
use axum::http::{HeaderName, Method, Request, StatusCode, Uri};
use axum::routing::get;
use hmac::{Hmac, Mac};
use md5::Md5;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use tower::ServiceExt;

const S3_XML_NAMESPACE: &str = "http://s3.amazonaws.com/doc/2006-03-01/";
const S3_MAX_LIST_KEYS: usize = 1000;
const S3_LIST_DEFAULT_MAX_KEYS: usize = 1000;
const S3_MULTIPART_MIN_PART_SIZE_BYTES: u64 = 5 * 1024 * 1024;
const S3_MULTIPART_MAX_PARTS: u32 = 10_000;
const S3_LIST_DEFAULT_MAX_PARTS: usize = 1000;
const S3_UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";
pub(crate) const S3_TRANSPORT_PREFIX: &str = "/s3";

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

#[derive(Debug, Clone)]
struct ParsedS3QueryAuthorization {
    parsed: ParsedS3Authorization,
    amz_date: String,
    payload_hash: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct S3BucketQuery {
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
    versions: Option<String>,
    versioning: Option<String>,
    delete: Option<String>,
    #[serde(rename = "key-marker")]
    key_marker: Option<String>,
    #[serde(rename = "version-id-marker")]
    version_id_marker: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct S3ObjectQuery {
    #[serde(rename = "versionId")]
    version_id: Option<String>,
    #[serde(rename = "uploadId")]
    upload_id: Option<String>,
    #[serde(rename = "partNumber")]
    part_number: Option<u32>,
    #[serde(rename = "part-number-marker")]
    part_number_marker: Option<u32>,
    #[serde(rename = "max-parts")]
    max_parts: Option<usize>,
    uploads: Option<String>,
}

#[derive(Debug, Clone)]
struct S3CopySource {
    bucket_name: String,
    object_key: String,
    version_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum S3MetadataDirective {
    Copy,
    Replace,
}

#[derive(Debug, Clone)]
struct S3ListContentEntry {
    key: String,
    etag: String,
    size_bytes: u64,
    modified_at_unix: u64,
}

#[derive(Debug, Clone)]
struct S3ListVersionEntry {
    key: String,
    version_id: String,
    etag: String,
    size_bytes: Option<u64>,
    modified_at_unix: u64,
    is_latest: bool,
    is_delete_marker: bool,
}

#[derive(Debug, Clone)]
enum S3ListVersionItem {
    Version(S3ListVersionEntry),
    CommonPrefix(String),
}

#[derive(Debug, Clone)]
struct CompletedMultipartPart {
    part_number: u32,
    etag: String,
}

#[derive(Debug, Clone)]
struct DeleteObjectsRequestItem {
    key: String,
    version_id: Option<String>,
}

#[derive(Debug, Clone)]
struct DeleteObjectsRequest {
    objects: Vec<DeleteObjectsRequestItem>,
    quiet: bool,
}

#[derive(Debug, Clone)]
struct DeleteObjectsDeletedEntry {
    key: String,
    version_id: Option<String>,
    delete_marker: bool,
    delete_marker_version_id: Option<String>,
}

#[derive(Debug, Clone)]
struct DeleteObjectsErrorEntry {
    key: String,
    version_id: Option<String>,
    code: &'static str,
    message: String,
}

#[derive(Debug, Clone)]
struct S3DeleteExecutionOutcome {
    header_version_id: String,
    batch_version_id: Option<String>,
    delete_marker: bool,
    delete_marker_version_id: Option<String>,
}

#[derive(Debug, Clone)]
enum S3DeleteExecutionError {
    NoSuchVersion,
    Internal(String),
}

pub(crate) fn build_listener_app() -> Router<ServerState> {
    Router::new()
        .route("/", get(list_buckets))
        .route(
            "/{bucket}",
            get(list_bucket_objects)
                .head(head_bucket)
                .post(post_bucket)
                .put(put_bucket)
                .delete(delete_bucket),
        )
        .route(
            "/{bucket}/{*key}",
            get(get_object)
                .head(head_object)
                .put(put_object)
                .delete(delete_object)
                .post(post_object),
        )
        .layer(DefaultBodyLimit::disable())
}

pub(crate) fn is_transport_path(path: &str) -> bool {
    path == S3_TRANSPORT_PREFIX
        || path == "/s3/"
        || path.starts_with("/s3/")
        || path.starts_with("/s3?")
}

pub(crate) async fn execute_transport_request(
    state: ServerState,
    method: Method,
    raw_path: &str,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(listener_path) = listener_path_from_transport_path(raw_path) else {
        return s3_error_response(
            StatusCode::NOT_FOUND,
            "NoSuchBucket",
            "the specified bucket does not exist",
            raw_path,
            &new_s3_request_id(),
        );
    };
    let uri = match listener_path.parse::<Uri>() {
        Ok(uri) => uri,
        Err(err) => {
            return s3_error_response(
                StatusCode::BAD_REQUEST,
                "InvalidURI",
                &format!("failed to parse transport S3 path: {err}"),
                raw_path,
                &new_s3_request_id(),
            );
        }
    };

    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .expect("S3 transport requests use valid methods and URIs");
    *request.headers_mut() = headers;

    match build_listener_app()
        .with_state(state)
        .oneshot(request)
        .await
    {
        Ok(response) => response,
        Err(err) => s3_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("failed dispatching S3 transport request: {err}"),
            raw_path,
            &new_s3_request_id(),
        ),
    }
}

fn listener_path_from_transport_path(raw_path: &str) -> Option<String> {
    let trimmed = raw_path.trim();
    let remainder = trimmed.strip_prefix(S3_TRANSPORT_PREFIX)?;
    Some(match remainder {
        "" | "/" => "/".to_string(),
        value if value.starts_with('/') => value.to_string(),
        value if value.starts_with('?') => format!("/{value}"),
        value => format!("/{value}"),
    })
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
    Query(query): Query<S3BucketQuery>,
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
    if query.versioning.is_some() {
        return get_bucket_versioning_response(&state, &uri, &request, &bucket_name).await;
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

    if query.versions.is_some() {
        return list_object_versions_response(&state, &uri, &request, &bucket, &query).await;
    }

    list_objects_v2_response(&state, &uri, &request, &bucket, &query).await
}

async fn put_bucket(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(bucket_name): Path<String>,
    Query(query): Query<S3BucketQuery>,
    payload: Bytes,
) -> Response {
    let request = match authenticate_request(&state, &Method::PUT, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if query.versioning.is_some() {
        return put_bucket_versioning_response(&state, &uri, &request, &bucket_name, payload).await;
    }
    if !request.access_key.allow_manage {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to create buckets",
            uri.path(),
            &request.request_id,
        );
    }

    let bucket_name = match normalize_s3_bucket_name(&bucket_name) {
        Ok(bucket_name) => bucket_name,
        Err(_) => {
            return s3_error_response(
                StatusCode::BAD_REQUEST,
                "InvalidBucketName",
                "the specified bucket is not valid",
                uri.path(),
                &request.request_id,
            );
        }
    };
    if !access_key_can_manage_bucket_name(&request.access_key, &bucket_name) {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to create this bucket",
            uri.path(),
            &request.request_id,
        );
    }
    if let Err(message) = parse_create_bucket_location_constraint(payload.as_ref()) {
        return s3_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            &message,
            uri.path(),
            &request.request_id,
        );
    }

    let now = unix_ts();
    let created = {
        let mut control_plane = state.s3.control_plane.lock().await;
        if let Some(bucket) = control_plane
            .buckets
            .iter_mut()
            .find(|bucket| bucket.bucket_name == bucket_name)
        {
            if bucket.deleted_at_unix.is_none() {
                return s3_error_response(
                    StatusCode::CONFLICT,
                    "BucketAlreadyOwnedByYou",
                    "the requested bucket already exists",
                    uri.path(),
                    &request.request_id,
                );
            }
            bucket.deleted_at_unix = None;
            bucket.updated_at_unix = now;
        } else {
            control_plane.buckets.push(S3BucketRecord {
                bucket_name: bucket_name.clone(),
                root_prefix: default_s3_bucket_root_prefix(&bucket_name),
                versioning_status: S3BucketVersioningStatus::Disabled,
                read_only: false,
                created_at_unix: now,
                updated_at_unix: now,
                created_by: Some(request.access_key.access_key_id.clone()),
                deleted_at_unix: None,
            });
        }
        *control_plane = normalize_s3_control_plane_state(control_plane.clone());
        control_plane
            .buckets
            .iter()
            .find(|bucket| bucket.bucket_name == bucket_name && bucket.deleted_at_unix.is_none())
            .cloned()
            .expect("bucket was just created or restored")
    };

    if let Err(err) = persist_s3_control_plane_state(&state, None).await {
        warn!(error = %err, bucket_name = %bucket_name, "failed to persist S3 bucket");
        return s3_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "failed to persist bucket metadata",
            uri.path(),
            &request.request_id,
        );
    }
    spawn_s3_control_plane_fanout(state.clone());

    let mut response = StatusCode::OK.into_response();
    append_request_id_header(&mut response, &request.request_id);
    if let Ok(location) = HeaderValue::from_str(&format!("/{}", created.bucket_name)) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

async fn post_bucket(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(bucket_name): Path<String>,
    Query(query): Query<S3BucketQuery>,
    payload: Bytes,
) -> Response {
    let request = match authenticate_request(&state, &Method::POST, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if query.delete.is_some() {
        return delete_objects_response(&state, &uri, &request, &bucket_name, payload).await;
    }
    s3_error_response(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        "bucket POST operations are not implemented yet",
        uri.path(),
        &request.request_id,
    )
}

async fn delete_bucket(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path(bucket_name): Path<String>,
) -> Response {
    let request = match authenticate_request(&state, &Method::DELETE, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
    if !request.access_key.allow_manage {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to delete buckets",
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
            "the access key is not allowed to delete this bucket",
            uri.path(),
            &request.request_id,
        );
    }

    let bucket_has_objects = {
        let store = read_store(&state, "s3.delete_bucket.inspect_objects").await;
        let inspector = store.store_index_inspector();
        inspector
            .current_object_hashes()
            .iter()
            .any(|(key, manifest_hash)| {
                manifest_hash.as_str() != TOMBSTONE_MANIFEST_HASH
                    && key.starts_with(&bucket.root_prefix)
            })
    };
    if bucket_has_objects {
        return s3_error_response(
            StatusCode::CONFLICT,
            "BucketNotEmpty",
            "the bucket you tried to delete is not empty",
            uri.path(),
            &request.request_id,
        );
    }

    {
        let mut control_plane = state.s3.control_plane.lock().await;
        let Some(bucket) = control_plane
            .buckets
            .iter_mut()
            .find(|bucket| bucket.bucket_name == bucket_name && bucket.deleted_at_unix.is_none())
        else {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
                uri.path(),
                &request.request_id,
            );
        };
        bucket.deleted_at_unix = Some(unix_ts());
        bucket.updated_at_unix = unix_ts();
        *control_plane = normalize_s3_control_plane_state(control_plane.clone());
    }

    if let Err(err) = persist_s3_control_plane_state(&state, None).await {
        warn!(error = %err, bucket_name = %bucket_name, "failed to persist S3 bucket deletion");
        return s3_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "failed to persist bucket metadata",
            uri.path(),
            &request.request_id,
        );
    }
    spawn_s3_control_plane_fanout(state.clone());

    let mut response = StatusCode::NO_CONTENT.into_response();
    append_request_id_header(&mut response, &request.request_id);
    response
}

async fn list_objects_v2_response(
    state: &ServerState,
    uri: &Uri,
    request: &S3RequestContext,
    bucket: &S3BucketRecord,
    query: &S3BucketQuery,
) -> Response {
    let prefix = query.prefix.clone().unwrap_or_default();
    let delimiter = query.delimiter.as_deref().filter(|value| !value.is_empty());
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

    let relative_keys_by_object_key = object_hashes
        .iter()
        .filter(|(key, manifest_hash)| {
            manifest_hash.as_str() != TOMBSTONE_MANIFEST_HASH
                && key.starts_with(&bucket.root_prefix)
                && access_key_allows_storage_path(&request.access_key, key)
        })
        .filter_map(|(key, _)| {
            full_key_to_object_key(&bucket, key).map(|object_key| (object_key, key.clone()))
        })
        .collect::<HashMap<_, _>>();
    let mut relative_keys = relative_keys_by_object_key
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    relative_keys.sort();

    let listing_scope = format!("s3:{}", bucket.bucket_name);
    let page = match crate::listing::paginate_sorted_keys(
        &relative_keys,
        &listing_scope,
        crate::listing::KeyListingPrefixMode::ExactStartsWith,
        &prefix,
        delimiter,
        delimiter.map(|_| 1usize),
        query.continuation_token.as_deref(),
        query.start_after.as_deref(),
        max_keys,
    ) {
        Ok(page) => page,
        Err(message) => {
            return s3_error_response(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                &message,
                uri.path(),
                &request.request_id,
            );
        }
    };

    let mut contents = Vec::new();
    let mut common_prefixes = Vec::new();
    let mut selected_hashes = HashMap::new();
    let mut selected_object_ids = HashMap::new();
    for entry in &page.entries {
        match entry.kind {
            crate::listing::KeyListingEntryKind::Object => {
                let Some(full_key) = relative_keys_by_object_key.get(&entry.path) else {
                    continue;
                };
                let manifest_hash = object_hashes.get(full_key).cloned().unwrap_or_default();
                selected_hashes.insert(full_key.clone(), manifest_hash);
                if let Some(object_id) = object_ids.get(full_key).cloned() {
                    selected_object_ids.insert(full_key.clone(), object_id);
                }
                contents.push((entry.path.clone(), full_key.clone()));
            }
            crate::listing::KeyListingEntryKind::CommonPrefix => {
                common_prefixes.push(entry.path.clone());
            }
        }
    }

    let is_truncated = page.has_more;
    let next_continuation_token = page.next_cursor;

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
        bucket,
        &prefix,
        delimiter.unwrap_or(""),
        max_keys,
        query.continuation_token.as_deref(),
        next_continuation_token.as_deref(),
        is_truncated,
        key_count,
        &content_entries,
        &common_prefixes,
    );

    xml_response(StatusCode::OK, xml, &request.request_id)
}

async fn get_bucket_versioning_response(
    state: &ServerState,
    uri: &Uri,
    request: &S3RequestContext,
    bucket_name: &str,
) -> Response {
    let bucket = match resolve_bucket(state, bucket_name).await {
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

    xml_response(
        StatusCode::OK,
        render_bucket_versioning_result(&bucket),
        &request.request_id,
    )
}

async fn put_bucket_versioning_response(
    state: &ServerState,
    uri: &Uri,
    request: &S3RequestContext,
    bucket_name: &str,
    payload: Bytes,
) -> Response {
    if !request.access_key.allow_write {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to change bucket versioning",
            uri.path(),
            &request.request_id,
        );
    }

    let requested_status = match parse_bucket_versioning_status(
        std::str::from_utf8(payload.as_ref()).unwrap_or_default(),
    ) {
        Ok(status) => status,
        Err(message) => {
            return s3_error_response(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &message,
                uri.path(),
                &request.request_id,
            );
        }
    };

    let mut changed = false;
    {
        let mut control_plane = state.s3.control_plane.lock().await;
        let Some(bucket) = control_plane
            .buckets
            .iter_mut()
            .find(|bucket| bucket.bucket_name == bucket_name && bucket.deleted_at_unix.is_none())
        else {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified bucket does not exist",
                uri.path(),
                &request.request_id,
            );
        };
        if !access_key_allows_bucket(&request.access_key, bucket) {
            return s3_error_response(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "the access key is not allowed to access this bucket",
                uri.path(),
                &request.request_id,
            );
        }
        if bucket.read_only {
            return s3_error_response(
                StatusCode::FORBIDDEN,
                "AccessDenied",
                "the bucket mapping is read-only",
                uri.path(),
                &request.request_id,
            );
        }
        if bucket.versioning_status != requested_status {
            bucket.versioning_status = requested_status;
            bucket.updated_at_unix = unix_ts();
            changed = true;
        }
        *control_plane = normalize_s3_control_plane_state(control_plane.clone());
    }

    if changed {
        if let Err(err) = persist_s3_control_plane_state(state, None).await {
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("failed to persist bucket versioning configuration: {err:#}"),
                uri.path(),
                &request.request_id,
            );
        }
        spawn_s3_control_plane_fanout(state.clone());
    }

    let mut response = StatusCode::OK.into_response();
    append_request_id_header(&mut response, &request.request_id);
    response
}

async fn list_object_versions_response(
    state: &ServerState,
    uri: &Uri,
    request: &S3RequestContext,
    bucket: &S3BucketRecord,
    query: &S3BucketQuery,
) -> Response {
    let prefix = query.prefix.clone().unwrap_or_default();
    let delimiter = query.delimiter.as_deref().filter(|value| !value.is_empty());
    let max_keys = query
        .max_keys
        .unwrap_or(S3_LIST_DEFAULT_MAX_KEYS)
        .min(S3_MAX_LIST_KEYS);
    if bucket.versioning_status != S3BucketVersioningStatus::Enabled {
        return xml_response(
            StatusCode::OK,
            render_list_object_versions_result(
                bucket,
                &prefix,
                delimiter,
                query.key_marker.as_deref(),
                query.version_id_marker.as_deref(),
                max_keys,
                false,
                None,
                None,
                &[],
                &[],
            ),
            &request.request_id,
        );
    }
    let full_prefix = if prefix.is_empty() {
        None
    } else {
        Some(format!("{}{}", bucket.root_prefix, prefix))
    };

    let store = read_store(state, "s3.list_object_versions.records").await;
    let records = match store
        .list_s3_object_versions(&bucket.bucket_name, full_prefix.as_deref())
        .await
    {
        Ok(records) => records,
        Err(err) => {
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("failed to inspect S3 object versions: {err:#}"),
                uri.path(),
                &request.request_id,
            );
        }
    };

    let mut records_by_key = BTreeMap::<String, Vec<S3ObjectVersionRecord>>::new();
    for record in records {
        records_by_key
            .entry(record.ironmesh_key.clone())
            .or_default()
            .push(record);
    }

    let mut all_entries = Vec::<S3ListVersionEntry>::new();
    for (full_key, key_records) in records_by_key {
        if !access_key_allows_storage_path(&request.access_key, &full_key) {
            continue;
        }
        let Some(object_key) = full_key_to_object_key(bucket, &full_key) else {
            continue;
        };
        if !prefix.is_empty() && !object_key.starts_with(&prefix) {
            continue;
        }

        let version_graph = match store.list_versions(&full_key).await {
            Ok(graph) => graph,
            Err(err) => {
                return s3_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("failed to inspect object version graph: {err:#}"),
                    uri.path(),
                    &request.request_id,
                );
            }
        };
        let ordered_records = linearize_s3_version_records(version_graph.as_ref(), &key_records);
        let latest_version_id = ordered_records
            .first()
            .map(|record| record.version_id.clone());

        for record in ordered_records {
            let inspection = match store
                .inspect_object_version(&full_key, &record.version_id)
                .await
            {
                Ok(Some(inspection)) => inspection,
                Ok(None) => continue,
                Err(err) => {
                    return s3_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("failed to inspect object version details: {err:#}"),
                        uri.path(),
                        &request.request_id,
                    );
                }
            };

            all_entries.push(S3ListVersionEntry {
                key: object_key.clone(),
                version_id: record.version_id.clone(),
                etag: record.etag.clone(),
                size_bytes: inspection.total_size_bytes,
                modified_at_unix: inspection.created_at_unix,
                is_latest: latest_version_id
                    .as_deref()
                    .is_some_and(|latest| latest == record.version_id),
                is_delete_marker: inspection.is_delete_marker,
            });
        }
    }
    drop(store);

    let all_items = if let Some(delimiter) = delimiter {
        let mut items = Vec::<S3ListVersionItem>::new();
        let mut emitted_common_prefixes = HashSet::<String>::new();
        for entry in all_entries {
            let Some(relative_suffix) = entry.key.strip_prefix(&prefix) else {
                items.push(S3ListVersionItem::Version(entry));
                continue;
            };
            let Some(index) = relative_suffix.find(delimiter) else {
                items.push(S3ListVersionItem::Version(entry));
                continue;
            };
            let common_prefix = format!("{}{delimiter}", &entry.key[..prefix.len() + index]);
            if emitted_common_prefixes.insert(common_prefix.clone()) {
                items.push(S3ListVersionItem::CommonPrefix(common_prefix));
            }
        }
        items
    } else {
        all_entries
            .into_iter()
            .map(S3ListVersionItem::Version)
            .collect::<Vec<_>>()
    };

    let mut collected_entries = Vec::<S3ListVersionEntry>::new();
    let mut collected_common_prefixes = Vec::<String>::new();
    let mut next_key_marker = None::<String>;
    let mut next_version_id_marker = None::<String>;
    let mut started = query.key_marker.is_none();
    let requested_key_marker = query.key_marker.as_deref();
    let requested_version_id_marker = query.version_id_marker.as_deref();

    for item in all_items {
        let item_key = match &item {
            S3ListVersionItem::Version(entry) => entry.key.as_str(),
            S3ListVersionItem::CommonPrefix(prefix) => prefix.as_str(),
        };
        if !started {
            match item_key.cmp(requested_key_marker.unwrap_or_default()) {
                std::cmp::Ordering::Less => continue,
                std::cmp::Ordering::Greater => started = true,
                std::cmp::Ordering::Equal => {
                    if let S3ListVersionItem::Version(entry) = &item
                        && let Some(version_id_marker) = requested_version_id_marker
                        && entry.version_id != version_id_marker
                    {
                        continue;
                    }
                    started = true;
                }
            }
        }

        if collected_entries.len() + collected_common_prefixes.len() >= max_keys {
            match &item {
                S3ListVersionItem::Version(entry) => {
                    next_key_marker = Some(entry.key.clone());
                    next_version_id_marker = Some(entry.version_id.clone());
                }
                S3ListVersionItem::CommonPrefix(prefix) => {
                    next_key_marker = Some(prefix.clone());
                    next_version_id_marker = None;
                }
            }
            break;
        }
        match item {
            S3ListVersionItem::Version(entry) => collected_entries.push(entry),
            S3ListVersionItem::CommonPrefix(prefix) => collected_common_prefixes.push(prefix),
        }
    }

    let xml = render_list_object_versions_result(
        bucket,
        &prefix,
        delimiter,
        query.key_marker.as_deref(),
        query.version_id_marker.as_deref(),
        max_keys,
        next_key_marker.is_some(),
        next_key_marker.as_deref(),
        next_version_id_marker.as_deref(),
        &collected_entries,
        &collected_common_prefixes,
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

async fn post_object(
    State(state): State<ServerState>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    Path((bucket_name, raw_key)): Path<(String, String)>,
    Query(query): Query<S3ObjectQuery>,
    payload: Bytes,
) -> Response {
    let request = match authenticate_request(&state, &Method::POST, &uri, &headers).await {
        Ok(request) => request,
        Err(response) => return response,
    };
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

    if query.uploads.is_some() {
        return create_multipart_upload_response(
            &state, &uri, &headers, &request, &bucket, &full_key,
        )
        .await;
    }
    if query.upload_id.is_some() {
        return complete_multipart_upload_response(
            &state, &uri, &request, &bucket, &full_key, &query, payload,
        )
        .await;
    }

    s3_error_response(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        "object POST operations are not implemented yet",
        uri.path(),
        &request.request_id,
    )
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
    if query.upload_id.is_some() || query.part_number.is_some() {
        return upload_multipart_part_response(
            &state, &uri, &headers, &request, &bucket, &full_key, &query, payload,
        )
        .await;
    }
    if header_value_name(&headers, "x-amz-copy-source").is_some() {
        return copy_object_response(&state, &uri, &headers, &request, &bucket, &full_key).await;
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

async fn copy_object_response(
    state: &ServerState,
    uri: &Uri,
    headers: &HeaderMap,
    request: &S3RequestContext,
    destination_bucket: &S3BucketRecord,
    destination_full_key: &str,
) -> Response {
    if !request.access_key.allow_read {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to read copy sources",
            uri.path(),
            &request.request_id,
        );
    }

    let Some(raw_copy_source) = header_value_name(headers, "x-amz-copy-source") else {
        return s3_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "x-amz-copy-source is required for CopyObject",
            uri.path(),
            &request.request_id,
        );
    };
    let copy_source = match parse_copy_source(&raw_copy_source) {
        Ok(copy_source) => copy_source,
        Err(message) => {
            return s3_error_response(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                &message,
                uri.path(),
                &request.request_id,
            );
        }
    };
    let metadata_directive = match parse_metadata_directive(headers) {
        Ok(directive) => directive,
        Err(message) => {
            return s3_error_response(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                &message,
                uri.path(),
                &request.request_id,
            );
        }
    };

    let source_bucket = match resolve_bucket(state, &copy_source.bucket_name).await {
        Some(bucket) => bucket,
        None => {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchBucket",
                "the specified source bucket does not exist",
                uri.path(),
                &request.request_id,
            );
        }
    };
    let source_full_key = format!("{}{}", source_bucket.root_prefix, copy_source.object_key);
    if !access_key_allows_object(&request.access_key, &source_bucket, &source_full_key) {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to read the source object path",
            uri.path(),
            &request.request_id,
        );
    }

    let replace_metadata = matches!(metadata_directive, S3MetadataDirective::Replace)
        .then(|| object_metadata_from_headers(headers));
    let actor = s3_actor_context(&request.access_key);
    let mut store = lock_store(state, "s3.copy_object.store").await;
    let source_version_id = match resolve_copy_source_version(
        &store,
        &source_bucket,
        &source_full_key,
        copy_source.version_id.as_deref(),
        uri.path(),
        &request.request_id,
    )
    .await
    {
        Ok(version) => version,
        Err(response) => return response,
    };
    let destination_head_before = match store.list_versions(destination_full_key).await {
        Ok(graph) => graph.and_then(|graph| graph.preferred_head_version_id),
        Err(err) => {
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("failed to inspect destination versions before copy: {err:#}"),
                uri.path(),
                &request.request_id,
            );
        }
    };
    if source_full_key == destination_full_key
        && metadata_directive == S3MetadataDirective::Copy
        && destination_head_before.as_deref() == Some(source_version_id.as_str())
    {
        return s3_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidRequest",
            "copying an object onto itself without changing metadata is not supported",
            uri.path(),
            &request.request_id,
        );
    }

    let copied_metadata = match metadata_directive {
        S3MetadataDirective::Copy => {
            match store.load_object_version_metadata(&source_version_id).await {
                Ok(metadata) => metadata.unwrap_or_default(),
                Err(err) => {
                    return s3_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("failed to load source object metadata: {err:#}"),
                        uri.path(),
                        &request.request_id,
                    );
                }
            }
        }
        S3MetadataDirective::Replace => replace_metadata.unwrap_or_default(),
    };

    let copy_result = if copy_source.version_id.is_some() || source_full_key == destination_full_key
    {
        store
            .restore_version_path(
                &source_full_key,
                &source_version_id,
                destination_full_key,
                true,
            )
            .await
    } else {
        store
            .copy_object_path(&source_full_key, destination_full_key, true)
            .await
    };
    match copy_result {
        Ok(PathMutationResult::Applied) => {}
        Ok(PathMutationResult::SourceMissing) => {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                if copy_source.version_id.is_some() {
                    "NoSuchVersion"
                } else {
                    "NoSuchKey"
                },
                "the specified copy source does not exist",
                uri.path(),
                &request.request_id,
            );
        }
        Ok(PathMutationResult::TargetExists) => {
            return s3_error_response(
                StatusCode::CONFLICT,
                "InvalidRequest",
                "the destination object could not be overwritten",
                uri.path(),
                &request.request_id,
            );
        }
        Err(err) => {
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("failed to copy S3 object: {err:#}"),
                uri.path(),
                &request.request_id,
            );
        }
    }

    let destination_graph = match store.list_versions(destination_full_key).await {
        Ok(Some(graph)) => graph,
        Ok(None) => {
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "the destination object is missing after copy",
                uri.path(),
                &request.request_id,
            );
        }
        Err(err) => {
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("failed to inspect destination versions after copy: {err:#}"),
                uri.path(),
                &request.request_id,
            );
        }
    };
    let Some(destination_head_version_id) = destination_graph.preferred_head_version_id.clone()
    else {
        return s3_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "the destination object has no preferred head after copy",
            uri.path(),
            &request.request_id,
        );
    };
    let Some(destination_head) = destination_graph
        .versions
        .iter()
        .find(|record| record.version_id == destination_head_version_id)
        .cloned()
    else {
        return s3_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            "the destination head version could not be loaded after copy",
            uri.path(),
            &request.request_id,
        );
    };

    let mut destination_metadata = copied_metadata;
    destination_metadata.version_id = destination_head.version_id.clone();
    destination_metadata.updated_at_unix = unix_ts();
    if let Err(err) = store
        .persist_object_version_metadata(&destination_metadata)
        .await
    {
        return s3_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("failed to persist destination object metadata: {err:#}"),
            uri.path(),
            &request.request_id,
        );
    }

    let destination_etag = object_etag(&destination_head.manifest_hash);
    if let Err(err) = store
        .persist_s3_object_version(&S3ObjectVersionRecord {
            bucket_name: destination_bucket.bucket_name.clone(),
            ironmesh_key: destination_full_key.to_string(),
            version_id: destination_head.version_id.clone(),
            etag: destination_etag.clone(),
            multipart_part_count: None,
            created_at_unix: unix_ts(),
        })
        .await
    {
        return s3_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("failed to persist destination S3 version record: {err:#}"),
            uri.path(),
            &request.request_id,
        );
    }
    drop(store);

    publish_namespace_change(state);
    spawn_media_metadata_warmup(
        state.clone(),
        destination_full_key.to_string(),
        destination_head.manifest_hash.clone(),
    );

    let mut cluster = state.cluster.lock().await;
    cluster.note_replica(destination_full_key, state.node_id);
    cluster.note_replica(
        format!("{}@{}", destination_full_key, destination_head.version_id),
        state.node_id,
    );
    drop(cluster);
    if let Err(err) = persist_cluster_replicas_state(state).await {
        warn!(
            error = %err,
            key = %destination_full_key,
            "failed persisting cluster replicas after S3 copy"
        );
    }
    if should_trigger_autonomous_post_write_replication(
        state.autonomous_replication_on_put_enabled,
        false,
    ) {
        enqueue_autonomous_post_write_replication(
            state,
            autonomous_post_write_replication_subjects(
                destination_full_key,
                &destination_head.version_id,
            ),
        )
        .await;
    }
    record_data_change_event(
        state,
        PendingDataChangeEvent {
            action: DataChangeAction::Copy,
            actor: Some(actor),
            path: destination_full_key.to_string(),
            from_path: Some(source_full_key),
            to_path: Some(destination_full_key.to_string()),
            recursive: false,
            affected_path_count: 1,
            total_size_bytes: None,
            version_id: Some(destination_head.version_id.clone()),
            snapshot_id: None,
            upload_mode: None,
        },
    )
    .await;

    let mut response = xml_response(
        StatusCode::OK,
        render_copy_object_result(&destination_etag, destination_head.created_at_unix),
        &request.request_id,
    );
    append_etag_header(&mut response, &destination_etag);
    append_version_id_header(&mut response, Some(&destination_head.version_id));
    response
}

async fn create_multipart_upload_response(
    state: &ServerState,
    _uri: &Uri,
    headers: &HeaderMap,
    request: &S3RequestContext,
    bucket: &S3BucketRecord,
    full_key: &str,
) -> Response {
    let now = unix_ts();
    let session = UploadSessionRecord {
        upload_id: Uuid::now_v7().to_string(),
        owner_device_id: None,
        key: full_key.to_string(),
        total_size_bytes: 0,
        chunk_size_bytes: 0,
        chunk_count: 0,
        state: VersionConsistencyState::Confirmed,
        parent_version_ids: Vec::new(),
        explicit_version_id: None,
        assembly_mode: UploadAssemblyMode::Multipart,
        received_chunks: Vec::new(),
        multipart_parts: BTreeMap::new(),
        multipart_bucket_name: Some(bucket.bucket_name.clone()),
        multipart_object_metadata: Some(object_metadata_from_headers(headers)),
        multipart_completed_result: None,
        created_at_unix: now,
        updated_at_unix: now,
        expires_at_unix: now.saturating_add(UPLOAD_SESSION_TTL_SECS),
        finalizing: false,
        completed: false,
        completed_result: None,
    };

    let mut sessions = write_upload_sessions(state, "s3.multipart.create").await;
    prune_expired_upload_sessions(&mut sessions, now);
    sessions
        .sessions
        .insert(session.upload_id.clone(), session.clone());
    drop(sessions);
    persist_upload_session_store_after_mutation(state, "s3_create_multipart_upload").await;

    xml_response(
        StatusCode::OK,
        render_create_multipart_upload_result(
            &bucket.bucket_name,
            full_key_to_object_key(bucket, full_key)
                .unwrap_or_default()
                .as_str(),
            &session.upload_id,
        ),
        &request.request_id,
    )
}

async fn upload_multipart_part_response(
    state: &ServerState,
    uri: &Uri,
    headers: &HeaderMap,
    request: &S3RequestContext,
    bucket: &S3BucketRecord,
    full_key: &str,
    query: &S3ObjectQuery,
    payload: Bytes,
) -> Response {
    let Some(upload_id) = query.upload_id.as_deref() else {
        return s3_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "uploadId is required for UploadPart",
            uri.path(),
            &request.request_id,
        );
    };
    let Some(part_number) = query.part_number else {
        return s3_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "partNumber is required for UploadPart",
            uri.path(),
            &request.request_id,
        );
    };
    if !(1..=S3_MULTIPART_MAX_PARTS).contains(&part_number) {
        return s3_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "partNumber must be between 1 and 10000",
            uri.path(),
            &request.request_id,
        );
    }

    let now = unix_ts();
    {
        let mut sessions = write_upload_sessions(state, "s3.multipart.upload_part.preflight").await;
        prune_expired_upload_sessions(&mut sessions, now);
        let Some(session) = sessions.sessions.get(upload_id) else {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchUpload",
                "the specified multipart upload does not exist",
                uri.path(),
                &request.request_id,
            );
        };
        if !multipart_upload_session_matches(session, &bucket.bucket_name, full_key)
            || session.completed
            || session.finalizing
        {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchUpload",
                "the specified multipart upload does not exist",
                uri.path(),
                &request.request_id,
            );
        }
    }

    let chunk_refs = match ingest_payload_to_chunk_refs(state, payload.as_ref()).await {
        Ok(chunk_refs) => chunk_refs,
        Err(err) => {
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("failed to ingest multipart upload part: {err:#}"),
                uri.path(),
                &request.request_id,
            );
        }
    };
    let etag = part_etag(payload.as_ref());

    let mut sessions = write_upload_sessions(state, "s3.multipart.upload_part.commit").await;
    prune_expired_upload_sessions(&mut sessions, unix_ts());
    let Some(session) = sessions.sessions.get_mut(upload_id) else {
        return s3_error_response(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "the specified multipart upload does not exist",
            uri.path(),
            &request.request_id,
        );
    };
    if !multipart_upload_session_matches(session, &bucket.bucket_name, full_key)
        || session.completed
        || session.finalizing
    {
        return s3_error_response(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "the specified multipart upload does not exist",
            uri.path(),
            &request.request_id,
        );
    }

    session.multipart_parts.insert(
        part_number,
        StagedUploadPart {
            part_number,
            size_bytes: payload.len() as u64,
            chunk_refs,
            client_etag: Some(etag.clone()),
            checksum_sha256: header_value_name(headers, "x-amz-checksum-sha256"),
            created_at_unix: unix_ts(),
        },
    );
    session.updated_at_unix = unix_ts();
    session.expires_at_unix = session
        .updated_at_unix
        .saturating_add(UPLOAD_SESSION_TTL_SECS);
    drop(sessions);
    persist_upload_session_store_after_mutation(state, "s3_upload_multipart_part").await;

    let mut response = StatusCode::OK.into_response();
    append_request_id_header(&mut response, &request.request_id);
    append_etag_header(&mut response, &etag);
    response
}

async fn list_multipart_parts_response(
    state: &ServerState,
    uri: &Uri,
    request: &S3RequestContext,
    bucket: &S3BucketRecord,
    full_key: &str,
    query: &S3ObjectQuery,
) -> Response {
    if !request.access_key.allow_write {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to inspect multipart uploads",
            uri.path(),
            &request.request_id,
        );
    }
    let Some(upload_id) = query.upload_id.as_deref() else {
        return s3_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "uploadId is required for multipart part listings",
            uri.path(),
            &request.request_id,
        );
    };

    let now = unix_ts();
    let mut sessions = write_upload_sessions(state, "s3.multipart.list_parts").await;
    prune_expired_upload_sessions(&mut sessions, now);
    let Some(session) = sessions.sessions.get(upload_id) else {
        return s3_error_response(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "the specified multipart upload does not exist",
            uri.path(),
            &request.request_id,
        );
    };
    if !multipart_upload_session_matches(session, &bucket.bucket_name, full_key)
        || session.completed
    {
        return s3_error_response(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "the specified multipart upload does not exist",
            uri.path(),
            &request.request_id,
        );
    }

    let max_parts = query
        .max_parts
        .unwrap_or(S3_LIST_DEFAULT_MAX_PARTS)
        .max(1)
        .min(S3_LIST_DEFAULT_MAX_PARTS);
    let part_number_marker = query.part_number_marker.unwrap_or(0);
    let all_parts = session
        .multipart_parts
        .values()
        .filter(|part| part.part_number > part_number_marker)
        .cloned()
        .collect::<Vec<_>>();
    let is_truncated = all_parts.len() > max_parts;
    let parts = all_parts.into_iter().take(max_parts).collect::<Vec<_>>();
    let next_part_number_marker = if is_truncated {
        parts.last().map(|part| part.part_number)
    } else {
        None
    };

    xml_response(
        StatusCode::OK,
        render_list_parts_result(
            &bucket.bucket_name,
            full_key_to_object_key(bucket, full_key)
                .unwrap_or_default()
                .as_str(),
            upload_id,
            part_number_marker,
            max_parts,
            is_truncated,
            next_part_number_marker,
            &parts,
        ),
        &request.request_id,
    )
}

async fn complete_multipart_upload_response(
    state: &ServerState,
    uri: &Uri,
    request: &S3RequestContext,
    bucket: &S3BucketRecord,
    full_key: &str,
    query: &S3ObjectQuery,
    payload: Bytes,
) -> Response {
    let Some(upload_id) = query.upload_id.as_deref() else {
        return s3_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "uploadId is required for CompleteMultipartUpload",
            uri.path(),
            &request.request_id,
        );
    };
    let requested_parts = match parse_complete_multipart_upload_parts(
        std::str::from_utf8(payload.as_ref()).unwrap_or_default(),
    ) {
        Ok(parts) => parts,
        Err(message) => {
            return s3_error_response(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &message,
                uri.path(),
                &request.request_id,
            );
        }
    };

    let (multipart_metadata, selected_parts, existing_completed) = {
        let now = unix_ts();
        let mut sessions = write_upload_sessions(state, "s3.multipart.complete.prepare").await;
        prune_expired_upload_sessions(&mut sessions, now);
        let Some(session) = sessions.sessions.get_mut(upload_id) else {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchUpload",
                "the specified multipart upload does not exist",
                uri.path(),
                &request.request_id,
            );
        };
        if !multipart_upload_session_matches(session, &bucket.bucket_name, full_key) {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchUpload",
                "the specified multipart upload does not exist",
                uri.path(),
                &request.request_id,
            );
        }
        if session.completed {
            if let Some(result) = session.multipart_completed_result.clone() {
                let mut response = xml_response(
                    StatusCode::OK,
                    render_complete_multipart_upload_result(
                        &bucket.bucket_name,
                        full_key_to_object_key(bucket, full_key)
                            .unwrap_or_default()
                            .as_str(),
                        &result,
                    ),
                    &request.request_id,
                );
                append_request_id_header(&mut response, &request.request_id);
                append_etag_header(&mut response, &result.etag);
                append_version_id_header(&mut response, Some(&result.version_id));
                return response;
            }
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchUpload",
                "the specified multipart upload does not exist",
                uri.path(),
                &request.request_id,
            );
        }
        if session.finalizing {
            return s3_error_response(
                StatusCode::CONFLICT,
                "InvalidRequest",
                "the multipart upload is already being finalized",
                uri.path(),
                &request.request_id,
            );
        }

        let mut selected_parts = Vec::with_capacity(requested_parts.len());
        let mut previous_part_number = 0u32;
        for requested_part in &requested_parts {
            if requested_part.part_number <= previous_part_number {
                return s3_error_response(
                    StatusCode::BAD_REQUEST,
                    "InvalidPartOrder",
                    "multipart upload parts must be completed in strictly increasing part-number order",
                    uri.path(),
                    &request.request_id,
                );
            }
            previous_part_number = requested_part.part_number;

            let Some(staged_part) = session.multipart_parts.get(&requested_part.part_number) else {
                return s3_error_response(
                    StatusCode::BAD_REQUEST,
                    "InvalidPart",
                    "one or more multipart upload parts are missing",
                    uri.path(),
                    &request.request_id,
                );
            };
            if normalize_etag(staged_part.client_etag.as_deref().unwrap_or_default())
                != normalize_etag(&requested_part.etag)
            {
                return s3_error_response(
                    StatusCode::BAD_REQUEST,
                    "InvalidPart",
                    "one or more multipart upload part ETags did not match",
                    uri.path(),
                    &request.request_id,
                );
            }
            selected_parts.push(staged_part.clone());
        }
        for staged_part in selected_parts
            .iter()
            .take(selected_parts.len().saturating_sub(1))
        {
            if staged_part.size_bytes < S3_MULTIPART_MIN_PART_SIZE_BYTES {
                return s3_error_response(
                    StatusCode::BAD_REQUEST,
                    "EntityTooSmall",
                    "all multipart upload parts except the final part must be at least 5 MiB",
                    uri.path(),
                    &request.request_id,
                );
            }
        }

        session.finalizing = true;
        session.updated_at_unix = now;
        session.expires_at_unix = now.saturating_add(UPLOAD_SESSION_TTL_SECS);
        (
            session
                .multipart_object_metadata
                .clone()
                .unwrap_or_default(),
            selected_parts,
            session.multipart_completed_result.clone(),
        )
    };
    if let Some(result) = existing_completed {
        let mut response = xml_response(
            StatusCode::OK,
            render_complete_multipart_upload_result(
                &bucket.bucket_name,
                full_key_to_object_key(bucket, full_key)
                    .unwrap_or_default()
                    .as_str(),
                &result,
            ),
            &request.request_id,
        );
        append_etag_header(&mut response, &result.etag);
        append_version_id_header(&mut response, Some(&result.version_id));
        return response;
    }

    let mut chunk_refs = Vec::new();
    let mut total_size_bytes = 0u64;
    let mut part_etags = Vec::with_capacity(selected_parts.len());
    for part in &selected_parts {
        total_size_bytes = total_size_bytes.saturating_add(part.size_bytes);
        part_etags.push(part.client_etag.clone().unwrap_or_default());
        chunk_refs.extend(part.chunk_refs.clone());
    }
    let multipart_etag = match complete_multipart_etag(&part_etags) {
        Ok(etag) => etag,
        Err(message) => {
            let mut sessions =
                write_upload_sessions(state, "s3.multipart.complete.rollback.etag").await;
            if let Some(session) = sessions.sessions.get_mut(upload_id) {
                session.finalizing = false;
                session.updated_at_unix = unix_ts();
                session.expires_at_unix = session
                    .updated_at_unix
                    .saturating_add(UPLOAD_SESSION_TTL_SECS);
            }
            drop(sessions);
            persist_upload_session_store_after_mutation(state, "s3_complete_multipart_etag_error")
                .await;
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &message,
                uri.path(),
                &request.request_id,
            );
        }
    };

    let mut store = lock_store(state, "s3.multipart.complete.put_object_from_chunks").await;
    let outcome = match store
        .put_object_from_chunks(
            full_key,
            total_size_bytes as usize,
            &chunk_refs,
            PutOptions::default(),
        )
        .await
    {
        Ok(outcome) => outcome,
        Err(err) => {
            drop(store);
            let mut sessions = write_upload_sessions(state, "s3.multipart.complete.rollback").await;
            if let Some(session) = sessions.sessions.get_mut(upload_id) {
                session.finalizing = false;
                session.updated_at_unix = unix_ts();
                session.expires_at_unix = session
                    .updated_at_unix
                    .saturating_add(UPLOAD_SESSION_TTL_SECS);
            }
            drop(sessions);
            persist_upload_session_store_after_mutation(state, "s3_complete_multipart_error").await;
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("failed to finalize multipart upload: {err:#}"),
                uri.path(),
                &request.request_id,
            );
        }
    };
    let mut object_metadata = multipart_metadata;
    object_metadata.version_id = outcome.version_id.clone();
    object_metadata.updated_at_unix = unix_ts();
    if let Err(err) = store
        .persist_object_version_metadata(&object_metadata)
        .await
    {
        return s3_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("failed to persist multipart object metadata: {err:#}"),
            uri.path(),
            &request.request_id,
        );
    }
    if let Err(err) = store
        .persist_s3_object_version(&S3ObjectVersionRecord {
            bucket_name: bucket.bucket_name.clone(),
            ironmesh_key: full_key.to_string(),
            version_id: outcome.version_id.clone(),
            etag: multipart_etag.clone(),
            multipart_part_count: Some(selected_parts.len() as u32),
            created_at_unix: unix_ts(),
        })
        .await
    {
        return s3_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("failed to persist multipart S3 version metadata: {err:#}"),
            uri.path(),
            &request.request_id,
        );
    }
    drop(store);

    publish_namespace_change(state);
    spawn_media_metadata_warmup(
        state.clone(),
        full_key.to_string(),
        outcome.manifest_hash.clone(),
    );
    let mut cluster = state.cluster.lock().await;
    cluster.note_replica(full_key, state.node_id);
    cluster.note_replica(
        format!("{}@{}", full_key, outcome.version_id),
        state.node_id,
    );
    drop(cluster);
    if let Err(err) = persist_cluster_replicas_state(state).await {
        warn!(
            error = %err,
            key = %full_key,
            "failed persisting cluster replicas after multipart completion"
        );
    }
    if should_trigger_autonomous_post_write_replication(
        state.autonomous_replication_on_put_enabled,
        false,
    ) {
        enqueue_autonomous_post_write_replication(
            state,
            autonomous_post_write_replication_subjects(full_key, &outcome.version_id),
        )
        .await;
    }
    record_data_change_event(
        state,
        PendingDataChangeEvent {
            action: DataChangeAction::Upload,
            actor: Some(s3_actor_context(&request.access_key)),
            path: full_key.to_string(),
            from_path: None,
            to_path: None,
            recursive: false,
            affected_path_count: 1,
            total_size_bytes: Some(total_size_bytes),
            version_id: Some(outcome.version_id.clone()),
            snapshot_id: Some(outcome.snapshot_id.clone()),
            upload_mode: Some(DataChangeUploadMode::Chunked),
        },
    )
    .await;

    let completed_result = MultipartUploadCompleteResult {
        version_id: outcome.version_id.clone(),
        etag: multipart_etag.clone(),
        modified_at_unix: unix_ts(),
        total_size_bytes,
        part_count: selected_parts.len() as u32,
    };
    let mut sessions = write_upload_sessions(state, "s3.multipart.complete.finish").await;
    if let Some(session) = sessions.sessions.get_mut(upload_id) {
        session.completed = true;
        session.finalizing = false;
        session.total_size_bytes = total_size_bytes;
        session.multipart_completed_result = Some(completed_result.clone());
        session.multipart_parts.clear();
        session.updated_at_unix = unix_ts();
        session.expires_at_unix = session
            .updated_at_unix
            .saturating_add(UPLOAD_SESSION_TTL_SECS);
    }
    drop(sessions);
    persist_upload_session_store_after_mutation(state, "s3_complete_multipart_finish").await;

    let mut response = xml_response(
        StatusCode::OK,
        render_complete_multipart_upload_result(
            &bucket.bucket_name,
            full_key_to_object_key(bucket, full_key)
                .unwrap_or_default()
                .as_str(),
            &completed_result,
        ),
        &request.request_id,
    );
    append_etag_header(&mut response, &completed_result.etag);
    append_version_id_header(&mut response, Some(&completed_result.version_id));
    response
}

async fn abort_multipart_upload_response(
    state: &ServerState,
    uri: &Uri,
    request: &S3RequestContext,
    bucket_name: &str,
    raw_key: &str,
    query: &S3ObjectQuery,
) -> Response {
    if !request.access_key.allow_write {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to abort multipart uploads",
            uri.path(),
            &request.request_id,
        );
    }
    let Some(upload_id) = query.upload_id.as_deref() else {
        return s3_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "uploadId is required to abort a multipart upload",
            uri.path(),
            &request.request_id,
        );
    };

    let bucket = match resolve_bucket(state, bucket_name).await {
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
            "the access key is not allowed to write this object path",
            uri.path(),
            &request.request_id,
        );
    }

    let now = unix_ts();
    let mut sessions = write_upload_sessions(state, "s3.multipart.abort").await;
    prune_expired_upload_sessions(&mut sessions, now);
    let Some(session) = sessions.sessions.get(upload_id) else {
        return s3_error_response(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "the specified multipart upload does not exist",
            uri.path(),
            &request.request_id,
        );
    };
    if !multipart_upload_session_matches(session, &bucket.bucket_name, &full_key) {
        return s3_error_response(
            StatusCode::NOT_FOUND,
            "NoSuchUpload",
            "the specified multipart upload does not exist",
            uri.path(),
            &request.request_id,
        );
    }
    sessions.sessions.remove(upload_id);
    drop(sessions);
    persist_upload_session_store_after_mutation(state, "s3_abort_multipart_upload").await;

    let mut response = StatusCode::NO_CONTENT.into_response();
    append_request_id_header(&mut response, &request.request_id);
    response
}

async fn execute_s3_object_version_delete(
    state: &ServerState,
    request: &S3RequestContext,
    bucket: &S3BucketRecord,
    full_key: &str,
    version_id: &str,
) -> Result<S3DeleteExecutionOutcome, S3DeleteExecutionError> {
    let actor = s3_actor_context(&request.access_key);
    let mut store = lock_store(state, "s3.delete_object_version.store").await;
    let outcome = store
        .delete_object_version_for_key(full_key, version_id)
        .await
        .map_err(|err| {
            S3DeleteExecutionError::Internal(format!("failed to delete S3 object version: {err:#}"))
        })?;
    let Some(outcome) = outcome else {
        return Err(S3DeleteExecutionError::NoSuchVersion);
    };
    if let Err(err) = store
        .delete_s3_object_version(&bucket.bucket_name, &outcome.version_id)
        .await
    {
        return Err(S3DeleteExecutionError::Internal(format!(
            "failed to delete S3 object version record: {err:#}"
        )));
    }
    drop(store);

    publish_namespace_change(state);
    let version_subject = format!("{full_key}@{}", outcome.version_id);
    let mut cluster = state.cluster.lock().await;
    cluster.remove_replica(&version_subject, state.node_id);
    cluster.remove_available(&version_subject, state.node_id);
    if !outcome.current_object_exists {
        cluster.remove_replica(full_key, state.node_id);
        cluster.remove_available(full_key, state.node_id);
    }
    drop(cluster);
    if let Err(err) = persist_cluster_replicas_state(state).await {
        warn!(
            error = %err,
            key = %full_key,
            version_id = %outcome.version_id,
            "failed persisting cluster replicas after S3 version delete"
        );
    }
    record_data_change_event(
        state,
        PendingDataChangeEvent {
            action: DataChangeAction::Delete,
            actor: Some(actor),
            path: full_key.to_string(),
            from_path: None,
            to_path: None,
            recursive: false,
            affected_path_count: 1,
            total_size_bytes: None,
            version_id: Some(outcome.version_id.clone()),
            snapshot_id: None,
            upload_mode: None,
        },
    )
    .await;

    Ok(S3DeleteExecutionOutcome {
        header_version_id: outcome.version_id.clone(),
        batch_version_id: Some(outcome.version_id.clone()),
        delete_marker: outcome.was_delete_marker,
        delete_marker_version_id: outcome.was_delete_marker.then_some(outcome.version_id),
    })
}

async fn execute_s3_current_object_delete(
    state: &ServerState,
    request: &S3RequestContext,
    bucket: &S3BucketRecord,
    full_key: &str,
) -> Result<S3DeleteExecutionOutcome, S3DeleteExecutionError> {
    let actor = s3_actor_context(&request.access_key);
    let mut store = lock_store(state, "s3.delete_object.store").await;
    let version_id = store
        .tombstone_object(full_key, PutOptions::default())
        .await
        .map_err(|err| {
            S3DeleteExecutionError::Internal(format!("failed to delete S3 object: {err:#}"))
        })?;
    let s3_object_version = S3ObjectVersionRecord {
        bucket_name: bucket.bucket_name.clone(),
        ironmesh_key: full_key.to_string(),
        version_id: version_id.clone(),
        etag: object_etag(TOMBSTONE_MANIFEST_HASH),
        multipart_part_count: None,
        created_at_unix: unix_ts(),
    };
    if let Err(err) = store.persist_s3_object_version(&s3_object_version).await {
        return Err(S3DeleteExecutionError::Internal(format!(
            "failed to persist S3 tombstone version record: {err:#}"
        )));
    }
    drop(store);

    publish_namespace_change(state);
    let mut cluster = state.cluster.lock().await;
    cluster.note_replica(full_key, state.node_id);
    cluster.note_replica(format!("{}@{}", full_key, version_id), state.node_id);
    drop(cluster);
    if let Err(err) = persist_cluster_replicas_state(state).await {
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
            state,
            autonomous_post_write_replication_subjects(full_key, &version_id),
        )
        .await;
    }
    record_data_change_event(
        state,
        PendingDataChangeEvent {
            action: DataChangeAction::Delete,
            actor: Some(actor),
            path: full_key.to_string(),
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

    let expose_delete_marker = bucket.versioning_status == S3BucketVersioningStatus::Enabled;
    Ok(S3DeleteExecutionOutcome {
        header_version_id: version_id.clone(),
        batch_version_id: None,
        delete_marker: expose_delete_marker,
        delete_marker_version_id: expose_delete_marker.then_some(version_id),
    })
}

async fn delete_object_version_response(
    state: &ServerState,
    request_path: &str,
    request: &S3RequestContext,
    bucket: &S3BucketRecord,
    full_key: &str,
    version_id: &str,
) -> Response {
    let outcome = match execute_s3_object_version_delete(
        state, request, bucket, full_key, version_id,
    )
    .await
    {
        Ok(outcome) => outcome,
        Err(S3DeleteExecutionError::NoSuchVersion) => {
            return s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchVersion",
                "the specified version does not exist",
                request_path,
                &request.request_id,
            );
        }
        Err(S3DeleteExecutionError::Internal(message)) => {
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &message,
                request_path,
                &request.request_id,
            );
        }
    };

    let mut response = StatusCode::NO_CONTENT.into_response();
    append_request_id_header(&mut response, &request.request_id);
    append_version_id_header(&mut response, Some(&outcome.header_version_id));
    if outcome.delete_marker {
        append_delete_marker_header(&mut response);
    }
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
    if query.upload_id.is_some() {
        return abort_multipart_upload_response(
            &state,
            &uri,
            &request,
            &bucket_name,
            &raw_key,
            &query,
        )
        .await;
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
    if let Some(version_id) = query.version_id.as_deref() {
        return delete_object_version_response(
            &state,
            uri.path(),
            &request,
            &bucket,
            &full_key,
            version_id,
        )
        .await;
    }

    let outcome = match execute_s3_current_object_delete(&state, &request, &bucket, &full_key).await
    {
        Ok(outcome) => outcome,
        Err(S3DeleteExecutionError::Internal(message)) => {
            return s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &message,
                uri.path(),
                &request.request_id,
            );
        }
        Err(S3DeleteExecutionError::NoSuchVersion) => {
            unreachable!("current deletes do not resolve version IDs")
        }
    };

    let mut response = StatusCode::NO_CONTENT.into_response();
    append_request_id_header(&mut response, &request.request_id);
    append_version_id_header(&mut response, Some(&outcome.header_version_id));
    if outcome.delete_marker {
        append_delete_marker_header(&mut response);
    }
    response
}

async fn delete_objects_response(
    state: &ServerState,
    uri: &Uri,
    request: &S3RequestContext,
    bucket_name: &str,
    payload: Bytes,
) -> Response {
    if !request.access_key.allow_delete {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to delete objects",
            uri.path(),
            &request.request_id,
        );
    }
    let bucket = match resolve_bucket(state, bucket_name).await {
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
    if !access_key_allows_bucket(&request.access_key, &bucket) {
        return s3_error_response(
            StatusCode::FORBIDDEN,
            "AccessDenied",
            "the access key is not allowed to access this bucket",
            uri.path(),
            &request.request_id,
        );
    }

    let delete_request = match parse_delete_objects_request(payload.as_ref()) {
        Ok(request) => request,
        Err(message) => {
            return s3_error_response(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                &message,
                uri.path(),
                &request.request_id,
            );
        }
    };

    let mut deleted = Vec::new();
    let mut errors = Vec::new();
    for object in delete_request.objects {
        let full_key = format!(
            "{}{}",
            bucket.root_prefix,
            object.key.trim_start_matches('/')
        );
        if !access_key_allows_object(&request.access_key, &bucket, &full_key) {
            errors.push(DeleteObjectsErrorEntry {
                key: object.key,
                version_id: object.version_id,
                code: "AccessDenied",
                message: "the access key is not allowed to delete this object path".to_string(),
            });
            continue;
        }

        let outcome = if let Some(version_id) = object.version_id.as_deref() {
            match execute_s3_object_version_delete(state, request, &bucket, &full_key, version_id)
                .await
            {
                Ok(outcome) => Some(outcome),
                Err(S3DeleteExecutionError::NoSuchVersion) => {
                    errors.push(DeleteObjectsErrorEntry {
                        key: object.key.clone(),
                        version_id: object.version_id.clone(),
                        code: "NoSuchVersion",
                        message: "the specified version does not exist".to_string(),
                    });
                    None
                }
                Err(S3DeleteExecutionError::Internal(message)) => {
                    errors.push(DeleteObjectsErrorEntry {
                        key: object.key.clone(),
                        version_id: object.version_id.clone(),
                        code: "InternalError",
                        message,
                    });
                    None
                }
            }
        } else {
            match execute_s3_current_object_delete(state, request, &bucket, &full_key).await {
                Ok(outcome) => Some(outcome),
                Err(S3DeleteExecutionError::Internal(message)) => {
                    errors.push(DeleteObjectsErrorEntry {
                        key: object.key.clone(),
                        version_id: None,
                        code: "InternalError",
                        message,
                    });
                    None
                }
                Err(S3DeleteExecutionError::NoSuchVersion) => None,
            }
        };
        if let Some(outcome) = outcome {
            deleted.push(DeleteObjectsDeletedEntry {
                key: object.key,
                version_id: outcome.batch_version_id,
                delete_marker: outcome.delete_marker,
                delete_marker_version_id: outcome.delete_marker_version_id,
            });
        }
    }

    let mut response = xml_response(
        StatusCode::OK,
        render_delete_objects_result(delete_request.quiet, &deleted, &errors),
        &request.request_id,
    );
    append_request_id_header(&mut response, &request.request_id);
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
    if query.upload_id.is_some() {
        let response =
            list_multipart_parts_response(state, &uri, &request, &bucket, &full_key, &query).await;
        if head_only {
            return head_response_without_body(response);
        }
        return response;
    }
    if query.part_number.is_some() {
        return s3_error_response(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "partNumber requires uploadId for multipart upload operations",
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
    let effective_version_id = match resolved_version_id.as_deref() {
        Some(version_id) => Some(version_id.to_string()),
        None => {
            match resolve_current_head_version_id(state, &full_key, uri.path(), &request.request_id)
                .await
            {
                Ok(version_id) => version_id,
                Err(response) => return response,
            }
        }
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
            StatusCode::NOT_FOUND => {
                if let Some(version_id) = resolved_version_id
                    .as_deref()
                    .filter(|_| query.version_id.is_some())
                {
                    match inspect_object_version_for_s3(
                        state,
                        &full_key,
                        version_id,
                        uri.path(),
                        &request.request_id,
                    )
                    .await
                    {
                        Ok(Some(inspection)) if inspection.is_delete_marker => {
                            return build_delete_marker_version_response(
                                head_only,
                                &request.request_id,
                                version_id,
                                inspection.created_at_unix,
                            );
                        }
                        Ok(_) => {}
                        Err(response) => return response,
                    }
                }

                if query.version_id.is_none()
                    && bucket.versioning_status == S3BucketVersioningStatus::Enabled
                    && let Some(version_id) = resolved_version_id.as_deref()
                {
                    match inspect_object_version_for_s3(
                        state,
                        &full_key,
                        version_id,
                        uri.path(),
                        &request.request_id,
                    )
                    .await
                    {
                        Ok(Some(inspection)) if inspection.is_delete_marker => {
                            return build_current_delete_marker_response(
                                head_only,
                                uri.path(),
                                &request.request_id,
                            );
                        }
                        Ok(_) => {}
                        Err(response) => return response,
                    }
                }

                s3_error_response(
                    StatusCode::NOT_FOUND,
                    "NoSuchKey",
                    "the specified key does not exist",
                    uri.path(),
                    &request.request_id,
                )
            }
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

    let metadata = match effective_version_id.as_deref() {
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
    let s3_object_version = match effective_version_id.as_deref() {
        Some(version_id) => {
            let store = read_store(state, "s3.get_object.load_s3_version").await;
            match store
                .load_s3_object_version(&bucket.bucket_name, version_id)
                .await
            {
                Ok(record) => record,
                Err(err) => {
                    return s3_error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        &format!("failed to load S3 object version record: {err:#}"),
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
    if let Some(version) = s3_object_version.as_ref() {
        append_etag_header(&mut response, &version.etag);
    }
    response
}

async fn authenticate_request(
    state: &ServerState,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
) -> Result<S3RequestContext, Response> {
    let request_id = new_s3_request_id();
    if uri
        .query()
        .is_some_and(|query| query.contains("X-Amz-Signature="))
    {
        let parsed = match parse_presigned_authorization(uri) {
            Ok(parsed) => parsed,
            Err(message) => {
                return Err(s3_error_response(
                    StatusCode::FORBIDDEN,
                    "AuthorizationQueryParametersError",
                    &message,
                    uri.path(),
                    &request_id,
                ));
            }
        };
        if parsed.parsed.service != "s3" {
            return Err(s3_error_response(
                StatusCode::FORBIDDEN,
                "AuthorizationQueryParametersError",
                "the presigned credential scope must target the s3 service",
                uri.path(),
                &request_id,
            ));
        }

        let Some(access_key) = resolve_s3_access_key(state, &parsed.parsed.access_key_id).await
        else {
            return Err(s3_error_response(
                StatusCode::FORBIDDEN,
                "InvalidAccessKeyId",
                "the provided access key is not recognized",
                uri.path(),
                &request_id,
            ));
        };

        let expected_signature = match build_expected_presigned_signature(
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
            parsed.parsed.signature_hex.as_bytes(),
        ) {
            return Err(s3_error_response(
                StatusCode::FORBIDDEN,
                "SignatureDoesNotMatch",
                "the request signature we calculated does not match the provided signature",
                uri.path(),
                &request_id,
            ));
        }

        return Ok(S3RequestContext {
            request_id,
            access_key,
        });
    }

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

    let Some(access_key) = resolve_s3_access_key(state, &parsed.access_key_id).await else {
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
    parse_credential_scope(&credential, signed_headers, signature_hex)
}

fn parse_presigned_authorization(uri: &Uri) -> Result<ParsedS3QueryAuthorization, String> {
    let algorithm = query_parameter_value(uri, "X-Amz-Algorithm")?
        .ok_or_else(|| "X-Amz-Algorithm is missing".to_string())?;
    if algorithm != "AWS4-HMAC-SHA256" {
        return Err("only AWS4-HMAC-SHA256 presigned requests are supported".to_string());
    }

    let credential = query_parameter_value(uri, "X-Amz-Credential")?
        .ok_or_else(|| "X-Amz-Credential is missing".to_string())?;
    let amz_date = query_parameter_value(uri, "X-Amz-Date")?
        .ok_or_else(|| "X-Amz-Date is missing".to_string())?;
    let expires = query_parameter_value(uri, "X-Amz-Expires")?
        .ok_or_else(|| "X-Amz-Expires is missing".to_string())?;
    let expires = expires
        .parse::<u64>()
        .map_err(|_| "X-Amz-Expires must be an integer".to_string())?;
    if !(1..=604_800).contains(&expires) {
        return Err("X-Amz-Expires must be between 1 and 604800 seconds".to_string());
    }

    let signed_headers = query_parameter_value(uri, "X-Amz-SignedHeaders")?
        .ok_or_else(|| "X-Amz-SignedHeaders is missing".to_string())?
        .split(';')
        .map(|entry| entry.trim().to_ascii_lowercase())
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();
    let signature_hex = query_parameter_value(uri, "X-Amz-Signature")?
        .ok_or_else(|| "X-Amz-Signature is missing".to_string())?
        .to_ascii_lowercase();
    let parsed = parse_credential_scope(&credential, signed_headers, signature_hex)?;
    Ok(ParsedS3QueryAuthorization {
        parsed,
        amz_date,
        payload_hash: S3_UNSIGNED_PAYLOAD.to_string(),
    })
}

fn parse_credential_scope(
    credential: &str,
    signed_headers: Vec<String>,
    signature_hex: String,
) -> Result<ParsedS3Authorization, String> {
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

fn query_parameter_value(uri: &Uri, parameter_name: &str) -> Result<Option<String>, String> {
    for pair in uri.query().unwrap_or_default().split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name != parameter_name {
            continue;
        }
        let decoded = percent_encoding::percent_decode_str(value)
            .decode_utf8()
            .map_err(|_| {
                format!("query parameter {parameter_name} contains invalid percent-encoding")
            })?;
        return Ok(Some(decoded.to_string()));
    }
    Ok(None)
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

    let canonical_request = build_canonical_request(
        method,
        uri,
        headers,
        &parsed.signed_headers,
        payload_hash,
        &canonical_query_string(uri),
    )?;
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

fn build_expected_presigned_signature(
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    parsed: &ParsedS3QueryAuthorization,
    secret_material: &str,
) -> Result<String, String> {
    let canonical_request = build_canonical_request(
        method,
        uri,
        headers,
        &parsed.parsed.signed_headers,
        &parsed.payload_hash,
        &canonical_query_string_excluding(uri, "X-Amz-Signature"),
    )?;
    let canonical_request_hash = hex_sha256(canonical_request.as_bytes());
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{canonical_request_hash}",
        parsed.amz_date, parsed.parsed.credential_scope
    );
    let signing_key = derive_signing_key(
        secret_material,
        &parsed.parsed.date_scope,
        &parsed.parsed.region,
        &parsed.parsed.service,
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
    canonical_query: &str,
) -> Result<String, String> {
    let canonical_uri = if uri.path().is_empty() {
        "/"
    } else {
        uri.path()
    };
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
    canonical_query_string_excluding(uri, "")
}

fn canonical_query_string_excluding(uri: &Uri, excluded_name: &str) -> String {
    let mut pairs = uri
        .query()
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (name.to_string(), value.to_string())
        })
        .filter(|(name, _)| excluded_name.is_empty() || name != excluded_name)
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

fn default_s3_bucket_root_prefix(bucket_name: &str) -> String {
    format!("s3/{bucket_name}/")
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

async fn resolve_s3_access_key(
    state: &ServerState,
    access_key_id: &str,
) -> Option<S3AccessKeyRecord> {
    let control_plane = state.s3.control_plane.lock().await;
    control_plane
        .access_keys
        .iter()
        .find(|access_key| {
            access_key.access_key_id == access_key_id && access_key.revoked_at_unix.is_none()
        })
        .cloned()
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

fn access_key_can_manage_bucket_name(access_key: &S3AccessKeyRecord, bucket_name: &str) -> bool {
    access_key.bucket_scope.is_empty()
        || access_key
            .bucket_scope
            .iter()
            .any(|scope| scope == bucket_name)
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

fn multipart_upload_session_matches(
    session: &UploadSessionRecord,
    bucket_name: &str,
    full_key: &str,
) -> bool {
    session.assembly_mode == UploadAssemblyMode::Multipart
        && session.key == full_key
        && session.multipart_bucket_name.as_deref() == Some(bucket_name)
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
            return Err(s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchVersion",
                "the specified version does not exist",
                request_path,
                request_id,
            ));
        };
        if version.ironmesh_key != full_key {
            return Err(s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchVersion",
                "the specified version does not exist",
                request_path,
                request_id,
            ));
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

async fn resolve_current_head_version_id(
    state: &ServerState,
    full_key: &str,
    request_path: &str,
    request_id: &str,
) -> Result<Option<String>, Response> {
    let store = read_store(state, "s3.get_object.current_head_version").await;
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
    Ok(versions.and_then(|graph| graph.preferred_head_version_id))
}

async fn inspect_object_version_for_s3(
    state: &ServerState,
    full_key: &str,
    version_id: &str,
    request_path: &str,
    request_id: &str,
) -> Result<Option<ObjectVersionInspection>, Response> {
    let store = read_store(state, "s3.get_object.inspect_version").await;
    match store.inspect_object_version(full_key, version_id).await {
        Ok(inspection) => Ok(inspection),
        Err(err) => Err(s3_error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
            &format!("failed to inspect object version: {err:#}"),
            request_path,
            request_id,
        )),
    }
}

async fn resolve_copy_source_version(
    store: &storage::PersistentStore,
    bucket: &S3BucketRecord,
    full_key: &str,
    requested_version_id: Option<&str>,
    request_path: &str,
    request_id: &str,
) -> Result<String, Response> {
    if let Some(version_id) = requested_version_id {
        let version = match store
            .load_s3_object_version(&bucket.bucket_name, version_id)
            .await
        {
            Ok(version) => version,
            Err(err) => {
                return Err(s3_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    &format!("failed to load copy source version record: {err:#}"),
                    request_path,
                    request_id,
                ));
            }
        };
        let Some(version) = version else {
            return Err(s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchVersion",
                "the specified source version does not exist",
                request_path,
                request_id,
            ));
        };
        if version.ironmesh_key != full_key {
            return Err(s3_error_response(
                StatusCode::NOT_FOUND,
                "NoSuchVersion",
                "the specified source version does not exist",
                request_path,
                request_id,
            ));
        }
        return Ok(version.version_id);
    }

    let versions = match store.list_versions(full_key).await {
        Ok(versions) => versions,
        Err(err) => {
            return Err(s3_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                &format!("failed to inspect copy source versions: {err:#}"),
                request_path,
                request_id,
            ));
        }
    };
    let Some(versions) = versions else {
        return Err(s3_error_response(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "the specified copy source does not exist",
            request_path,
            request_id,
        ));
    };
    match versions.preferred_head_version_id {
        Some(version_id) => Ok(version_id),
        None => Err(s3_error_response(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "the specified copy source does not exist",
            request_path,
            request_id,
        )),
    }
}

fn parse_copy_source(value: &str) -> Result<S3CopySource, String> {
    let trimmed = value.trim().trim_start_matches('/');
    if trimmed.is_empty() {
        return Err("x-amz-copy-source must include a bucket and object key".to_string());
    }

    let (raw_path, raw_query) = trimmed.split_once('?').unwrap_or((trimmed, ""));
    let decoded_path = percent_encoding::percent_decode_str(raw_path)
        .decode_utf8()
        .map_err(|_| "x-amz-copy-source contains invalid percent-encoding".to_string())?;
    let (bucket_name, object_key) = decoded_path.split_once('/').ok_or_else(|| {
        "x-amz-copy-source must include both a bucket name and object key".to_string()
    })?;
    if bucket_name.trim().is_empty() || object_key.trim().is_empty() {
        return Err("x-amz-copy-source must include both a bucket name and object key".to_string());
    }

    let mut version_id = None::<String>;
    for pair in raw_query.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name != "versionId" {
            continue;
        }

        let decoded_value = percent_encoding::percent_decode_str(value)
            .decode_utf8()
            .map_err(|_| {
                "x-amz-copy-source versionId contains invalid percent-encoding".to_string()
            })?;
        if !decoded_value.is_empty() {
            version_id = Some(decoded_value.to_string());
        }
    }

    Ok(S3CopySource {
        bucket_name: bucket_name.to_string(),
        object_key: object_key.to_string(),
        version_id,
    })
}

fn parse_metadata_directive(headers: &HeaderMap) -> Result<S3MetadataDirective, String> {
    match header_value_name(headers, "x-amz-metadata-directive")
        .as_deref()
        .map(str::to_ascii_uppercase)
    {
        None => Ok(S3MetadataDirective::Copy),
        Some(value) if value == "COPY" => Ok(S3MetadataDirective::Copy),
        Some(value) if value == "REPLACE" => Ok(S3MetadataDirective::Replace),
        Some(_) => Err("x-amz-metadata-directive must be either COPY or REPLACE".to_string()),
    }
}

fn normalize_etag(value: &str) -> String {
    value.trim().trim_matches('"').to_ascii_lowercase()
}

fn part_etag(payload: &[u8]) -> String {
    let digest = Md5::digest(payload);
    format!("\"{}\"", hex_encode(digest.as_slice()))
}

fn complete_multipart_etag(part_etags: &[String]) -> Result<String, String> {
    if part_etags.is_empty() {
        return Err("multipart uploads must include at least one part".to_string());
    }

    let mut digests = Vec::with_capacity(part_etags.len() * 16);
    for etag in part_etags {
        let normalized = normalize_etag(etag);
        if normalized.len() != 32 {
            return Err("multipart part ETag must be a 32-character MD5 digest".to_string());
        }
        digests.extend(hex_decode(&normalized)?);
    }

    let digest = Md5::digest(&digests);
    Ok(format!(
        "\"{}-{}\"",
        hex_encode(digest.as_slice()),
        part_etags.len()
    ))
}

fn hex_decode(value: &str) -> Result<Vec<u8>, String> {
    fn decode_nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    if value.len() % 2 != 0 {
        return Err("hex-encoded values must have an even number of digits".to_string());
    }

    let mut decoded = Vec::with_capacity(value.len() / 2);
    for pair in value.as_bytes().chunks_exact(2) {
        let high = decode_nibble(pair[0])
            .ok_or_else(|| "hex-encoded values must only contain hexadecimal digits".to_string())?;
        let low = decode_nibble(pair[1])
            .ok_or_else(|| "hex-encoded values must only contain hexadecimal digits".to_string())?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn parse_complete_multipart_upload_parts(xml: &str) -> Result<Vec<CompletedMultipartPart>, String> {
    let parts_xml = xml_tag_blocks(xml, "Part");
    if parts_xml.is_empty() {
        return Err("CompleteMultipartUpload must include at least one Part element".to_string());
    }

    let mut parts = Vec::with_capacity(parts_xml.len());
    for part_xml in parts_xml {
        let Some(part_number_raw) = xml_tag_contents(part_xml, "PartNumber") else {
            return Err("each multipart Part must include a PartNumber".to_string());
        };
        let part_number = part_number_raw
            .parse::<u32>()
            .map_err(|_| "each multipart PartNumber must be a positive integer".to_string())?;
        if !(1..=S3_MULTIPART_MAX_PARTS).contains(&part_number) {
            return Err("each multipart PartNumber must be between 1 and 10000".to_string());
        }

        let Some(etag) = xml_tag_contents(part_xml, "ETag") else {
            return Err("each multipart Part must include an ETag".to_string());
        };
        let etag = etag.trim();
        if etag.is_empty() {
            return Err("multipart Part ETag values must not be empty".to_string());
        }

        parts.push(CompletedMultipartPart {
            part_number,
            etag: etag.to_string(),
        });
    }

    Ok(parts)
}

fn xml_tag_blocks<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let close = format!("</{tag}>");
    let mut blocks = Vec::new();
    let mut offset = 0usize;

    while let Some(start_rel) = xml[offset..].find(&format!("<{tag}")) {
        let open_start = offset + start_rel;
        let open_tag_end = open_start + tag.len() + 1;
        let Some(next_char) = xml[open_tag_end..].chars().next() else {
            break;
        };
        if next_char != '>' && next_char != '/' && !next_char.is_ascii_whitespace() {
            offset = open_tag_end;
            continue;
        }
        let Some(open_end_rel) = xml[open_start..].find('>') else {
            break;
        };
        let start = open_start + open_end_rel + 1;
        let Some(end_rel) = xml[start..].find(&close) else {
            break;
        };
        let end = start + end_rel;
        blocks.push(xml[start..end].trim());
        offset = end + close.len();
    }

    blocks
}

fn xml_tag_contents<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    xml_tag_blocks(xml, tag).into_iter().next()
}

fn parse_delete_objects_request(payload: &[u8]) -> Result<DeleteObjectsRequest, String> {
    if payload.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Err("DeleteObjects requires a non-empty XML request body".to_string());
    }
    let xml = std::str::from_utf8(payload)
        .map_err(|_| "DeleteObjects request bodies must be valid UTF-8 XML".to_string())?;
    let Some(delete_xml) = xml_tag_contents(xml, "Delete") else {
        return Err("DeleteObjects request bodies must include a Delete element".to_string());
    };
    let object_blocks = xml_tag_blocks(delete_xml, "Object");
    if object_blocks.is_empty() {
        return Err("DeleteObjects must include at least one Object element".to_string());
    }
    if object_blocks.len() > 1000 {
        return Err("DeleteObjects may not include more than 1000 Object elements".to_string());
    }

    let mut objects = Vec::with_capacity(object_blocks.len());
    for object_xml in object_blocks {
        let Some(key) = xml_tag_contents(object_xml, "Key") else {
            return Err("DeleteObjects Object elements must include a Key".to_string());
        };
        let version_id = xml_tag_contents(object_xml, "VersionId")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        objects.push(DeleteObjectsRequestItem {
            key: key.to_string(),
            version_id,
        });
    }

    let quiet = xml_tag_contents(delete_xml, "Quiet")
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    Ok(DeleteObjectsRequest { objects, quiet })
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

fn linearize_s3_version_records(
    summary: Option<&crate::storage::VersionGraphSummary>,
    records: &[S3ObjectVersionRecord],
) -> Vec<S3ObjectVersionRecord> {
    let records_by_version_id = records
        .iter()
        .cloned()
        .map(|record| (record.version_id.clone(), record))
        .collect::<HashMap<_, _>>();
    let version_summaries = summary
        .map(|summary| {
            summary
                .versions
                .iter()
                .map(|record| (record.version_id.clone(), record))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();

    let mut ordered = Vec::with_capacity(records.len());
    let mut visited = HashSet::<String>::new();
    let mut cursor = summary.and_then(|summary| summary.preferred_head_version_id.clone());
    while let Some(version_id) = cursor {
        if !visited.insert(version_id.clone()) {
            break;
        }
        if let Some(record) = records_by_version_id.get(&version_id) {
            ordered.push(record.clone());
        }
        cursor = version_summaries
            .get(&version_id)
            .and_then(|record| record.parent_version_ids.first())
            .cloned();
    }

    for record in records {
        if visited.insert(record.version_id.clone()) {
            ordered.push(record.clone());
        }
    }

    ordered
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

fn render_copy_object_result(etag: &str, modified_at_unix: u64) -> String {
    let mut xml =
        String::from(r#"<?xml version="1.0" encoding="UTF-8"?><CopyObjectResult xmlns=""#);
    xml.push('"');
    xml.push_str(S3_XML_NAMESPACE);
    xml.push_str(r#""><LastModified>"#);
    xml.push_str(&xml_escape(&s3_timestamp(modified_at_unix)));
    xml.push_str("</LastModified><ETag>");
    xml.push_str(&xml_escape(etag));
    xml.push_str("</ETag></CopyObjectResult>");
    xml
}

fn render_bucket_versioning_result(bucket: &S3BucketRecord) -> String {
    let mut xml =
        String::from(r#"<?xml version="1.0" encoding="UTF-8"?><VersioningConfiguration xmlns=""#);
    xml.push('"');
    xml.push_str(S3_XML_NAMESPACE);
    xml.push_str(r#"">"#);
    if bucket.versioning_status == S3BucketVersioningStatus::Enabled {
        xml.push_str("<Status>Enabled</Status>");
    }
    xml.push_str("</VersioningConfiguration>");
    xml
}

fn render_delete_objects_result(
    quiet: bool,
    deleted: &[DeleteObjectsDeletedEntry],
    errors: &[DeleteObjectsErrorEntry],
) -> String {
    let mut xml = String::from(r#"<?xml version="1.0" encoding="UTF-8"?><DeleteResult xmlns=""#);
    xml.push('"');
    xml.push_str(S3_XML_NAMESPACE);
    xml.push_str(r#"">"#);
    if !quiet {
        for entry in deleted {
            xml.push_str("<Deleted><Key>");
            xml.push_str(&xml_escape(&entry.key));
            xml.push_str("</Key>");
            if let Some(version_id) = entry.version_id.as_deref() {
                xml.push_str("<VersionId>");
                xml.push_str(&xml_escape(version_id));
                xml.push_str("</VersionId>");
            }
            if entry.delete_marker {
                xml.push_str("<DeleteMarker>true</DeleteMarker>");
            }
            if let Some(version_id) = entry.delete_marker_version_id.as_deref() {
                xml.push_str("<DeleteMarkerVersionId>");
                xml.push_str(&xml_escape(version_id));
                xml.push_str("</DeleteMarkerVersionId>");
            }
            xml.push_str("</Deleted>");
        }
    }
    for entry in errors {
        xml.push_str("<Error><Key>");
        xml.push_str(&xml_escape(&entry.key));
        xml.push_str("</Key>");
        if let Some(version_id) = entry.version_id.as_deref() {
            xml.push_str("<VersionId>");
            xml.push_str(&xml_escape(version_id));
            xml.push_str("</VersionId>");
        }
        xml.push_str("<Code>");
        xml.push_str(entry.code);
        xml.push_str("</Code><Message>");
        xml.push_str(&xml_escape(&entry.message));
        xml.push_str("</Message></Error>");
    }
    xml.push_str("</DeleteResult>");
    xml
}

fn render_list_object_versions_result(
    bucket: &S3BucketRecord,
    prefix: &str,
    delimiter: Option<&str>,
    key_marker: Option<&str>,
    version_id_marker: Option<&str>,
    max_keys: usize,
    is_truncated: bool,
    next_key_marker: Option<&str>,
    next_version_id_marker: Option<&str>,
    entries: &[S3ListVersionEntry],
    common_prefixes: &[String],
) -> String {
    let mut xml =
        String::from(r#"<?xml version="1.0" encoding="UTF-8"?><ListVersionsResult xmlns=""#);
    xml.push('"');
    xml.push_str(S3_XML_NAMESPACE);
    xml.push_str(r#""><Name>"#);
    xml.push_str(&xml_escape(&bucket.bucket_name));
    xml.push_str("</Name><Prefix>");
    xml.push_str(&xml_escape(prefix));
    xml.push_str("</Prefix><KeyMarker>");
    xml.push_str(&xml_escape(key_marker.unwrap_or("")));
    xml.push_str("</KeyMarker><VersionIdMarker>");
    xml.push_str(&xml_escape(version_id_marker.unwrap_or("")));
    xml.push_str("</VersionIdMarker><MaxKeys>");
    xml.push_str(&max_keys.to_string());
    xml.push_str("</MaxKeys>");
    if let Some(delimiter) = delimiter {
        xml.push_str("<Delimiter>");
        xml.push_str(&xml_escape(delimiter));
        xml.push_str("</Delimiter>");
    }
    xml.push_str("<IsTruncated>");
    xml.push_str(if is_truncated { "true" } else { "false" });
    xml.push_str("</IsTruncated>");
    if let Some(marker) = next_key_marker {
        xml.push_str("<NextKeyMarker>");
        xml.push_str(&xml_escape(marker));
        xml.push_str("</NextKeyMarker>");
    }
    if let Some(marker) = next_version_id_marker {
        xml.push_str("<NextVersionIdMarker>");
        xml.push_str(&xml_escape(marker));
        xml.push_str("</NextVersionIdMarker>");
    }
    for entry in entries {
        if entry.is_delete_marker {
            xml.push_str("<DeleteMarker><Key>");
            xml.push_str(&xml_escape(&entry.key));
            xml.push_str("</Key><VersionId>");
            xml.push_str(&xml_escape(&entry.version_id));
            xml.push_str("</VersionId><IsLatest>");
            xml.push_str(if entry.is_latest { "true" } else { "false" });
            xml.push_str("</IsLatest><LastModified>");
            xml.push_str(&xml_escape(&s3_timestamp(entry.modified_at_unix)));
            xml.push_str("</LastModified></DeleteMarker>");
        } else {
            xml.push_str("<Version><Key>");
            xml.push_str(&xml_escape(&entry.key));
            xml.push_str("</Key><VersionId>");
            xml.push_str(&xml_escape(&entry.version_id));
            xml.push_str("</VersionId><IsLatest>");
            xml.push_str(if entry.is_latest { "true" } else { "false" });
            xml.push_str("</IsLatest><LastModified>");
            xml.push_str(&xml_escape(&s3_timestamp(entry.modified_at_unix)));
            xml.push_str("</LastModified><ETag>");
            xml.push_str(&xml_escape(&entry.etag));
            xml.push_str("</ETag><Size>");
            xml.push_str(&entry.size_bytes.unwrap_or(0).to_string());
            xml.push_str("</Size><StorageClass>STANDARD</StorageClass></Version>");
        }
    }
    for prefix in common_prefixes {
        xml.push_str("<CommonPrefixes><Prefix>");
        xml.push_str(&xml_escape(prefix));
        xml.push_str("</Prefix></CommonPrefixes>");
    }
    xml.push_str("</ListVersionsResult>");
    xml
}

fn render_create_multipart_upload_result(
    bucket_name: &str,
    object_key: &str,
    upload_id: &str,
) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult xmlns=""#,
    );
    xml.push('"');
    xml.push_str(S3_XML_NAMESPACE);
    xml.push_str(r#""><Bucket>"#);
    xml.push_str(&xml_escape(bucket_name));
    xml.push_str("</Bucket><Key>");
    xml.push_str(&xml_escape(object_key));
    xml.push_str("</Key><UploadId>");
    xml.push_str(&xml_escape(upload_id));
    xml.push_str("</UploadId></InitiateMultipartUploadResult>");
    xml
}

fn render_list_parts_result(
    bucket_name: &str,
    object_key: &str,
    upload_id: &str,
    part_number_marker: u32,
    max_parts: usize,
    is_truncated: bool,
    next_part_number_marker: Option<u32>,
    parts: &[StagedUploadPart],
) -> String {
    let mut xml = String::from(r#"<?xml version="1.0" encoding="UTF-8"?><ListPartsResult xmlns=""#);
    xml.push('"');
    xml.push_str(S3_XML_NAMESPACE);
    xml.push_str(r#""><Bucket>"#);
    xml.push_str(&xml_escape(bucket_name));
    xml.push_str("</Bucket><Key>");
    xml.push_str(&xml_escape(object_key));
    xml.push_str("</Key><UploadId>");
    xml.push_str(&xml_escape(upload_id));
    xml.push_str("</UploadId><PartNumberMarker>");
    xml.push_str(&part_number_marker.to_string());
    xml.push_str("</PartNumberMarker><MaxParts>");
    xml.push_str(&max_parts.to_string());
    xml.push_str("</MaxParts><IsTruncated>");
    xml.push_str(if is_truncated { "true" } else { "false" });
    xml.push_str("</IsTruncated>");
    if let Some(marker) = next_part_number_marker {
        xml.push_str("<NextPartNumberMarker>");
        xml.push_str(&marker.to_string());
        xml.push_str("</NextPartNumberMarker>");
    }
    for part in parts {
        xml.push_str("<Part><PartNumber>");
        xml.push_str(&part.part_number.to_string());
        xml.push_str("</PartNumber><LastModified>");
        xml.push_str(&xml_escape(&s3_timestamp(part.created_at_unix)));
        xml.push_str("</LastModified><ETag>");
        xml.push_str(&xml_escape(part.client_etag.as_deref().unwrap_or_default()));
        xml.push_str("</ETag><Size>");
        xml.push_str(&part.size_bytes.to_string());
        xml.push_str("</Size></Part>");
    }
    xml.push_str("</ListPartsResult>");
    xml
}

fn render_complete_multipart_upload_result(
    bucket_name: &str,
    object_key: &str,
    result: &MultipartUploadCompleteResult,
) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUploadResult xmlns=""#,
    );
    xml.push('"');
    xml.push_str(S3_XML_NAMESPACE);
    xml.push_str(r#""><Location>/"#);
    xml.push_str(&xml_escape(bucket_name));
    xml.push('/');
    xml.push_str(&xml_escape(object_key));
    xml.push_str("</Location><Bucket>");
    xml.push_str(&xml_escape(bucket_name));
    xml.push_str("</Bucket><Key>");
    xml.push_str(&xml_escape(object_key));
    xml.push_str("</Key><ETag>");
    xml.push_str(&xml_escape(&result.etag));
    xml.push_str("</ETag></CompleteMultipartUploadResult>");
    xml
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

fn append_delete_marker_header(response: &mut Response) {
    response
        .headers_mut()
        .insert("x-amz-delete-marker", HeaderValue::from_static("true"));
}

fn append_last_modified_header(response: &mut Response, modified_at_unix: u64) {
    if let Ok(value) = HeaderValue::from_str(&s3_timestamp(modified_at_unix)) {
        response.headers_mut().insert(header::LAST_MODIFIED, value);
    }
}

fn build_current_delete_marker_response(
    head_only: bool,
    resource: &str,
    request_id: &str,
) -> Response {
    let mut response = if head_only {
        let mut response = StatusCode::NOT_FOUND.into_response();
        append_request_id_header(&mut response, request_id);
        response
    } else {
        s3_error_response(
            StatusCode::NOT_FOUND,
            "NoSuchKey",
            "the specified key does not exist",
            resource,
            request_id,
        )
    };
    append_delete_marker_header(&mut response);
    response
}

fn build_delete_marker_version_response(
    _head_only: bool,
    request_id: &str,
    version_id: &str,
    modified_at_unix: u64,
) -> Response {
    let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
    append_request_id_header(&mut response, request_id);
    append_delete_marker_header(&mut response);
    append_version_id_header(&mut response, Some(version_id));
    append_last_modified_header(&mut response, modified_at_unix);
    response
}

fn head_response_without_body(response: Response) -> Response {
    let (parts, _) = response.into_parts();
    Response::from_parts(parts, Body::empty())
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
}

fn parse_bucket_versioning_status(xml: &str) -> Result<S3BucketVersioningStatus, String> {
    let Some(status) = xml_tag_contents(xml, "Status") else {
        return Err("VersioningConfiguration must include a Status element".to_string());
    };
    match status.trim() {
        "Enabled" => Ok(S3BucketVersioningStatus::Enabled),
        "Suspended" | "Disabled" => Ok(S3BucketVersioningStatus::Disabled),
        _ => Err("VersioningConfiguration Status must be Enabled or Suspended".to_string()),
    }
}

fn parse_create_bucket_location_constraint(payload: &[u8]) -> Result<Option<String>, String> {
    if payload.iter().all(|byte| byte.is_ascii_whitespace()) {
        return Ok(None);
    }
    let xml = std::str::from_utf8(payload)
        .map_err(|_| "CreateBucket request bodies must be valid UTF-8 XML".to_string())?;
    let Some(location_constraint) = xml_tag_contents(xml, "LocationConstraint") else {
        return Err(
            "CreateBucket request bodies must include a LocationConstraint element when non-empty"
                .to_string(),
        );
    };
    let location_constraint = location_constraint.trim();
    if location_constraint.is_empty() {
        return Err("CreateBucket LocationConstraint must not be empty".to_string());
    }
    Ok(Some(location_constraint.to_string()))
}

fn s3_timestamp(unix_ts: u64) -> String {
    OffsetDateTime::from_unix_timestamp(unix_ts as i64)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH)
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}
