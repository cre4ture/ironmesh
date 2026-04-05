use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use common::{NodeId, StorageObjectMeta};
use reqwest::Client as HttpClient;
use reqwest::Method;
use reqwest::RequestBuilder;
use reqwest::StatusCode;
use reqwest::Url;
use reqwest::header::{
    ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, ETAG, HeaderMap, HeaderName, HeaderValue,
    IF_RANGE, RANGE,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use sync_core::{NamespaceEntry, SyncSnapshot};
use transport_sdk::{
    ClientIdentityMaterial, PeerIdentity, RelayHttpHeader, RelayHttpRequest, RelayHttpResponse,
    RelayTicketRequest, RendezvousControlClient, build_signed_request_headers,
    encode_optional_body_base64,
};

const LARGE_UPLOAD_THRESHOLD_BYTES: usize = 1024 * 1024;
const CHUNK_UPLOAD_SIZE_BYTES: usize = 1024 * 1024;
const DOWNLOAD_SEGMENT_SIZE_BYTES: usize = 1024 * 1024;
const STAGED_DOWNLOAD_COPY_BUFFER_SIZE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestedRange {
    pub offset: u64,
    pub length: u64,
}

impl std::fmt::Display for RequestedRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "@{}+{}", self.offset, self.length)
    }
}

#[derive(Clone)]
pub struct IronMeshClient {
    transport: ClientTransport,
    auth: ClientRequestAuth,
}

#[derive(Clone)]
enum ClientRequestAuth {
    None,
    SignedIdentity(ClientIdentityMaterial),
}

#[derive(Clone)]
enum ClientTransport {
    Direct {
        http: HttpClient,
        server_base_url: String,
    },
    Relay(ClientRelayTransport),
}

#[derive(Clone)]
struct ClientRelayTransport {
    rendezvous: RendezvousControlClient,
    request_base_url: String,
    target_node_id: NodeId,
}

#[derive(Debug)]
struct BufferedTransportResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

fn header_value_for_log(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .unwrap_or_else(|| "<none>".to_string())
}

fn blocking_runtime() -> Result<&'static tokio::runtime::Runtime> {
    static RUNTIME: OnceLock<Result<tokio::runtime::Runtime, String>> = OnceLock::new();

    match RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .thread_name("ironmesh-client-blocking")
            .build()
            .map_err(|error| error.to_string())
    }) {
        Ok(runtime) => Ok(runtime),
        Err(error) => Err(anyhow!(
            "failed to initialize shared blocking runtime: {error}"
        )),
    }
}

#[derive(Debug, Clone)]
pub struct RelativePathResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UploadMode {
    Direct,
    Chunked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadResult {
    pub meta: StorageObjectMeta,
    pub upload_mode: UploadMode,
    pub chunk_size_bytes: Option<usize>,
    pub chunk_count: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSessionStatus {
    pub upload_id: String,
    pub key: String,
    pub total_size_bytes: u64,
    pub chunk_size_bytes: usize,
    pub chunk_count: usize,
    pub received_indexes: Vec<usize>,
    pub completed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSessionChunkStatus {
    pub stored: bool,
    pub received_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UploadSessionCompleteInfo {
    pub snapshot_id: String,
    pub version_id: String,
    pub manifest_hash: String,
    pub state: String,
    pub new_chunks: usize,
    pub dedup_reused_chunks: usize,
    pub created_new_version: bool,
    pub total_size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectHeadInfo {
    pub total_size_bytes: u64,
    pub etag: Option<String>,
    pub accept_ranges: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadProgress {
    pub object_size_bytes: u64,
    pub range: RequestedRange,
    pub bytes_downloaded: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadRangeResult {
    pub object_size_bytes: u64,
    pub range: RequestedRange,
    pub bytes_downloaded: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DownloadRangeRequest<'a> {
    pub key: &'a str,
    pub snapshot: Option<&'a str>,
    pub version: Option<&'a str>,
    pub range: RequestedRange,
}

#[derive(Debug, Serialize)]
struct UploadSessionStartRequest {
    key: String,
    total_size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,
    #[serde(default)]
    parent: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_id: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
struct UploadSessionView {
    upload_id: String,
    key: String,
    total_size_bytes: u64,
    chunk_size_bytes: usize,
    chunk_count: usize,
    #[serde(default, alias = "received_chunks")]
    received_indexes: Vec<usize>,
    completed: bool,
    #[serde(default)]
    completed_result: Option<UploadSessionCompleteResponse>,
    #[allow(dead_code)]
    expires_at_unix: u64,
}

#[derive(Debug, Deserialize, Clone)]
struct UploadSessionChunkResponse {
    #[allow(dead_code)]
    stored: bool,
    received_index: usize,
}

#[derive(Debug, Deserialize, Clone)]
struct UploadSessionCompleteResponse {
    snapshot_id: String,
    version_id: String,
    manifest_hash: String,
    state: String,
    new_chunks: usize,
    dedup_reused_chunks: usize,
    created_new_version: bool,
    total_size_bytes: u64,
}

#[derive(Debug, Clone)]
struct ObjectHeadResponse {
    total_size_bytes: u64,
    etag: Option<String>,
    accept_ranges: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResumableUploadFileState {
    upload_id: String,
    key: String,
    source_size_bytes: u64,
    source_modified_unix_ms: u128,
    chunk_size_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ResumableDownloadFileState {
    key: String,
    snapshot: Option<String>,
    version: Option<String>,
    expected_size_bytes: u64,
    etag: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreIndexEntry {
    pub path: String,
    pub entry_type: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub content_hash: Option<String>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub modified_at_unix: Option<u64>,
    #[serde(default)]
    pub content_fingerprint: Option<String>,
    #[serde(default)]
    pub media: Option<StoreIndexMedia>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreIndexResponse {
    #[serde(default)]
    pub prefix: String,
    #[serde(default)]
    pub depth: usize,
    #[serde(default)]
    pub entry_count: usize,
    #[serde(default)]
    pub entries: Vec<StoreIndexEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VersionConsistencyState {
    Provisional,
    Confirmed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PreferredHeadReason {
    ConfirmedPreferredOverProvisional,
    ProvisionalFallbackNoConfirmed,
    DeterministicTiebreakVersionId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionRecordSummary {
    pub version_id: String,
    pub logical_path: Option<String>,
    pub parent_version_ids: Vec<String>,
    pub state: VersionConsistencyState,
    pub created_at_unix: u64,
    pub copied_from_object_id: Option<String>,
    pub copied_from_version_id: Option<String>,
    pub copied_from_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VersionGraphSummary {
    pub key: String,
    pub object_id: String,
    #[serde(default)]
    pub preferred_head_version_id: Option<String>,
    #[serde(default)]
    pub preferred_head_reason: Option<PreferredHeadReason>,
    #[serde(default)]
    pub head_version_ids: Vec<String>,
    #[serde(default)]
    pub versions: Vec<VersionRecordSummary>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StoreIndexView {
    Raw,
    Tree,
}

impl StoreIndexView {
    fn as_query_value(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Tree => "tree",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct StoreIndexChangeWaitResponse {
    pub sequence: u64,
    pub changed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreIndexMedia {
    pub status: String,
    pub content_fingerprint: String,
    #[serde(default)]
    pub media_type: Option<String>,
    #[serde(default)]
    pub mime_type: Option<String>,
    #[serde(default)]
    pub width: Option<u32>,
    #[serde(default)]
    pub height: Option<u32>,
    #[serde(default)]
    pub orientation: Option<u16>,
    #[serde(default)]
    pub taken_at_unix: Option<u64>,
    #[serde(default)]
    pub gps: Option<StoreIndexGps>,
    #[serde(default)]
    pub thumbnail: Option<StoreIndexThumbnail>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreIndexGps {
    pub latitude: f64,
    pub longitude: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreIndexThumbnail {
    pub url: String,
    pub profile: String,
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub size_bytes: u64,
}

#[derive(Debug, Serialize)]
struct PathMutationRequest {
    from_path: String,
    to_path: String,
    overwrite: bool,
}

#[derive(Debug, Serialize)]
struct SnapshotRestoreRequest {
    snapshot: String,
    from_path: String,
    to_path: String,
    recursive: bool,
    overwrite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SnapshotRestoreResponse {
    pub snapshot_id: String,
    pub source_path: String,
    pub target_path: String,
    pub recursive: bool,
    pub restored_count: usize,
}

impl IronMeshClient {
    pub fn from_direct_base_url(server_base_url: impl Into<String>) -> Self {
        Self::from_direct_http_client(server_base_url, HttpClient::new())
    }

    pub fn from_direct_http_client(server_base_url: impl Into<String>, http: HttpClient) -> Self {
        Self {
            transport: ClientTransport::Direct {
                http,
                server_base_url: server_base_url.into().trim_end_matches('/').to_string(),
            },
            auth: ClientRequestAuth::None,
        }
    }

    pub fn with_relay_transport(
        request_base_url: impl Into<String>,
        rendezvous: RendezvousControlClient,
        target_node_id: NodeId,
    ) -> Self {
        Self {
            transport: ClientTransport::Relay(ClientRelayTransport {
                rendezvous,
                request_base_url: request_base_url.into().trim_end_matches('/').to_string(),
                target_node_id,
            }),
            auth: ClientRequestAuth::None,
        }
    }

    pub fn with_client_identity(mut self, identity: ClientIdentityMaterial) -> Self {
        self.auth = ClientRequestAuth::SignedIdentity(identity);
        self
    }

    pub fn uses_relay_transport(&self) -> bool {
        matches!(self.transport, ClientTransport::Relay(_))
    }

    pub fn relay_target_node_id(&self) -> Option<NodeId> {
        match &self.transport {
            ClientTransport::Direct { .. } => None,
            ClientTransport::Relay(relay) => Some(relay.target_node_id),
        }
    }

    pub fn direct_server_base_url(&self) -> Option<&str> {
        match &self.transport {
            ClientTransport::Direct {
                server_base_url, ..
            } => Some(server_base_url.as_str()),
            ClientTransport::Relay(_) => None,
        }
    }

    pub fn rendezvous_client(&self) -> Option<RendezvousControlClient> {
        match &self.transport {
            ClientTransport::Direct { .. } => None,
            ClientTransport::Relay(relay) => Some(relay.rendezvous.clone()),
        }
    }

    fn server_base_url(&self) -> &str {
        match &self.transport {
            ClientTransport::Direct {
                server_base_url, ..
            } => server_base_url.as_str(),
            ClientTransport::Relay(relay) => relay.request_base_url.as_str(),
        }
    }

    fn request_auth_headers(&self, method: &Method, url: &Url) -> Result<Vec<RelayHttpHeader>> {
        match &self.auth {
            ClientRequestAuth::None => Ok(Vec::new()),
            ClientRequestAuth::SignedIdentity(identity) => {
                let path_and_query = path_and_query(url);
                let signed_headers = build_signed_request_headers(
                    identity,
                    method.as_str(),
                    &path_and_query,
                    unix_ts(),
                    None,
                )?;
                Ok(vec![
                    RelayHttpHeader {
                        name: transport_sdk::HEADER_CLUSTER_ID.to_string(),
                        value: signed_headers.cluster_id.to_string(),
                    },
                    RelayHttpHeader {
                        name: transport_sdk::HEADER_DEVICE_ID.to_string(),
                        value: signed_headers.device_id,
                    },
                    RelayHttpHeader {
                        name: transport_sdk::HEADER_CREDENTIAL_FINGERPRINT.to_string(),
                        value: signed_headers.credential_fingerprint,
                    },
                    RelayHttpHeader {
                        name: transport_sdk::HEADER_AUTH_TIMESTAMP.to_string(),
                        value: signed_headers.timestamp_unix.to_string(),
                    },
                    RelayHttpHeader {
                        name: transport_sdk::HEADER_AUTH_NONCE.to_string(),
                        value: signed_headers.nonce,
                    },
                    RelayHttpHeader {
                        name: transport_sdk::HEADER_AUTH_SIGNATURE.to_string(),
                        value: signed_headers.signature_base64,
                    },
                ])
            }
        }
    }

    fn apply_headers_to_request(
        &self,
        request: RequestBuilder,
        headers: &[RelayHttpHeader],
    ) -> RequestBuilder {
        headers.iter().fold(request, |request, header| {
            request.header(header.name.as_str(), header.value.as_str())
        })
    }

    fn relay_source_identity(&self) -> Result<PeerIdentity> {
        match &self.auth {
            ClientRequestAuth::SignedIdentity(identity) => {
                Ok(PeerIdentity::Device(identity.device_id))
            }
            ClientRequestAuth::None => {
                bail!("relay-backed client transport requires signed client identity material")
            }
        }
    }

    async fn execute_buffered_request(
        &self,
        method: Method,
        url: Url,
        mut headers: Vec<RelayHttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<BufferedTransportResponse> {
        let mut auth_headers = self.request_auth_headers(&method, &url)?;
        auth_headers.append(&mut headers);

        match &self.transport {
            ClientTransport::Direct { http, .. } => {
                let mut request = self.apply_headers_to_request(
                    http.request(method.clone(), url.clone()),
                    &auth_headers,
                );
                if let Some(body) = body {
                    request = request.body(body);
                }
                let response = request
                    .send()
                    .await
                    .with_context(|| format!("failed to execute {} {}", method, url))?;
                let status = response.status();
                let headers = response.headers().clone();
                let body = response.bytes().await.with_context(|| {
                    format!("failed to read response body for {} {}", method, url)
                })?;
                Ok(BufferedTransportResponse {
                    status,
                    headers,
                    body,
                })
            }
            ClientTransport::Relay(relay) => {
                let source = self.relay_source_identity()?;
                let ticket = relay
                    .rendezvous
                    .issue_relay_ticket(&RelayTicketRequest {
                        cluster_id: relay.rendezvous.config().cluster_id,
                        source,
                        target: PeerIdentity::Node(relay.target_node_id),
                        requested_expires_in_secs: Some(30),
                    })
                    .await
                    .with_context(|| {
                        format!(
                            "failed issuing relay ticket for client target node {}",
                            relay.target_node_id
                        )
                    })?;
                let response = relay
                    .rendezvous
                    .submit_relay_http_request(&RelayHttpRequest {
                        ticket,
                        request_id: uuid::Uuid::now_v7().to_string(),
                        method: method.as_str().to_string(),
                        path_and_query: path_and_query(&url),
                        headers: auth_headers,
                        body_base64: body.as_deref().and_then(encode_optional_body_base64),
                    })
                    .await
                    .with_context(|| format!("failed to relay {} {}", method, url))?;
                buffered_response_from_relay(response)
            }
        }
    }

    pub async fn put(&self, key: impl Into<String>, data: Bytes) -> Result<StorageObjectMeta> {
        let key = key.into();
        let url = self.store_key_url(&key)?;

        let response = self
            .execute_buffered_request(Method::PUT, url, Vec::new(), Some(data.to_vec()))
            .await
            .with_context(|| format!("failed to PUT object key={key}"))?;
        if !response.status.is_success() {
            bail!("server rejected PUT for key={key}: {}", response.status);
        }

        Ok(StorageObjectMeta {
            key,
            size_bytes: data.len(),
        })
    }

    pub async fn get(&self, key: impl AsRef<str>) -> Result<Bytes> {
        self.get_with_selector(key, None, None).await
    }

    pub async fn get_with_selector(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<Bytes> {
        let key = key.as_ref();
        let mut url = self.store_key_url(key)?;
        append_optional_query(&mut url, "snapshot", snapshot);
        append_optional_query(&mut url, "version", version);

        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to GET object key={key}"))?;
        if !response.status.is_success() {
            bail!(
                "object not found or inaccessible key={key}: {}",
                response.status
            );
        }
        Ok(response.body)
    }

    pub async fn rename_path(
        &self,
        from_path: impl Into<String>,
        to_path: impl Into<String>,
        overwrite: bool,
    ) -> Result<()> {
        let from_path = from_path.into();
        let to_path = to_path.into();
        let url = self.store_rename_url()?;
        let payload = serde_json::to_vec(&PathMutationRequest {
            from_path: from_path.clone(),
            to_path: to_path.clone(),
            overwrite,
        })
        .context("failed to encode rename request")?;

        let response = self
            .execute_buffered_request(
                Method::POST,
                url,
                vec![json_content_type_header()],
                Some(payload),
            )
            .await
            .with_context(|| format!("failed to rename {from_path} -> {to_path}"))?;

        match response.status {
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::NOT_FOUND => bail!("rename source path not found: {from_path}"),
            StatusCode::CONFLICT => bail!("rename target path already exists: {to_path}"),
            status => Err(anyhow!(
                "rename failed for {from_path} -> {to_path}: {status}"
            )),
        }
    }

    pub async fn copy_path(
        &self,
        from_path: impl Into<String>,
        to_path: impl Into<String>,
        overwrite: bool,
    ) -> Result<()> {
        let from_path = from_path.into();
        let to_path = to_path.into();
        let url = self.store_copy_url()?;
        let payload = serde_json::to_vec(&PathMutationRequest {
            from_path: from_path.clone(),
            to_path: to_path.clone(),
            overwrite,
        })
        .context("failed to encode copy request")?;

        let response = self
            .execute_buffered_request(
                Method::POST,
                url,
                vec![json_content_type_header()],
                Some(payload),
            )
            .await
            .with_context(|| format!("failed to copy {from_path} -> {to_path}"))?;

        match response.status {
            StatusCode::NO_CONTENT => Ok(()),
            StatusCode::NOT_FOUND => bail!("copy source path not found: {from_path}"),
            StatusCode::CONFLICT => bail!("copy target path already exists: {to_path}"),
            status => Err(anyhow!(
                "copy failed for {from_path} -> {to_path}: {status}"
            )),
        }
    }

    pub async fn restore_path_from_snapshot(
        &self,
        snapshot: impl Into<String>,
        from_path: impl Into<String>,
        to_path: impl Into<String>,
        recursive: bool,
        overwrite: bool,
    ) -> Result<SnapshotRestoreResponse> {
        let snapshot = snapshot.into();
        let from_path = from_path.into();
        let to_path = to_path.into();
        let url = self.store_restore_url()?;
        let payload = serde_json::to_vec(&SnapshotRestoreRequest {
            snapshot: snapshot.clone(),
            from_path: from_path.clone(),
            to_path: to_path.clone(),
            recursive,
            overwrite,
        })
        .context("failed to encode snapshot restore request")?;

        let response = self
            .execute_buffered_request(
                Method::POST,
                url,
                vec![json_content_type_header()],
                Some(payload),
            )
            .await
            .with_context(|| {
                format!(
                    "failed to restore snapshot={} path {} -> {}",
                    snapshot, from_path, to_path
                )
            })?;

        match response.status {
            StatusCode::OK => serde_json::from_slice::<SnapshotRestoreResponse>(&response.body)
                .context("failed to parse snapshot restore response"),
            StatusCode::NOT_FOUND => {
                bail!("snapshot restore source path not found in snapshot={snapshot}: {from_path}")
            }
            StatusCode::CONFLICT => {
                bail!("snapshot restore target path already exists: {to_path}")
            }
            status => Err(anyhow!(
                "snapshot restore failed for {from_path} -> {to_path}: {status}"
            )),
        }
    }

    pub async fn delete_path(&self, key: impl AsRef<str>) -> Result<()> {
        let key = key.as_ref();
        let mut url = self.store_delete_url()?;
        url.query_pairs_mut().append_pair("key", key);
        if key.ends_with('/') {
            url.query_pairs_mut().append_pair("recursive", "true");
        }

        let response = self
            .execute_buffered_request(Method::POST, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to delete path {key}"))?;

        match response.status {
            StatusCode::CREATED | StatusCode::NO_CONTENT => Ok(()),
            status => Err(anyhow!("delete failed for {key}: {status}")),
        }
    }

    pub async fn list_versions(&self, key: impl AsRef<str>) -> Result<Option<VersionGraphSummary>> {
        let key = key.as_ref();
        let url = self.store_versions_url(key)?;

        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to request /versions/{key}"))?;

        match response.status {
            StatusCode::OK => serde_json::from_slice::<VersionGraphSummary>(&response.body)
                .map(Some)
                .context("failed to parse /versions response"),
            StatusCode::NOT_FOUND => Ok(None),
            status => Err(anyhow!("versions lookup failed for {key}: {status}")),
        }
    }

    pub fn list_versions_blocking(
        &self,
        key: impl AsRef<str>,
    ) -> Result<Option<VersionGraphSummary>> {
        let key = key.as_ref().to_string();
        let runtime = blocking_runtime()?;
        runtime.block_on(self.list_versions(key))
    }

    pub async fn store_index(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<StoreIndexResponse> {
        self.store_index_with_view(prefix, depth, snapshot, None)
            .await
    }

    pub async fn store_index_with_view(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
        view: Option<StoreIndexView>,
    ) -> Result<StoreIndexResponse> {
        let mut url = self.store_index_url()?;
        url.query_pairs_mut()
            .append_pair("depth", &depth.max(1).to_string());
        append_optional_query(&mut url, "prefix", prefix);
        append_optional_query(&mut url, "snapshot", snapshot);
        if let Some(view) = view {
            url.query_pairs_mut()
                .append_pair("view", view.as_query_value());
        }

        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .context("failed to request /store/index")?;
        if !response.status.is_success() {
            bail!(
                "/store/index returned non-success status: {}",
                response.status
            );
        }

        let mut result = serde_json::from_slice::<StoreIndexResponse>(&response.body)
            .context("failed to parse /store/index response");

        if let Ok(ref mut response) = result {
            ensure_missing_folder_markers(&mut response.entries);
            response.entry_count = response.entries.len();
        }

        result
    }

    pub fn store_index_blocking(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<StoreIndexResponse> {
        self.store_index_with_view_blocking(prefix, depth, snapshot, None)
    }

    pub fn store_index_with_view_blocking(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
        view: Option<StoreIndexView>,
    ) -> Result<StoreIndexResponse> {
        let runtime = blocking_runtime()?;
        runtime.block_on(self.store_index_with_view(prefix, depth, snapshot, view))
    }

    pub async fn wait_for_store_index_change(
        &self,
        since: u64,
        timeout_ms: u64,
    ) -> Result<StoreIndexChangeWaitResponse> {
        let mut url = self.store_index_change_wait_url()?;
        url.query_pairs_mut()
            .append_pair("since", &since.to_string())
            .append_pair("timeout_ms", &timeout_ms.max(250).to_string());

        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .context("failed to request /store/index/changes/wait")?;
        if !response.status.is_success() {
            bail!(
                "/store/index/changes/wait returned non-success status: {}",
                response.status
            );
        }
        serde_json::from_slice::<StoreIndexChangeWaitResponse>(&response.body)
            .context("failed to parse /store/index/changes/wait response")
    }

    pub fn wait_for_store_index_change_blocking(
        &self,
        since: u64,
        timeout_ms: u64,
    ) -> Result<StoreIndexChangeWaitResponse> {
        let runtime = blocking_runtime()?;
        runtime.block_on(self.wait_for_store_index_change(since, timeout_ms))
    }

    pub async fn get_json_path(&self, path: &str) -> Result<serde_json::Value> {
        let url = self.relative_url(path)?;
        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to request {path}"))?;
        if !response.status.is_success() {
            bail!("{path} returned non-success status: {}", response.status);
        }
        serde_json::from_slice::<serde_json::Value>(&response.body)
            .with_context(|| format!("failed to parse JSON response from {path}"))
    }

    pub fn get_json_path_blocking(&self, path: &str) -> Result<serde_json::Value> {
        let path = path.to_string();
        let runtime = blocking_runtime()?;
        runtime.block_on(self.get_json_path(&path))
    }

    pub async fn get_relative_path(&self, path: &str) -> Result<RelativePathResponse> {
        let url = self.relative_url(path)?;
        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to request {path}"))?;
        Ok(RelativePathResponse {
            status: response.status,
            headers: response.headers,
            body: response.body,
        })
    }

    pub fn get_relative_path_blocking(&self, path: &str) -> Result<RelativePathResponse> {
        let path = path.to_string();
        let runtime = blocking_runtime()?;
        runtime.block_on(self.get_relative_path(&path))
    }

    async fn start_upload_session(
        &self,
        key: &str,
        total_size_bytes: u64,
    ) -> Result<UploadSessionView> {
        let url = self.store_upload_session_start_url()?;
        let payload = serde_json::to_vec(&UploadSessionStartRequest {
            key: key.to_string(),
            total_size_bytes,
            state: None,
            parent: Vec::new(),
            version_id: None,
        })
        .context("failed to encode upload session start payload")?;

        let response = self
            .execute_buffered_request(
                Method::POST,
                url,
                vec![json_content_type_header()],
                Some(payload),
            )
            .await
            .with_context(|| format!("failed to start upload session for key={key}"))?;
        if !response.status.is_success() {
            bail!(
                "server rejected upload session start for key={key}: {}",
                response.status
            );
        }

        serde_json::from_slice::<UploadSessionView>(&response.body)
            .with_context(|| format!("failed to parse upload session start response for {key}"))
    }

    pub async fn begin_upload_session(
        &self,
        key: impl AsRef<str>,
        total_size_bytes: u64,
    ) -> Result<UploadSessionStatus> {
        let view = self
            .start_upload_session(key.as_ref(), total_size_bytes)
            .await?;
        Ok(upload_session_status_from_view(view))
    }

    async fn get_upload_session(&self, upload_id: &str) -> Result<Option<UploadSessionView>> {
        let url = self.store_upload_session_url(upload_id)?;
        let response = self
            .execute_buffered_request(Method::GET, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to query upload session {upload_id}"))?;

        match response.status {
            StatusCode::OK => serde_json::from_slice::<UploadSessionView>(&response.body)
                .with_context(|| format!("failed to parse upload session {upload_id}"))
                .map(Some),
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN => Ok(None),
            status => Err(anyhow!(
                "upload session query failed for {upload_id}: {status}"
            )),
        }
    }

    async fn upload_session_chunk(
        &self,
        upload_id: &str,
        index: usize,
        payload: Vec<u8>,
    ) -> Result<UploadSessionChunkResponse> {
        let url = self.store_upload_session_chunk_url(upload_id, index)?;
        let response = self
            .execute_buffered_request(Method::PUT, url, Vec::new(), Some(payload))
            .await
            .with_context(|| format!("failed to upload chunk {index} for session={upload_id}"))?;
        if !response.status.is_success() {
            bail!(
                "upload session chunk rejected for session={upload_id} index={index}: {}",
                response.status
            );
        }

        serde_json::from_slice::<UploadSessionChunkResponse>(&response.body).with_context(|| {
            format!("failed to parse upload session chunk response for session={upload_id}")
        })
    }

    pub async fn upload_session_chunk_bytes(
        &self,
        upload_id: &str,
        index: usize,
        payload: Vec<u8>,
    ) -> Result<UploadSessionChunkStatus> {
        let response = self.upload_session_chunk(upload_id, index, payload).await?;
        Ok(UploadSessionChunkStatus {
            stored: response.stored,
            received_index: response.received_index,
        })
    }

    async fn complete_upload_session(
        &self,
        upload_id: &str,
    ) -> Result<UploadSessionCompleteResponse> {
        let url = self.store_upload_session_complete_url(upload_id)?;
        let response = self
            .execute_buffered_request(Method::POST, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to complete upload session {upload_id}"))?;

        if !response.status.is_success() {
            bail!(
                "upload session completion rejected for session={upload_id}: {}",
                response.status
            );
        }

        serde_json::from_slice::<UploadSessionCompleteResponse>(&response.body).with_context(|| {
            format!("failed to parse upload session completion response for {upload_id}")
        })
    }

    pub async fn finalize_upload_session(
        &self,
        upload_id: &str,
    ) -> Result<UploadSessionCompleteInfo> {
        let response = self.complete_upload_session(upload_id).await?;
        Ok(upload_session_complete_info_from_response(response))
    }

    async fn head_object_response(
        &self,
        key: &str,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<ObjectHeadResponse> {
        let mut url = self.store_key_url(key)?;
        append_optional_query(&mut url, "snapshot", snapshot);
        append_optional_query(&mut url, "version", version);

        let response = self
            .execute_buffered_request(Method::HEAD, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to HEAD object key={key}"))?;
        if !response.status.is_success() {
            bail!(
                "object not found or inaccessible key={key}: {}",
                response.status
            );
        }

        let total_size_bytes = response
            .headers
            .get("x-ironmesh-object-size")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .or_else(|| {
                response
                    .headers
                    .get(CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok())
            })
            .unwrap_or(0);

        let head_response = ObjectHeadResponse {
            total_size_bytes,
            etag: response
                .headers
                .get(ETAG)
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string),
            accept_ranges: response
                .headers
                .get(ACCEPT_RANGES)
                .and_then(|value| value.to_str().ok())
                .map(|value| value.eq_ignore_ascii_case("bytes"))
                .unwrap_or(false),
        };

        tracing::info!(
            "client head-object response: key={} snapshot={} version={} status={} content_length={} object_size={} etag={} accept_ranges={}",
            key,
            snapshot.unwrap_or("<none>"),
            version.unwrap_or("<none>"),
            response.status,
            header_value_for_log(&response.headers, CONTENT_LENGTH.as_str()),
            head_response.total_size_bytes,
            head_response.etag.as_deref().unwrap_or("<none>"),
            head_response.accept_ranges
        );

        Ok(head_response)
    }

    async fn get_object_range_response(
        &self,
        key: &str,
        snapshot: Option<&str>,
        version: Option<&str>,
        start: u64,
        end_inclusive: u64,
        if_range: Option<&str>,
    ) -> Result<BufferedTransportResponse> {
        let mut url = self.store_key_url(key)?;
        append_optional_query(&mut url, "snapshot", snapshot);
        append_optional_query(&mut url, "version", version);

        let mut headers = vec![range_header(start, end_inclusive)];
        if let Some(if_range) = if_range {
            headers.push(simple_header(IF_RANGE, if_range)?);
        }

        let response = self
            .execute_buffered_request(Method::GET, url, headers, None)
            .await
            .with_context(|| {
                format!("failed to GET object range key={key} start={start} end={end_inclusive}")
            })?;

        tracing::info!(
            "client range-response: key={} snapshot={} version={} start={} end={} status={} content_length={} content_range={} object_size={} etag={} accept_ranges={} body_len={}",
            key,
            snapshot.unwrap_or("<none>"),
            version.unwrap_or("<none>"),
            start,
            end_inclusive,
            response.status,
            header_value_for_log(&response.headers, CONTENT_LENGTH.as_str()),
            header_value_for_log(&response.headers, CONTENT_RANGE.as_str()),
            header_value_for_log(&response.headers, "x-ironmesh-object-size"),
            header_value_for_log(&response.headers, ETAG.as_str()),
            header_value_for_log(&response.headers, ACCEPT_RANGES.as_str()),
            response.body.len()
        );

        Ok(response)
    }

    async fn download_with_range_requests(
        &self,
        key: &str,
        snapshot: Option<&str>,
        version: Option<&str>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let head = self.head_object_response(key, snapshot, version).await?;
        if head.total_size_bytes == 0 {
            writer
                .flush()
                .with_context(|| format!("failed to flush output for key={key}"))?;
            return Ok(());
        }

        if !head.accept_ranges {
            let payload = self.get_with_selector(key, snapshot, version).await?;
            writer
                .write_all(payload.as_ref())
                .with_context(|| format!("failed to write payload chunk for key={key}"))?;
            writer
                .flush()
                .with_context(|| format!("failed to flush output for key={key}"))?;
            return Ok(());
        }

        let mut offset = 0_u64;
        while offset < head.total_size_bytes {
            let end_inclusive = std::cmp::min(
                offset + DOWNLOAD_SEGMENT_SIZE_BYTES as u64 - 1,
                head.total_size_bytes - 1,
            );
            let response = self
                .get_object_range_response(
                    key,
                    snapshot,
                    version,
                    offset,
                    end_inclusive,
                    head.etag.as_deref(),
                )
                .await?;

            match response.status {
                StatusCode::PARTIAL_CONTENT => {
                    let expected_len = (end_inclusive - offset + 1) as usize;
                    if response.body.len() != expected_len {
                        tracing::info!(
                            "client range-response length mismatch: key={} range_start={} range_end={} expected_len={} actual_len={} status={} content_length={} content_range={} object_size={} etag={}",
                            key,
                            offset,
                            end_inclusive,
                            expected_len,
                            response.body.len(),
                            response.status,
                            header_value_for_log(&response.headers, CONTENT_LENGTH.as_str()),
                            header_value_for_log(&response.headers, CONTENT_RANGE.as_str()),
                            header_value_for_log(&response.headers, "x-ironmesh-object-size"),
                            header_value_for_log(&response.headers, ETAG.as_str())
                        );
                        bail!(
                            "server returned unexpected range length for key={key}: expected={expected_len} actual={}",
                            response.body.len()
                        );
                    }
                    writer
                        .write_all(response.body.as_ref())
                        .with_context(|| format!("failed to write payload chunk for key={key}"))?;
                    offset = end_inclusive + 1;
                }
                StatusCode::OK if offset == 0 => {
                    writer
                        .write_all(response.body.as_ref())
                        .with_context(|| format!("failed to write payload chunk for key={key}"))?;
                    offset = head.total_size_bytes;
                }
                status => {
                    bail!("server rejected ranged download for key={key}: {status}");
                }
            }
        }

        writer
            .flush()
            .with_context(|| format!("failed to flush output for key={key}"))?;
        Ok(())
    }

    async fn download_range_to_writer_with_progress(
        &self,
        request: DownloadRangeRequest<'_>,
        writer: &mut dyn Write,
        on_progress: &mut dyn FnMut(DownloadProgress),
        should_cancel: &dyn Fn() -> bool,
    ) -> Result<DownloadRangeResult> {
        let key = request.key;
        let snapshot = request.snapshot;
        let version = request.version;
        let head = await_download_with_cancellation(
            self.head_object_response(key, snapshot, version),
            should_cancel,
            format!("download canceled for key={key}"),
        )
        .await?;
        let range_start = request.range.offset.min(head.total_size_bytes);
        let range_end_exclusive = range_start
            .saturating_add(request.range.length)
            .min(head.total_size_bytes);
        let range_length = range_end_exclusive.saturating_sub(range_start);

        on_progress(DownloadProgress {
            object_size_bytes: head.total_size_bytes,
            range: RequestedRange {
                offset: range_start,
                length: range_length,
            },
            bytes_downloaded: 0,
        });

        if range_length == 0 {
            writer
                .flush()
                .with_context(|| format!("failed to flush output for key={key}"))?;
            return Ok(DownloadRangeResult {
                object_size_bytes: head.total_size_bytes,
                range: RequestedRange {
                    offset: range_start,
                    length: range_length,
                },
                bytes_downloaded: 0,
            });
        }

        if !head.accept_ranges {
            if range_start != 0 || range_length != head.total_size_bytes {
                bail!(
                    "server does not support byte ranges for key={key}, cannot satisfy requested range start={range_start} length={range_length}"
                );
            }

            if should_cancel() {
                bail!("download canceled for key={key}");
            }

            let payload = await_download_with_cancellation(
                self.get_with_selector(key, snapshot, version),
                should_cancel,
                format!("download canceled for key={key}"),
            )
            .await?;
            writer
                .write_all(payload.as_ref())
                .with_context(|| format!("failed to write payload chunk for key={key}"))?;
            writer
                .flush()
                .with_context(|| format!("failed to flush output for key={key}"))?;

            let bytes_downloaded = payload.len() as u64;
            on_progress(DownloadProgress {
                object_size_bytes: head.total_size_bytes,
                range: RequestedRange {
                    offset: range_start,
                    length: range_length,
                },
                bytes_downloaded,
            });

            return Ok(DownloadRangeResult {
                object_size_bytes: head.total_size_bytes,
                range: RequestedRange {
                    offset: range_start,
                    length: range_length,
                },
                bytes_downloaded,
            });
        }

        let mut offset = range_start;
        let mut bytes_downloaded = 0_u64;
        while offset < range_end_exclusive {
            if should_cancel() {
                bail!("download canceled for key={key}");
            }

            let end_inclusive = std::cmp::min(
                offset + DOWNLOAD_SEGMENT_SIZE_BYTES as u64 - 1,
                range_end_exclusive - 1,
            );
            let response = await_download_with_cancellation(
                self.get_object_range_response(
                    key,
                    snapshot,
                    version,
                    offset,
                    end_inclusive,
                    head.etag.as_deref(),
                ),
                should_cancel,
                format!("download canceled for key={key}"),
            )
            .await?;

            match response.status {
                StatusCode::PARTIAL_CONTENT => {
                    let expected_len = (end_inclusive - offset + 1) as usize;
                    if response.body.len() != expected_len {
                        bail!(
                            "server returned unexpected range length for key={key}: expected={expected_len} actual={}",
                            response.body.len()
                        );
                    }
                    writer
                        .write_all(response.body.as_ref())
                        .with_context(|| format!("failed to write payload chunk for key={key}"))?;
                    bytes_downloaded += response.body.len() as u64;
                    offset = end_inclusive + 1;
                    on_progress(DownloadProgress {
                        object_size_bytes: head.total_size_bytes,
                        range: RequestedRange {
                            offset: range_start,
                            length: range_length,
                        },
                        bytes_downloaded,
                    });
                }
                StatusCode::OK if offset == 0 && range_length == head.total_size_bytes => {
                    writer
                        .write_all(response.body.as_ref())
                        .with_context(|| format!("failed to write payload chunk for key={key}"))?;
                    bytes_downloaded = response.body.len() as u64;
                    offset = range_end_exclusive;
                    on_progress(DownloadProgress {
                        object_size_bytes: head.total_size_bytes,
                        range: RequestedRange {
                            offset: range_start,
                            length: range_length,
                        },
                        bytes_downloaded,
                    });
                }
                status => {
                    bail!("server rejected ranged download for key={key}: {status}");
                }
            }
        }

        writer
            .flush()
            .with_context(|| format!("failed to flush output for key={key}"))?;
        Ok(DownloadRangeResult {
            object_size_bytes: head.total_size_bytes,
            range: RequestedRange {
                offset: range_start,
                length: range_length,
            },
            bytes_downloaded,
        })
    }

    pub fn put_file_resumable(
        &self,
        key: impl Into<String>,
        source_path: impl AsRef<Path>,
        state_path: impl AsRef<Path>,
    ) -> Result<UploadResult> {
        let key = key.into();
        let source_path = source_path.as_ref();
        let state_path = state_path.as_ref();
        let metadata = fs::metadata(source_path).with_context(|| {
            format!("failed to inspect upload source {}", source_path.display())
        })?;
        let source_size_bytes = metadata.len();
        let source_modified_unix_ms = file_modified_unix_ms(&metadata);

        if source_size_bytes <= LARGE_UPLOAD_THRESHOLD_BYTES as u64 {
            let mut file = File::open(source_path).with_context(|| {
                format!("failed to open upload source {}", source_path.display())
            })?;
            return self.put_large_aware_reader(key, &mut file, source_size_bytes);
        }

        let runtime = blocking_runtime()?;

        let persisted = load_json_file::<ResumableUploadFileState>(state_path)?.filter(|state| {
            state.key == key
                && state.source_size_bytes == source_size_bytes
                && state.source_modified_unix_ms == source_modified_unix_ms
        });

        let mut session = match persisted {
            Some(state) => match runtime.block_on(self.get_upload_session(&state.upload_id))? {
                Some(session)
                    if session.key == key && session.total_size_bytes == source_size_bytes =>
                {
                    session
                }
                _ => {
                    remove_file_if_exists(state_path)?;
                    runtime.block_on(self.start_upload_session(&key, source_size_bytes))?
                }
            },
            None => runtime.block_on(self.start_upload_session(&key, source_size_bytes))?,
        };

        persist_json_file_atomic(
            state_path,
            &ResumableUploadFileState {
                upload_id: session.upload_id.clone(),
                key: key.clone(),
                source_size_bytes,
                source_modified_unix_ms,
                chunk_size_bytes: session.chunk_size_bytes,
            },
        )?;
        maybe_abort_after_resumable_upload_state_persist(&key, state_path);

        if session.completed {
            remove_file_if_exists(state_path)?;
            if let Some(ref completed) = session.completed_result {
                return Ok(upload_result_from_session_complete(
                    &key, &session, completed,
                ));
            }
        }

        let received = session
            .received_indexes
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut file = File::open(source_path)
            .with_context(|| format!("failed to open upload source {}", source_path.display()))?;
        let mut buffer = vec![0_u8; session.chunk_size_bytes];

        for index in 0..session.chunk_count {
            if received.contains(&index) {
                continue;
            }

            let offset = (index as u64)
                .checked_mul(session.chunk_size_bytes as u64)
                .context("upload chunk offset overflow")?;
            file.seek(SeekFrom::Start(offset)).with_context(|| {
                format!("failed to seek upload source {}", source_path.display())
            })?;

            let expected_size = expected_chunk_size(
                session.total_size_bytes,
                session.chunk_size_bytes,
                session.chunk_count,
                index,
            )
            .context("failed to determine expected upload chunk size")?;
            file.read_exact(&mut buffer[..expected_size])
                .with_context(|| {
                    format!(
                        "failed to read upload chunk index={index} from {}",
                        source_path.display()
                    )
                })?;

            let response = runtime.block_on(self.upload_session_chunk(
                &session.upload_id,
                index,
                buffer[..expected_size].to_vec(),
            ))?;
            if response.received_index != index {
                bail!(
                    "server acknowledged unexpected upload chunk index={} expected={index}",
                    response.received_index
                );
            }
        }

        let completed = runtime.block_on(self.complete_upload_session(&session.upload_id))?;
        remove_file_if_exists(state_path)?;
        session.completed_result = Some(completed.clone());
        Ok(upload_result_from_session_complete(
            &key, &session, &completed,
        ))
    }

    fn put_sized_reader_via_upload_session(
        &self,
        key: impl Into<String>,
        reader: &mut dyn Read,
        total_size_bytes: u64,
    ) -> Result<UploadResult> {
        let key = key.into();
        let runtime = blocking_runtime()?;
        let session = runtime.block_on(self.start_upload_session(&key, total_size_bytes))?;
        let mut buffer = vec![0_u8; session.chunk_size_bytes];

        for index in 0..session.chunk_count {
            let expected_size = expected_chunk_size(
                total_size_bytes,
                session.chunk_size_bytes,
                session.chunk_count,
                index,
            )
            .context("failed to determine expected upload chunk size")?;
            reader
                .read_exact(&mut buffer[..expected_size])
                .with_context(|| {
                    format!("failed reading upload chunk index={index} for key={key}")
                })?;
            let response = runtime.block_on(self.upload_session_chunk(
                &session.upload_id,
                index,
                buffer[..expected_size].to_vec(),
            ))?;
            if response.received_index != index {
                bail!(
                    "server acknowledged unexpected upload chunk index={} expected={index}",
                    response.received_index
                );
            }
        }

        let completed = runtime.block_on(self.complete_upload_session(&session.upload_id))?;
        Ok(upload_result_from_session_complete(
            &key, &session, &completed,
        ))
    }

    pub fn download_file_resumable(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
        target_path: impl AsRef<Path>,
        temp_path: impl AsRef<Path>,
        state_path: impl AsRef<Path>,
    ) -> Result<()> {
        let key = key.as_ref();
        let target_path = target_path.as_ref();
        let temp_path = temp_path.as_ref();
        let state_path = state_path.as_ref();
        let snapshot_owned = snapshot.map(ToString::to_string);
        let version_owned = version.map(ToString::to_string);

        let runtime = blocking_runtime()?;
        let head = runtime.block_on(self.head_object_response(
            key,
            snapshot_owned.as_deref(),
            version_owned.as_deref(),
        ))?;

        if head.total_size_bytes == 0 {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("failed to create target directory {}", parent.display())
                })?;
            }
            fs::write(target_path, []).with_context(|| {
                format!("failed to write empty object {}", target_path.display())
            })?;
            remove_file_if_exists(temp_path)?;
            remove_file_if_exists(state_path)?;
            return Ok(());
        }

        if !head.accept_ranges {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(temp_path)
                .with_context(|| format!("failed to create temp file {}", temp_path.display()))?;
            runtime.block_on(self.download_with_range_requests(
                key,
                snapshot_owned.as_deref(),
                version_owned.as_deref(),
                &mut file,
            ))?;
            file.sync_all()
                .with_context(|| format!("failed to flush temp file {}", temp_path.display()))?;
            place_downloaded_file(temp_path, target_path)?;
            remove_file_if_exists(state_path)?;
            return Ok(());
        }

        let Some(current_etag) = head.etag.clone() else {
            bail!("server omitted ETag for resumable download key={key}");
        };

        let expected_state = ResumableDownloadFileState {
            key: key.to_string(),
            snapshot: snapshot_owned.clone(),
            version: version_owned.clone(),
            expected_size_bytes: head.total_size_bytes,
            etag: current_etag.clone(),
        };

        let should_reset = load_json_file::<ResumableDownloadFileState>(state_path)?
            .is_some_and(|persisted| persisted != expected_state);
        if should_reset {
            remove_file_if_exists(temp_path)?;
            remove_file_if_exists(state_path)?;
        }

        persist_json_file_atomic(state_path, &expected_state)?;
        if let Some(parent) = temp_path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create temp directory {}", parent.display()))?;
        }
        if let Some(parent) = target_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!("failed to create target directory {}", parent.display())
            })?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(temp_path)
            .with_context(|| {
                format!("failed to open temp download file {}", temp_path.display())
            })?;

        let mut offset = file
            .metadata()
            .with_context(|| format!("failed to inspect temp file {}", temp_path.display()))?
            .len();
        if offset > head.total_size_bytes {
            file.set_len(0)
                .with_context(|| format!("failed to reset temp file {}", temp_path.display()))?;
            offset = 0;
        }
        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("failed to seek temp file {}", temp_path.display()))?;

        while offset < head.total_size_bytes {
            let end_inclusive = std::cmp::min(
                offset + DOWNLOAD_SEGMENT_SIZE_BYTES as u64 - 1,
                head.total_size_bytes - 1,
            );
            let response = runtime.block_on(self.get_object_range_response(
                key,
                snapshot_owned.as_deref(),
                version_owned.as_deref(),
                offset,
                end_inclusive,
                Some(current_etag.as_str()),
            ))?;

            match response.status {
                StatusCode::PARTIAL_CONTENT => {
                    let expected_len = (end_inclusive - offset + 1) as usize;
                    if response.body.len() != expected_len {
                        bail!(
                            "server returned unexpected range length for key={key}: expected={expected_len} actual={}",
                            response.body.len()
                        );
                    }
                    file.write_all(response.body.as_ref()).with_context(|| {
                        format!("failed to write temp download file {}", temp_path.display())
                    })?;
                    file.sync_data().with_context(|| {
                        format!(
                            "failed to persist temp download file {}",
                            temp_path.display()
                        )
                    })?;
                    offset = end_inclusive + 1;
                }
                StatusCode::OK if offset == 0 => {
                    file.set_len(0).with_context(|| {
                        format!("failed to reset temp download file {}", temp_path.display())
                    })?;
                    file.seek(SeekFrom::Start(0)).with_context(|| {
                        format!("failed to seek temp download file {}", temp_path.display())
                    })?;
                    file.write_all(response.body.as_ref()).with_context(|| {
                        format!("failed to write temp download file {}", temp_path.display())
                    })?;
                    file.sync_data().with_context(|| {
                        format!(
                            "failed to persist temp download file {}",
                            temp_path.display()
                        )
                    })?;
                    offset = response.body.len() as u64;
                }
                status => {
                    bail!("server rejected resumable download for key={key}: {status}");
                }
            }
        }

        file.sync_all()
            .with_context(|| format!("failed to flush temp file {}", temp_path.display()))?;
        place_downloaded_file(temp_path, target_path)?;
        remove_file_if_exists(state_path)?;
        Ok(())
    }

    pub fn download_to_writer_resumable_staged(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
        writer: &mut dyn Write,
        staging_root: impl AsRef<Path>,
    ) -> Result<()> {
        let key = key.as_ref();
        let snapshot_owned = snapshot.map(ToString::to_string);
        let version_owned = version.map(ToString::to_string);
        let staging_root = staging_root.as_ref();

        let (target_path, temp_path, state_path) = staged_download_paths(
            staging_root,
            key,
            snapshot_owned.as_deref(),
            version_owned.as_deref(),
        );
        self.download_file_resumable(
            key,
            snapshot_owned.as_deref(),
            version_owned.as_deref(),
            &target_path,
            &temp_path,
            &state_path,
        )?;
        stream_staged_download_and_cleanup(&target_path, &temp_path, &state_path, writer, key)
    }

    pub async fn load_snapshot_from_server(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<SyncSnapshot> {
        let response = self.store_index(prefix, depth, snapshot).await?;
        Ok(snapshot_from_store_index_entries(response.entries))
    }

    pub fn load_snapshot_from_server_blocking(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<SyncSnapshot> {
        let runtime = blocking_runtime()?;
        runtime.block_on(self.load_snapshot_from_server(prefix, depth, snapshot))
    }

    pub fn delete_path_blocking(&self, key: impl AsRef<str>) -> Result<()> {
        let key = key.as_ref().to_string();

        let runtime = blocking_runtime()?;
        runtime.block_on(self.delete_path(key))
    }

    pub fn rename_path_blocking(
        &self,
        from_path: impl Into<String>,
        to_path: impl Into<String>,
        overwrite: bool,
    ) -> Result<()> {
        let from_path = from_path.into();
        let to_path = to_path.into();

        let runtime = blocking_runtime()?;
        runtime.block_on(self.rename_path(from_path, to_path, overwrite))
    }

    pub async fn put_large_aware(
        &self,
        key: impl Into<String>,
        data: Bytes,
    ) -> Result<UploadResult> {
        let key = key.into();
        let length = data.len();

        if length <= LARGE_UPLOAD_THRESHOLD_BYTES {
            let meta = self.put(key, data).await?;
            return Ok(UploadResult {
                meta,
                upload_mode: UploadMode::Direct,
                chunk_size_bytes: None,
                chunk_count: None,
            });
        }
        let session = self.start_upload_session(&key, length as u64).await?;
        for (index, chunk) in data.chunks(CHUNK_UPLOAD_SIZE_BYTES).enumerate() {
            self.upload_session_chunk(&session.upload_id, index, chunk.to_vec())
                .await?;
        }
        let completed = self.complete_upload_session(&session.upload_id).await?;
        Ok(upload_result_from_session_complete(
            &key, &session, &completed,
        ))
    }

    pub fn put_large_aware_reader(
        &self,
        key: impl Into<String>,
        reader: &mut dyn std::io::Read,
        length: u64,
    ) -> Result<UploadResult> {
        let key = key.into();

        tracing::info!("starting upload for key={key} with length={length} bytes");

        if length <= LARGE_UPLOAD_THRESHOLD_BYTES as u64 {
            tracing::info!("using direct upload for key={key} with length={length} bytes");

            let mut buf = Vec::with_capacity(std::cmp::min(length as usize, 8192));
            let mut limited = reader.take(length);
            std::io::Read::read_to_end(&mut limited, &mut buf)
                .with_context(|| format!("failed reading payload for key={key}"))?;

            let runtime = blocking_runtime()?;
            return runtime.block_on(async {
                let meta = self.put(key, Bytes::from(buf)).await?;
                Ok(UploadResult {
                    meta,
                    upload_mode: UploadMode::Direct,
                    chunk_size_bytes: None,
                    chunk_count: None,
                })
            });
        }

        tracing::info!("using chunked upload for key={key} with length={length} bytes");

        self.put_sized_reader_via_upload_session(key, reader, length)
    }

    pub fn get_with_selector_writer(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let key = key.as_ref();
        let runtime = blocking_runtime()?;
        runtime.block_on(self.download_with_range_requests(key, snapshot, version, writer))
    }

    pub fn download_range_to_writer_with_progress_blocking(
        &self,
        request: DownloadRangeRequest<'_>,
        writer: &mut dyn Write,
        on_progress: &mut dyn FnMut(DownloadProgress),
        should_cancel: &dyn Fn() -> bool,
    ) -> Result<DownloadRangeResult> {
        let key_owned = request.key.to_string();
        let snapshot_owned = request.snapshot.map(ToString::to_string);
        let version_owned = request.version.map(ToString::to_string);
        let runtime = blocking_runtime()?;
        runtime.block_on(self.download_range_to_writer_with_progress(
            DownloadRangeRequest {
                key: key_owned.as_str(),
                snapshot: snapshot_owned.as_deref(),
                version: version_owned.as_deref(),
                range: request.range,
            },
            writer,
            on_progress,
            should_cancel,
        ))
    }

    pub async fn get_object_size(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<u64> {
        let key = key.as_ref();
        let mut url = self.store_key_url(key)?;
        append_optional_query(&mut url, "snapshot", snapshot);
        append_optional_query(&mut url, "version", version);

        let response = self.head_object_response(key, snapshot, version).await?;

        Ok(response.total_size_bytes)
    }

    pub async fn head_object(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<ObjectHeadInfo> {
        let key = key.as_ref();
        let response = self.head_object_response(key, snapshot, version).await?;
        Ok(ObjectHeadInfo {
            total_size_bytes: response.total_size_bytes,
            etag: response.etag,
            accept_ranges: response.accept_ranges,
        })
    }

    pub fn head_object_blocking(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<ObjectHeadInfo> {
        let key = key.as_ref().to_string();
        let snapshot = snapshot.map(|value| value.to_string());
        let version = version.map(|value| value.to_string());
        let runtime = blocking_runtime()?;
        runtime.block_on(self.head_object(&key, snapshot.as_deref(), version.as_deref()))
    }

    pub fn get_object_size_blocking(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
    ) -> Result<u64> {
        let key = key.as_ref().to_string();
        let snapshot = snapshot.map(|value| value.to_string());
        let version = version.map(|value| value.to_string());

        let runtime = blocking_runtime()?;
        runtime.block_on(self.get_object_size(&key, snapshot.as_deref(), version.as_deref()))
    }

    fn store_key_url(&self, key: &str) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("server URL cannot be a base"))?;
        segments.push("store");
        segments.push(key);
        drop(segments);

        Ok(url)
    }

    fn relative_url(&self, path: &str) -> Result<Url> {
        let path = path.trim();
        if path.is_empty() {
            bail!("relative request path is empty");
        }

        let base_url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;
        base_url
            .join(path.trim_start_matches('/'))
            .with_context(|| format!("failed to build request URL from {} and {path}", base_url))
    }

    fn store_index_url(&self) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("index");
        }

        Ok(url)
    }

    fn store_versions_url(&self, key: &str) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("versions");
            segments.push(key);
        }

        Ok(url)
    }

    fn store_index_change_wait_url(&self) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("index");
            segments.push("changes");
            segments.push("wait");
        }

        Ok(url)
    }

    fn store_rename_url(&self) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("rename");
        }

        Ok(url)
    }

    fn store_copy_url(&self) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("copy");
        }

        Ok(url)
    }

    fn store_delete_url(&self) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("delete");
        }

        Ok(url)
    }

    fn store_restore_url(&self) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("restore");
        }

        Ok(url)
    }

    fn store_upload_session_start_url(&self) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("uploads");
            segments.push("start");
        }

        Ok(url)
    }

    fn store_upload_session_url(&self, upload_id: &str) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("uploads");
            segments.push(upload_id);
        }

        Ok(url)
    }

    fn store_upload_session_chunk_url(&self, upload_id: &str, index: usize) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("uploads");
            segments.push(upload_id);
            segments.push("chunk");
            segments.push(&index.to_string());
        }

        Ok(url)
    }

    fn store_upload_session_complete_url(&self, upload_id: &str) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push("uploads");
            segments.push(upload_id);
            segments.push("complete");
        }

        Ok(url)
    }
}

async fn await_download_with_cancellation<T, F>(
    future: F,
    should_cancel: &dyn Fn() -> bool,
    cancel_message: String,
) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    if should_cancel() {
        bail!("{cancel_message}");
    }

    tokio::select! {
        result = future => result,
        _ = wait_for_download_cancellation(should_cancel) => bail!("{cancel_message}"),
    }
}

async fn wait_for_download_cancellation(should_cancel: &dyn Fn() -> bool) {
    loop {
        if should_cancel() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn buffered_response_from_relay(response: RelayHttpResponse) -> Result<BufferedTransportResponse> {
    let status = StatusCode::from_u16(response.status)
        .with_context(|| format!("invalid relayed HTTP status {}", response.status))?;
    let body = Bytes::from(response.body_bytes()?);
    let mut headers = HeaderMap::new();
    for header in response.headers {
        let name = HeaderName::from_bytes(header.name.as_bytes())
            .with_context(|| format!("invalid relayed header name {}", header.name))?;
        let value = HeaderValue::from_str(&header.value)
            .with_context(|| format!("invalid relayed header value for {}", header.name))?;
        headers.append(name, value);
    }
    Ok(BufferedTransportResponse {
        status,
        headers,
        body,
    })
}

fn json_content_type_header() -> RelayHttpHeader {
    RelayHttpHeader {
        name: "content-type".to_string(),
        value: "application/json".to_string(),
    }
}

fn range_header(start: u64, end_inclusive: u64) -> RelayHttpHeader {
    RelayHttpHeader {
        name: RANGE.as_str().to_string(),
        value: format!("bytes={start}-{end_inclusive}"),
    }
}

fn simple_header(name: HeaderName, value: &str) -> Result<RelayHttpHeader> {
    let header_value =
        HeaderValue::from_str(value).with_context(|| format!("invalid header value for {name}"))?;
    Ok(RelayHttpHeader {
        name: name.as_str().to_string(),
        value: header_value
            .to_str()
            .context("header value must be valid utf-8")?
            .to_string(),
    })
}

fn expected_chunk_size(
    total_size_bytes: u64,
    chunk_size_bytes: usize,
    chunk_count: usize,
    index: usize,
) -> Option<usize> {
    if index >= chunk_count {
        return None;
    }
    if total_size_bytes == 0 {
        return Some(0);
    }
    if index + 1 == chunk_count {
        let remainder = total_size_bytes as usize % chunk_size_bytes;
        return Some(if remainder == 0 {
            chunk_size_bytes
        } else {
            remainder
        });
    }
    Some(chunk_size_bytes)
}

fn upload_result_from_session_complete(
    key: &str,
    session: &UploadSessionView,
    completed: &UploadSessionCompleteResponse,
) -> UploadResult {
    let _ = (
        &completed.snapshot_id,
        &completed.version_id,
        &completed.manifest_hash,
        &completed.state,
        completed.new_chunks,
        completed.dedup_reused_chunks,
        completed.created_new_version,
    );
    UploadResult {
        meta: StorageObjectMeta {
            key: key.to_string(),
            size_bytes: completed.total_size_bytes as usize,
        },
        upload_mode: UploadMode::Chunked,
        chunk_size_bytes: Some(session.chunk_size_bytes),
        chunk_count: Some(session.chunk_count),
    }
}

fn maybe_abort_after_resumable_upload_state_persist(key: &str, state_path: &Path) {
    if !cfg!(debug_assertions) {
        return;
    }

    let crash_key = std::env::var("IRONMESH_TEST_CRASH_AFTER_UPLOAD_STATE_KEY").ok();
    if crash_key.as_deref() == Some(key) && state_path.is_file() {
        std::process::abort();
    }
}

fn upload_session_status_from_view(view: UploadSessionView) -> UploadSessionStatus {
    UploadSessionStatus {
        upload_id: view.upload_id,
        key: view.key,
        total_size_bytes: view.total_size_bytes,
        chunk_size_bytes: view.chunk_size_bytes,
        chunk_count: view.chunk_count,
        received_indexes: view.received_indexes,
        completed: view.completed,
    }
}

fn upload_session_complete_info_from_response(
    response: UploadSessionCompleteResponse,
) -> UploadSessionCompleteInfo {
    UploadSessionCompleteInfo {
        snapshot_id: response.snapshot_id,
        version_id: response.version_id,
        manifest_hash: response.manifest_hash,
        state: response.state,
        new_chunks: response.new_chunks,
        dedup_reused_chunks: response.dedup_reused_chunks,
        created_new_version: response.created_new_version,
        total_size_bytes: response.total_size_bytes,
    }
}

fn staged_download_paths(
    staging_root: &Path,
    key: &str,
    snapshot: Option<&str>,
    version: Option<&str>,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    let stem = staged_download_stem(key, snapshot, version);
    (
        staging_root.join(format!("{stem}.bin")),
        staging_root.join(format!("{stem}.part")),
        staging_root.join(format!("{stem}.json")),
    )
}

fn staged_download_stem(key: &str, snapshot: Option<&str>, version: Option<&str>) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(key.as_bytes());
    hasher.update(&[0]);
    hasher.update(snapshot.unwrap_or_default().as_bytes());
    hasher.update(&[0]);
    hasher.update(version.unwrap_or_default().as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn stream_staged_download_and_cleanup(
    target_path: &Path,
    temp_path: &Path,
    state_path: &Path,
    writer: &mut dyn Write,
    key: &str,
) -> Result<()> {
    let stream_result = (|| -> Result<()> {
        let mut file = File::open(target_path)
            .with_context(|| format!("failed to open staged download {}", target_path.display()))?;
        let mut buffer = vec![0_u8; STAGED_DOWNLOAD_COPY_BUFFER_SIZE_BYTES];
        loop {
            let read = file.read(&mut buffer).with_context(|| {
                format!("failed to read staged download {}", target_path.display())
            })?;
            if read == 0 {
                break;
            }
            writer
                .write_all(&buffer[..read])
                .with_context(|| format!("failed to write staged download output for key={key}"))?;
        }
        writer
            .flush()
            .with_context(|| format!("failed to flush staged download output for key={key}"))?;
        Ok(())
    })();

    if stream_result.is_ok() {
        remove_file_if_exists(target_path)?;
        remove_file_if_exists(temp_path)?;
        remove_file_if_exists(state_path)?;
    }

    stream_result
}

fn load_json_file<T>(path: &Path) -> Result<Option<T>>
where
    T: for<'de> Deserialize<'de>,
{
    match fs::read(path) {
        Ok(payload) => serde_json::from_slice(&payload)
            .with_context(|| format!("failed to parse {}", path.display()))
            .map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

fn persist_json_file_atomic<T>(path: &Path, value: &T) -> Result<()>
where
    T: Serialize,
{
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let payload = serde_json::to_vec_pretty(value)
        .with_context(|| format!("failed to encode {}", path.display()))?;
    let temp_path = path.with_extension(format!(
        "{}tmp",
        path.extension()
            .and_then(|value| value.to_str())
            .map(|value| format!("{value}."))
            .unwrap_or_default()
    ));
    fs::write(&temp_path, payload)
        .with_context(|| format!("failed to write {}", temp_path.display()))?;
    fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed to place transfer state {} into {}",
            temp_path.display(),
            path.display()
        )
    })?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn place_downloaded_file(temp_path: &Path, target_path: &Path) -> Result<()> {
    match fs::remove_file(target_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error)
                .with_context(|| format!("failed to replace {}", target_path.display()));
        }
    }
    fs::rename(temp_path, target_path).with_context(|| {
        format!(
            "failed to place downloaded file {} into {}",
            temp_path.display(),
            target_path.display()
        )
    })
}

fn file_modified_unix_ms(metadata: &fs::Metadata) -> u128 {
    metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_millis())
        .unwrap_or(0)
}

pub fn normalize_server_base_url(input: &str) -> Result<Url> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("server base URL is empty"));
    }

    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    };

    let mut normalized =
        Url::parse(&with_scheme).with_context(|| format!("invalid server base URL: {input}"))?;
    if !normalized.path().ends_with('/') {
        let path = format!("{}/", normalized.path());
        normalized.set_path(&path);
    }

    Ok(normalized)
}

fn ensure_missing_folder_markers(entries: &mut Vec<StoreIndexEntry>) {
    let mut existing = BTreeSet::new();
    for entry in entries.iter() {
        existing.insert(entry.path.clone());
    }

    let mut to_add = BTreeSet::new();
    for entry in entries.iter() {
        let path = entry.path.trim_end_matches('/');
        if path.is_empty() {
            continue;
        }

        let segments: Vec<&str> = path
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        if segments.len() < 2 {
            continue;
        }

        for index in 1..segments.len() {
            let marker = format!("{}/", segments[..index].join("/"));
            if !existing.contains(&marker) {
                to_add.insert(marker);
            }
        }
    }

    for marker in to_add {
        if existing.insert(marker.clone()) {
            entries.push(StoreIndexEntry {
                path: marker,
                entry_type: "prefix".to_string(),
                version: None,
                content_hash: None,
                size_bytes: None,
                modified_at_unix: None,
                content_fingerprint: None,
                media: None,
            });
        }
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));
}

fn append_optional_query(url: &mut Url, key: &str, value: Option<&str>) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        url.query_pairs_mut().append_pair(key, value);
    }
}

fn path_and_query(url: &Url) -> String {
    match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    }
}

fn unix_ts() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn snapshot_from_store_index_entries(entries: Vec<StoreIndexEntry>) -> SyncSnapshot {
    let mut remote = Vec::with_capacity(entries.len());

    for entry in entries {
        if (entry.entry_type == "prefix") || entry.path.ends_with('/') {
            let directory_path = entry.path.trim_end_matches('/').to_string();
            if !directory_path.is_empty() {
                remote.push(NamespaceEntry::directory(directory_path));
            }
            continue;
        }

        let version = entry.version.unwrap_or_else(|| "server-head".to_string());
        let content_hash = entry
            .content_hash
            .unwrap_or_else(|| format!("server-head:{}", entry.path));
        let mut remote_entry =
            NamespaceEntry::file_sized(entry.path.clone(), version, content_hash, entry.size_bytes);
        remote_entry.content_fingerprint = entry.content_fingerprint;
        remote.push(remote_entry);
    }

    SyncSnapshot {
        local: Vec::new(),
        remote,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        body::Body,
        extract::{Path as AxumPath, State},
        http::{Response, header},
        routing::{get, post},
    };
    use std::sync::{Arc, Barrier};
    use tokio::sync::Mutex;
    use transport_sdk::{
        RelayTicket, RelayTicketRequest, RendezvousClientConfig, RendezvousControlClient,
    };

    #[test]
    fn object_url_builder_escapes_segments() {
        let client = IronMeshClient::from_direct_base_url("http://127.0.0.1:18080/");
        let url = client
            .store_key_url("read me.txt")
            .expect("object url should build");
        assert_eq!(url.as_str(), "http://127.0.0.1:18080/store/read%20me.txt");
    }

    #[test]
    fn normalize_server_base_url_adds_scheme_and_trailing_slash() {
        let normalized = normalize_server_base_url("127.0.0.1:18080").expect("url should be valid");
        assert_eq!(normalized.as_str(), "http://127.0.0.1:18080/");
    }

    #[test]
    fn snapshot_conversion_maps_prefix_and_keys() {
        let snapshot = snapshot_from_store_index_entries(vec![
            StoreIndexEntry {
                path: "docs/".to_string(),
                entry_type: "prefix".to_string(),
                version: None,
                content_hash: None,
                size_bytes: None,
                modified_at_unix: None,
                content_fingerprint: None,
                media: None,
            },
            StoreIndexEntry {
                path: "docs/readme.txt".to_string(),
                entry_type: "key".to_string(),
                version: None,
                content_hash: None,
                size_bytes: Some(42),
                modified_at_unix: None,
                content_fingerprint: Some("cfp-readme".to_string()),
                media: None,
            },
        ]);

        assert_eq!(snapshot.local.len(), 0);
        assert_eq!(snapshot.remote.len(), 2);
        assert_eq!(snapshot.remote[0], NamespaceEntry::directory("docs"));
        assert_eq!(snapshot.remote[1].path, "docs/readme.txt");
        assert_eq!(snapshot.remote[1].version.as_deref(), Some("server-head"));
        assert_eq!(
            snapshot.remote[1].content_hash.as_deref(),
            Some("server-head:docs/readme.txt")
        );
        assert_eq!(
            snapshot.remote[1].content_fingerprint.as_deref(),
            Some("cfp-readme")
        );
        assert_eq!(snapshot.remote[1].size_bytes, Some(42));
    }

    #[test]
    fn ensure_missing_folder_markers_adds_nested_parents() {
        let mut entries = vec![StoreIndexEntry {
            path: "a/b/c.txt".to_string(),
            entry_type: "key".to_string(),
            version: None,
            content_hash: None,
            size_bytes: Some(7),
            modified_at_unix: None,
            content_fingerprint: None,
            media: None,
        }];

        ensure_missing_folder_markers(&mut entries);

        let paths = entries
            .into_iter()
            .map(|entry| entry.path)
            .collect::<Vec<_>>();
        assert_eq!(paths, vec!["a/", "a/b/", "a/b/c.txt"]);
    }

    #[test]
    fn ensure_missing_folder_markers_keeps_existing_markers_unique() {
        let mut entries = vec![
            StoreIndexEntry {
                path: "docs/".to_string(),
                entry_type: "prefix".to_string(),
                version: None,
                content_hash: None,
                size_bytes: None,
                modified_at_unix: None,
                content_fingerprint: None,
                media: None,
            },
            StoreIndexEntry {
                path: "docs/guides/readme.md".to_string(),
                entry_type: "key".to_string(),
                version: None,
                content_hash: None,
                size_bytes: Some(11),
                modified_at_unix: None,
                content_fingerprint: None,
                media: None,
            },
        ];

        ensure_missing_folder_markers(&mut entries);

        let paths = entries
            .into_iter()
            .map(|entry| entry.path)
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            vec!["docs/", "docs/guides/", "docs/guides/readme.md"]
        );
    }

    #[test]
    fn delete_url_builder_builds_expected_path() {
        let client = IronMeshClient::from_direct_base_url("http://127.0.0.1:18080/");
        let url = client.store_delete_url().expect("delete url should build");
        assert_eq!(url.as_str(), "http://127.0.0.1:18080/store/delete");
    }

    #[test]
    fn versions_url_builder_builds_expected_path() {
        let client = IronMeshClient::from_direct_base_url("http://127.0.0.1:18080/");
        let url = client.store_versions_url("docs/readme.txt").unwrap();
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:18080/versions/docs%2Freadme.txt"
        );
    }

    #[tokio::test]
    async fn list_versions_parses_version_graph_summary() {
        async fn versions(
            axum::extract::Path(key): axum::extract::Path<String>,
        ) -> axum::Json<VersionGraphSummary> {
            axum::Json(VersionGraphSummary {
                key,
                object_id: "obj-123".to_string(),
                preferred_head_version_id: Some("v2".to_string()),
                preferred_head_reason: Some(PreferredHeadReason::DeterministicTiebreakVersionId),
                head_version_ids: vec!["v2".to_string()],
                versions: vec![VersionRecordSummary {
                    version_id: "v2".to_string(),
                    logical_path: Some("docs/readme.txt".to_string()),
                    parent_version_ids: vec!["v1".to_string()],
                    state: VersionConsistencyState::Confirmed,
                    created_at_unix: 123,
                    copied_from_object_id: None,
                    copied_from_version_id: None,
                    copied_from_path: None,
                }],
            })
        }

        let app = axum::Router::new().route("/versions/{key}", axum::routing::get(versions));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener should have addr");
        let server = axum::serve(listener, app.into_make_service());
        let handle = tokio::spawn(async move {
            let _ = server.await;
        });

        let client = IronMeshClient::from_direct_base_url(format!("http://{addr}"));
        let versions = client
            .list_versions("docs/readme.txt")
            .await
            .expect("versions should parse")
            .expect("versions should exist");

        assert_eq!(versions.object_id, "obj-123");
        assert_eq!(versions.preferred_head_version_id.as_deref(), Some("v2"));
        assert_eq!(versions.versions.len(), 1);
        assert_eq!(versions.versions[0].version_id, "v2");

        handle.abort();
    }

    #[derive(Clone)]
    struct RelayTestState {
        captured_request: Arc<Mutex<Option<RelayHttpRequest>>>,
    }

    #[tokio::test]
    async fn relay_transport_executes_store_index_request_with_signed_device_identity() {
        async fn issue_ticket(Json(request): Json<RelayTicketRequest>) -> Json<RelayTicket> {
            Json(RelayTicket {
                cluster_id: request.cluster_id,
                session_id: "relay-session-1".to_string(),
                source: request.source,
                target: request.target,
                relay_urls: vec!["http://127.0.0.1:1".to_string()],
                issued_at_unix: 1,
                expires_at_unix: 61,
            })
        }

        async fn relay_request(
            State(state): State<RelayTestState>,
            Json(request): Json<RelayHttpRequest>,
        ) -> Json<RelayHttpResponse> {
            *state.captured_request.lock().await = Some(request.clone());
            Json(RelayHttpResponse {
                cluster_id: request.ticket.cluster_id,
                session_id: request.ticket.session_id.clone(),
                request_id: request.request_id.clone(),
                responder: request.ticket.target.clone(),
                status: 200,
                headers: vec![RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                }],
                body_base64: encode_optional_body_base64(
                    serde_json::to_string(&StoreIndexResponse {
                        prefix: String::new(),
                        depth: 1,
                        entry_count: 1,
                        entries: vec![StoreIndexEntry {
                            path: "docs/readme.txt".to_string(),
                            entry_type: "key".to_string(),
                            version: Some("v1".to_string()),
                            content_hash: Some("hash-1".to_string()),
                            size_bytes: Some(42),
                            modified_at_unix: None,
                            content_fingerprint: None,
                            media: None,
                        }],
                    })
                    .expect("store index response should serialize")
                    .as_bytes(),
                ),
            })
        }

        let relay_state = RelayTestState {
            captured_request: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route("/control/relay/ticket", post(issue_ticket))
            .route("/relay/http/request", post(relay_request))
            .with_state(relay_state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("relay test server should run");
        });

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("relay-test-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let target_node_id = NodeId::new_v4();
        let rendezvous = RendezvousControlClient::new(
            RendezvousClientConfig {
                cluster_id: identity.cluster_id,
                rendezvous_urls: vec![format!("http://{addr}")],
                heartbeat_interval_secs: 15,
            },
            None,
            None,
        )
        .expect("rendezvous client should build");

        let client = IronMeshClient::with_relay_transport(
            "https://relay.invalid/",
            rendezvous,
            target_node_id,
        )
        .with_client_identity(identity.clone());

        let response = client
            .store_index(None, 1, None)
            .await
            .expect("store index over relay should succeed");

        assert_eq!(response.entry_count, 2);
        assert_eq!(response.entries[0].path, "docs/");
        assert_eq!(response.entries[1].path, "docs/readme.txt");

        let captured = relay_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("relay request should be captured");
        assert_eq!(
            captured.ticket.source,
            PeerIdentity::Device(identity.device_id)
        );
        assert_eq!(captured.ticket.target, PeerIdentity::Node(target_node_id));
        assert_eq!(captured.path_and_query, "/store/index?depth=1");
        assert!(
            captured
                .headers
                .iter()
                .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                    && header.value == identity.device_id.to_string())
        );

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn relay_transport_executes_generic_json_get_request() {
        async fn issue_ticket(Json(request): Json<RelayTicketRequest>) -> Json<RelayTicket> {
            Json(RelayTicket {
                cluster_id: request.cluster_id,
                session_id: "relay-session-2".to_string(),
                source: request.source,
                target: request.target,
                relay_urls: vec!["http://127.0.0.1:1".to_string()],
                issued_at_unix: 1,
                expires_at_unix: 61,
            })
        }

        async fn relay_request(
            State(state): State<RelayTestState>,
            Json(request): Json<RelayHttpRequest>,
        ) -> Json<RelayHttpResponse> {
            *state.captured_request.lock().await = Some(request.clone());
            Json(RelayHttpResponse {
                cluster_id: request.ticket.cluster_id,
                session_id: request.ticket.session_id.clone(),
                request_id: request.request_id.clone(),
                responder: request.ticket.target.clone(),
                status: 200,
                headers: vec![RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                }],
                body_base64: encode_optional_body_base64(br#"{"status":"ok"}"#),
            })
        }

        let relay_state = RelayTestState {
            captured_request: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route("/control/relay/ticket", post(issue_ticket))
            .route("/relay/http/request", post(relay_request))
            .with_state(relay_state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("relay test server should run");
        });

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("relay-test-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let target_node_id = NodeId::new_v4();
        let rendezvous = RendezvousControlClient::new(
            RendezvousClientConfig {
                cluster_id: identity.cluster_id,
                rendezvous_urls: vec![format!("http://{addr}")],
                heartbeat_interval_secs: 15,
            },
            None,
            None,
        )
        .expect("rendezvous client should build");

        let client = IronMeshClient::with_relay_transport(
            "https://relay.invalid/",
            rendezvous,
            target_node_id,
        )
        .with_client_identity(identity.clone());

        let response = client
            .get_json_path("/cluster/status")
            .await
            .expect("generic JSON GET over relay should succeed");

        assert_eq!(response["status"], "ok");

        let captured = relay_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("relay request should be captured");
        assert_eq!(captured.path_and_query, "/cluster/status");
        assert!(
            captured
                .headers
                .iter()
                .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                    && header.value == identity.device_id.to_string())
        );

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn relay_transport_executes_relative_path_get_request() {
        async fn issue_ticket(Json(request): Json<RelayTicketRequest>) -> Json<RelayTicket> {
            Json(RelayTicket {
                cluster_id: request.cluster_id,
                session_id: "relay-session-3".to_string(),
                source: request.source,
                target: request.target,
                relay_urls: vec!["http://127.0.0.1:1".to_string()],
                issued_at_unix: 1,
                expires_at_unix: 61,
            })
        }

        async fn relay_request(
            State(state): State<RelayTestState>,
            Json(request): Json<RelayHttpRequest>,
        ) -> Json<RelayHttpResponse> {
            *state.captured_request.lock().await = Some(request.clone());
            Json(RelayHttpResponse {
                cluster_id: request.ticket.cluster_id,
                session_id: request.ticket.session_id.clone(),
                request_id: request.request_id.clone(),
                responder: request.ticket.target.clone(),
                status: 200,
                headers: vec![RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "image/jpeg".to_string(),
                }],
                body_base64: encode_optional_body_base64(b"thumb-jpeg-bytes"),
            })
        }

        let relay_state = RelayTestState {
            captured_request: Arc::new(Mutex::new(None)),
        };
        let router = Router::new()
            .route("/control/relay/ticket", post(issue_ticket))
            .route("/relay/http/request", post(relay_request))
            .with_state(relay_state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener should bind");
        let addr = listener.local_addr().expect("listener addr");
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("relay test server should run");
        });

        let mut identity = ClientIdentityMaterial::generate(
            uuid::Uuid::now_v7(),
            None,
            Some("relay-test-device".to_string()),
        )
        .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());
        let target_node_id = NodeId::new_v4();
        let rendezvous = RendezvousControlClient::new(
            RendezvousClientConfig {
                cluster_id: identity.cluster_id,
                rendezvous_urls: vec![format!("http://{addr}")],
                heartbeat_interval_secs: 15,
            },
            None,
            None,
        )
        .expect("rendezvous client should build");

        let client = IronMeshClient::with_relay_transport(
            "https://relay.invalid/",
            rendezvous,
            target_node_id,
        )
        .with_client_identity(identity.clone());

        let response = client
            .get_relative_path("/media/thumbnail?key=gallery%2Fcat.png")
            .await
            .expect("relative GET over relay should succeed");

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body.as_ref(), b"thumb-jpeg-bytes");

        let captured = relay_state
            .captured_request
            .lock()
            .await
            .clone()
            .expect("relay request should be captured");
        assert_eq!(
            captured.path_and_query,
            "/media/thumbnail?key=gallery%2Fcat.png"
        );
        assert!(
            captured
                .headers
                .iter()
                .any(|header| header.name == transport_sdk::HEADER_DEVICE_ID
                    && header.value == identity.device_id.to_string())
        );

        server.abort();
        let _ = server.await;
    }

    #[test]
    fn blocking_range_download_handles_concurrent_overlapping_requests() {
        fn build_range_response(
            payload: &[u8],
            status: StatusCode,
            start: usize,
            end_inclusive: usize,
        ) -> Response<Body> {
            Response::builder()
                .status(status)
                .header("x-ironmesh-object-size", payload.len().to_string())
                .header(ETAG.as_str(), "\"test-etag\"")
                .header(ACCEPT_RANGES.as_str(), "bytes")
                .header(
                    CONTENT_LENGTH.as_str(),
                    (end_inclusive - start + 1).to_string(),
                )
                .header(
                    CONTENT_RANGE.as_str(),
                    format!("bytes {start}-{end_inclusive}/{}", payload.len()),
                )
                .body(Body::from(payload[start..=end_inclusive].to_vec()))
                .expect("range response should build")
        }

        fn parse_range_header(range: &str, total_len: usize) -> (usize, usize) {
            let trimmed = range
                .strip_prefix("bytes=")
                .expect("range header should have bytes= prefix");
            let (start, end) = trimmed
                .split_once('-')
                .expect("range header should contain dash");
            let start = start.parse::<usize>().expect("range start should parse");
            let end = end.parse::<usize>().expect("range end should parse");
            assert!(start <= end, "range start must not exceed end");
            assert!(end < total_len, "range end must stay within payload");
            (start, end)
        }

        async fn head_store(
            State(payload): State<Arc<Vec<u8>>>,
            AxumPath(_key): AxumPath<String>,
        ) -> Response<Body> {
            Response::builder()
                .status(StatusCode::OK)
                .header("x-ironmesh-object-size", payload.len().to_string())
                .header(ETAG.as_str(), "\"test-etag\"")
                .header(ACCEPT_RANGES.as_str(), "bytes")
                .header(CONTENT_LENGTH.as_str(), payload.len().to_string())
                .body(Body::empty())
                .expect("head response should build")
        }

        async fn get_store(
            State(payload): State<Arc<Vec<u8>>>,
            AxumPath(_key): AxumPath<String>,
            headers: HeaderMap,
        ) -> Response<Body> {
            tokio::time::sleep(Duration::from_millis(20)).await;

            match headers.get(RANGE).and_then(|value| value.to_str().ok()) {
                Some(range) => {
                    let (start, end_inclusive) = parse_range_header(range, payload.len());
                    build_range_response(
                        &payload,
                        StatusCode::PARTIAL_CONTENT,
                        start,
                        end_inclusive,
                    )
                }
                None => Response::builder()
                    .status(StatusCode::OK)
                    .header("x-ironmesh-object-size", payload.len().to_string())
                    .header(ETAG.as_str(), "\"test-etag\"")
                    .header(ACCEPT_RANGES.as_str(), "bytes")
                    .header(header::CONTENT_LENGTH, payload.len().to_string())
                    .body(Body::from(payload.as_ref().clone()))
                    .expect("full response should build"),
            }
        }

        let payload = Arc::new(
            (0..200_000)
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>(),
        );

        let app = Router::new()
            .route("/store/{*key}", get(get_store).head(head_store))
            .with_state(payload.clone());
        let (addr_tx, addr_rx) = std::sync::mpsc::sync_channel(1);
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server_thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("server runtime should build");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("listener should bind");
                addr_tx
                    .send(listener.local_addr().expect("listener should have addr"))
                    .expect("server addr should send");
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = shutdown_rx.await;
                    })
                    .await
                    .expect("range server should run");
            });
        });

        let addr = addr_rx.recv().expect("server addr should arrive");
        let client = IronMeshClient::from_direct_base_url(format!("http://{addr}"));
        let requests = [
            (0_u64, 65_536_u64),
            (65_536_u64, 4_096_u64),
            (69_632_u64, 61_440_u64),
            (131_072_u64, payload.len() as u64 - 131_072_u64),
        ];

        for _round in 0..8 {
            let barrier = Arc::new(Barrier::new(requests.len()));
            let mut handles = Vec::new();
            for (start, length) in requests {
                let client = client.clone();
                let barrier = barrier.clone();
                let expected = payload[start as usize..(start + length) as usize].to_vec();
                handles.push(std::thread::spawn(move || {
                    let mut writer = Vec::new();
                    let mut progress_updates = Vec::new();
                    barrier.wait();
                    let result = client
                        .download_range_to_writer_with_progress_blocking(
                            DownloadRangeRequest {
                                key: "photos/test.jpg",
                                snapshot: None,
                                version: None,
                                range: RequestedRange {
                                    offset: start,
                                    length,
                                },
                            },
                            &mut writer,
                            &mut |progress| progress_updates.push(progress),
                            &|| false,
                        )
                        .expect("blocking ranged download should succeed");
                    assert_eq!(writer, expected);
                    assert_eq!(result.range.offset, start);
                    assert_eq!(result.range.length, length);
                    assert_eq!(result.bytes_downloaded, length);
                    assert!(
                        progress_updates
                            .last()
                            .is_some_and(|progress| progress.bytes_downloaded == length),
                        "final progress update should report the completed byte count",
                    );
                }));
            }

            for handle in handles {
                handle.join().expect("download worker should complete");
            }
        }

        let _ = shutdown_tx.send(());
        server_thread.join().expect("server thread should stop");
    }
}
