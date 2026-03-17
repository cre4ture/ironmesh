use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use common::{NodeId, StorageObjectMeta};
use reqwest::Client as HttpClient;
use reqwest::Method;
use reqwest::RequestBuilder;
use reqwest::StatusCode;
use reqwest::Url;
use reqwest::header::{CONTENT_LENGTH, HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use sync_core::{NamespaceEntry, SyncSnapshot};
use transport_sdk::{
    ClientIdentityMaterial, PeerIdentity, RelayHttpHeader, RelayHttpRequest, RelayHttpResponse,
    RelayTicketRequest, RendezvousControlClient, build_signed_request_headers,
    encode_optional_body_base64,
};

const LARGE_UPLOAD_THRESHOLD_BYTES: usize = 1024 * 1024;
const CHUNK_UPLOAD_SIZE_BYTES: usize = 1024 * 1024;

#[derive(Clone)]
pub struct IronMeshClient {
    transport: ClientTransport,
    auth: ClientRequestAuth,
}

#[derive(Clone)]
enum ClientRequestAuth {
    None,
    BearerToken(String),
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

#[derive(Debug, Deserialize)]
struct StoreChunkUploadResponse {
    hash: String,
    size_bytes: usize,
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
struct CompleteStoreUploadRequest {
    total_size_bytes: usize,
    chunks: Vec<CompleteStoreUploadChunkRef>,
}

#[derive(Debug, Serialize)]
struct CompleteStoreUploadChunkRef {
    hash: String,
    size_bytes: usize,
}

#[derive(Debug, Serialize)]
struct PathMutationRequest {
    from_path: String,
    to_path: String,
    overwrite: bool,
}

impl IronMeshClient {
    pub fn new(server_base_url: impl Into<String>) -> Self {
        Self::with_http_client(server_base_url, HttpClient::new())
    }

    pub fn with_http_client(server_base_url: impl Into<String>, http: HttpClient) -> Self {
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

    pub fn with_bearer_token(mut self, bearer_token: impl Into<String>) -> Self {
        self.auth = ClientRequestAuth::BearerToken(bearer_token.into());
        self
    }

    pub fn with_client_identity(mut self, identity: ClientIdentityMaterial) -> Self {
        self.auth = ClientRequestAuth::SignedIdentity(identity);
        self
    }

    fn server_base_url(&self) -> &str {
        match &self.transport {
            ClientTransport::Direct {
                server_base_url, ..
            } => server_base_url.as_str(),
            ClientTransport::Relay(relay) => relay.request_base_url.as_str(),
        }
    }

    fn direct_http(&self) -> Option<&HttpClient> {
        match &self.transport {
            ClientTransport::Direct { http, .. } => Some(http),
            ClientTransport::Relay(_) => None,
        }
    }

    fn request_auth_headers(&self, method: &Method, url: &Url) -> Result<Vec<RelayHttpHeader>> {
        match &self.auth {
            ClientRequestAuth::None => Ok(Vec::new()),
            ClientRequestAuth::BearerToken(token) => Ok(vec![RelayHttpHeader {
                name: "authorization".to_string(),
                value: format!("Bearer {token}"),
            }]),
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
            ClientRequestAuth::None | ClientRequestAuth::BearerToken(_) => {
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

    pub async fn store_index(
        &self,
        prefix: Option<&str>,
        depth: usize,
        snapshot: Option<&str>,
    ) -> Result<StoreIndexResponse> {
        let mut url = self.store_index_url()?;
        url.query_pairs_mut()
            .append_pair("depth", &depth.max(1).to_string());
        append_optional_query(&mut url, "prefix", prefix);
        append_optional_query(&mut url, "snapshot", snapshot);

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
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for store index request")?;
        runtime.block_on(self.store_index(prefix, depth, snapshot))
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
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for store index change wait request")?;
        runtime.block_on(self.wait_for_store_index_change(since, timeout_ms))
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
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for snapshot load")?;
        runtime.block_on(self.load_snapshot_from_server(prefix, depth, snapshot))
    }

    pub fn delete_path_blocking(&self, key: impl AsRef<str>) -> Result<()> {
        let key = key.as_ref().to_string();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for delete request")?;
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

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for rename request")?;
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

        let chunk_upload_url = self.store_chunk_upload_url()?;
        let complete_url = self.store_complete_url(&key)?;
        let mut uploaded_total: usize = 0;
        let mut chunk_refs = Vec::new();

        for chunk in data.chunks(CHUNK_UPLOAD_SIZE_BYTES) {
            uploaded_total = uploaded_total
                .checked_add(chunk.len())
                .context("uploaded byte count overflow")?;

            let response = self
                .execute_buffered_request(
                    Method::POST,
                    chunk_upload_url.clone(),
                    Vec::new(),
                    Some(chunk.to_vec()),
                )
                .await
                .with_context(|| format!("failed to upload chunk for key={key}"))?;
            if !response.status.is_success() {
                bail!("chunk upload rejected for key={key}: {}", response.status);
            }

            let uploaded = serde_json::from_slice::<StoreChunkUploadResponse>(&response.body)
                .with_context(|| format!("failed to parse chunk upload response for {key}"))?;

            chunk_refs.push(CompleteStoreUploadChunkRef {
                hash: uploaded.hash,
                size_bytes: uploaded.size_bytes,
            });
        }

        let complete_payload = CompleteStoreUploadRequest {
            total_size_bytes: uploaded_total,
            chunks: chunk_refs,
        };

        let response = self
            .execute_buffered_request(
                Method::POST,
                complete_url,
                vec![json_content_type_header()],
                Some(
                    serde_json::to_vec(&complete_payload)
                        .context("failed to encode chunked upload completion payload")?,
                ),
            )
            .await
            .with_context(|| format!("failed to finalize chunked upload for key={key}"))?;
        if !response.status.is_success() {
            bail!(
                "chunked finalize rejected for key={key}: {}",
                response.status
            );
        }

        Ok(UploadResult {
            meta: StorageObjectMeta {
                key,
                size_bytes: complete_payload.total_size_bytes,
            },
            upload_mode: UploadMode::Chunked,
            chunk_size_bytes: Some(CHUNK_UPLOAD_SIZE_BYTES),
            chunk_count: Some(complete_payload.chunks.len()),
        })
    }

    pub fn put_large_aware_reader(
        &self,
        key: impl Into<String>,
        reader: &mut dyn std::io::Read,
        length: u64,
    ) -> Result<UploadResult> {
        let key = key.into();

        eprintln!("starting upload for key={key} with length={length} bytes");

        if length <= LARGE_UPLOAD_THRESHOLD_BYTES as u64 {
            eprintln!("using direct upload for key={key} with length={length} bytes");

            let mut buf = Vec::with_capacity(std::cmp::min(length as usize, 8192));
            let mut limited = reader.take(length);
            std::io::Read::read_to_end(&mut limited, &mut buf)
                .with_context(|| format!("failed reading payload for key={key}"))?;

            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("failed to create runtime for upload")?;
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

        eprintln!("using chunked upload for key={key} with length={length} bytes");

        self.put_chunked_reader(key, reader)
    }

    pub fn put_chunked_reader(
        &self,
        key: impl Into<String>,
        reader: &mut dyn std::io::Read,
    ) -> Result<UploadResult> {
        let key = key.into();
        let chunk_upload_url = self.store_chunk_upload_url()?;
        let complete_url = self.store_complete_url(&key)?;

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for upload")?;

        let mut uploaded_total: usize = 0;
        let mut chunk_refs = Vec::new();
        let mut chunk = vec![0u8; CHUNK_UPLOAD_SIZE_BYTES];

        loop {
            let read_bytes = reader
                .read(&mut chunk)
                .with_context(|| format!("failed reading chunk for key={key}"))?;
            if read_bytes == 0 {
                break;
            }

            uploaded_total = uploaded_total
                .checked_add(read_bytes)
                .context("uploaded byte count overflow")?;

            let response = runtime
                .block_on(self.execute_buffered_request(
                    Method::POST,
                    chunk_upload_url.clone(),
                    Vec::new(),
                    Some(chunk[..read_bytes].to_vec()),
                ))
                .with_context(|| format!("failed to upload chunk for key={key}"))?;
            if !response.status.is_success() {
                bail!("chunk upload rejected for key={key}: {}", response.status);
            }

            let uploaded = serde_json::from_slice::<StoreChunkUploadResponse>(&response.body)
                .with_context(|| format!("failed to parse chunk upload response for {key}"))?;

            chunk_refs.push(CompleteStoreUploadChunkRef {
                hash: uploaded.hash,
                size_bytes: uploaded.size_bytes,
            });
        }

        if chunk_refs.is_empty() {
            let meta = runtime.block_on(self.put(key, Bytes::new()))?;
            return Ok(UploadResult {
                meta,
                upload_mode: UploadMode::Direct,
                chunk_size_bytes: None,
                chunk_count: None,
            });
        }

        let complete_payload = CompleteStoreUploadRequest {
            total_size_bytes: uploaded_total,
            chunks: chunk_refs,
        };

        let response = runtime
            .block_on(
                self.execute_buffered_request(
                    Method::POST,
                    complete_url,
                    vec![json_content_type_header()],
                    Some(
                        serde_json::to_vec(&complete_payload)
                            .context("failed to encode chunked upload completion payload")?,
                    ),
                ),
            )
            .with_context(|| format!("failed to finalize chunked upload for key={key}"))?;
        if !response.status.is_success() {
            bail!(
                "chunked finalize rejected for key={key}: {}",
                response.status
            );
        }

        Ok(UploadResult {
            meta: StorageObjectMeta {
                key,
                size_bytes: complete_payload.total_size_bytes,
            },
            upload_mode: UploadMode::Chunked,
            chunk_size_bytes: Some(CHUNK_UPLOAD_SIZE_BYTES),
            chunk_count: Some(complete_payload.chunks.len()),
        })
    }

    pub fn get_with_selector_writer(
        &self,
        key: impl AsRef<str>,
        snapshot: Option<&str>,
        version: Option<&str>,
        writer: &mut dyn Write,
    ) -> Result<()> {
        let key = key.as_ref();
        let mut url = self.store_key_url(key)?;
        append_optional_query(&mut url, "snapshot", snapshot);
        append_optional_query(&mut url, "version", version);

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for download")?;

        if matches!(self.transport, ClientTransport::Relay(_)) {
            let payload = runtime
                .block_on(self.get_with_selector(key, snapshot, version))
                .with_context(|| format!("failed to GET object key={key}"))?;
            writer
                .write_all(payload.as_ref())
                .with_context(|| format!("failed to write payload chunk for key={key}"))?;
            writer
                .flush()
                .with_context(|| format!("failed to flush output for key={key}"))?;
            return Ok(());
        }

        let direct_http = self
            .direct_http()
            .ok_or_else(|| anyhow!("direct HTTP transport is unavailable"))?;
        let request_headers = self.request_auth_headers(&Method::GET, &url)?;
        let mut response = runtime
            .block_on(
                self.apply_headers_to_request(direct_http.get(url.clone()), &request_headers)
                    .send(),
            )
            .with_context(|| format!("failed to GET object key={key}"))?
            .error_for_status()
            .with_context(|| format!("object not found or inaccessible key={key}"))?;

        loop {
            let chunk = runtime
                .block_on(response.chunk())
                .with_context(|| format!("failed to read payload chunk for key={key}"))?;

            match chunk {
                Some(chunk) => writer
                    .write_all(chunk.as_ref())
                    .with_context(|| format!("failed to write payload chunk for key={key}"))?,
                None => break,
            }
        }

        writer
            .flush()
            .with_context(|| format!("failed to flush output for key={key}"))?;
        Ok(())
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

        let response = self
            .execute_buffered_request(Method::HEAD, url, Vec::new(), None)
            .await
            .with_context(|| format!("failed to HEAD object key={key}"))?;

        if response.status == StatusCode::METHOD_NOT_ALLOWED {
            let bytes = self.get_with_selector(key, snapshot, version).await?;
            return Ok(bytes.len() as u64);
        }

        if !response.status.is_success() {
            bail!(
                "object not found or inaccessible key={key}: {}",
                response.status
            );
        }

        if let Some(content_length) = buffered_content_length(&response)
            && content_length > 0
        {
            return Ok(content_length);
        }

        let bytes = self.get_with_selector(key, snapshot, version).await?;
        Ok(bytes.len() as u64)
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

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .context("failed to create runtime for object size request")?;
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

    fn store_chunk_upload_url(&self) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store-chunks");
            segments.push("upload");
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

    fn store_complete_url(&self, key: &str) -> Result<Url> {
        let mut url = reqwest::Url::parse(self.server_base_url())
            .with_context(|| format!("invalid server URL: {}", self.server_base_url()))?;

        {
            let mut segments = url
                .path_segments_mut()
                .map_err(|_| anyhow!("server URL cannot be a base"))?;
            segments.push("store");
            segments.push(key);
        }
        url.query_pairs_mut().append_pair("complete", "");

        Ok(url)
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

fn buffered_content_length(response: &BufferedTransportResponse) -> Option<u64> {
    response
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .or(Some(response.body.len() as u64))
}

fn json_content_type_header() -> RelayHttpHeader {
    RelayHttpHeader {
        name: "content-type".to_string(),
        value: "application/json".to_string(),
    }
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
        remote.push(NamespaceEntry::file_sized(
            entry.path.clone(),
            version,
            content_hash,
            entry.size_bytes,
        ));
    }

    SyncSnapshot {
        local: Vec::new(),
        remote,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::State, routing::post};
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use transport_sdk::{
        RelayTicket, RelayTicketRequest, RendezvousClientConfig, RendezvousControlClient,
    };

    #[test]
    fn object_url_builder_escapes_segments() {
        let client = IronMeshClient::new("http://127.0.0.1:18080/");
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
                content_fingerprint: None,
                media: None,
            },
            StoreIndexEntry {
                path: "docs/readme.txt".to_string(),
                entry_type: "key".to_string(),
                version: None,
                content_hash: None,
                size_bytes: Some(42),
                content_fingerprint: None,
                media: None,
            },
        ]);

        assert_eq!(snapshot.local.len(), 0);
        assert_eq!(snapshot.remote.len(), 2);
        assert_eq!(snapshot.remote[0], NamespaceEntry::directory("docs"));
        assert_eq!(
            snapshot.remote[1],
            NamespaceEntry::file_sized(
                "docs/readme.txt",
                "server-head",
                "server-head:docs/readme.txt",
                Some(42),
            )
        );
    }

    #[test]
    fn ensure_missing_folder_markers_adds_nested_parents() {
        let mut entries = vec![StoreIndexEntry {
            path: "a/b/c.txt".to_string(),
            entry_type: "key".to_string(),
            version: None,
            content_hash: None,
            size_bytes: Some(7),
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
                content_fingerprint: None,
                media: None,
            },
            StoreIndexEntry {
                path: "docs/guides/readme.md".to_string(),
                entry_type: "key".to_string(),
                version: None,
                content_hash: None,
                size_bytes: Some(11),
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
        let client = IronMeshClient::new("http://127.0.0.1:18080/");
        let url = client.store_delete_url().expect("delete url should build");
        assert_eq!(url.as_str(), "http://127.0.0.1:18080/store/delete");
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
}
