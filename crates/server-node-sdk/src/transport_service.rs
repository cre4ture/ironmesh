use anyhow::{Context, Result};
use axum::body::to_bytes;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, Uri};
use axum::response::{IntoResponse, Response};
use percent_encoding::percent_decode_str;

use crate::{
    BufferedTransportRequest, BufferedTransportResponse, ServerState, StoreIndexQuery,
    TransportHeader, cluster_status, get_media_thumbnail_response, get_object_response, health,
    join_peer_url, latency_diagnostic, list_nodes, list_store_index_response,
    list_versions_response, transport_headers_from_response,
};

pub(super) async fn execute_buffered_transport_request(
    state: &ServerState,
    local_http: &reqwest::Client,
    local_base_url: &str,
    request: &BufferedTransportRequest,
) -> Result<BufferedTransportResponse> {
    if let Some(response) = try_execute_direct_transport_request(state, request).await? {
        return Ok(response);
    }

    execute_fallback_local_http_request(local_http, local_base_url, request).await
}

async fn try_execute_direct_transport_request(
    state: &ServerState,
    request: &BufferedTransportRequest,
) -> Result<Option<BufferedTransportResponse>> {
    let method = request.method.trim();
    let raw_path = request.path.trim();
    let path_only = raw_path.split_once('?').map(|(path, _)| path).unwrap_or(raw_path);
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
            let query = parse_query::<StoreIndexQuery>(raw_path).map_err(|err| {
                anyhow::anyhow!("failed parsing store index query {raw_path}: {err}")
            })?;
            Some(list_store_index_response(state, query, "/media/thumbnail").await)
        }
        ("GET", "/media/thumbnail") => {
            let query = parse_query::<crate::MediaThumbnailQuery>(raw_path).map_err(|err| {
                anyhow::anyhow!("failed parsing media thumbnail query {raw_path}: {err}")
            })?;
            Some(get_media_thumbnail_response(state, query).await)
        }
        ("GET", path) if path.starts_with("/store/") => {
            let query = parse_query::<crate::ObjectGetQuery>(raw_path).map_err(|err| {
                anyhow::anyhow!("failed parsing object query {raw_path}: {err}")
            })?;
            let key = decode_route_tail(path, "/store/")?;
            Some(get_object_response(state, &key, query, &headers, false).await)
        }
        ("HEAD", path) if path.starts_with("/store/") => {
            let query = parse_query::<crate::ObjectGetQuery>(raw_path).map_err(|err| {
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

async fn execute_fallback_local_http_request(
    local_http: &reqwest::Client,
    local_base_url: &str,
    request: &BufferedTransportRequest,
) -> Result<BufferedTransportResponse> {
    let url = join_peer_url(local_base_url, &request.path)?;
    let method = reqwest::Method::from_bytes(request.method.as_bytes()).with_context(|| {
        format!(
            "invalid multiplexed transport fallback HTTP method {}",
            request.method
        )
    })?;
    let mut outbound = local_http.request(method, url);
    for header in &request.headers {
        if header.name.eq_ignore_ascii_case("host")
            || header.name.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        outbound = outbound.header(&header.name, &header.value);
    }
    if !request.body.is_empty() {
        outbound = outbound.body(request.body.clone());
    }

    let response = outbound
        .send()
        .await
        .context("failed executing fallback local multiplex transport request")?;
    let status = response.status().as_u16();
    let headers = transport_headers_from_response(response.headers());
    let body = response
        .bytes()
        .await
        .context("failed reading fallback local multiplex transport response body")?
        .to_vec();

    Ok(BufferedTransportResponse {
        request_id: request.request_id.clone(),
        status,
        headers,
        body,
    })
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
    let tail = path
        .strip_prefix(prefix)
        .ok_or_else(|| anyhow::anyhow!("transport request path {path} did not start with {prefix}"))?;
    percent_decode_str(tail)
        .decode_utf8()
        .map(|value| value.into_owned())
        .context("failed decoding percent-encoded transport path tail")
}

pub(super) fn header_map_from_transport_headers(headers: &[TransportHeader]) -> Result<HeaderMap> {
    let mut header_map = HeaderMap::new();
    for header in headers {
        let name = header.name.parse::<axum::http::HeaderName>().with_context(|| {
            format!("invalid transport header name {}", header.name)
        })?;
        let value = HeaderValue::from_str(&header.value).with_context(|| {
            format!("invalid transport header value for {}", header.name)
        })?;
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
