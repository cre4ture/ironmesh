use anyhow::{Context, Result, anyhow, bail};
use reqwest::StatusCode;

use crate::relay::RelayHttpHeader;

pub const RELAY_HTTP_TUNNEL_CHUNK_SIZE_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRelayWireHttpRequest {
    pub method: String,
    pub path_and_query: String,
    pub headers: Vec<RelayHttpHeader>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRelayWireHttpResponse {
    pub status: u16,
    pub headers: Vec<RelayHttpHeader>,
    pub body: Vec<u8>,
}

pub fn encode_relay_wire_http_request(
    method: &str,
    path_and_query: &str,
    host: &str,
    headers: &[RelayHttpHeader],
    body: &[u8],
) -> Result<Vec<u8>> {
    let method = method.trim();
    if method.is_empty() {
        bail!("relay wire HTTP request method must not be empty");
    }
    let path_and_query = path_and_query.trim();
    if path_and_query.is_empty() || !path_and_query.starts_with('/') {
        bail!("relay wire HTTP request path_and_query must start with '/'");
    }
    let host = host.trim();
    if host.is_empty() {
        bail!("relay wire HTTP request host must not be empty");
    }

    let mut request = format!("{method} {path_and_query} HTTP/1.1\r\n");
    request.push_str(&format!("host: {host}\r\n"));

    for header in headers {
        if should_skip_request_header(&header.name) {
            continue;
        }
        append_header_line(&mut request, &header.name, &header.value)?;
    }

    request.push_str("connection: close\r\n");
    request.push_str(&format!("content-length: {}\r\n", body.len()));
    request.push_str("\r\n");

    let mut encoded = request.into_bytes();
    encoded.extend_from_slice(body);
    Ok(encoded)
}

pub fn encode_relay_wire_http_response_head(
    status: u16,
    headers: &[RelayHttpHeader],
) -> Result<Vec<u8>> {
    let status = StatusCode::from_u16(status)
        .with_context(|| format!("invalid relay wire HTTP status {status}"))?;
    let reason = status.canonical_reason().unwrap_or("Unknown Status");
    let mut response = format!("HTTP/1.1 {} {}\r\n", status.as_u16(), reason);

    for header in headers {
        if should_skip_response_header(&header.name) {
            continue;
        }
        append_header_line(&mut response, &header.name, &header.value)?;
    }

    response.push_str("connection: close\r\n");
    response.push_str("\r\n");
    Ok(response.into_bytes())
}

pub fn parse_relay_wire_http_request(bytes: &[u8]) -> Result<ParsedRelayWireHttpRequest> {
    let (head, body_bytes) = split_relay_wire_head_body(bytes)?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow!("relay wire HTTP request is missing a request line"))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| anyhow!("relay wire HTTP request is missing a method"))?;
    let path_and_query = request_parts
        .next()
        .ok_or_else(|| anyhow!("relay wire HTTP request is missing a path"))?;
    let version = request_parts
        .next()
        .ok_or_else(|| anyhow!("relay wire HTTP request is missing an HTTP version"))?;
    if version != "HTTP/1.1" {
        bail!("unsupported relay wire HTTP request version {version}");
    }

    let headers = parse_headers(lines.collect::<Vec<_>>().as_slice())?;
    let body = body_for_headers(&headers, body_bytes, false)?;
    Ok(ParsedRelayWireHttpRequest {
        method: method.to_string(),
        path_and_query: path_and_query.to_string(),
        headers,
        body,
    })
}

pub fn parse_relay_wire_http_response(bytes: &[u8]) -> Result<ParsedRelayWireHttpResponse> {
    parse_relay_wire_http_response_with_options(bytes, false)
}

pub fn parse_relay_wire_http_head_response(bytes: &[u8]) -> Result<ParsedRelayWireHttpResponse> {
    parse_relay_wire_http_response_with_options(bytes, true)
}

fn parse_relay_wire_http_response_with_options(
    bytes: &[u8],
    ignore_content_length: bool,
) -> Result<ParsedRelayWireHttpResponse> {
    let (head, body_bytes) = split_relay_wire_head_body(bytes)?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| anyhow!("relay wire HTTP response is missing a status line"))?;
    let mut status_parts = status_line.splitn(3, ' ');
    let version = status_parts
        .next()
        .ok_or_else(|| anyhow!("relay wire HTTP response is missing an HTTP version"))?;
    if version != "HTTP/1.1" {
        bail!("unsupported relay wire HTTP response version {version}");
    }
    let status = status_parts
        .next()
        .ok_or_else(|| anyhow!("relay wire HTTP response is missing a status code"))?
        .parse::<u16>()
        .context("failed parsing relay wire HTTP status code")?;
    let _reason = status_parts.next().unwrap_or_default();

    let headers = parse_headers(lines.collect::<Vec<_>>().as_slice())?;
    let body = body_for_headers(&headers, body_bytes, ignore_content_length)?;
    Ok(ParsedRelayWireHttpResponse {
        status,
        headers,
        body,
    })
}

fn split_relay_wire_head_body(bytes: &[u8]) -> Result<(String, &[u8])> {
    let head_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| anyhow!("relay wire HTTP message is missing a header terminator"))?;
    let head = std::str::from_utf8(&bytes[..head_end])
        .context("relay wire HTTP header block must be valid UTF-8")?;
    Ok((head.to_string(), &bytes[head_end + 4..]))
}

fn parse_headers(lines: &[&str]) -> Result<Vec<RelayHttpHeader>> {
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| anyhow!("invalid relay wire HTTP header line {line:?}"))?;
        let name = name.trim();
        if name.is_empty() {
            bail!("relay wire HTTP header name must not be empty");
        }
        let value = value.trim_start();
        headers.push(RelayHttpHeader {
            name: name.to_string(),
            value: value.to_string(),
        });
    }
    Ok(headers)
}

fn body_for_headers(
    headers: &[RelayHttpHeader],
    bytes: &[u8],
    ignore_content_length: bool,
) -> Result<Vec<u8>> {
    if let Some(length) = header_value_case_insensitive(headers, "content-length")
        && !ignore_content_length
    {
        let expected = length
            .parse::<usize>()
            .with_context(|| format!("invalid content-length header {length}"))?;
        if bytes.len() != expected {
            bail!(
                "relay wire HTTP body length mismatch: expected={expected} actual={}",
                bytes.len()
            );
        }
        return Ok(bytes.to_vec());
    }

    if let Some(transfer_encoding) = header_value_case_insensitive(headers, "transfer-encoding")
        && transfer_encoding.eq_ignore_ascii_case("chunked")
    {
        bail!("chunked relay wire HTTP messages are not supported");
    }

    Ok(bytes.to_vec())
}

fn header_value_case_insensitive<'a>(
    headers: &'a [RelayHttpHeader],
    name: &str,
) -> Option<&'a str> {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case(name))
        .map(|header| header.value.as_str())
}

fn append_header_line(buffer: &mut String, name: &str, value: &str) -> Result<()> {
    let name = name.trim();
    if name.is_empty() {
        bail!("relay wire HTTP header name must not be empty");
    }
    if name.contains('\r') || name.contains('\n') || value.contains('\r') || value.contains('\n') {
        bail!("relay wire HTTP header values must not contain CR or LF characters");
    }
    buffer.push_str(name);
    buffer.push_str(": ");
    buffer.push_str(value.trim());
    buffer.push_str("\r\n");
    Ok(())
}

fn should_skip_request_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("host")
        || name.eq_ignore_ascii_case("connection")
        || name.eq_ignore_ascii_case("content-length")
}

fn should_skip_response_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("connection") || name.eq_ignore_ascii_case("transfer-encoding")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_roundtrips_headers_and_body() {
        let encoded = encode_relay_wire_http_request(
            "GET",
            "/store/index?depth=1",
            "relay.invalid",
            &[
                RelayHttpHeader {
                    name: "x-test".to_string(),
                    value: "alpha".to_string(),
                },
                RelayHttpHeader {
                    name: "range".to_string(),
                    value: "bytes=0-10".to_string(),
                },
            ],
            b"payload",
        )
        .expect("request should encode");

        let parsed = parse_relay_wire_http_request(&encoded).expect("request should parse");
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.path_and_query, "/store/index?depth=1");
        assert_eq!(parsed.body, b"payload");
        assert!(
            parsed
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("host")
                    && header.value == "relay.invalid")
        );
        assert!(parsed.headers.iter().any(
            |header| header.name.eq_ignore_ascii_case("range") && header.value == "bytes=0-10"
        ));
    }

    #[test]
    fn response_roundtrips_headers_and_body() {
        let mut encoded = encode_relay_wire_http_response_head(
            206,
            &[
                RelayHttpHeader {
                    name: "content-type".to_string(),
                    value: "application/json".to_string(),
                },
                RelayHttpHeader {
                    name: "content-range".to_string(),
                    value: "bytes 0-3/4".to_string(),
                },
                RelayHttpHeader {
                    name: "content-length".to_string(),
                    value: "4".to_string(),
                },
            ],
        )
        .expect("response head should encode");
        encoded.extend_from_slice(b"body");

        let parsed = parse_relay_wire_http_response(&encoded).expect("response should parse");
        assert_eq!(parsed.status, 206);
        assert_eq!(parsed.body, b"body");
        assert!(
            parsed
                .headers
                .iter()
                .any(|header| header.name.eq_ignore_ascii_case("content-range")
                    && header.value == "bytes 0-3/4")
        );
    }
}
