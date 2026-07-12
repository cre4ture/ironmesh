use super::*;
use axum::http::{
    HeaderMap, HeaderValue,
    header::{CACHE_CONTROL, CONTENT_TYPE, ETAG, IF_NONE_MATCH},
};
use axum::response::Response;
use std::sync::OnceLock;

mod generated_assets {
    include!(concat!(env!("OUT_DIR"), "/server_admin_assets.rs"));
}

const INDEX_HTML_TEMPLATE: &str =
    include_str!(concat!(env!("OUT_DIR"), "/server_admin_index.html"));
const GENERATED_ASSETS_SOURCE: &str =
    include_str!(concat!(env!("OUT_DIR"), "/server_admin_assets.rs"));
const FAVICON_SVG: &str = include_str!("../../../docs/assets/ironmesh-favicon.svg");

const HTML_CACHE_CONTROL: &str = "no-cache";
const ENTRYPOINT_CACHE_CONTROL: &str = "public, max-age=0, must-revalidate";
const STATIC_ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
const FAVICON_CACHE_CONTROL: &str = "public, max-age=86400, must-revalidate";

static INDEX_HTML: OnceLock<Box<str>> = OnceLock::new();
static INDEX_ENTRYPOINT_PATHS: OnceLock<(String, String)> = OnceLock::new();
static INDEX_APP_CSS: OnceLock<Box<str>> = OnceLock::new();
static INDEX_APP_JS: OnceLock<Box<str>> = OnceLock::new();
static INDEX_HTML_ETAG: OnceLock<HeaderValue> = OnceLock::new();
static INDEX_CSS_ETAG: OnceLock<HeaderValue> = OnceLock::new();
static INDEX_JS_ETAG: OnceLock<HeaderValue> = OnceLock::new();
static FAVICON_ETAG: OnceLock<HeaderValue> = OnceLock::new();

pub(crate) async fn index(headers: HeaderMap) -> impl IntoResponse {
    cacheable_response(
        &headers,
        index_html().as_bytes(),
        "text/html; charset=utf-8",
        HTML_CACHE_CONTROL,
        index_html_etag(),
    )
}

pub(crate) async fn favicon(headers: HeaderMap) -> impl IntoResponse {
    cacheable_response(
        &headers,
        FAVICON_SVG.as_bytes(),
        "image/svg+xml; charset=utf-8",
        FAVICON_CACHE_CONTROL,
        favicon_etag(),
    )
}

#[derive(Debug, Deserialize)]
pub(crate) struct LogsQuery {
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct LogsResponse {
    entries: Vec<LogBufferEntry>,
}

pub(crate) async fn list_logs(
    State(state): State<ServerState>,
    Query(query): Query<LogsQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(200).clamp(1, 1000);
    (
        StatusCode::OK,
        Json(LogsResponse {
            entries: state.log_buffer.recent(limit),
        }),
    )
        .into_response()
}

pub(crate) async fn app_css(headers: HeaderMap) -> impl IntoResponse {
    cacheable_response(
        &headers,
        app_css_content().as_bytes(),
        "text/css; charset=utf-8",
        ENTRYPOINT_CACHE_CONTROL,
        index_css_etag(),
    )
}

pub(crate) async fn app_js(headers: HeaderMap) -> impl IntoResponse {
    cacheable_response(
        &headers,
        app_js_content().as_bytes(),
        "application/javascript; charset=utf-8",
        ENTRYPOINT_CACHE_CONTROL,
        index_js_etag(),
    )
}

pub(crate) async fn static_asset(
    Path(path): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let logical_path = format!("assets/{path}");
    match generated_assets::asset(&logical_path) {
        Some((bytes, content_type)) => cacheable_response(
            &headers,
            bytes,
            content_type,
            STATIC_ASSET_CACHE_CONTROL,
            &build_etag(bytes),
        ),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn cacheable_response(
    request_headers: &HeaderMap,
    body: &'static [u8],
    content_type: &'static str,
    cache_control: &'static str,
    etag: &HeaderValue,
) -> Response {
    if matches_if_none_match(request_headers, etag) {
        return (
            StatusCode::NOT_MODIFIED,
            [
                (CACHE_CONTROL, HeaderValue::from_static(cache_control)),
                (ETAG, etag.clone()),
            ],
        )
            .into_response();
    }

    (
        StatusCode::OK,
        [
            (CONTENT_TYPE, HeaderValue::from_static(content_type)),
            (CACHE_CONTROL, HeaderValue::from_static(cache_control)),
            (ETAG, etag.clone()),
        ],
        body,
    )
        .into_response()
}

fn matches_if_none_match(request_headers: &HeaderMap, etag: &HeaderValue) -> bool {
    let Some(if_none_match) = request_headers.get(IF_NONE_MATCH) else {
        return false;
    };
    let Ok(if_none_match) = if_none_match.to_str() else {
        return false;
    };
    let Ok(expected) = etag.to_str() else {
        return false;
    };

    if_none_match.split(',').map(str::trim).any(|candidate| {
        candidate == "*" || candidate == expected || candidate.strip_prefix("W/") == Some(expected)
    })
}

fn build_etag(bytes: &[u8]) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{:016x}-{}\"", fnv1a64(bytes), bytes.len()))
        .expect("generated etag must be a valid header value")
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

fn index_html_etag() -> &'static HeaderValue {
    INDEX_HTML_ETAG.get_or_init(|| build_etag(index_html().as_bytes()))
}

fn index_css_etag() -> &'static HeaderValue {
    INDEX_CSS_ETAG.get_or_init(|| build_etag(app_css_content().as_bytes()))
}

fn index_js_etag() -> &'static HeaderValue {
    INDEX_JS_ETAG.get_or_init(|| build_etag(app_js_content().as_bytes()))
}

fn favicon_etag() -> &'static HeaderValue {
    FAVICON_ETAG.get_or_init(|| build_etag(FAVICON_SVG.as_bytes()))
}

fn index_html() -> &'static str {
    INDEX_HTML.get_or_init(|| {
        let (script_path, stylesheet_path) = index_entrypoint_paths();
        INDEX_HTML_TEMPLATE
            .replace("/ui/app.js", script_path)
            .replace("/ui/app.css", stylesheet_path)
            .into_boxed_str()
    })
}

fn app_css_content() -> &'static str {
    INDEX_APP_CSS.get_or_init(|| {
        let (_, stylesheet_path) = index_entrypoint_paths();
        format!("@import url(\"{stylesheet_path}\");\n").into_boxed_str()
    })
}

fn app_js_content() -> &'static str {
    INDEX_APP_JS.get_or_init(|| {
        let (script_path, _) = index_entrypoint_paths();
        format!("import \"{script_path}\";\n").into_boxed_str()
    })
}

fn index_entrypoint_paths() -> (&'static str, &'static str) {
    let (script_path, stylesheet_path) = INDEX_ENTRYPOINT_PATHS.get_or_init(|| {
        let script_path = find_generated_asset_path("assets/index-", ".js").unwrap_or_else(|| {
            panic!("failed locating hashed server-admin JS entrypoint in generated assets")
        });
        let stylesheet_path =
            find_generated_asset_path("assets/index-", ".css").unwrap_or_else(|| {
                panic!("failed locating hashed server-admin CSS entrypoint in generated assets")
            });
        (format!("/{script_path}"), format!("/{stylesheet_path}"))
    });

    (script_path.as_str(), stylesheet_path.as_str())
}

fn find_generated_asset_path(prefix: &str, suffix: &str) -> Option<String> {
    GENERATED_ASSETS_SOURCE.lines().find_map(|line| {
        let candidate = line.split('"').nth(1)?;
        if candidate.starts_with(prefix) && candidate.ends_with(suffix) {
            Some(candidate.to_string())
        } else {
            None
        }
    })
}
