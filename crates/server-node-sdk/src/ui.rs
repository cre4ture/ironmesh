use super::*;
use axum::http::header::{CONTENT_TYPE, HeaderValue};
use axum::response::Html;

const INDEX_HTML_TEMPLATE: &str =
    include_str!(concat!(env!("OUT_DIR"), "/server_admin_index.html"));
const INDEX_CSS: &str = include_str!(concat!(env!("OUT_DIR"), "/server_admin_app.css"));
const INDEX_JS: &str = include_str!(concat!(env!("OUT_DIR"), "/server_admin_app.js"));
const FAVICON_SVG: &str = include_str!("../../../docs/assets/ironmesh-favicon.svg");

pub(crate) async fn index() -> Html<&'static str> {
    Html(INDEX_HTML_TEMPLATE)
}

pub(crate) async fn favicon() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("image/svg+xml; charset=utf-8"),
        )],
        FAVICON_SVG,
    )
}

#[derive(Debug, Deserialize)]
pub(crate) struct LogsQuery {
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct LogsResponse {
    entries: Vec<String>,
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

pub(crate) async fn app_css() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("text/css; charset=utf-8"),
        )],
        INDEX_CSS,
    )
}

pub(crate) async fn app_js() -> impl IntoResponse {
    (
        StatusCode::OK,
        [(
            CONTENT_TYPE,
            HeaderValue::from_static("application/javascript; charset=utf-8"),
        )],
        INDEX_JS,
    )
}
