//! `stats-collector-server` — the central hardware-reliability telemetry ingestion service.
//!
//! See `docs/server-node-hardware-reliability-telemetry-strategy.md` for the full design
//! (Status: Concept, this crate implements the ingestion slice of Sections 5, 6 and 7 only).
//!
//! This is a deliberately small, standalone service (Section 5.1/5.4): unlike
//! `rendezvous-server`, it has **no per-node identity or mTLS** — the entire point is that the
//! collector cannot tell which cluster/operator a given record came from (Section 5.2). Abuse
//! protection is via rate limiting (see [`rate_limit`]) rather than authentication.
//!
//! Not implemented in this slice (left for later work, see the module docs in `ingest` and
//! `storage` for the specific seams left in place):
//! - the periodic aggregation batch job that condenses raw rows into k-anonymous fleet stats,
//! - the public k-anonymity-safe dashboard/API,
//! - real geo-IP country-code derivation (the `country_code` column exists but is always `NULL`),
//! - production TLS/deployment wiring (this crate only binds a plain HTTP listener; putting it
//!   behind TLS at `creax.de:44044` is a deployment concern, not something hardcoded here).

pub mod ingest;
pub mod rate_limit;
pub mod storage;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::Serialize;
use serde_json::Value;
use tracing::warn;

use crate::ingest::{PayloadValidationError, validate_payload};
use crate::rate_limit::SlidingWindowLimiter;
use crate::storage::IngestStorage;

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Per-source-IP limit: generous enough that a handful of nodes sharing one NAT'd IP (a small
/// office/homelab cluster) don't trip it, but low enough to blunt a single-source flood, given
/// the expected send cadence is one batch every 6-24h per node (Section 6).
pub const RATE_LIMIT_PER_IP_MAX_REQUESTS: u32 = 20;
pub const RATE_LIMIT_PER_IP_WINDOW: Duration = Duration::from_secs(60 * 60);

/// Per-`telemetry_subject_id` limit: a well-behaved node sends at most a couple of batches per
/// hour even in the worst case (e.g. retries after failures, Section 6), so this stays tight.
pub const RATE_LIMIT_PER_SUBJECT_MAX_REQUESTS: u32 = 4;
pub const RATE_LIMIT_PER_SUBJECT_WINDOW: Duration = Duration::from_secs(60 * 60);

/// Default local bind address, overridable via `STATS_COLLECTOR_BIND_ADDR`.
pub const DEFAULT_BIND_ADDR: &str = "127.0.0.1:44044";

/// Default SQLite path, overridable via `STATS_COLLECTOR_DB_PATH`.
pub const DEFAULT_DB_PATH: &str = "stats-collector.sqlite3";

#[derive(Clone)]
pub struct StatsCollectorAppState {
    storage: Arc<IngestStorage>,
    ip_limiter: Arc<SlidingWindowLimiter>,
    subject_limiter: Arc<SlidingWindowLimiter>,
}

impl StatsCollectorAppState {
    /// Builds app state with the default (documented) rate limits.
    pub fn new(storage: IngestStorage) -> Self {
        Self::with_rate_limits(
            storage,
            RATE_LIMIT_PER_IP_MAX_REQUESTS,
            RATE_LIMIT_PER_IP_WINDOW,
            RATE_LIMIT_PER_SUBJECT_MAX_REQUESTS,
            RATE_LIMIT_PER_SUBJECT_WINDOW,
        )
    }

    /// Builds app state with custom rate limits, primarily so tests can use tight limits without
    /// waiting out a real window.
    pub fn with_rate_limits(
        storage: IngestStorage,
        ip_max_requests: u32,
        ip_window: Duration,
        subject_max_requests: u32,
        subject_window: Duration,
    ) -> Self {
        Self {
            storage: Arc::new(storage),
            ip_limiter: Arc::new(SlidingWindowLimiter::new(ip_max_requests, ip_window)),
            subject_limiter: Arc::new(SlidingWindowLimiter::new(
                subject_max_requests,
                subject_window,
            )),
        }
    }

    /// Runs one sweep of stale rate-limit bookkeeping. Intended to be called periodically (see
    /// `main.rs`) so long-running processes don't accumulate unbounded per-key state for callers
    /// that never come back.
    pub fn cleanup_rate_limiters(&self) {
        self.ip_limiter.cleanup_stale_entries();
        self.subject_limiter.cleanup_stale_entries();
    }

    /// Exposes the underlying storage, e.g. for a future admin/erasure endpoint (Section 4.5).
    pub fn storage(&self) -> &IngestStorage {
        &self.storage
    }
}

/// Builds the axum [`Router`] for this service. Callers are responsible for TLS termination and
/// for actually binding/serving it (see `main.rs`).
pub fn build_router(state: StatsCollectorAppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route(
            "/v1/ingest/hardware-reliability",
            post(ingest_hardware_reliability),
        )
        .with_state(state)
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    software_version: &'static str,
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        software_version: PACKAGE_VERSION,
    })
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

impl IntoResponse for PayloadValidationError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: self.message(),
            }),
        )
            .into_response()
    }
}

struct RateLimited;

impl IntoResponse for RateLimited {
    fn into_response(self) -> Response {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "rate limit exceeded".to_string(),
            }),
        )
            .into_response()
    }
}

async fn ingest_hardware_reliability(
    State(state): State<StatsCollectorAppState>,
    ConnectInfo(source_addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<Value>,
) -> Response {
    let validated = match validate_payload(&payload) {
        Ok(validated) => validated,
        Err(error) => return error.into_response(),
    };

    // The source IP is used only transiently, in-memory, as a rate-limit key — it is never
    // logged, stored, or forwarded (see `storage.rs` module docs and Section 2.6).
    if !state
        .ip_limiter
        .check_and_record(&source_addr.ip().to_string())
    {
        return RateLimited.into_response();
    }
    if !state
        .subject_limiter
        .check_and_record(&validated.telemetry_subject_id)
    {
        return RateLimited.into_response();
    }

    let received_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let raw_payload_json = payload.to_string();
    let insert_result = state.storage.insert(
        received_at_unix,
        &validated.telemetry_subject_id,
        validated.schema_version,
        &raw_payload_json,
    );

    if let Err(error) = insert_result {
        warn!(%error, "failed to persist hardware-reliability ingestion record");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "failed to persist payload".to_string(),
            }),
        )
            .into_response();
    }

    StatusCode::ACCEPTED.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::{Request, header};
    use serde_json::json;
    use tower::ServiceExt;

    fn test_state() -> StatsCollectorAppState {
        StatsCollectorAppState::with_rate_limits(
            IngestStorage::open_in_memory().expect("storage should open"),
            RATE_LIMIT_PER_IP_MAX_REQUESTS,
            RATE_LIMIT_PER_IP_WINDOW,
            RATE_LIMIT_PER_SUBJECT_MAX_REQUESTS,
            RATE_LIMIT_PER_SUBJECT_WINDOW,
        )
    }

    fn source_addr(ip_suffix: u8) -> SocketAddr {
        format!("203.0.113.{ip_suffix}:51000")
            .parse()
            .expect("test source addr should parse")
    }

    fn ingest_request(body: Value, addr: SocketAddr) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri("/v1/ingest/hardware-reliability")
            .header(header::CONTENT_TYPE, "application/json")
            .extension(ConnectInfo(addr))
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .expect("request should build")
    }

    #[tokio::test]
    async fn health_route_reports_ok() {
        let router = build_router(test_state());
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .expect("request should build"),
            )
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn happy_path_ingest_then_row_exists() {
        let state = test_state();
        let router = build_router(state.clone());
        let payload = json!({
            "schema_version": 1,
            "telemetry_subject_id": "subject-happy-path",
            "generated_at_unix": 1_752_912_000_u64,
            "ironmesh_version": "1.0.35",
            "hardware_profile_id": "hp-abc",
            "country_code": "DE",
            "node_lifecycle": {"uptime_seconds": 100},
            "storage_devices": [],
            "memory_ecc": {"available": true},
            "reliability_findings_summary": [],
            "collectors": [{"collector_id": "smartctl", "available": true}],
        });

        let response = router
            .oneshot(ingest_request(payload, source_addr(1)))
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let records = state
            .storage
            .records_for_subject("subject-happy-path")
            .expect("query should succeed");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].schema_version, 1);
        // Even though the payload above included a country_code, it must never be trusted:
        // this slice always stores NULL until real geo-IP derivation exists (Section 4.2).
        assert_eq!(records[0].country_code, None);
    }

    #[tokio::test]
    async fn tolerates_unknown_top_level_fields() {
        let state = test_state();
        let router = build_router(state.clone());
        let payload = json!({
            "schema_version": 1,
            "telemetry_subject_id": "subject-tolerant",
            "a_field_from_the_future": {"whatever": [1, 2, 3]},
        });

        let response = router
            .oneshot(ingest_request(payload, source_addr(2)))
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(state.storage.count().expect("count should succeed"), 1);
    }

    #[tokio::test]
    async fn rejects_unsupported_schema_version() {
        let state = test_state();
        let router = build_router(state.clone());
        let payload = json!({
            "schema_version": 2,
            "telemetry_subject_id": "subject-bad-version",
        });

        let response = router
            .oneshot(ingest_request(payload, source_addr(3)))
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.storage.count().expect("count should succeed"), 0);
    }

    #[tokio::test]
    async fn rejects_missing_telemetry_subject_id() {
        let router = build_router(test_state());
        let payload = json!({ "schema_version": 1 });

        let response = router
            .oneshot(ingest_request(payload, source_addr(4)))
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rate_limits_after_n_requests_from_same_subject() {
        let state = StatsCollectorAppState::with_rate_limits(
            IngestStorage::open_in_memory().expect("storage should open"),
            RATE_LIMIT_PER_IP_MAX_REQUESTS,
            RATE_LIMIT_PER_IP_WINDOW,
            2,
            Duration::from_secs(60 * 60),
        );
        let router = build_router(state.clone());
        let addr = source_addr(5);

        for _ in 0..2 {
            let payload = json!({
                "schema_version": 1,
                "telemetry_subject_id": "subject-rate-limited",
            });
            let response = router
                .clone()
                .oneshot(ingest_request(payload, addr))
                .await
                .expect("router should respond");
            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }

        let payload = json!({
            "schema_version": 1,
            "telemetry_subject_id": "subject-rate-limited",
        });
        let response = router
            .oneshot(ingest_request(payload, addr))
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(state.storage.count().expect("count should succeed"), 2);
    }

    #[tokio::test]
    async fn rate_limits_after_n_requests_from_same_ip() {
        let state = StatsCollectorAppState::with_rate_limits(
            IngestStorage::open_in_memory().expect("storage should open"),
            2,
            Duration::from_secs(60 * 60),
            RATE_LIMIT_PER_SUBJECT_MAX_REQUESTS,
            RATE_LIMIT_PER_SUBJECT_WINDOW,
        );
        let router = build_router(state.clone());
        let addr = source_addr(6);

        for index in 0..2 {
            let payload = json!({
                "schema_version": 1,
                "telemetry_subject_id": format!("subject-ip-{index}"),
            });
            let response = router
                .clone()
                .oneshot(ingest_request(payload, addr))
                .await
                .expect("router should respond");
            assert_eq!(response.status(), StatusCode::ACCEPTED);
        }

        let payload = json!({
            "schema_version": 1,
            "telemetry_subject_id": "subject-ip-another",
        });
        let response = router
            .oneshot(ingest_request(payload, addr))
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }
}
