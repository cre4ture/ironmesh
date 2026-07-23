//! `stats-collector-server` — the central hardware-reliability telemetry ingestion service.
//!
//! See `docs/server-node-hardware-reliability-telemetry-strategy.md` for the full design; this
//! crate implements Sections 5-7: tolerant ingestion, append-only raw storage, k-anonymity-safe
//! public aggregates ([`aggregate`], Section 4.3), admin-token-guarded GDPR access/erasure
//! (Section 4.5), and a retention sweeper (Section 4.6).
//!
//! This is a deliberately small, standalone service (Section 5.1/5.4): unlike
//! `rendezvous-server`, it has **no per-node identity or mTLS** — the entire point is that the
//! collector cannot tell which cluster/operator a given record came from (Section 5.2). Abuse
//! protection is via rate limiting (see [`rate_limit`]) rather than authentication.
//!
//! Left for later work (seams are in place):
//! - a real geo-IP-backed [`country::CountryResolver`] (the default [`country::NoopCountryResolver`]
//!   resolves nothing, so no GeoIP database is bundled here — Section 4.2),
//! - moving the on-request aggregation to a periodic batch job if the fleet ever outgrows it,
//! - production TLS/deployment wiring (this crate binds a plain HTTP listener; terminating TLS at
//!   `creax.de:44044` is a deployment concern, not something hardcoded here).

pub mod aggregate;
pub mod country;
pub mod ingest;
pub mod rate_limit;
pub mod storage;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::Router;
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{info, warn};

use crate::aggregate::{FleetSummary, summarize};
use crate::country::{CountryResolver, NoopCountryResolver};
use crate::ingest::{PayloadValidationError, validate_payload};
use crate::rate_limit::SlidingWindowLimiter;
use crate::storage::{IngestStorage, StoredRecord};

const PACKAGE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Admin authentication header, matching the server-node admin plane convention
/// (`x-ironmesh-admin-token`). See doc Section 5.3.
pub const ADMIN_TOKEN_HEADER: &str = "x-ironmesh-admin-token";

/// Default k-anonymity minimum group size for published aggregates (doc Section 4.3).
pub const DEFAULT_K_ANONYMITY_MIN: u32 = 5;

/// Default raw-data retention window before pruning (doc Section 4.6).
pub const DEFAULT_RETENTION_DAYS: u64 = 180;

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
    /// Admin bearer token for the raw-access / erasure endpoints (doc Sections 4.5, 5.3). `None`
    /// means "not configured", in which case those endpoints return 412 rather than operating
    /// unauthenticated.
    admin_token: Option<Arc<String>>,
    /// Minimum distinct-subject group size for published aggregates (doc Section 4.3).
    k_anonymity_min: u32,
    /// Server-side country-code derivation (doc Section 4.2); the default resolves nothing.
    country_resolver: Arc<dyn CountryResolver>,
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
    /// waiting out a real window. Admin token unset, default k-anonymity, no-op country resolver;
    /// use the `with_*` builders to override.
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
            admin_token: None,
            k_anonymity_min: DEFAULT_K_ANONYMITY_MIN,
            country_resolver: Arc::new(NoopCountryResolver),
        }
    }

    /// Sets the admin token (empty/whitespace is treated as unset).
    pub fn with_admin_token(mut self, admin_token: Option<String>) -> Self {
        self.admin_token = admin_token
            .map(|token| token.trim().to_string())
            .filter(|token| !token.is_empty())
            .map(Arc::new);
        self
    }

    /// Overrides the k-anonymity minimum group size.
    pub fn with_k_anonymity_min(mut self, k_anonymity_min: u32) -> Self {
        self.k_anonymity_min = k_anonymity_min.max(1);
        self
    }

    /// Plugs in a country resolver (e.g. a GeoIP-backed one in production, doc Section 4.2).
    pub fn with_country_resolver(mut self, resolver: Arc<dyn CountryResolver>) -> Self {
        self.country_resolver = resolver;
        self
    }

    /// Runs one sweep of stale rate-limit bookkeeping. Intended to be called periodically (see
    /// `main.rs`) so long-running processes don't accumulate unbounded per-key state for callers
    /// that never come back.
    pub fn cleanup_rate_limiters(&self) {
        self.ip_limiter.cleanup_stale_entries();
        self.subject_limiter.cleanup_stale_entries();
    }

    /// Exposes the underlying storage.
    pub fn storage(&self) -> &IngestStorage {
        &self.storage
    }

    /// Deletes raw rows older than `retention_days` (doc Section 4.6). Returns the number pruned.
    /// Intended to be called periodically (see `main.rs`).
    pub fn prune_expired(&self, retention_days: u64) -> anyhow::Result<usize> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let cutoff = now.saturating_sub((retention_days.saturating_mul(24 * 60 * 60)) as i64);
        self.storage.delete_older_than(cutoff)
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
        // Public, k-anonymity-safe fleet statistics (doc Sections 4.3, 5.3).
        .route("/v1/stats/summary", get(stats_summary))
        // Admin-token-protected GDPR access + erasure (doc Section 4.5).
        .route("/v1/admin/raw", get(admin_raw_records))
        .route(
            "/v1/admin/subject/{telemetry_subject_id}",
            delete(admin_delete_subject),
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

    // Derive the coarse country code from the source IP, then let the IP go out of scope — it is
    // never stored or logged (doc Sections 4.2, 2.6). Any `country_code` in the payload body is
    // ignored; only this server-derived value is trusted.
    let country_code = state.country_resolver.resolve(source_addr.ip());

    let raw_payload_json = payload.to_string();
    let insert_result = state.storage.insert(
        received_at_unix,
        &validated.telemetry_subject_id,
        validated.schema_version,
        country_code.as_deref(),
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

fn internal_error(message: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            error: message.to_string(),
        }),
    )
        .into_response()
}

/// Public, k-anonymity-safe fleet statistics (doc Sections 4.3, 5.3). Computed on request; the
/// small target fleet makes this cheap, and the code is structured so a periodic batch job could
/// replace the on-request computation later without changing the response shape.
async fn stats_summary(State(state): State<StatsCollectorAppState>) -> Response {
    match state.storage.all_records() {
        Ok(records) => {
            let summary: FleetSummary = summarize(&records, state.k_anonymity_min);
            (StatusCode::OK, Json(summary)).into_response()
        }
        Err(error) => {
            warn!(%error, "failed to compute fleet summary");
            internal_error("failed to compute summary")
        }
    }
}

/// Authorizes an admin request against the configured token. Returns 412 when no token is
/// configured (mirrors the server-node "denied_unconfigured" stance) and 401 on missing/mismatched
/// tokens. The comparison is constant-time.
fn authorize_admin(state: &StatsCollectorAppState, headers: &HeaderMap) -> Result<(), StatusCode> {
    let Some(expected) = state.admin_token.as_ref() else {
        return Err(StatusCode::PRECONDITION_FAILED);
    };
    let provided = headers
        .get(ADMIN_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, Deserialize)]
struct RawQuery {
    telemetry_subject_id: String,
}

#[derive(Debug, Serialize)]
struct RawRecordsResponse {
    telemetry_subject_id: String,
    records: Vec<RawRecordView>,
}

#[derive(Debug, Serialize)]
struct RawRecordView {
    received_at_unix: i64,
    schema_version: u32,
    country_code: Option<String>,
    payload: Value,
}

fn raw_record_view(record: StoredRecord) -> RawRecordView {
    RawRecordView {
        received_at_unix: record.received_at_unix,
        schema_version: record.schema_version,
        country_code: record.country_code,
        payload: serde_json::from_str(&record.raw_payload_json).unwrap_or(Value::Null),
    }
}

/// GDPR access (doc Section 4.5): returns all raw records for a `telemetry_subject_id`. The subject
/// id itself is the only credential needed to inspect "your" data, since it is not personally
/// identifying and cannot be mapped back to a node without the node's local salt.
async fn admin_raw_records(
    State(state): State<StatsCollectorAppState>,
    headers: HeaderMap,
    Query(query): Query<RawQuery>,
) -> Response {
    if let Err(status) = authorize_admin(&state, &headers) {
        return status.into_response();
    }
    match state
        .storage
        .records_for_subject(&query.telemetry_subject_id)
    {
        Ok(records) => {
            let records = records.into_iter().map(raw_record_view).collect();
            (
                StatusCode::OK,
                Json(RawRecordsResponse {
                    telemetry_subject_id: query.telemetry_subject_id,
                    records,
                }),
            )
                .into_response()
        }
        Err(error) => {
            warn!(%error, "failed to read raw records for subject");
            internal_error("failed to read records")
        }
    }
}

#[derive(Debug, Serialize)]
struct DeleteSubjectResponse {
    telemetry_subject_id: String,
    deleted_records: usize,
}

/// GDPR erasure (doc Section 4.5): deletes all raw records for a `telemetry_subject_id`. Aggregated
/// k-anonymous statistics already published do not need retroactive correction (standard practice
/// for aggregates).
async fn admin_delete_subject(
    State(state): State<StatsCollectorAppState>,
    headers: HeaderMap,
    Path(telemetry_subject_id): Path<String>,
) -> Response {
    if let Err(status) = authorize_admin(&state, &headers) {
        return status.into_response();
    }
    match state.storage.delete_subject(&telemetry_subject_id) {
        Ok(deleted_records) => {
            info!(deleted_records, "erased telemetry subject on request");
            (
                StatusCode::OK,
                Json(DeleteSubjectResponse {
                    telemetry_subject_id,
                    deleted_records,
                }),
            )
                .into_response()
        }
        Err(error) => {
            warn!(%error, "failed to erase telemetry subject");
            internal_error("failed to erase subject")
        }
    }
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

    /// A country resolver that always returns a fixed code, so tests can exercise the country path
    /// without a GeoIP database.
    struct FixedCountryResolver(&'static str);
    impl country::CountryResolver for FixedCountryResolver {
        fn resolve(&self, _source_ip: std::net::IpAddr) -> Option<String> {
            Some(self.0.to_string())
        }
    }

    async fn body_json(response: Response) -> Value {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body should read");
        serde_json::from_slice(&bytes).expect("body should be json")
    }

    #[tokio::test]
    async fn ingest_stores_server_derived_country_not_payload_country() {
        let state = StatsCollectorAppState::with_rate_limits(
            IngestStorage::open_in_memory().expect("storage should open"),
            RATE_LIMIT_PER_IP_MAX_REQUESTS,
            RATE_LIMIT_PER_IP_WINDOW,
            RATE_LIMIT_PER_SUBJECT_MAX_REQUESTS,
            RATE_LIMIT_PER_SUBJECT_WINDOW,
        )
        .with_country_resolver(Arc::new(FixedCountryResolver("DE")));
        let router = build_router(state.clone());

        // Payload lies about being in the US; the server must record its own derived "DE".
        let payload = json!({
            "schema_version": 1,
            "telemetry_subject_id": "subject-country",
            "country_code": "US",
        });
        let response = router
            .oneshot(ingest_request(payload, source_addr(20)))
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::ACCEPTED);

        let records = state
            .storage
            .records_for_subject("subject-country")
            .unwrap();
        assert_eq!(records[0].country_code.as_deref(), Some("DE"));
    }

    #[tokio::test]
    async fn stats_summary_applies_k_anonymity_suppression() {
        let storage = IngestStorage::open_in_memory().expect("storage should open");
        // 5 subjects on "common" (visible at k=5), 1 on "rare" (suppressed).
        for i in 0..5 {
            storage
                .insert(
                    i,
                    &format!("s-common-{i}"),
                    1,
                    None,
                    "{\"hardware_profile_id\":\"common\"}",
                )
                .unwrap();
        }
        storage
            .insert(100, "s-rare", 1, None, "{\"hardware_profile_id\":\"rare\"}")
            .unwrap();
        let state = StatsCollectorAppState::new(storage).with_k_anonymity_min(5);
        let router = build_router(state);

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/v1/stats/summary")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["total_subjects"], 6);
        let profiles = body["by_hardware_profile"].as_array().unwrap();
        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0]["hardware_profile_id"], "common");
    }

    #[tokio::test]
    async fn admin_endpoints_return_412_when_no_token_configured() {
        let router = build_router(test_state());
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/raw?telemetry_subject_id=whatever")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    }

    #[tokio::test]
    async fn admin_raw_requires_matching_token() {
        let state = test_state().with_admin_token(Some("secret".to_string()));
        let router = build_router(state);
        let response = router
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/raw?telemetry_subject_id=whatever")
                    .header(ADMIN_TOKEN_HEADER, "wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn admin_access_then_erasure_roundtrip() {
        let storage = IngestStorage::open_in_memory().expect("storage should open");
        storage
            .insert(1, "subject-x", 1, None, "{\"hardware_profile_id\":\"p\"}")
            .unwrap();
        storage
            .insert(2, "subject-x", 1, None, "{\"hardware_profile_id\":\"p\"}")
            .unwrap();
        let state = StatsCollectorAppState::new(storage).with_admin_token(Some("tok".to_string()));
        let router = build_router(state.clone());

        // Access returns both records.
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/admin/raw?telemetry_subject_id=subject-x")
                    .header(ADMIN_TOKEN_HEADER, "tok")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["records"].as_array().unwrap().len(), 2);

        // Erasure deletes them.
        let response = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/admin/subject/subject-x")
                    .header(ADMIN_TOKEN_HEADER, "tok")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("router should respond");
        assert_eq!(response.status(), StatusCode::OK);
        let body = body_json(response).await;
        assert_eq!(body["deleted_records"], 2);
        assert_eq!(state.storage.count().unwrap(), 0);
    }
}
