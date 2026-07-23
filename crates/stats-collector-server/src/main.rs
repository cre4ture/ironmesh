//! Binary entry point for the hardware-reliability stats collector service.
//!
//! Configuration is via environment variables only (no domain/TLS is hardcoded here — where and
//! how this binds is a deployment concern, see
//! `docs/server-node-hardware-reliability-telemetry-strategy.md` Section 5.2):
//! - `STATS_COLLECTOR_BIND_ADDR`: address to bind, defaults to `127.0.0.1:44044`.
//! - `STATS_COLLECTOR_DB_PATH`: path to the SQLite database file, defaults to
//!   `stats-collector.sqlite3` in the current working directory.
//! - `STATS_COLLECTOR_ADMIN_TOKEN`: bearer token guarding the raw-access / erasure endpoints
//!   (doc Sections 4.5, 5.3). When unset, those endpoints return 412 instead of operating
//!   unauthenticated.
//! - `STATS_COLLECTOR_K_ANONYMITY_MIN`: minimum group size for published aggregates
//!   (doc Section 4.3), defaults to 5.
//! - `STATS_COLLECTOR_RETENTION_DAYS`: raw-data retention window before pruning (doc Section 4.6),
//!   defaults to 180.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use stats_collector_server::{
    DEFAULT_BIND_ADDR, DEFAULT_DB_PATH, DEFAULT_K_ANONYMITY_MIN, DEFAULT_RETENTION_DAYS,
    StatsCollectorAppState, build_router, storage::IngestStorage,
};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

/// How often to sweep stale per-key rate-limit bookkeeping (see
/// `StatsCollectorAppState::cleanup_rate_limiters`).
const RATE_LIMIT_CLEANUP_INTERVAL: Duration = Duration::from_secs(15 * 60);

/// How often to enforce raw-data retention (doc Section 4.6). Daily is ample for a day-granularity
/// cutoff.
const RETENTION_SWEEP_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let bind_addr: SocketAddr = std::env::var("STATS_COLLECTOR_BIND_ADDR")
        .unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string())
        .parse()
        .context("invalid STATS_COLLECTOR_BIND_ADDR")?;
    let db_path =
        std::env::var("STATS_COLLECTOR_DB_PATH").unwrap_or_else(|_| DEFAULT_DB_PATH.to_string());
    let admin_token = std::env::var("STATS_COLLECTOR_ADMIN_TOKEN").ok();
    let k_anonymity_min = std::env::var("STATS_COLLECTOR_K_ANONYMITY_MIN")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(DEFAULT_K_ANONYMITY_MIN);
    let retention_days = std::env::var("STATS_COLLECTOR_RETENTION_DAYS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(DEFAULT_RETENTION_DAYS);

    if admin_token.is_none() {
        warn!(
            "STATS_COLLECTOR_ADMIN_TOKEN is not set; the admin raw-access and erasure endpoints will return 412"
        );
    }

    let storage = IngestStorage::open(&db_path)
        .with_context(|| format!("failed to open stats-collector database at {db_path}"))?;
    let state = StatsCollectorAppState::new(storage)
        .with_admin_token(admin_token)
        .with_k_anonymity_min(k_anonymity_min);

    spawn_rate_limit_cleanup(state.clone());
    spawn_retention_sweeper(state.clone(), retention_days);

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;

    info!(
        %bind_addr,
        db_path = %db_path,
        k_anonymity_min,
        retention_days,
        "stats-collector-server listening"
    );

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .context("stats-collector-server stopped unexpectedly")?;

    Ok(())
}

fn spawn_rate_limit_cleanup(state: StatsCollectorAppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RATE_LIMIT_CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            state.cleanup_rate_limiters();
        }
    });
}

fn spawn_retention_sweeper(state: StatsCollectorAppState, retention_days: u64) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(RETENTION_SWEEP_INTERVAL);
        loop {
            interval.tick().await;
            match state.prune_expired(retention_days) {
                Ok(removed) if removed > 0 => {
                    info!(removed, retention_days, "pruned expired telemetry records")
                }
                Ok(_) => {}
                Err(error) => warn!(%error, "failed to prune expired telemetry records"),
            }
        }
    });
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}
