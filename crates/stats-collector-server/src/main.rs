//! Binary entry point for the hardware-reliability stats collector service.
//!
//! Configuration is via environment variables only (no domain/TLS is hardcoded here — where and
//! how this binds is a deployment concern, see
//! `docs/server-node-hardware-reliability-telemetry-strategy.md` Section 5.2):
//! - `STATS_COLLECTOR_BIND_ADDR`: address to bind, defaults to `127.0.0.1:44044`.
//! - `STATS_COLLECTOR_DB_PATH`: path to the SQLite database file, defaults to
//!   `stats-collector.sqlite3` in the current working directory.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use stats_collector_server::{
    DEFAULT_BIND_ADDR, DEFAULT_DB_PATH, StatsCollectorAppState, build_router,
    storage::IngestStorage,
};
use tracing::info;
use tracing_subscriber::EnvFilter;

/// How often to sweep stale per-key rate-limit bookkeeping (see
/// `StatsCollectorAppState::cleanup_rate_limiters`).
const RATE_LIMIT_CLEANUP_INTERVAL: Duration = Duration::from_secs(15 * 60);

#[tokio::main]
async fn main() -> Result<()> {
    init_tracing();

    let bind_addr: SocketAddr = std::env::var("STATS_COLLECTOR_BIND_ADDR")
        .unwrap_or_else(|_| DEFAULT_BIND_ADDR.to_string())
        .parse()
        .context("invalid STATS_COLLECTOR_BIND_ADDR")?;
    let db_path =
        std::env::var("STATS_COLLECTOR_DB_PATH").unwrap_or_else(|_| DEFAULT_DB_PATH.to_string());

    let storage = IngestStorage::open(&db_path)
        .with_context(|| format!("failed to open stats-collector database at {db_path}"))?;
    let state = StatsCollectorAppState::new(storage);

    spawn_rate_limit_cleanup(state.clone());

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;

    info!(%bind_addr, db_path = %db_path, "stats-collector-server listening");

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

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}
