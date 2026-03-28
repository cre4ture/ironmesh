use std::sync::Once;

use tracing::Subscriber;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Layer};

pub fn env_filter_from_default_env(default_directive: &str) -> EnvFilter {
    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_directive))
}

pub fn compact_fmt_layer<S>() -> impl Layer<S> + Send + Sync
where
    S: Subscriber + for<'span> LookupSpan<'span>,
{
    tracing_subscriber::fmt::layer()
        .with_timer(tracing_subscriber::fmt::time::SystemTime)
        .with_target(false)
        .compact()
}

pub fn init_compact_tracing(env_filter: EnvFilter) {
    static TRACING_INIT: Once = Once::new();
    TRACING_INIT.call_once(move || {
        let _ = tracing_subscriber::registry()
            .with(env_filter)
            .with(compact_fmt_layer())
            .try_init();
    });
}

pub fn init_compact_tracing_default(default_directive: &str) {
    init_compact_tracing(env_filter_from_default_env(default_directive));
}
