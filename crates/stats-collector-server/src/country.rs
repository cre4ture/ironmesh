//! Server-side country-code derivation (doc Section 4.2).
//!
//! Per the design, the *only* location signal ever kept is a coarse ISO-3166-1 alpha-2 country
//! code, and it is derived **server-side from the request's source IP** — never self-reported by
//! the node. Crucially, the raw source IP is used only transiently to resolve the country and is
//! then discarded: it is never persisted, logged, or forwarded (Section 2.6 / 4.2).
//!
//! This crate ships only a [`NoopCountryResolver`] (always `None`), so no GeoIP database or extra
//! dependency is pulled in here. A production deployment plugs in a real resolver (e.g. backed by a
//! MaxMind/DB-IP database) via [`crate::StatsCollectorAppState::with_country_resolver`] without any
//! other code change — the ingestion path already calls the trait and stores whatever it returns.

use std::net::IpAddr;

/// Resolves a coarse country code from a request's source IP. Implementations MUST NOT retain,
/// log, or forward the IP itself — only the returned country code may leave the call.
pub trait CountryResolver: Send + Sync {
    /// Returns an ISO-3166-1 alpha-2 country code (e.g. `"DE"`), or `None` when the country is
    /// unknown / cannot be determined.
    fn resolve(&self, source_ip: IpAddr) -> Option<String>;
}

/// Default resolver: always `None`. Keeps the collector free of any GeoIP dependency while leaving
/// the `country_code` column in place as a seam (doc Section 4.2).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopCountryResolver;

impl CountryResolver for NoopCountryResolver {
    fn resolve(&self, _source_ip: IpAddr) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_resolver_never_resolves_a_country() {
        let resolver = NoopCountryResolver;
        assert_eq!(resolver.resolve("203.0.113.7".parse().unwrap()), None);
        assert_eq!(resolver.resolve("::1".parse().unwrap()), None);
    }
}
