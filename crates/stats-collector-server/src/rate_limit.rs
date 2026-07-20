//! A small in-memory, sliding-window rate limiter.
//!
//! Per `docs/server-node-hardware-reliability-telemetry-strategy.md` Section 5.2, this ingestion
//! endpoint deliberately has no per-node identity/auth, so abuse protection is via rate limiting
//! per source IP and per `telemetry_subject_id` instead. A single-process, in-memory limiter is
//! sufficient for this slice (no distributed rate limiting is required).

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A sliding-window request counter keyed by an arbitrary string (source IP, or
/// `telemetry_subject_id`).
pub struct SlidingWindowLimiter {
    windows: Mutex<HashMap<String, VecDeque<Instant>>>,
    max_requests: u32,
    window: Duration,
}

impl SlidingWindowLimiter {
    pub fn new(max_requests: u32, window: Duration) -> Self {
        Self {
            windows: Mutex::new(HashMap::new()),
            max_requests,
            window,
        }
    }

    /// Checks whether `key` is currently within its rate limit, and if so, records this attempt.
    ///
    /// Returns `true` if the request is allowed, `false` if the caller has exceeded
    /// `max_requests` within the trailing `window`. The check-and-record happens under a single
    /// lock acquisition, so concurrent requests for the same key cannot race past the limit.
    pub fn check_and_record(&self, key: &str) -> bool {
        let now = Instant::now();
        let mut windows = self
            .windows
            .lock()
            .expect("rate limiter mutex should not be poisoned");
        let entry = windows.entry(key.to_string()).or_default();
        Self::prune(entry, now, self.window);

        if entry.len() as u32 >= self.max_requests {
            false
        } else {
            entry.push_back(now);
            true
        }
    }

    fn prune(entry: &mut VecDeque<Instant>, now: Instant, window: Duration) {
        while let Some(&oldest) = entry.front() {
            if now.duration_since(oldest) > window {
                entry.pop_front();
            } else {
                break;
            }
        }
    }

    /// Drops any tracked keys that have no requests left in the current window. Intended to be
    /// called periodically (e.g. from a background task) so that one-off callers that never
    /// return don't accumulate in memory forever.
    pub fn cleanup_stale_entries(&self) {
        let now = Instant::now();
        let mut windows = self
            .windows
            .lock()
            .expect("rate limiter mutex should not be poisoned");
        windows.retain(|_, entry| {
            Self::prune(entry, now, self.window);
            !entry.is_empty()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_limit_then_denies() {
        let limiter = SlidingWindowLimiter::new(3, Duration::from_secs(60));
        assert!(limiter.check_and_record("a"));
        assert!(limiter.check_and_record("a"));
        assert!(limiter.check_and_record("a"));
        assert!(!limiter.check_and_record("a"));
    }

    #[test]
    fn tracks_keys_independently() {
        let limiter = SlidingWindowLimiter::new(1, Duration::from_secs(60));
        assert!(limiter.check_and_record("a"));
        assert!(limiter.check_and_record("b"));
        assert!(!limiter.check_and_record("a"));
        assert!(!limiter.check_and_record("b"));
    }

    #[test]
    fn cleanup_drops_only_empty_entries() {
        let limiter = SlidingWindowLimiter::new(5, Duration::from_millis(1));
        assert!(limiter.check_and_record("a"));
        std::thread::sleep(Duration::from_millis(5));
        limiter.cleanup_stale_entries();
        let windows = limiter.windows.lock().expect("lock should succeed");
        assert!(!windows.contains_key("a"));
    }
}
