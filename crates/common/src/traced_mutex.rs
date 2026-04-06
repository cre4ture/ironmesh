use std::ops::{Deref, DerefMut};
use std::sync::Mutex as StdMutex;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, MutexGuard};
use tokio::time::Instant as TokioInstant;
use tracing::warn;

#[derive(Clone, Copy, Debug)]
pub struct TracedMutexConfig {
    wait_log_after: Duration,
    wait_log_every: Duration,
    hold_log_after: Duration,
}

impl TracedMutexConfig {
    pub const fn new(
        wait_log_after: Duration,
        wait_log_every: Duration,
        hold_log_after: Duration,
    ) -> Self {
        Self {
            wait_log_after,
            wait_log_every,
            hold_log_after,
        }
    }
}

#[derive(Clone, Copy)]
struct TracedMutexOwner {
    operation: &'static str,
    acquired_at: Instant,
}

pub struct TracedMutex<T> {
    name: &'static str,
    inner: Mutex<T>,
    owner: StdMutex<Option<TracedMutexOwner>>,
    config: TracedMutexConfig,
}

pub struct TracedMutexGuard<'a, T> {
    mutex_name: &'static str,
    operation: &'static str,
    waited_ms: u128,
    acquired_at: Instant,
    owner: &'a StdMutex<Option<TracedMutexOwner>>,
    hold_log_after: Duration,
    guard: MutexGuard<'a, T>,
}

impl<T> TracedMutex<T> {
    pub fn new(name: &'static str, value: T, config: TracedMutexConfig) -> Self {
        Self {
            name,
            inner: Mutex::new(value),
            owner: StdMutex::new(None),
            config: TracedMutexConfig {
                wait_log_after: config.wait_log_after,
                wait_log_every: if config.wait_log_every.is_zero() {
                    Duration::from_secs(1)
                } else {
                    config.wait_log_every
                },
                hold_log_after: config.hold_log_after,
            },
        }
    }

    pub async fn lock(&self, operation: &'static str) -> TracedMutexGuard<'_, T> {
        let wait_started_at = Instant::now();
        let mut wait_logged = false;
        let lock_future = self.inner.lock();
        tokio::pin!(lock_future);
        let wait_timer = tokio::time::sleep(self.config.wait_log_after);
        tokio::pin!(wait_timer);

        let guard = loop {
            tokio::select! {
                guard = &mut lock_future => {
                    break guard;
                }
                _ = &mut wait_timer => {
                    wait_logged = true;
                    self.log_wait(operation, wait_started_at.elapsed().as_millis());
                    wait_timer
                        .as_mut()
                        .reset(TokioInstant::now() + self.config.wait_log_every);
                }
            }
        };

        let waited_ms = wait_started_at.elapsed().as_millis();
        if !wait_logged && waited_ms >= self.config.wait_log_after.as_millis() {
            self.log_wait(operation, waited_ms);
        }

        let acquired_at = Instant::now();
        {
            let mut owner = self.owner.lock().unwrap();
            *owner = Some(TracedMutexOwner {
                operation,
                acquired_at,
            });
        }

        TracedMutexGuard {
            mutex_name: self.name,
            operation,
            waited_ms,
            acquired_at,
            owner: &self.owner,
            hold_log_after: self.config.hold_log_after,
            guard,
        }
    }

    fn log_wait(&self, operation: &'static str, waited_ms: u128) {
        let blocking_owner = { *self.owner.lock().unwrap() };
        if let Some(owner) = blocking_owner {
            warn!(
                mutex = self.name,
                operation,
                waited_ms,
                blocking_operation = owner.operation,
                blocking_observed_hold_ms = owner.acquired_at.elapsed().as_millis(),
                "slow mutex lock wait"
            );
        } else {
            warn!(
                mutex = self.name,
                operation, waited_ms, "slow mutex lock wait"
            );
        }
    }
}

impl<T> TracedMutexGuard<'_, T> {
    pub fn waited_ms(&self) -> u128 {
        self.waited_ms
    }
}

impl<T> Deref for TracedMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for TracedMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<T> Drop for TracedMutexGuard<'_, T> {
    fn drop(&mut self) {
        let hold_ms = self.acquired_at.elapsed().as_millis();
        {
            let mut owner = self.owner.lock().unwrap();
            if owner.as_ref().is_some_and(|current| {
                current.operation == self.operation && current.acquired_at == self.acquired_at
            }) {
                *owner = None;
            }
        }

        if hold_ms >= self.hold_log_after.as_millis() {
            warn!(
                mutex = self.mutex_name,
                operation = self.operation,
                waited_ms = self.waited_ms,
                hold_ms,
                "slow mutex lock hold"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn log_wait_without_owner_is_safe() {
        let mutex = TracedMutex::new(
            "test-mutex",
            1_u32,
            TracedMutexConfig::new(Duration::from_millis(10), Duration::ZERO, Duration::ZERO),
        );

        mutex.log_wait("probe", 25);
    }

    #[tokio::test]
    async fn traced_mutex_tracks_owner_waits_and_mutations() {
        let mutex = Arc::new(TracedMutex::new(
            "test-mutex",
            1_u32,
            TracedMutexConfig::new(
                Duration::from_millis(1),
                Duration::ZERO,
                Duration::from_millis(1),
            ),
        ));

        assert_eq!(mutex.config.wait_log_every, Duration::from_secs(1));

        let mut first_guard = mutex.lock("first").await;
        assert_eq!(first_guard.waited_ms(), 0);
        assert_eq!(*first_guard, 1);
        *first_guard = 2;
        assert_eq!(
            mutex
                .owner
                .lock()
                .unwrap()
                .as_ref()
                .map(|owner| owner.operation),
            Some("first")
        );

        let waiter_mutex = Arc::clone(&mutex);
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let waiter = tokio::spawn(async move {
            let mut second_guard = waiter_mutex.lock("second").await;
            *second_guard += 1;
            let waited_ms = second_guard.waited_ms();
            release_rx.await.unwrap();
            waited_ms
        });

        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop(first_guard);

        tokio::task::yield_now().await;
        assert_eq!(
            mutex
                .owner
                .lock()
                .unwrap()
                .as_ref()
                .map(|owner| owner.operation),
            Some("second")
        );

        release_tx.send(()).unwrap();
        let waited_ms = waiter.await.unwrap();
        assert!(waited_ms >= 1);

        assert!(mutex.owner.lock().unwrap().is_none());

        let final_guard = mutex.lock("final").await;
        assert_eq!(final_guard.waited_ms(), 0);
        assert_eq!(*final_guard, 3);
    }
}
