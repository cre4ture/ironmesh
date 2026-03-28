use std::ops::{Deref, DerefMut};
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tokio::time::Instant as TokioInstant;
use tracing::warn;

#[derive(Clone, Copy, Debug)]
pub struct TracedRwLockConfig {
    wait_log_after: Duration,
    wait_log_every: Duration,
    hold_log_after: Duration,
}

impl TracedRwLockConfig {
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TracedRwLockMode {
    Read,
    Write,
}

impl TracedRwLockMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

#[derive(Clone, Copy)]
struct TracedRwLockOwner {
    owner_id: u64,
    operation: &'static str,
    acquired_at: Instant,
}

#[derive(Default)]
struct TracedRwLockState {
    readers: Vec<TracedRwLockOwner>,
    writer: Option<TracedRwLockOwner>,
}

#[derive(Clone, Copy)]
struct BlockingOwnerSnapshot {
    mode: TracedRwLockMode,
    operation: &'static str,
    observed_hold_ms: u128,
    owner_count: usize,
}

pub struct TracedRwLock<T> {
    name: &'static str,
    inner: RwLock<T>,
    state: StdMutex<TracedRwLockState>,
    next_owner_id: AtomicU64,
    config: TracedRwLockConfig,
}

pub struct TracedRwLockReadGuard<'a, T> {
    lock_name: &'static str,
    owner_id: u64,
    operation: &'static str,
    waited_ms: u128,
    acquired_at: Instant,
    state: &'a StdMutex<TracedRwLockState>,
    hold_log_after: Duration,
    guard: RwLockReadGuard<'a, T>,
}

pub struct TracedRwLockWriteGuard<'a, T> {
    lock_name: &'static str,
    owner_id: u64,
    operation: &'static str,
    waited_ms: u128,
    acquired_at: Instant,
    state: &'a StdMutex<TracedRwLockState>,
    hold_log_after: Duration,
    guard: RwLockWriteGuard<'a, T>,
}

impl<T> TracedRwLock<T> {
    pub fn new(name: &'static str, value: T, config: TracedRwLockConfig) -> Self {
        Self {
            name,
            inner: RwLock::new(value),
            state: StdMutex::new(TracedRwLockState::default()),
            next_owner_id: AtomicU64::new(1),
            config: TracedRwLockConfig {
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

    pub async fn read(&self, operation: &'static str) -> TracedRwLockReadGuard<'_, T> {
        let wait_started_at = Instant::now();
        let mut wait_logged = false;
        let lock_future = self.inner.read();
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
                    self.log_wait(TracedRwLockMode::Read, operation, wait_started_at.elapsed().as_millis());
                    wait_timer
                        .as_mut()
                        .reset(TokioInstant::now() + self.config.wait_log_every);
                }
            }
        };

        let waited_ms = wait_started_at.elapsed().as_millis();
        if !wait_logged && waited_ms >= self.config.wait_log_after.as_millis() {
            self.log_wait(TracedRwLockMode::Read, operation, waited_ms);
        }

        let owner_id = self.next_owner_id.fetch_add(1, Ordering::Relaxed);
        let acquired_at = Instant::now();
        {
            let mut state = self.state.lock().unwrap();
            state.readers.push(TracedRwLockOwner {
                owner_id,
                operation,
                acquired_at,
            });
        }

        TracedRwLockReadGuard {
            lock_name: self.name,
            owner_id,
            operation,
            waited_ms,
            acquired_at,
            state: &self.state,
            hold_log_after: self.config.hold_log_after,
            guard,
        }
    }

    pub async fn write(&self, operation: &'static str) -> TracedRwLockWriteGuard<'_, T> {
        let wait_started_at = Instant::now();
        let mut wait_logged = false;
        let lock_future = self.inner.write();
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
                    self.log_wait(TracedRwLockMode::Write, operation, wait_started_at.elapsed().as_millis());
                    wait_timer
                        .as_mut()
                        .reset(TokioInstant::now() + self.config.wait_log_every);
                }
            }
        };

        let waited_ms = wait_started_at.elapsed().as_millis();
        if !wait_logged && waited_ms >= self.config.wait_log_after.as_millis() {
            self.log_wait(TracedRwLockMode::Write, operation, waited_ms);
        }

        let owner_id = self.next_owner_id.fetch_add(1, Ordering::Relaxed);
        let acquired_at = Instant::now();
        {
            let mut state = self.state.lock().unwrap();
            state.writer = Some(TracedRwLockOwner {
                owner_id,
                operation,
                acquired_at,
            });
        }

        TracedRwLockWriteGuard {
            lock_name: self.name,
            owner_id,
            operation,
            waited_ms,
            acquired_at,
            state: &self.state,
            hold_log_after: self.config.hold_log_after,
            guard,
        }
    }

    fn blocking_owner_snapshot(&self) -> Option<BlockingOwnerSnapshot> {
        let state = self.state.lock().unwrap();
        if let Some(writer) = state.writer {
            return Some(BlockingOwnerSnapshot {
                mode: TracedRwLockMode::Write,
                operation: writer.operation,
                observed_hold_ms: writer.acquired_at.elapsed().as_millis(),
                owner_count: 1,
            });
        }

        let oldest_reader = state
            .readers
            .iter()
            .min_by_key(|owner| owner.acquired_at)
            .copied()?;
        Some(BlockingOwnerSnapshot {
            mode: TracedRwLockMode::Read,
            operation: oldest_reader.operation,
            observed_hold_ms: oldest_reader.acquired_at.elapsed().as_millis(),
            owner_count: state.readers.len(),
        })
    }

    fn log_wait(&self, mode: TracedRwLockMode, operation: &'static str, waited_ms: u128) {
        if let Some(blocking_owner) = self.blocking_owner_snapshot() {
            warn!(
                rwlock = self.name,
                mode = mode.as_str(),
                operation,
                waited_ms,
                blocking_mode = blocking_owner.mode.as_str(),
                blocking_operation = blocking_owner.operation,
                blocking_owner_count = blocking_owner.owner_count,
                blocking_observed_hold_ms = blocking_owner.observed_hold_ms,
                "slow rwlock wait"
            );
        } else {
            warn!(
                rwlock = self.name,
                mode = mode.as_str(),
                operation,
                waited_ms,
                "slow rwlock wait"
            );
        }
    }
}

impl<T> TracedRwLockReadGuard<'_, T> {
    pub fn waited_ms(&self) -> u128 {
        self.waited_ms
    }
}

impl<T> Deref for TracedRwLockReadGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> Drop for TracedRwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        let hold_ms = self.acquired_at.elapsed().as_millis();
        {
            let mut state = self.state.lock().unwrap();
            if let Some(index) = state
                .readers
                .iter()
                .position(|owner| owner.owner_id == self.owner_id)
            {
                state.readers.swap_remove(index);
            }
        }

        if hold_ms >= self.hold_log_after.as_millis() {
            warn!(
                rwlock = self.lock_name,
                mode = TracedRwLockMode::Read.as_str(),
                operation = self.operation,
                waited_ms = self.waited_ms,
                hold_ms,
                "slow rwlock hold"
            );
        }
    }
}

impl<T> TracedRwLockWriteGuard<'_, T> {
    pub fn waited_ms(&self) -> u128 {
        self.waited_ms
    }
}

impl<T> Deref for TracedRwLockWriteGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.guard
    }
}

impl<T> DerefMut for TracedRwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.guard
    }
}

impl<T> Drop for TracedRwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        let hold_ms = self.acquired_at.elapsed().as_millis();
        {
            let mut state = self.state.lock().unwrap();
            if state
                .writer
                .as_ref()
                .is_some_and(|owner| owner.owner_id == self.owner_id)
            {
                state.writer = None;
            }
        }

        if hold_ms >= self.hold_log_after.as_millis() {
            warn!(
                rwlock = self.lock_name,
                mode = TracedRwLockMode::Write.as_str(),
                operation = self.operation,
                waited_ms = self.waited_ms,
                hold_ms,
                "slow rwlock hold"
            );
        }
    }
}
