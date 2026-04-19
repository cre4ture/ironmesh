use crate::{
    DesktopStatusDocument, RemoteStatusUpdate, StatusFacet, StatusSnapshot, build_status_document,
    poll_remote_status, sleep_with_stop, starting_snapshot, write_status_document,
};
use anyhow::{Context, Result, anyhow};
use client_sdk::IronMeshClient;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct DesktopStatusPublisherOptions {
    pub profile_label: String,
    pub root_dir: PathBuf,
    pub connection_target: String,
    pub status_file: PathBuf,
}

pub struct DesktopStatusPublisher {
    profile_label: String,
    root_dir: PathBuf,
    connection_target: String,
    status_file: PathBuf,
    snapshot: Mutex<StatusSnapshot>,
}

impl DesktopStatusPublisher {
    pub fn new(options: &DesktopStatusPublisherOptions) -> Result<Self> {
        let publisher = Self {
            profile_label: options.profile_label.clone(),
            root_dir: options.root_dir.clone(),
            connection_target: options.connection_target.clone(),
            status_file: options.status_file.clone(),
            snapshot: Mutex::new(starting_snapshot(
                &options.root_dir,
                &options.connection_target,
            )),
        };
        publisher.persist()?;
        Ok(publisher)
    }

    pub fn update_connection(&self, facet: StatusFacet) -> Result<()> {
        let mut snapshot = self.lock_snapshot()?;
        snapshot.connection = facet;
        self.persist_locked(&snapshot)
    }

    pub fn update_sync(&self, facet: StatusFacet) -> Result<()> {
        let mut snapshot = self.lock_snapshot()?;
        snapshot.sync = facet;
        self.persist_locked(&snapshot)
    }

    pub fn update_replication(&self, facet: StatusFacet) -> Result<()> {
        let mut snapshot = self.lock_snapshot()?;
        snapshot.replication = facet;
        self.persist_locked(&snapshot)
    }

    pub fn update_remote(&self, update: &RemoteStatusUpdate) -> Result<()> {
        let mut snapshot = self.lock_snapshot()?;
        snapshot.connection = update.connection.clone();
        snapshot.replication = update.replication.clone();
        self.persist_locked(&snapshot)
    }

    pub fn update_remote_error(&self, error: &anyhow::Error) -> Result<()> {
        let mut snapshot = self.lock_snapshot()?;
        snapshot.connection = StatusFacet::new(
            "error",
            "Connection unavailable",
            format!("{error:#}"),
            "network-error-symbolic",
        );
        snapshot.replication = StatusFacet::new(
            "unknown",
            "Replication unavailable",
            "Waiting for a successful server connection",
            "dialog-question-symbolic",
        );
        self.persist_locked(&snapshot)
    }

    pub fn current_document(&self) -> Result<DesktopStatusDocument> {
        let snapshot = self.lock_snapshot()?.clone();
        Ok(build_status_document(
            self.profile_label.clone(),
            &self.root_dir,
            self.connection_target.clone(),
            &snapshot,
        ))
    }

    pub fn persist(&self) -> Result<()> {
        let snapshot = self.lock_snapshot()?.clone();
        self.persist_locked(&snapshot)
    }

    fn lock_snapshot(&self) -> Result<std::sync::MutexGuard<'_, StatusSnapshot>> {
        self.snapshot
            .lock()
            .map_err(|_| anyhow!("desktop status snapshot lock poisoned"))
    }

    fn persist_locked(&self, snapshot: &StatusSnapshot) -> Result<()> {
        let document = build_status_document(
            self.profile_label.clone(),
            &self.root_dir,
            self.connection_target.clone(),
            snapshot,
        );
        write_status_document(&self.status_file, &document)
    }
}

pub fn spawn_remote_status_thread(
    running: Arc<AtomicBool>,
    publisher: Arc<DesktopStatusPublisher>,
    client: IronMeshClient,
    remote_status_poll_interval_ms: u64,
    thread_name: impl Into<String>,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name(thread_name.into())
        .spawn(move || {
            let poll_interval = Duration::from_millis(remote_status_poll_interval_ms.max(1_000));

            while running.load(Ordering::SeqCst) {
                match poll_remote_status(&client) {
                    Ok(update) => {
                        if let Err(error) = publisher.update_remote(&update) {
                            tracing::warn!(
                                "desktop-status: failed to persist remote status: {error:#}"
                            );
                        }
                    }
                    Err(error) => {
                        if let Err(persist_error) = publisher.update_remote_error(&error) {
                            tracing::warn!(
                                "desktop-status: failed to persist remote error: {persist_error:#}"
                            );
                        }
                    }
                }

                sleep_with_stop(&running, poll_interval);
            }
        })
        .context("failed to spawn desktop status remote thread")
}
