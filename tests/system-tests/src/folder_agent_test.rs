#![cfg(test)]

use crate::framework::{ChildGuard, binary_path, fresh_data_dir, start_server, stop_server};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use client_sdk::IronMeshClient;
use client_sdk::normalize_server_base_url;
use reqwest::StatusCode;
use rusqlite::Connection;
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::{sleep, timeout};

async fn start_folder_agent(
    server_base_url: &str,
    root_dir: &Path,
    prefix: Option<&str>,
    remote_refresh_interval_ms: u64,
    local_scan_interval_ms: u64,
    no_watch_local: bool,
) -> Result<ChildGuard> {
    let agent_bin = binary_path("ironmesh-folder-agent")?;

    let mut command = Command::new(agent_bin);
    command
        .arg("--root-dir")
        .arg(root_dir)
        .arg("--server-base-url")
        .arg(server_base_url)
        .args(
            prefix
                .map(|value| vec!["--prefix".to_string(), value.to_string()])
                .unwrap_or_default(),
        )
        .arg("--remote-refresh-interval-ms")
        .arg(remote_refresh_interval_ms.to_string())
        .arg("--local-scan-interval-ms")
        .arg(local_scan_interval_ms.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if no_watch_local {
        command.arg("--no-watch-local");
    }

    let mut child = command
        .spawn()
        .context("failed to spawn ironmesh-folder-agent")?;

    sleep(Duration::from_millis(300)).await;
    if let Some(status) = child
        .try_wait()
        .context("failed to query folder-agent process state")?
    {
        bail!("ironmesh-folder-agent exited early with status {status}");
    }

    Ok(ChildGuard::new(child))
}

async fn run_folder_agent_once(
    server_base_url: &str,
    root_dir: &Path,
    prefix: Option<&str>,
    remote_refresh_interval_ms: u64,
    local_scan_interval_ms: u64,
    no_watch_local: bool,
) -> Result<()> {
    let agent_bin = binary_path("ironmesh-folder-agent")?;

    let mut command = Command::new(agent_bin);
    command
        .arg("--run-once")
        .arg("--root-dir")
        .arg(root_dir)
        .arg("--server-base-url")
        .arg(server_base_url)
        .args(
            prefix
                .map(|value| vec!["--prefix".to_string(), value.to_string()])
                .unwrap_or_default(),
        )
        .arg("--remote-refresh-interval-ms")
        .arg(remote_refresh_interval_ms.to_string())
        .arg("--local-scan-interval-ms")
        .arg(local_scan_interval_ms.to_string())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if no_watch_local {
        command.arg("--no-watch-local");
    }

    let status = timeout(Duration::from_secs(30), command.status())
        .await
        .context("folder-agent --run-once timed out")?
        .context("failed to execute folder-agent --run-once")?;

    if !status.success() {
        bail!("folder-agent --run-once failed with status {status}");
    }

    Ok(())
}

async fn wait_for_local_file_bytes(path: &Path, expected: &[u8], retries: usize) -> Result<()> {
    for _ in 0..retries {
        if let Ok(bytes) = fs::read(path)
            && bytes.as_slice() == expected
        {
            return Ok(());
        }

        sleep(Duration::from_millis(100)).await;
    }

    bail!(
        "local file {} did not match expected payload",
        path.display()
    )
}

async fn wait_for_local_dir(path: &Path, retries: usize) -> Result<()> {
    for _ in 0..retries {
        if path.is_dir() {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }

    bail!("local directory did not materialize: {}", path.display())
}

async fn wait_for_local_absence(path: &Path, retries: usize) -> Result<()> {
    for _ in 0..retries {
        if !path.exists() {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }

    bail!("local path was expected to disappear: {}", path.display())
}

async fn wait_for_remote_file_bytes(
    sdk: &IronMeshClient,
    key: &str,
    expected: &[u8],
    retries: usize,
) -> Result<()> {
    for _ in 0..retries {
        if let Ok(bytes) = sdk.get(key).await
            && bytes.as_ref() == expected
        {
            return Ok(());
        }

        sleep(Duration::from_millis(100)).await;
    }

    bail!("remote file {key} did not match expected payload")
}

async fn wait_for_remote_directory(
    sdk: &IronMeshClient,
    dir_path: &str,
    retries: usize,
) -> Result<()> {
    let normalized = dir_path.trim_matches('/');
    for _ in 0..retries {
        if let Ok(index) = sdk.store_index(None, 64, None).await {
            let found = index
                .entries
                .iter()
                .any(|entry| entry.path.trim_matches('/') == normalized);
            if found {
                return Ok(());
            }
        }

        sleep(Duration::from_millis(100)).await;
    }

    bail!("remote directory marker not observed for {normalized}")
}

async fn wait_for_remote_file_absence(
    sdk: &IronMeshClient,
    key: &str,
    retries: usize,
) -> Result<()> {
    for _ in 0..retries {
        let get_missing = sdk.get(key).await.is_err();
        if let Ok(index) = sdk.store_index(None, 64, None).await {
            let index_missing = !index.entries.iter().any(|entry| entry.path == key);
            if get_missing && index_missing {
                return Ok(());
            }
        }

        sleep(Duration::from_millis(100)).await;
    }

    bail!("remote file {key} was expected to be deleted")
}

async fn delete_remote_key_by_query(base_url: &str, key: &str) -> Result<()> {
    let http = reqwest::Client::new();
    let response = http
        .post(format!("{}/store/delete", base_url.trim_end_matches('/')))
        .query(&[("key", key)])
        .send()
        .await
        .with_context(|| format!("failed to request remote delete for key={key}"))?;

    if response.status() != StatusCode::CREATED {
        bail!(
            "remote delete for key={} returned unexpected status {}",
            key,
            response.status()
        );
    }

    Ok(())
}

async fn stop_folder_agent(agent: &mut ChildGuard) {
    agent.stop().await.ok();
}

fn baseline_db_path(
    root_dir: &Path,
    server_base_url: &str,
    prefix: Option<&str>,
) -> Result<PathBuf> {
    let mut hasher = DefaultHasher::new();
    root_dir.to_string_lossy().hash(&mut hasher);
    prefix.unwrap_or_default().hash(&mut hasher);
    normalize_server_base_url(server_base_url)?.hash(&mut hasher);
    let fingerprint = hasher.finish();

    let mut path = std::env::temp_dir();
    path.push("ironmesh-folder-agent");
    path.push(format!("baseline-{fingerprint:016x}.sqlite"));
    Ok(path)
}

fn delete_baseline_entry(root_dir: &Path, server_base_url: &str, path: &str) -> Result<()> {
    let baseline_path = baseline_db_path(root_dir, server_base_url, None)?;
    let connection = Connection::open(&baseline_path)
        .with_context(|| format!("failed to open sqlite baseline {}", baseline_path.display()))?;
    connection
        .execute("DELETE FROM baseline_entries WHERE path = ?1", [path])
        .with_context(|| format!("failed to delete sqlite baseline row for {path}"))?;
    Ok(())
}

fn startup_conflicts(root_dir: &Path, server_base_url: &str) -> Result<Vec<(String, String)>> {
    let baseline_path = baseline_db_path(root_dir, server_base_url, None)?;
    let connection = Connection::open(&baseline_path)
        .with_context(|| format!("failed to open sqlite baseline {}", baseline_path.display()))?;
    let mut statement = connection
        .prepare("SELECT path, reason FROM conflicts")
        .context("failed to query sqlite conflicts rows")?;
    let rows = statement
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .context("failed to decode sqlite conflicts rows")?;

    let mut values = Vec::new();
    for row in rows {
        values.push(row.context("failed to decode sqlite conflict row")?);
    }
    Ok(values)
}

fn baseline_integrity_check(root_dir: &Path, server_base_url: &str) -> Result<String> {
    let baseline_path = baseline_db_path(root_dir, server_base_url, None)?;
    let connection = Connection::open(&baseline_path)
        .with_context(|| format!("failed to open sqlite baseline {}", baseline_path.display()))?;
    connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .context("failed to execute sqlite integrity_check")
}

async fn wait_for_startup_conflict_reason(
    root_dir: &Path,
    server_base_url: &str,
    path: &str,
    reason: &str,
    retries: usize,
) -> Result<()> {
    for _ in 0..retries {
        if let Ok(conflicts) = startup_conflicts(root_dir, server_base_url)
            && conflicts.iter().any(|(conflict_path, conflict_reason)| {
                conflict_path == path && conflict_reason == reason
            })
        {
            return Ok(());
        }
        sleep(Duration::from_millis(100)).await;
    }

    bail!("startup conflict not found for path={path} reason={reason}")
}

async fn wait_for_remote_prefix_entry_count(
    sdk: &IronMeshClient,
    prefix: &str,
    expected_min: usize,
    retries: usize,
) -> Result<()> {
    let normalized_prefix = prefix.trim_matches('/');
    for _ in 0..retries {
        if let Ok(index) = sdk.store_index(None, 64, None).await {
            let observed = index
                .entries
                .iter()
                .filter(|entry| {
                    let path = entry.path.trim_matches('/');
                    path.starts_with(normalized_prefix)
                })
                .count();
            if observed >= expected_min {
                return Ok(());
            }
        }
        sleep(Duration::from_millis(100)).await;
    }

    bail!("remote prefix {normalized_prefix} did not reach at least {expected_min} entries")
}

#[tokio::test]
async fn folder_agent_bootstrap_materializes_remote_tree() -> Result<()> {
    let bind = "127.0.0.1:19410";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-bootstrap-root");

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        sdk.put_large_aware(
            "bootstrap/docs/readme.txt",
            Bytes::from_static(b"bootstrap-readme"),
        )
        .await?;
        sdk.put_large_aware(
            "bootstrap/docs/nested/note.txt",
            Bytes::from_static(b"bootstrap-note"),
        )
        .await?;
        sdk.put("bootstrap/empty/", Bytes::new()).await?;

        let mut agent = start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        let scenario = async {
            wait_for_local_file_bytes(
                &local_root.join("bootstrap/docs/readme.txt"),
                b"bootstrap-readme",
                200,
            )
            .await?;
            wait_for_local_file_bytes(
                &local_root.join("bootstrap/docs/nested/note.txt"),
                b"bootstrap-note",
                200,
            )
            .await?;
            wait_for_local_dir(&local_root.join("bootstrap/empty"), 200).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut agent).await;
        scenario
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_uploads_local_files_and_empty_directory_markers() -> Result<()> {
    let bind = "127.0.0.1:19411";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-upload-root");

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        let mut agent = start_folder_agent(&base_url, &local_root, None, 250, 250, true).await?;
        let scenario = async {
            fs::create_dir_all(local_root.join("upload/empty-dir"))?;
            fs::create_dir_all(local_root.join("upload/nested"))?;
            fs::write(local_root.join("upload/data.txt"), b"upload-data")?;
            fs::write(local_root.join("upload/nested/file.bin"), b"upload-nested")?;

            wait_for_remote_file_bytes(&sdk, "upload/data.txt", b"upload-data", 220).await?;
            wait_for_remote_file_bytes(&sdk, "upload/nested/file.bin", b"upload-nested", 220)
                .await?;
            wait_for_remote_directory(&sdk, "upload/empty-dir", 220).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut agent).await;
        scenario
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_applies_remote_add_update_delete_without_restart() -> Result<()> {
    let bind = "127.0.0.1:19412";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-remote-refresh-root");

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        sdk.put_large_aware("live/item.txt", Bytes::from_static(b"version-one"))
            .await?;

        let mut agent = start_folder_agent(&base_url, &local_root, None, 250, 2_000, true).await?;
        let scenario = async {
            let item_path = local_root.join("live/item.txt");
            let added_path = local_root.join("live/new.txt");

            wait_for_local_file_bytes(&item_path, b"version-one", 220).await?;

            sdk.put_large_aware("live/item.txt", Bytes::from_static(b"version-two-extended"))
                .await?;
            wait_for_local_file_bytes(&item_path, b"version-two-extended", 220).await?;

            sdk.put_large_aware("live/new.txt", Bytes::from_static(b"remote-added"))
                .await?;
            wait_for_local_file_bytes(&added_path, b"remote-added", 220).await?;

            delete_remote_key_by_query(&base_url, "live/new.txt").await?;
            wait_for_local_absence(&added_path, 220).await?;

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut agent).await;
        scenario
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_run_once_bootstraps_and_exits() -> Result<()> {
    let bind = "127.0.0.1:19413";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-run-once-root");

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        sdk.put_large_aware("once/seed.txt", Bytes::from_static(b"seed-remote"))
            .await?;

        fs::create_dir_all(local_root.join("once"))?;
        fs::write(local_root.join("once/local.txt"), b"local-before-run")?;

        run_folder_agent_once(&base_url, &local_root, None, 250, 250, true).await?;

        wait_for_local_file_bytes(&local_root.join("once/seed.txt"), b"seed-remote", 120).await?;
        wait_for_local_file_bytes(&local_root.join("once/local.txt"), b"local-before-run", 120)
            .await?;

        Ok::<(), anyhow::Error>(())
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_propagates_local_file_deletions_to_remote() -> Result<()> {
    let bind = "127.0.0.1:19414";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-delete-root");

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        sdk.put_large_aware("delete-me/target.txt", Bytes::from_static(b"to-delete"))
            .await?;

        let mut agent = start_folder_agent(&base_url, &local_root, None, 250, 250, true).await?;
        let scenario = async {
            let local_file = local_root.join("delete-me/target.txt");
            wait_for_local_file_bytes(&local_file, b"to-delete", 220).await?;

            fs::remove_file(&local_file)
                .with_context(|| format!("failed to remove local file {}", local_file.display()))?;

            wait_for_remote_file_absence(&sdk, "delete-me/target.txt", 220).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut agent).await;
        scenario
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_detects_remote_add_and_modify_done_while_stopped_after_restart() -> Result<()>
{
    let bind = "127.0.0.1:19415";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-restart-remote-change-root");

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        sdk.put_large_aware(
            "restart-detect/existing.txt",
            Bytes::from_static(b"before-stop-version"),
        )
        .await?;

        let mut first_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        wait_for_local_file_bytes(
            &local_root.join("restart-detect/existing.txt"),
            b"before-stop-version",
            220,
        )
        .await?;
        stop_folder_agent(&mut first_run).await;

        sdk.put_large_aware(
            "restart-detect/existing.txt",
            Bytes::from_static(b"after-restart-modified"),
        )
        .await?;
        sdk.put_large_aware(
            "restart-detect/offline/new.txt",
            Bytes::from_static(b"after-restart-added"),
        )
        .await?;

        let mut second_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        let scenario = async {
            wait_for_local_file_bytes(
                &local_root.join("restart-detect/existing.txt"),
                b"after-restart-modified",
                220,
            )
            .await?;
            wait_for_local_file_bytes(
                &local_root.join("restart-detect/offline/new.txt"),
                b"after-restart-added",
                220,
            )
            .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut second_run).await;
        scenario
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_detects_local_add_and_modify_done_while_stopped_after_restart() -> Result<()>
{
    let bind = "127.0.0.1:19416";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-restart-local-change-root");

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        fs::create_dir_all(local_root.join("local-offline")).with_context(|| {
            format!(
                "failed to create local directory {}",
                local_root.join("local-offline").display()
            )
        })?;
        fs::write(local_root.join("local-offline/new1.txt"), b"offline-v1").with_context(|| {
            format!(
                "failed to write local file {}",
                local_root.join("local-offline/new1.txt").display()
            )
        })?;
        let mut first_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        stop_folder_agent(&mut first_run).await;

        fs::create_dir_all(local_root.join("local-offline2")).with_context(|| {
            format!(
                "failed to create local directory {}",
                local_root.join("local-offline2").display()
            )
        })?;
        fs::write(local_root.join("local-offline2/new1.txt"), b"offline-v1").with_context(
            || {
                format!(
                    "failed to write local file {}",
                    local_root.join("local-offline2/new1.txt").display()
                )
            },
        )?;

        fs::write(local_root.join("local-offline/new2.txt"), b"offline-v1").with_context(|| {
            format!(
                "failed to write local file {}",
                local_root.join("local-offline/new2.txt").display()
            )
        })?;
        fs::write(
            local_root.join("local-offline/new1.txt"),
            b"offline-v2-modified",
        )
        .with_context(|| {
            format!(
                "failed to modify local file {}",
                local_root.join("local-offline/new1.txt").display()
            )
        })?;

        let mut second_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        let scenario = async {
            wait_for_remote_file_bytes(&sdk, "local-offline2/new1.txt", b"offline-v1", 220).await?;
            wait_for_remote_file_bytes(&sdk, "local-offline/new1.txt", b"offline-v2-modified", 220)
                .await?;
            wait_for_remote_file_bytes(&sdk, "local-offline/new2.txt", b"offline-v1", 220).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut second_run).await;
        scenario
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_prefix_scope_maps_local_root_to_selected_remote_subtree() -> Result<()> {
    let bind = "127.0.0.1:19417";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-prefix-scope-root");
    let scope_prefix = "scoped/team-a";

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        sdk.put_large_aware("scoped/team-a/seed.txt", Bytes::from_static(b"scoped-seed"))
            .await?;
        sdk.put_large_aware("outside/keep.txt", Bytes::from_static(b"outside"))
            .await?;

        let mut agent =
            start_folder_agent(&base_url, &local_root, Some(scope_prefix), 2_000, 250, true)
                .await?;
        let scenario = async {
            // Remote scoped content appears directly at local root.
            wait_for_local_file_bytes(&local_root.join("seed.txt"), b"scoped-seed", 220).await?;
            assert!(
                !local_root.join("scoped").exists(),
                "scoped prefix should not be re-created under local root"
            );

            // New local file is uploaded under prefix, not at remote root.
            fs::write(local_root.join("new.txt"), b"local-new-scoped").with_context(|| {
                format!(
                    "failed to write local file {}",
                    local_root.join("new.txt").display()
                )
            })?;
            wait_for_remote_file_bytes(&sdk, "scoped/team-a/new.txt", b"local-new-scoped", 220)
                .await?;
            wait_for_remote_file_absence(&sdk, "new.txt", 80).await?;

            // Local deletion only affects scoped key.
            fs::remove_file(local_root.join("seed.txt")).with_context(|| {
                format!(
                    "failed to remove local file {}",
                    local_root.join("seed.txt").display()
                )
            })?;
            wait_for_remote_file_absence(&sdk, "scoped/team-a/seed.txt", 220).await?;
            wait_for_remote_file_bytes(&sdk, "outside/keep.txt", b"outside", 220).await?;

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut agent).await;
        scenario
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_recovers_local_offline_changes_after_unfriendly_stop() -> Result<()> {
    let bind = "127.0.0.1:19418";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-unfriendly-stop-root");

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        fs::create_dir_all(local_root.join("crash-case")).with_context(|| {
            format!(
                "failed to create local directory {}",
                local_root.join("crash-case").display()
            )
        })?;
        fs::write(local_root.join("crash-case/existing.txt"), b"before-crash").with_context(
            || {
                format!(
                    "failed to write local file {}",
                    local_root.join("crash-case/existing.txt").display()
                )
            },
        )?;

        let mut first_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;

        wait_for_remote_file_bytes(&sdk, "crash-case/existing.txt", b"before-crash", 220).await?;

        // Intentionally kill the process (unfriendly stop simulation).
        stop_folder_agent(&mut first_run).await;

        fs::write(
            local_root.join("crash-case/existing.txt"),
            b"after-crash-modified",
        )
        .with_context(|| {
            format!(
                "failed to modify local file {}",
                local_root.join("crash-case/existing.txt").display()
            )
        })?;
        fs::write(local_root.join("crash-case/new.txt"), b"after-crash-added").with_context(
            || {
                format!(
                    "failed to write local file {}",
                    local_root.join("crash-case/new.txt").display()
                )
            },
        )?;

        let mut second_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        let scenario = async {
            wait_for_remote_file_bytes(
                &sdk,
                "crash-case/existing.txt",
                b"after-crash-modified",
                220,
            )
            .await?;
            wait_for_remote_file_bytes(&sdk, "crash-case/new.txt", b"after-crash-added", 220)
                .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut second_run).await;
        scenario
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_applies_path_level_recovery_when_baseline_row_is_missing() -> Result<()> {
    let bind = "127.0.0.1:19419";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-path-recovery-root");

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        sdk.put_large_aware("path-recovery/a.txt", Bytes::from_static(b"remote-a-v1"))
            .await?;
        sdk.put_large_aware("path-recovery/b.txt", Bytes::from_static(b"remote-b-v1"))
            .await?;
        sdk.put_large_aware("path-recovery/c.txt", Bytes::from_static(b"remote-c-v1"))
            .await?;

        let mut first_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        wait_for_local_file_bytes(&local_root.join("path-recovery/a.txt"), b"remote-a-v1", 220)
            .await?;
        wait_for_local_file_bytes(&local_root.join("path-recovery/b.txt"), b"remote-b-v1", 220)
            .await?;
        wait_for_local_file_bytes(&local_root.join("path-recovery/c.txt"), b"remote-c-v1", 220)
            .await?;
        stop_folder_agent(&mut first_run).await;

        fs::write(local_root.join("path-recovery/a.txt"), b"local-a-v2").with_context(|| {
            format!(
                "failed to write local file {}",
                local_root.join("path-recovery/a.txt").display()
            )
        })?;
        sdk.put_large_aware("path-recovery/c.txt", Bytes::from_static(b"remote-c-v2"))
            .await?;

        // Simulate partial state loss: one baseline row disappears.
        delete_baseline_entry(&local_root, &base_url, "path-recovery/b.txt")?;

        let mut second_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        let scenario = async {
            // Changed local file is preserved and uploaded.
            wait_for_remote_file_bytes(&sdk, "path-recovery/a.txt", b"local-a-v2", 220).await?;
            // Unchanged local file with missing baseline row does not force global recovery.
            wait_for_remote_file_bytes(&sdk, "path-recovery/b.txt", b"remote-b-v1", 220).await?;
            // Remote update still applies on unaffected path.
            wait_for_local_file_bytes(&local_root.join("path-recovery/c.txt"), b"remote-c-v2", 220)
                .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut second_run).await;
        scenario
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_respects_remote_delete_intent_for_unchanged_local_after_restart() -> Result<()>
{
    let bind = "127.0.0.1:19420";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-remote-delete-intent-root");

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        sdk.put_large_aware("delete-intent/target.txt", Bytes::from_static(b"remote-v1"))
            .await?;

        let mut first_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        wait_for_local_file_bytes(
            &local_root.join("delete-intent/target.txt"),
            b"remote-v1",
            220,
        )
        .await?;
        stop_folder_agent(&mut first_run).await;

        delete_remote_key_by_query(&base_url, "delete-intent/target.txt").await?;
        wait_for_remote_file_absence(&sdk, "delete-intent/target.txt", 220).await?;

        let mut second_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        let scenario = async {
            wait_for_remote_file_absence(&sdk, "delete-intent/target.txt", 220).await?;
            wait_for_local_absence(&local_root.join("delete-intent/target.txt"), 220).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut second_run).await;
        scenario
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_records_dual_modify_conflict_when_baseline_row_is_missing() -> Result<()> {
    let bind = "127.0.0.1:19421";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-dual-modify-conflict-root");

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        sdk.put_large_aware("conflict/x.txt", Bytes::from_static(b"remote-v1"))
            .await?;

        let mut first_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        wait_for_local_file_bytes(&local_root.join("conflict/x.txt"), b"remote-v1", 220).await?;
        stop_folder_agent(&mut first_run).await;

        fs::write(local_root.join("conflict/x.txt"), b"local-v2").with_context(|| {
            format!(
                "failed to modify local file {}",
                local_root.join("conflict/x.txt").display()
            )
        })?;
        sdk.put_large_aware("conflict/x.txt", Bytes::from_static(b"remote-v2"))
            .await?;
        delete_baseline_entry(&local_root, &base_url, "conflict/x.txt")?;

        let mut second_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        let scenario = async {
            // Safety policy for this ambiguous case: keep local bytes.
            wait_for_remote_file_bytes(&sdk, "conflict/x.txt", b"local-v2", 220).await?;

            wait_for_startup_conflict_reason(
                &local_root,
                &base_url,
                "conflict/x.txt",
                "dual_modify_missing_baseline",
                120,
            )
            .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut second_run).await;
        scenario
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_records_dual_modify_conflict_when_baseline_row_exists() -> Result<()> {
    let bind = "127.0.0.1:19423";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-dual-modify-conflict-baseline-root");

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        sdk.put_large_aware("conflict2/y.txt", Bytes::from_static(b"remote-v1"))
            .await?;

        let mut first_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        wait_for_local_file_bytes(&local_root.join("conflict2/y.txt"), b"remote-v1", 220).await?;
        stop_folder_agent(&mut first_run).await;

        fs::write(local_root.join("conflict2/y.txt"), b"local-v2").with_context(|| {
            format!(
                "failed to modify local file {}",
                local_root.join("conflict2/y.txt").display()
            )
        })?;
        sdk.put_large_aware("conflict2/y.txt", Bytes::from_static(b"remote-v2"))
            .await?;

        let mut second_run =
            start_folder_agent(&base_url, &local_root, None, 2_000, 250, true).await?;
        let scenario = async {
            // Safety policy: keep local bytes, but record the dual-modify conflict.
            wait_for_remote_file_bytes(&sdk, "conflict2/y.txt", b"local-v2", 220).await?;
            wait_for_startup_conflict_reason(
                &local_root,
                &base_url,
                "conflict2/y.txt",
                "dual_modify_conflict",
                120,
            )
            .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut second_run).await;
        scenario
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_recovers_after_crash_during_active_sync_writes() -> Result<()> {
    let bind = "127.0.0.1:19422";
    let base_url = format!("http://{bind}");
    let local_root = fresh_data_dir("folder-agent-crash-active-write-root");

    let mut server = start_server(bind).await?;
    let sdk = IronMeshClient::new(&base_url);

    let result = async {
        let large_payload = vec![b'x'; 2 * 1024 * 1024];
        fs::create_dir_all(local_root.join("crash-active")).with_context(|| {
            format!(
                "failed to create local directory {}",
                local_root.join("crash-active").display()
            )
        })?;
        fs::write(local_root.join("crash-active/local-a.bin"), &large_payload).with_context(
            || {
                format!(
                    "failed to write local file {}",
                    local_root.join("crash-active/local-a.bin").display()
                )
            },
        )?;
        fs::write(local_root.join("crash-active/local-b.bin"), &large_payload).with_context(
            || {
                format!(
                    "failed to write local file {}",
                    local_root.join("crash-active/local-b.bin").display()
                )
            },
        )?;
        fs::write(local_root.join("crash-active/local-c.bin"), &large_payload).with_context(
            || {
                format!(
                    "failed to write local file {}",
                    local_root.join("crash-active/local-c.bin").display()
                )
            },
        )?;

        sdk.put_large_aware(
            "crash-active/remote-base.txt",
            Bytes::from_static(b"remote-v1"),
        )
        .await?;

        let mut first_run =
            start_folder_agent(&base_url, &local_root, None, 1_500, 100, true).await?;

        // Wait until active sync starts and at least one local upload hits remote.
        wait_for_remote_prefix_entry_count(&sdk, "crash-active/local-", 1, 320).await?;

        // Abrupt process termination during active syncing.
        stop_folder_agent(&mut first_run).await;

        let integrity = baseline_integrity_check(&local_root, &base_url)?;
        assert_eq!(integrity.to_lowercase(), "ok");

        fs::write(
            local_root.join("crash-active/local-a.bin"),
            b"local-a-after-crash",
        )
        .with_context(|| {
            format!(
                "failed to modify local file {}",
                local_root.join("crash-active/local-a.bin").display()
            )
        })?;
        fs::write(
            local_root.join("crash-active/local-new.txt"),
            b"local-new-after-crash",
        )
        .with_context(|| {
            format!(
                "failed to create local file {}",
                local_root.join("crash-active/local-new.txt").display()
            )
        })?;

        sdk.put_large_aware(
            "crash-active/remote-base.txt",
            Bytes::from_static(b"remote-v2-after-crash"),
        )
        .await?;
        sdk.put_large_aware(
            "crash-active/remote-new.txt",
            Bytes::from_static(b"remote-new-after-crash"),
        )
        .await?;

        let mut second_run =
            start_folder_agent(&base_url, &local_root, None, 1_500, 100, true).await?;
        let scenario = async {
            wait_for_remote_file_bytes(
                &sdk,
                "crash-active/local-a.bin",
                b"local-a-after-crash",
                360,
            )
            .await?;
            wait_for_remote_file_bytes(
                &sdk,
                "crash-active/local-new.txt",
                b"local-new-after-crash",
                360,
            )
            .await?;

            wait_for_remote_file_bytes(&sdk, "crash-active/local-b.bin", &large_payload, 360)
                .await?;
            wait_for_remote_file_bytes(&sdk, "crash-active/local-c.bin", &large_payload, 360)
                .await?;

            wait_for_local_file_bytes(
                &local_root.join("crash-active/remote-base.txt"),
                b"remote-v2-after-crash",
                360,
            )
            .await?;
            wait_for_local_file_bytes(
                &local_root.join("crash-active/remote-new.txt"),
                b"remote-new-after-crash",
                360,
            )
            .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut second_run).await;
        scenario
    }
    .await;

    stop_server(&mut server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}
