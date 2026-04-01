#![cfg(test)]

use crate::framework::{
    ChildGuard, EnrolledTestClient, TEST_ADMIN_TOKEN, binary_path, fresh_data_dir,
    issue_bootstrap_bundle_and_enroll_client, lock_test_resources, path_resource_key,
    start_authenticated_server, stop_server,
};
use anyhow::{Context, Result, bail};
use bytes::Bytes;
use client_sdk::IronMeshClient;
use rusqlite::{Connection, OptionalExtension};
use std::fs;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::{sleep, timeout};
use uuid::Uuid;

#[derive(Debug, Clone)]
struct FolderAgentConnection {
    connection_target: String,
    server_base_url: Option<String>,
    bootstrap_path: Option<PathBuf>,
    client_identity_path: Option<PathBuf>,
}

impl FolderAgentConnection {
    fn from_enrolled(enrolled: &EnrolledTestClient) -> Result<Self> {
        Ok(Self {
            connection_target: enrolled.bootstrap.connection_target_label()?,
            server_base_url: None,
            bootstrap_path: Some(enrolled.bootstrap_path.clone()),
            client_identity_path: Some(crate::framework::default_client_identity_path(
                &enrolled.bootstrap_path,
            )),
        })
    }

    fn apply_to_command(&self, command: &mut Command) {
        if let Some(server_base_url) = self.server_base_url.as_deref() {
            command.arg("--server-base-url").arg(server_base_url);
        }
        if let Some(bootstrap_path) = self.bootstrap_path.as_deref() {
            command.arg("--bootstrap-file").arg(bootstrap_path);
        }
        if let Some(client_identity_path) = self.client_identity_path.as_deref() {
            command
                .arg("--client-identity-file")
                .arg(client_identity_path);
        }
    }

    fn target_label(&self) -> &str {
        &self.connection_target
    }
}

struct AuthenticatedFolderAgentFixture {
    server: ChildGuard,
    sdk: IronMeshClient,
    connection: FolderAgentConnection,
}

async fn start_authenticated_folder_agent_fixture(
    bind: &str,
) -> Result<AuthenticatedFolderAgentFixture> {
    let nonce = bind.replace(['.', ':'], "-");
    let data_dir = fresh_data_dir(&format!("folder-agent-auth-server-{nonce}"));
    let client_dir = fresh_data_dir(&format!("folder-agent-auth-client-{nonce}"));
    let node_id = Uuid::new_v4().to_string();
    let server = start_authenticated_server(bind, &data_dir, &node_id, 1).await?;
    let base_url = format!("http://{bind}");
    let http = reqwest::Client::new();
    let enrolled = issue_bootstrap_bundle_and_enroll_client(
        &http,
        &base_url,
        TEST_ADMIN_TOKEN,
        &client_dir,
        "folder-agent.bootstrap.json",
        Some("folder-agent-test"),
        Some(3600),
    )
    .await?;
    let sdk = enrolled.build_client_async().await?;
    let connection = FolderAgentConnection::from_enrolled(&enrolled)?;
    Ok(AuthenticatedFolderAgentFixture {
        server,
        sdk,
        connection,
    })
}

async fn start_folder_agent(
    connection: &FolderAgentConnection,
    root_dir: &Path,
    prefix: Option<&str>,
    remote_refresh_interval_ms: u64,
    local_scan_interval_ms: u64,
    no_watch_local: bool,
) -> Result<ChildGuard> {
    let agent_bin = binary_path("ironmesh-folder-agent")?;
    let resource_guards = lock_test_resources([
        "folder-agent-process".to_string(),
        path_resource_key(root_dir),
    ])
    .await;

    let mut command = Command::new(agent_bin);
    command.arg("--root-dir").arg(root_dir);
    connection.apply_to_command(&mut command);
    command
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

    Ok(ChildGuard::with_resources(child, resource_guards))
}

async fn spawn_folder_agent_no_wait(
    connection: &FolderAgentConnection,
    root_dir: &Path,
    prefix: Option<&str>,
    remote_refresh_interval_ms: u64,
    local_scan_interval_ms: u64,
    extra_env: &[(&str, &str)],
    no_watch_local: bool,
) -> Result<ChildGuard> {
    let agent_bin = binary_path("ironmesh-folder-agent")?;
    let resource_guards = lock_test_resources([
        "folder-agent-process".to_string(),
        path_resource_key(root_dir),
    ])
    .await;

    let mut command = Command::new(agent_bin);
    command.arg("--root-dir").arg(root_dir);
    connection.apply_to_command(&mut command);
    command
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

    for (key, value) in extra_env {
        command.env(key, value);
    }

    if no_watch_local {
        command.arg("--no-watch-local");
    }

    let child = command
        .spawn()
        .context("failed to spawn ironmesh-folder-agent")?;

    Ok(ChildGuard::with_resources(child, resource_guards))
}

async fn run_folder_agent_once(
    connection: &FolderAgentConnection,
    root_dir: &Path,
    prefix: Option<&str>,
    remote_refresh_interval_ms: u64,
    local_scan_interval_ms: u64,
    no_watch_local: bool,
) -> Result<()> {
    let agent_bin = binary_path("ironmesh-folder-agent")?;
    let _resource_guards = lock_test_resources([
        "folder-agent-process".to_string(),
        path_resource_key(root_dir),
    ])
    .await;

    let mut command = Command::new(agent_bin);
    command.arg("--run-once").arg("--root-dir").arg(root_dir);
    connection.apply_to_command(&mut command);
    command
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

async fn wait_for_local_file_size_and_prefix(
    path: &Path,
    expected_size: u64,
    expected_prefix: &[u8],
    retries: usize,
) -> Result<()> {
    for _ in 0..retries {
        if let Ok(metadata) = fs::metadata(path)
            && metadata.is_file()
            && metadata.len() == expected_size
        {
            let mut file = std::fs::File::open(path)?;
            let mut prefix = vec![0_u8; expected_prefix.len()];
            if file.read_exact(&mut prefix).is_ok() && prefix.as_slice() == expected_prefix {
                return Ok(());
            }
        }

        sleep(Duration::from_millis(100)).await;
    }

    bail!(
        "local file {} did not reach expected size/prefix",
        path.display()
    )
}

fn local_files_in_dir_containing(dir: &Path, needle: &str) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    if !dir.is_dir() {
        return Ok(found);
    }

    for entry in
        fs::read_dir(dir).with_context(|| format!("failed to read dir {}", dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("");
        if !file_name.contains(needle) {
            continue;
        }
        if path.is_file() {
            found.push(path);
        }
    }

    Ok(found)
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

async fn assert_remote_store_index_has_no_paths_containing(
    sdk: &IronMeshClient,
    needle: &str,
    checks: usize,
) -> Result<()> {
    for _ in 0..checks {
        let index = sdk.store_index(None, 128, None).await?;
        let bad = index
            .entries
            .iter()
            .find(|entry| entry.path.contains(needle));
        if let Some(entry) = bad {
            bail!("remote store index unexpectedly contains {}", entry.path);
        }
        sleep(Duration::from_millis(100)).await;
    }
    Ok(())
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

async fn delete_remote_key_by_query(sdk: &IronMeshClient, key: &str) -> Result<()> {
    sdk.delete_path(key)
        .await
        .with_context(|| format!("failed to request remote delete for key={key}"))
}

async fn stop_folder_agent(agent: &mut ChildGuard) {
    agent.stop().await.ok();
}

fn baseline_db_path(
    root_dir: &Path,
    connection_target: &str,
    prefix: Option<&str>,
) -> Result<PathBuf> {
    let mut hasher = DefaultHasher::new();
    root_dir.to_string_lossy().hash(&mut hasher);
    prefix.unwrap_or_default().hash(&mut hasher);
    connection_target.hash(&mut hasher);
    let fingerprint = hasher.finish();

    let mut path = std::env::temp_dir();
    path.push("ironmesh-folder-agent");
    path.push(format!("baseline-{fingerprint:016x}.sqlite"));
    Ok(path)
}

fn delete_baseline_entry(root_dir: &Path, connection_target: &str, path: &str) -> Result<()> {
    let baseline_path = baseline_db_path(root_dir, connection_target, None)?;
    let connection = Connection::open(&baseline_path)
        .with_context(|| format!("failed to open sqlite baseline {}", baseline_path.display()))?;
    connection
        .execute("DELETE FROM baseline_entries WHERE path = ?1", [path])
        .with_context(|| format!("failed to delete sqlite baseline row for {path}"))?;
    Ok(())
}

fn startup_conflicts(root_dir: &Path, connection_target: &str) -> Result<Vec<(String, String)>> {
    let baseline_path = baseline_db_path(root_dir, connection_target, None)?;
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

fn baseline_integrity_check(root_dir: &Path, connection_target: &str) -> Result<String> {
    let baseline_path = baseline_db_path(root_dir, connection_target, None)?;
    let connection = Connection::open(&baseline_path)
        .with_context(|| format!("failed to open sqlite baseline {}", baseline_path.display()))?;
    connection
        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
        .context("failed to execute sqlite integrity_check")
}

async fn wait_for_baseline_content_hash(
    root_dir: &Path,
    connection_target: &str,
    path: &str,
    retries: usize,
) -> Result<String> {
    for _ in 0..retries {
        let baseline_path = baseline_db_path(root_dir, connection_target, None)?;
        if let Ok(connection) = Connection::open(&baseline_path) {
            let content_hash: Option<String> = connection
                .query_row(
                    "SELECT content_hash FROM baseline_entries WHERE path = ?1",
                    [path],
                    |row| row.get::<_, Option<String>>(0),
                )
                .optional()
                .with_context(|| format!("failed to query sqlite baseline hash for {path}"))?
                .flatten()
                .filter(|value| !value.trim().is_empty());
            if let Some(content_hash) = content_hash {
                return Ok(content_hash);
            }
        }

        sleep(Duration::from_millis(100)).await;
    }

    bail!("expected baseline hash to be present for path={path}")
}

async fn wait_for_startup_conflict_reason(
    root_dir: &Path,
    connection_target: &str,
    path: &str,
    reason: &str,
    retries: usize,
) -> Result<()> {
    for _ in 0..retries {
        if let Ok(conflicts) = startup_conflicts(root_dir, connection_target)
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

async fn wait_for_remote_prefix_entry_count_before_baseline_hash(
    root_dir: &Path,
    connection_target: &str,
    sdk: &IronMeshClient,
    prefix: &str,
    expected_min: usize,
    baseline_hash_path: &str,
    retries: usize,
) -> Result<()> {
    let normalized_prefix = prefix.trim_matches('/');

    for _ in 0..retries {
        let remote_ready = match sdk.store_index(None, 64, None).await {
            Ok(index) => {
                index
                    .entries
                    .iter()
                    .filter(|entry| {
                        let path = entry.path.trim_matches('/');
                        path.starts_with(normalized_prefix)
                    })
                    .count()
                    >= expected_min
            }
            Err(_) => false,
        };
        let baseline_hash_present = {
            let baseline_path = baseline_db_path(root_dir, connection_target, None)?;
            if let Ok(connection) = Connection::open(&baseline_path) {
                connection
                    .query_row(
                        "SELECT content_hash FROM baseline_entries WHERE path = ?1",
                        [baseline_hash_path],
                        |row| row.get::<_, Option<String>>(0),
                    )
                    .optional()
                    .ok()
                    .flatten()
                    .flatten()
                    .is_some_and(|value| !value.trim().is_empty())
            } else {
                false
            }
        };

        if remote_ready && !baseline_hash_present {
            return Ok(());
        }

        sleep(Duration::from_millis(100)).await;
    }

    bail!(
        "remote prefix {normalized_prefix} did not reach at least {expected_min} entries before baseline hash appeared for path={baseline_hash_path}"
    )
}

#[tokio::test]
async fn folder_agent_bootstrap_materializes_remote_tree() -> Result<()> {
    let bind = "127.0.0.1:19410";
    let local_root = fresh_data_dir("folder-agent-bootstrap-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

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

        let mut agent =
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
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

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_uploads_local_files_and_empty_directory_markers() -> Result<()> {
    let bind = "127.0.0.1:19411";
    let local_root = fresh_data_dir("folder-agent-upload-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

    let result = async {
        let mut agent =
            start_folder_agent(&fixture.connection, &local_root, None, 250, 250, true).await?;
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

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_applies_remote_add_update_delete_without_restart() -> Result<()> {
    let bind = "127.0.0.1:19412";
    let local_root = fresh_data_dir("folder-agent-remote-refresh-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

    let result = async {
        sdk.put_large_aware("live/item.txt", Bytes::from_static(b"version-one"))
            .await?;

        let mut agent =
            start_folder_agent(&fixture.connection, &local_root, None, 250, 2_000, true).await?;
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

            delete_remote_key_by_query(&sdk, "live/new.txt").await?;
            wait_for_local_absence(&added_path, 220).await?;

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut agent).await;
        scenario
    }
    .await;

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_run_once_bootstraps_and_exits() -> Result<()> {
    let bind = "127.0.0.1:19413";
    let local_root = fresh_data_dir("folder-agent-run-once-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

    let result = async {
        sdk.put_large_aware("once/seed.txt", Bytes::from_static(b"seed-remote"))
            .await?;

        fs::create_dir_all(local_root.join("once"))?;
        fs::write(local_root.join("once/local.txt"), b"local-before-run")?;

        run_folder_agent_once(&fixture.connection, &local_root, None, 250, 250, true).await?;

        wait_for_local_file_bytes(&local_root.join("once/seed.txt"), b"seed-remote", 120).await?;
        wait_for_local_file_bytes(&local_root.join("once/local.txt"), b"local-before-run", 120)
            .await?;

        Ok::<(), anyhow::Error>(())
    }
    .await;

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_propagates_local_file_deletions_to_remote() -> Result<()> {
    let bind = "127.0.0.1:19414";
    let local_root = fresh_data_dir("folder-agent-delete-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

    let result = async {
        sdk.put_large_aware("delete-me/target.txt", Bytes::from_static(b"to-delete"))
            .await?;

        let mut agent =
            start_folder_agent(&fixture.connection, &local_root, None, 250, 250, true).await?;
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

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_detects_remote_add_and_modify_done_while_stopped_after_restart() -> Result<()>
{
    let bind = "127.0.0.1:19415";
    let local_root = fresh_data_dir("folder-agent-restart-remote-change-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

    let result = async {
        sdk.put_large_aware(
            "restart-detect/existing.txt",
            Bytes::from_static(b"before-stop-version"),
        )
        .await?;

        let mut first_run =
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
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
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
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

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_detects_local_add_and_modify_done_while_stopped_after_restart() -> Result<()>
{
    let bind = "127.0.0.1:19416";
    let local_root = fresh_data_dir("folder-agent-restart-local-change-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

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
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
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
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
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

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_prefix_scope_maps_local_root_to_selected_remote_subtree() -> Result<()> {
    let bind = "127.0.0.1:19417";
    let local_root = fresh_data_dir("folder-agent-prefix-scope-root");
    let scope_prefix = "scoped/team-a";

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

    let result = async {
        sdk.put_large_aware("scoped/team-a/seed.txt", Bytes::from_static(b"scoped-seed"))
            .await?;
        sdk.put_large_aware("outside/keep.txt", Bytes::from_static(b"outside"))
            .await?;

        let mut agent = start_folder_agent(
            &fixture.connection,
            &local_root,
            Some(scope_prefix),
            2_000,
            250,
            true,
        )
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

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_nested_prefix_uploads_camera_files_under_full_scope() -> Result<()> {
    let bind = "127.0.0.1:19426";
    let local_root = fresh_data_dir("folder-agent-camera-prefix-root");
    let scope_prefix = "cameras/vm1";

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

    let result = async {
        sdk.put_large_aware(
            "cameras/vm1/already-there.jpg",
            Bytes::from_static(b"seed-camera"),
        )
        .await?;
        sdk.put_large_aware("cameras/vm2/other.jpg", Bytes::from_static(b"other-camera"))
            .await?;

        let mut agent = start_folder_agent(
            &fixture.connection,
            &local_root,
            Some(scope_prefix),
            2_000,
            250,
            true,
        )
        .await?;
        let scenario = async {
            wait_for_local_file_bytes(&local_root.join("already-there.jpg"), b"seed-camera", 220)
                .await?;
            assert!(
                !local_root.join("cameras").exists(),
                "nested scoped prefix should not be recreated under local root"
            );

            fs::write(local_root.join("IMG20260314_200501.jpg"), b"camera-one")?;
            fs::create_dir_all(local_root.join("nested"))?;
            fs::write(
                local_root.join("nested/IMG20260314_200502.jpg"),
                b"camera-two",
            )?;

            wait_for_remote_file_bytes(
                &sdk,
                "cameras/vm1/IMG20260314_200501.jpg",
                b"camera-one",
                220,
            )
            .await?;
            wait_for_remote_file_bytes(
                &sdk,
                "cameras/vm1/nested/IMG20260314_200502.jpg",
                b"camera-two",
                220,
            )
            .await?;

            wait_for_remote_file_absence(&sdk, "IMG20260314_200501.jpg", 80).await?;
            wait_for_remote_file_absence(&sdk, "cameras/IMG20260314_200501.jpg", 80).await?;
            wait_for_remote_file_absence(&sdk, "cameras/nested/IMG20260314_200502.jpg", 80).await?;
            wait_for_remote_file_absence(&sdk, "vm1/IMG20260314_200501.jpg", 80).await?;

            wait_for_remote_file_bytes(&sdk, "cameras/vm2/other.jpg", b"other-camera", 220).await?;

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut agent).await;
        scenario
    }
    .await;

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_recovers_local_offline_changes_after_unfriendly_stop() -> Result<()> {
    let bind = "127.0.0.1:19418";
    let local_root = fresh_data_dir("folder-agent-unfriendly-stop-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

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
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;

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
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
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

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_applies_path_level_recovery_when_baseline_row_is_missing() -> Result<()> {
    let bind = "127.0.0.1:19419";
    let local_root = fresh_data_dir("folder-agent-path-recovery-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

    let result = async {
        sdk.put_large_aware("path-recovery/a.txt", Bytes::from_static(b"remote-a-v1"))
            .await?;
        sdk.put_large_aware("path-recovery/b.txt", Bytes::from_static(b"remote-b-v1"))
            .await?;
        sdk.put_large_aware("path-recovery/c.txt", Bytes::from_static(b"remote-c-v1"))
            .await?;

        let mut first_run =
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
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
        delete_baseline_entry(
            &local_root,
            fixture.connection.target_label(),
            "path-recovery/b.txt",
        )?;

        let mut second_run =
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
        let recovery_retries = 360;
        let scenario = async {
            // Changed local file is preserved and uploaded.
            wait_for_remote_file_bytes(
                &sdk,
                "path-recovery/a.txt",
                b"local-a-v2",
                recovery_retries,
            )
            .await?;
            // Unchanged local file with missing baseline row does not force global recovery.
            wait_for_remote_file_bytes(
                &sdk,
                "path-recovery/b.txt",
                b"remote-b-v1",
                recovery_retries,
            )
            .await?;
            // Remote update still applies on unaffected path.
            wait_for_local_file_bytes(
                &local_root.join("path-recovery/c.txt"),
                b"remote-c-v2",
                recovery_retries,
            )
            .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut second_run).await;
        scenario
    }
    .await;

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_respects_remote_delete_intent_for_unchanged_local_after_restart() -> Result<()>
{
    let bind = "127.0.0.1:19420";
    let local_root = fresh_data_dir("folder-agent-remote-delete-intent-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

    let result = async {
        sdk.put_large_aware("delete-intent/target.txt", Bytes::from_static(b"remote-v1"))
            .await?;

        let mut first_run =
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
        wait_for_local_file_bytes(
            &local_root.join("delete-intent/target.txt"),
            b"remote-v1",
            220,
        )
        .await?;
        stop_folder_agent(&mut first_run).await;

        delete_remote_key_by_query(&sdk, "delete-intent/target.txt").await?;
        wait_for_remote_file_absence(&sdk, "delete-intent/target.txt", 220).await?;

        let mut second_run =
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
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

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_records_dual_modify_conflict_when_baseline_row_is_missing() -> Result<()> {
    let bind = "127.0.0.1:19421";
    let local_root = fresh_data_dir("folder-agent-dual-modify-conflict-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

    let result = async {
        sdk.put_large_aware("conflict/x.txt", Bytes::from_static(b"remote-v1"))
            .await?;

        let mut first_run =
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
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
        delete_baseline_entry(
            &local_root,
            fixture.connection.target_label(),
            "conflict/x.txt",
        )?;

        let mut second_run =
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
        let scenario = async {
            // Safety policy for this ambiguous case: keep local bytes.
            wait_for_remote_file_bytes(&sdk, "conflict/x.txt", b"local-v2", 220).await?;

            wait_for_startup_conflict_reason(
                &local_root,
                fixture.connection.target_label(),
                "conflict/x.txt",
                "dual_modify_missing_baseline",
                240,
            )
            .await?;

            let conflict_dir = local_root.join(".ironmesh-conflicts/remote/conflict");
            let mut found_remote_copy = false;
            if let Ok(entries) = fs::read_dir(&conflict_dir) {
                for entry in entries {
                    let path = entry?.path();
                    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                        continue;
                    };
                    if !file_name.starts_with("x.txt.remote-conflict-") {
                        continue;
                    }
                    let bytes = fs::read(&path)?;
                    if bytes.as_slice() == b"remote-v2" {
                        found_remote_copy = true;
                        break;
                    }
                }
            }
            if !found_remote_copy {
                bail!(
                    "expected remote conflict copy for conflict/x.txt under {}",
                    conflict_dir.display()
                );
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut second_run).await;
        scenario
    }
    .await;

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_records_dual_modify_conflict_when_baseline_row_exists() -> Result<()> {
    let bind = "127.0.0.1:19423";
    let local_root = fresh_data_dir("folder-agent-dual-modify-conflict-baseline-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

    let result = async {
        sdk.put_large_aware("conflict2/y.txt", Bytes::from_static(b"remote-v1"))
            .await?;

        let mut first_run =
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
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
            start_folder_agent(&fixture.connection, &local_root, None, 2_000, 250, true).await?;
        let scenario = async {
            // Safety policy: keep local bytes, but record the dual-modify conflict.
            wait_for_remote_file_bytes(&sdk, "conflict2/y.txt", b"local-v2", 220).await?;
            wait_for_startup_conflict_reason(
                &local_root,
                fixture.connection.target_label(),
                "conflict2/y.txt",
                "dual_modify_conflict",
                240,
            )
            .await?;

            let conflict_dir = local_root.join(".ironmesh-conflicts/remote/conflict2");
            let mut found_remote_copy = false;
            if let Ok(entries) = fs::read_dir(&conflict_dir) {
                for entry in entries {
                    let path = entry?.path();
                    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
                        continue;
                    };
                    if !file_name.starts_with("y.txt.remote-conflict-") {
                        continue;
                    }
                    let bytes = fs::read(&path)?;
                    if bytes.as_slice() == b"remote-v2" {
                        found_remote_copy = true;
                        break;
                    }
                }
            }
            if !found_remote_copy {
                bail!(
                    "expected remote conflict copy for conflict2/y.txt under {}",
                    conflict_dir.display()
                );
            }
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut second_run).await;
        scenario
    }
    .await;

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_recovers_after_crash_during_active_sync_writes() -> Result<()> {
    let bind = "127.0.0.1:19422";
    let local_root = fresh_data_dir("folder-agent-crash-active-write-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

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
            start_folder_agent(&fixture.connection, &local_root, None, 1_500, 100, true).await?;

        // Crash only after active sync has landed at least one file remotely but before the final
        // large pre-crash upload has a persisted baseline hash, so restart recovery still has
        // real upload work left to finish and does not race a just-finished upload against the
        // next startup snapshot.
        wait_for_remote_prefix_entry_count_before_baseline_hash(
            &local_root,
            fixture.connection.target_label(),
            &sdk,
            "crash-active/local-",
            1,
            "crash-active/local-c.bin",
            320,
        )
        .await?;

        // Abrupt process termination during active syncing.
        stop_folder_agent(&mut first_run).await;

        let integrity = baseline_integrity_check(&local_root, fixture.connection.target_label())?;
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
            start_folder_agent(&fixture.connection, &local_root, None, 1_500, 100, true).await?;
        let recovery_retries = 720;
        let scenario = async {
            wait_for_remote_file_bytes(
                &sdk,
                "crash-active/local-a.bin",
                b"local-a-after-crash",
                recovery_retries,
            )
            .await?;
            // Large resumed uploads can legitimately finish before the small post-crash add.
            wait_for_remote_file_bytes(
                &sdk,
                "crash-active/local-b.bin",
                &large_payload,
                recovery_retries,
            )
            .await?;
            wait_for_remote_file_bytes(
                &sdk,
                "crash-active/local-c.bin",
                &large_payload,
                recovery_retries,
            )
            .await?;
            wait_for_remote_file_bytes(
                &sdk,
                "crash-active/local-new.txt",
                b"local-new-after-crash",
                recovery_retries,
            )
            .await?;

            wait_for_local_file_bytes(
                &local_root.join("crash-active/remote-base.txt"),
                b"remote-v2-after-crash",
                recovery_retries,
            )
            .await?;
            wait_for_local_file_bytes(
                &local_root.join("crash-active/remote-new.txt"),
                b"remote-new-after-crash",
                recovery_retries,
            )
            .await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut second_run).await;
        scenario
    }
    .await;

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_ignores_partial_download_artifacts_after_crash() -> Result<()> {
    let bind = "127.0.0.1:19424";
    let local_root = fresh_data_dir("folder-agent-partial-download-artifacts-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

    let result = async {
        sdk.put_large_aware(
            "partial-download/target.bin",
            Bytes::from_static(b"remote-v1"),
        )
        .await?;

        let mut first_run =
            start_folder_agent(&fixture.connection, &local_root, None, 250, 250, true).await?;
        wait_for_local_file_bytes(
            &local_root.join("partial-download/target.bin"),
            b"remote-v1",
            220,
        )
        .await?;

        let mut large_payload = Vec::with_capacity(32 * 1024 * 1024);
        large_payload.extend_from_slice(b"REMOTE-V2-");
        large_payload.resize(32 * 1024 * 1024, b'x');
        let expected_size = large_payload.len() as u64;

        sdk.put_large_aware(
            "partial-download/target.bin",
            Bytes::from(large_payload.clone()),
        )
        .await?;

        let target = local_root.join("partial-download/target.bin");
        let staged_download_dir = local_root.join(".ironmesh/transfers/downloads");
        let mut artifact: Option<PathBuf> = None;
        for _ in 0..400 {
            if let Ok(bytes) = fs::read(&target)
                && bytes.as_slice() == b"remote-v1"
            {
                let artifacts = local_files_in_dir_containing(&staged_download_dir, ".part")?;
                if let Some(path) = artifacts.first() {
                    artifact = Some(path.clone());
                    break;
                }
            }
            sleep(Duration::from_millis(25)).await;
        }

        let artifact = artifact.context("did not observe download temp artifact before crash")?;

        // Kill the agent while it is mid-download (temp file exists, target still old).
        stop_folder_agent(&mut first_run).await;

        assert!(
            artifact.exists(),
            "expected temp artifact to remain after crash: {}",
            artifact.display()
        );

        let mut second_run = spawn_folder_agent_no_wait(
            &fixture.connection,
            &local_root,
            None,
            250,
            250,
            &[(
                "IRONMESH_TEST_CONFLICT_COPY_SLEEP_AFTER_TEMP_CREATE_MS",
                "2000",
            )],
            true,
        )
        .await?;
        let scenario = async {
            // Restart should resume or replace the hidden staged download and remove leftovers.
            for _ in 0..120 {
                if !artifact.exists() {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
            assert!(
                !artifact.exists(),
                "expected temp artifact to be cleaned up on restart: {}",
                artifact.display()
            );

            wait_for_local_file_size_and_prefix(&target, expected_size, b"REMOTE-V2-", 360).await?;
            assert_remote_store_index_has_no_paths_containing(&sdk, "ironmesh-part-", 20).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut second_run).await;
        scenario
    }
    .await;

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}

#[tokio::test]
async fn folder_agent_recovers_after_crash_during_conflict_copy_download() -> Result<()> {
    let bind = "127.0.0.1:19425";
    let local_root = fresh_data_dir("folder-agent-conflict-copy-crash-root");

    let mut fixture = start_authenticated_folder_agent_fixture(bind).await?;
    let sdk = fixture.sdk.clone();

    let result = async {
        sdk.put_large_aware("conflict-copy/target.bin", Bytes::from_static(b"remote-v1"))
            .await?;

        let mut first_run =
            start_folder_agent(&fixture.connection, &local_root, None, 250, 250, true).await?;
        wait_for_local_file_bytes(
            &local_root.join("conflict-copy/target.bin"),
            b"remote-v1",
            220,
        )
        .await?;
        stop_folder_agent(&mut first_run).await;

        let baseline_hash = wait_for_baseline_content_hash(
            &local_root,
            fixture.connection.target_label(),
            "conflict-copy/target.bin",
            240,
        )
        .await?;

        let local_v2 = b"local-v2-longer-than-remote-v1";
        fs::write(local_root.join("conflict-copy/target.bin"), local_v2).with_context(|| {
            format!(
                "failed to modify local file {}",
                local_root.join("conflict-copy/target.bin").display()
            )
        })?;

        sdk.put_large_aware("conflict-copy/target.bin", Bytes::from_static(b"remote-v2"))
            .await?;
        let index = sdk.store_index(None, 64, None).await?;
        let remote_hash = index
            .entries
            .iter()
            .find(|entry| entry.path == "conflict-copy/target.bin")
            .and_then(|entry| entry.content_hash.clone())
            .filter(|value| !value.trim().is_empty())
            .context("expected remote content_hash for conflict-copy/target.bin")?;
        assert_ne!(
            baseline_hash, remote_hash,
            "expected remote content_hash to differ from baseline after remote update"
        );

        let conflict_dir = local_root.join(".ironmesh-conflicts/remote/conflict-copy");

        // Deterministic crash injection: abort right after creating the conflict temp file.
        let agent_bin = binary_path("ironmesh-folder-agent")?;
        let mut crash_run = Command::new(agent_bin);
        crash_run
            .arg("--run-once")
            .arg("--root-dir")
            .arg(&local_root);
        fixture.connection.apply_to_command(&mut crash_run);
        crash_run
            .arg("--remote-refresh-interval-ms")
            .arg("250")
            .arg("--local-scan-interval-ms")
            .arg("250")
            .arg("--no-watch-local")
            .env("IRONMESH_TEST_CRASH_AFTER_CONFLICT_COPY_TEMP_CREATE", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let status = timeout(Duration::from_secs(20), crash_run.status())
            .await
            .context("folder-agent crash injection timed out")?
            .context("failed to execute folder-agent crash injection")?;
        if status.success() {
            bail!("expected folder-agent crash injection run to fail, got status {status}");
        }

        let artifacts = local_files_in_dir_containing(&conflict_dir, "ironmesh-part-")?;
        let artifact = artifacts
            .into_iter()
            .next()
            .context("expected conflict-copy temp artifact after crash injection")?;

        assert!(
            artifact.exists(),
            "expected conflict-copy temp artifact to exist after crash injection: {}",
            artifact.display()
        );

        let mut third_run =
            start_folder_agent(&fixture.connection, &local_root, None, 250, 250, true).await?;
        let scenario = async {
            for _ in 0..120 {
                if !artifact.exists() {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }
            assert!(
                !artifact.exists(),
                "expected conflict-copy temp artifact to be cleaned up on restart: {}",
                artifact.display()
            );

            // Safety policy: local bytes win on the canonical path.
            wait_for_remote_file_bytes(&sdk, "conflict-copy/target.bin", local_v2, 360).await?;

            // But the remote bytes must be preserved as a conflict copy.
            let mut conflict_copy: Option<PathBuf> = None;
            for _ in 0..200 {
                if let Ok(entries) = fs::read_dir(&conflict_dir) {
                    for entry in entries {
                        let path = entry?.path();
                        let Some(file_name) = path.file_name().and_then(|value| value.to_str())
                        else {
                            continue;
                        };
                        if file_name.starts_with("target.bin.remote-conflict-") {
                            conflict_copy = Some(path);
                            break;
                        }
                    }
                }
                if conflict_copy.is_some() {
                    break;
                }
                sleep(Duration::from_millis(50)).await;
            }

            let conflict_copy =
                conflict_copy.context("did not observe remote conflict copy after restart")?;
            wait_for_local_file_bytes(&conflict_copy, b"remote-v2", 60).await?;

            assert_remote_store_index_has_no_paths_containing(&sdk, "ironmesh-part-", 20).await?;
            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_folder_agent(&mut third_run).await;
        scenario
    }
    .await;

    stop_server(&mut fixture.server).await;
    let _ = fs::remove_dir_all(&local_root);
    result
}
