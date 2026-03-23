#[cfg(test)]
mod tests {
    const CHUNK_UPLOAD_THRESHOLD_BYTES: usize = 1024 * 1024;

    use std::fs;
    use std::io::Cursor;

    use anyhow::{Context, Result};
    use bytes::Bytes;
    use client_sdk::{ClientNode, ContentAddressedClientCache, IronMeshClient, UploadMode};
    use serde_json::json;
    use uuid::Uuid;

    use crate::framework::{
        EnrolledTestClient, TEST_ADMIN_TOKEN, fresh_data_dir,
        issue_bootstrap_bundle_and_enroll_client, latest_snapshot_id_for_client,
        start_authenticated_server, start_open_server_with_config, stop_server,
    };

    async fn start_authenticated_test_client(
        bind: &str,
        server_name: &str,
        client_name: &str,
    ) -> Result<(crate::framework::ChildGuard, EnrolledTestClient)> {
        let data_dir = fresh_data_dir(server_name);
        let client_dir = fresh_data_dir(client_name);
        let node_id = Uuid::new_v4().to_string();
        let server = start_authenticated_server(bind, &data_dir, &node_id, 1).await?;
        let base_url = format!("http://{bind}");
        let http = reqwest::Client::new();
        let enrolled = issue_bootstrap_bundle_and_enroll_client(
            &http,
            &base_url,
            TEST_ADMIN_TOKEN,
            &client_dir,
            "client.bootstrap.json",
            Some(client_name),
            Some(3600),
        )
        .await?;
        Ok((server, enrolled))
    }

    fn count_files_recursively(root: &std::path::Path) -> Result<usize> {
        fn visit(path: &std::path::Path, total: &mut usize) -> Result<()> {
            for entry in std::fs::read_dir(path)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    visit(&path, total)?;
                } else {
                    *total += 1;
                }
            }
            Ok(())
        }

        let mut total = 0;
        visit(root, &mut total)?;
        Ok(total)
    }

    #[tokio::test]
    async fn sdk_roundtrip_against_live_server() -> Result<()> {
        let bind = "127.0.0.1:19230";
        let (mut server, enrolled) =
            start_authenticated_test_client(bind, "sdk-roundtrip-server", "sdk-roundtrip-client")
                .await?;

        let client = ClientNode::with_client(enrolled.build_client_async().await?);
        let key = "sdk-roundtrip";
        let value = Bytes::from_static(b"hello-from-sdk");

        client.put(key, value.clone()).await?;
        let fetched = client.get(key).await?;
        assert_eq!(fetched, value);

        stop_server(&mut server).await;
        Ok(())
    }

    #[tokio::test]
    async fn client_node_cache_entries_and_remove_cached_work() -> Result<()> {
        let bind = "127.0.0.1:19231";
        let (mut server, enrolled) = start_authenticated_test_client(
            bind,
            "client-node-cache-server",
            "client-node-cache-client",
        )
        .await?;

        let client = ClientNode::with_client(enrolled.build_client_async().await?);
        let key = "cache-key";
        let payload = Bytes::from_static(b"cached-value");

        let result = async {
            client.put(key, payload.clone()).await?;

            let fetched = client.get(key).await?;
            assert_eq!(fetched, payload);

            let entries = client.cache_entries().await;
            assert!(
                entries
                    .iter()
                    .any(|entry| { entry.key == key && entry.size_bytes == payload.len() })
            );

            client.remove_cached(key).await?;
            assert!(client.remove_cached(key).await.is_err());

            let refetched = client.get_cached_or_fetch(key).await?;
            assert_eq!(refetched, payload);
            let entries = client.cache_entries().await;
            assert!(entries.iter().any(|entry| entry.key == key));

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn client_node_snapshot_and_reader_writer_paths_work() -> Result<()> {
        let bind = "127.0.0.1:19232";
        let (mut server, enrolled) = start_authenticated_test_client(
            bind,
            "client-node-snapshots-server",
            "client-node-snapshots-client",
        )
        .await?;

        let sdk = enrolled.build_client_async().await?;
        let client = ClientNode::with_client(sdk.clone());

        let result = async {
            let versioned_key = "history/client-node";
            let first = Bytes::from_static(b"v1-from-client-node");
            let second = Bytes::from_static(b"v2-from-client-node");

            client.put(versioned_key, first.clone()).await?;
            let snapshot_id = latest_snapshot_id_for_client(&sdk).await?;
            client
                .put_large_aware(versioned_key, second.clone())
                .await?;

            let historical = client
                .get_with_selector(versioned_key, Some(&snapshot_id), None)
                .await?;
            assert_eq!(historical, first);

            let latest = client.get(versioned_key).await?;
            assert_eq!(latest, second);

            let snapshot_for_writer = snapshot_id.clone();
            let writer_client = client.clone();
            let historical_writer = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                let mut historical_writer = Vec::new();
                writer_client.get_with_selector_writer(
                    versioned_key,
                    Some(&snapshot_for_writer),
                    None,
                    &mut historical_writer,
                )?;
                Ok(historical_writer)
            })
            .await
            .context("client_node get_with_selector_writer task join failed")??;
            assert_eq!(historical_writer, first);

            let chunked_key = "reader/client-node";
            client
                .put(chunked_key, Bytes::from_static(b"old-value"))
                .await?;

            let chunked_payload =
                vec![b'R'; CHUNK_UPLOAD_THRESHOLD_BYTES + (CHUNK_UPLOAD_THRESHOLD_BYTES / 4)];
            let expected_chunked_payload = chunked_payload.clone();
            let chunked_payload_len = chunked_payload.len() as u64;
            let blocking_client = client.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                let mut reader = Cursor::new(chunked_payload);
                let report = blocking_client.put_large_aware_reader(
                    chunked_key,
                    &mut reader,
                    chunked_payload_len,
                )?;
                assert!(matches!(report.upload_mode, UploadMode::Chunked));
                Ok(())
            })
            .await
            .context("put_large_aware_reader task join failed")??;

            let entries = client.cache_entries().await;
            assert!(
                !entries.iter().any(|entry| entry.key == chunked_key),
                "put_large_aware_reader should invalidate cached entry for the key"
            );

            let refreshed = client.get_cached_or_fetch(chunked_key).await?;
            assert_eq!(refreshed, Bytes::from(expected_chunked_payload));

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn ironmesh_client_upload_modes_and_reader_writer_paths_work() -> Result<()> {
        let bind = "127.0.0.1:19233";
        let (mut server, enrolled) = start_authenticated_test_client(
            bind,
            "ironmesh-client-upload-modes-server",
            "ironmesh-client-upload-modes-client",
        )
        .await?;

        let sdk = enrolled.build_client_async().await?;

        let result = async {
            let direct_report = sdk
                .put_large_aware("large-aware/direct", Bytes::from_static(b"small"))
                .await?;
            assert!(matches!(direct_report.upload_mode, UploadMode::Direct));
            assert_eq!(direct_report.chunk_size_bytes, None);
            assert_eq!(direct_report.chunk_count, None);

            let large_payload = vec![b'L'; CHUNK_UPLOAD_THRESHOLD_BYTES + 128];
            let large_report = sdk
                .put_large_aware("large-aware/chunked", Bytes::from(large_payload.clone()))
                .await?;
            assert!(matches!(large_report.upload_mode, UploadMode::Chunked));
            assert_eq!(
                large_report.chunk_size_bytes,
                Some(CHUNK_UPLOAD_THRESHOLD_BYTES)
            );
            assert!(large_report.chunk_count.unwrap_or(0) >= 2);
            let fetched_large = sdk.get("large-aware/chunked").await?;
            assert_eq!(fetched_large, Bytes::from(large_payload));

            let small_reader_sdk = sdk.clone();
            let small_reader_report = tokio::task::spawn_blocking(move || -> Result<_> {
                let payload = b"reader-direct";
                let mut reader = Cursor::new(payload.to_vec());
                small_reader_sdk.put_large_aware_reader(
                    "reader/direct",
                    &mut reader,
                    payload.len() as u64,
                )
            })
            .await
            .context("put_large_aware_reader task join failed")??;
            assert!(matches!(
                small_reader_report.upload_mode,
                UploadMode::Direct
            ));
            assert_eq!(
                sdk.get("reader/direct").await?,
                Bytes::from_static(b"reader-direct")
            );

            let chunked_reader_sdk = sdk.clone();
            tokio::task::spawn_blocking(move || -> Result<_> {
                let payload =
                    vec![b'C'; CHUNK_UPLOAD_THRESHOLD_BYTES + (CHUNK_UPLOAD_THRESHOLD_BYTES / 2)];
                let payload_len = payload.len() as u64;
                let mut reader = Cursor::new(payload);
                chunked_reader_sdk.put_large_aware_reader(
                    "reader/chunked",
                    &mut reader,
                    payload_len,
                )
            })
            .await
            .context("put_large_aware_reader task join failed")??;

            let writer_sdk = sdk.clone();
            let writer = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                let mut writer = Vec::new();
                writer_sdk.get_with_selector_writer("reader/chunked", None, None, &mut writer)?;
                Ok(writer)
            })
            .await
            .context("get_with_selector_writer task join failed")??;
            assert_eq!(
                writer,
                vec![b'C'; CHUNK_UPLOAD_THRESHOLD_BYTES + (CHUNK_UPLOAD_THRESHOLD_BYTES / 2)]
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn ironmesh_client_put_large_aware_covers_small_and_large_bytes_and_reader_uploads()
    -> Result<()> {
        let bind = "127.0.0.1:19237";
        let (mut server, enrolled) = start_authenticated_test_client(
            bind,
            "ironmesh-client-large-aware-server",
            "ironmesh-client-large-aware-client",
        )
        .await?;

        let sdk = enrolled.build_client_async().await?;

        let result = async {
            let small_bytes_payload = Bytes::from_static(b"bytes-small-upload");
            let small_bytes_report = sdk
                .put_large_aware("coverage/bytes-small", small_bytes_payload.clone())
                .await?;
            assert!(matches!(small_bytes_report.upload_mode, UploadMode::Direct));
            assert_eq!(
                small_bytes_report.meta.size_bytes,
                small_bytes_payload.len()
            );
            assert_eq!(sdk.get("coverage/bytes-small").await?, small_bytes_payload);

            let large_bytes_payload = vec![b'B'; CHUNK_UPLOAD_THRESHOLD_BYTES + 257];
            let large_bytes_report = sdk
                .put_large_aware(
                    "coverage/bytes-large",
                    Bytes::from(large_bytes_payload.clone()),
                )
                .await?;
            assert!(matches!(
                large_bytes_report.upload_mode,
                UploadMode::Chunked
            ));
            assert_eq!(
                large_bytes_report.chunk_size_bytes,
                Some(CHUNK_UPLOAD_THRESHOLD_BYTES)
            );
            assert_eq!(large_bytes_report.chunk_count, Some(2));
            assert_eq!(
                sdk.get("coverage/bytes-large").await?,
                Bytes::from(large_bytes_payload)
            );

            let small_reader_sdk = sdk.clone();
            let small_reader_payload = b"reader-small-upload".to_vec();
            let small_reader_expected = small_reader_payload.clone();
            let small_reader_report = tokio::task::spawn_blocking(move || -> Result<_> {
                let mut reader = Cursor::new(small_reader_payload.clone());
                small_reader_sdk.put_large_aware_reader(
                    "coverage/reader-small",
                    &mut reader,
                    small_reader_payload.len() as u64,
                )
            })
            .await
            .context("small put_large_aware_reader task join failed")??;
            assert!(matches!(
                small_reader_report.upload_mode,
                UploadMode::Direct
            ));
            assert_eq!(
                small_reader_report.meta.size_bytes,
                small_reader_expected.len()
            );
            assert_eq!(
                sdk.get("coverage/reader-small").await?,
                Bytes::from(small_reader_expected)
            );

            let large_reader_sdk = sdk.clone();
            let large_reader_payload =
                vec![b'R'; CHUNK_UPLOAD_THRESHOLD_BYTES + (CHUNK_UPLOAD_THRESHOLD_BYTES / 2)];
            let large_reader_expected = large_reader_payload.clone();
            let expected_chunk_count = large_reader_payload
                .len()
                .div_ceil(CHUNK_UPLOAD_THRESHOLD_BYTES);
            let large_reader_report = tokio::task::spawn_blocking(move || -> Result<_> {
                let mut reader = Cursor::new(large_reader_payload.clone());
                large_reader_sdk.put_large_aware_reader(
                    "coverage/reader-large",
                    &mut reader,
                    large_reader_payload.len() as u64,
                )
            })
            .await
            .context("large put_large_aware_reader task join failed")??;
            assert!(matches!(
                large_reader_report.upload_mode,
                UploadMode::Chunked
            ));
            assert_eq!(
                large_reader_report.chunk_size_bytes,
                Some(CHUNK_UPLOAD_THRESHOLD_BYTES)
            );
            assert_eq!(large_reader_report.chunk_count, Some(expected_chunk_count));
            assert_eq!(
                sdk.get("coverage/reader-large").await?,
                Bytes::from(large_reader_expected)
            );

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn ironmesh_client_snapshot_store_index_and_snapshot_loading_work() -> Result<()> {
        let bind = "127.0.0.1:19234";
        let (mut server, enrolled) = start_authenticated_test_client(
            bind,
            "ironmesh-client-snapshots-server",
            "ironmesh-client-snapshots-client",
        )
        .await?;

        let sdk = enrolled.build_client_async().await?;

        let result = async {
            let versioned_key = "history/sdk";
            sdk.put(versioned_key, Bytes::from_static(b"sdk-v1"))
                .await?;
            let snapshot_id = latest_snapshot_id_for_client(&sdk).await?;
            sdk.put(versioned_key, Bytes::from_static(b"sdk-v2"))
                .await?;

            let latest = sdk.get_with_selector(versioned_key, None, None).await?;
            assert_eq!(latest, Bytes::from_static(b"sdk-v2"));

            let historical = sdk
                .get_with_selector(versioned_key, Some(&snapshot_id), None)
                .await?;
            assert_eq!(historical, Bytes::from_static(b"sdk-v1"));

            for key in ["docs/readme.txt", "docs/guide/intro.md", "docs/api/v1.json"] {
                sdk.put(key, Bytes::from_static(b"x")).await?;
            }

            let index = sdk.store_index(Some("docs"), 1, None).await?;
            assert!(index.entry_count >= 3);
            assert!(
                index
                    .entries
                    .iter()
                    .any(|entry| { entry.path == "docs/readme.txt" && entry.entry_type == "key" })
            );
            assert!(
                index
                    .entries
                    .iter()
                    .any(|entry| { entry.path == "docs/api/" && entry.entry_type == "prefix" })
            );
            assert!(
                index
                    .entries
                    .iter()
                    .any(|entry| { entry.path == "docs/guide/" && entry.entry_type == "prefix" })
            );

            let blocking_sdk = sdk.clone();
            let blocking_index = tokio::task::spawn_blocking(move || {
                blocking_sdk.store_index_blocking(Some("docs"), 1, None)
            })
            .await
            .context("store_index_blocking task join failed")??;
            assert_eq!(blocking_index.entries.len(), index.entries.len());

            let loaded_snapshot = sdk.load_snapshot_from_server(Some("docs"), 1, None).await?;
            assert!(loaded_snapshot.local.is_empty());
            let readme_index_entry = index
                .entries
                .iter()
                .find(|entry| entry.path == "docs/readme.txt" && entry.entry_type == "key")
                .context("docs/readme.txt entry missing from store index response")?;
            let expected_version = readme_index_entry
                .version
                .as_deref()
                .unwrap_or("server-head");
            let expected_content_hash = readme_index_entry
                .content_hash
                .as_deref()
                .map(ToString::to_string)
                .unwrap_or_else(|| "server-head:docs/readme.txt".to_string());
            assert!(loaded_snapshot.remote.iter().any(|entry| {
                entry.path == "docs/readme.txt"
                    && entry.version.as_deref() == Some(expected_version)
                    && entry.content_hash.as_deref() == Some(expected_content_hash.as_str())
            }));
            assert!(loaded_snapshot.remote.iter().any(|entry| {
                entry.path == "docs/api" && entry.version.is_none() && entry.content_hash.is_none()
            }));

            let blocking_sdk = sdk.clone();
            let blocking_snapshot = tokio::task::spawn_blocking(move || {
                blocking_sdk.load_snapshot_from_server_blocking(Some("docs"), 1, None)
            })
            .await
            .context("load_snapshot_from_server_blocking task join failed")??;
            assert_eq!(blocking_snapshot.remote.len(), loaded_snapshot.remote.len());

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn ironmesh_client_missing_object_returns_errors() -> Result<()> {
        let bind = "127.0.0.1:19235";
        let (mut server, enrolled) = start_authenticated_test_client(
            bind,
            "ironmesh-client-missing-object-server",
            "ironmesh-client-missing-object-client",
        )
        .await?;

        let sdk = enrolled.build_client_async().await?;

        let result = async {
            assert!(sdk.get("missing-key").await.is_err());
            assert!(
                sdk.get_with_selector("missing-key", None, None)
                    .await
                    .is_err()
            );

            let missing_writer_sdk = sdk.clone();
            let writer_result = tokio::task::spawn_blocking(move || {
                let mut writer = Vec::new();
                missing_writer_sdk.get_with_selector_writer("missing-key", None, None, &mut writer)
            })
            .await
            .context("missing-key writer task join failed")?;
            assert!(writer_result.is_err());

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn content_addressed_client_cache_persists_and_reuses_local_content() -> Result<()> {
        let bind = "127.0.0.1:19236";
        let (mut server, enrolled) = start_authenticated_test_client(
            bind,
            "content-addressed-cache-server",
            "content-addressed-cache-client",
        )
        .await?;
        let cache_dir = fresh_data_dir("content-addressed-client-cache");

        let result = async {
            let client = ContentAddressedClientCache::with_client(
                enrolled.build_client_async().await?,
                &cache_dir,
            )?;
            let payload = Bytes::from(vec![b'Z'; CHUNK_UPLOAD_THRESHOLD_BYTES + 4096]);

            client.put("cached/a", payload.clone()).await?;
            client.copy_path("cached/a", "cached/b", false).await?;

            let entries = client.cache_entries().await?;
            assert_eq!(entries.len(), 2);
            assert!(entries.iter().any(|entry| entry.key == "cached/a"));
            assert!(entries.iter().any(|entry| entry.key == "cached/b"));

            let chunk_count_before_rename = count_files_recursively(&cache_dir.join("chunks"))?;

            client.rename_path("cached/b", "cached/c", false).await?;
            client.delete_path("cached/a").await?;

            let persisted_client = ContentAddressedClientCache::with_client(
                enrolled.build_client_async().await?,
                &cache_dir,
            )?;
            let cached = persisted_client.get_cached_or_fetch("cached/c").await?;
            assert_eq!(cached, payload);

            let entries = persisted_client.cache_entries().await?;
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].key, "cached/c");

            let chunk_count_after_restart = count_files_recursively(&cache_dir.join("chunks"))?;
            assert_eq!(chunk_count_after_restart, chunk_count_before_rename);

            persisted_client.remove_cached("cached/c").await?;
            assert!(persisted_client.remove_cached("cached/c").await.is_err());

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn upload_sessions_survive_server_restart_and_complete() -> Result<()> {
        let bind = "127.0.0.1:19238";
        let server_data_dir = fresh_data_dir("upload-session-restart-server");
        let node_id = Uuid::new_v4().to_string();
        let base_url = format!("http://{bind}");
        let http = reqwest::Client::new();

        let mut server = start_open_server_with_config(bind, &server_data_dir, &node_id, 1).await?;

        let payload = vec![b'U'; (CHUNK_UPLOAD_THRESHOLD_BYTES * 2) + 333];
        let start_response = http
            .post(format!("{base_url}/store/uploads/start"))
            .header("content-type", "application/json")
            .body(
                serde_json::to_vec(&json!({
                    "key": "resumable/upload.bin",
                    "total_size_bytes": payload.len(),
                }))
                .context("failed to encode upload session start request")?,
            )
            .send()
            .await?;
        assert_eq!(start_response.status(), reqwest::StatusCode::CREATED);
        let start_json = start_response
            .json::<serde_json::Value>()
            .await
            .context("failed to decode upload session start response")?;
        let upload_id = start_json
            .get("upload_id")
            .and_then(|value| value.as_str())
            .context("upload session start response missing upload_id")?
            .to_string();

        let first_chunk_response = http
            .put(format!("{base_url}/store/uploads/{upload_id}/chunk/0"))
            .body(payload[..CHUNK_UPLOAD_THRESHOLD_BYTES].to_vec())
            .send()
            .await?;
        assert_eq!(first_chunk_response.status(), reqwest::StatusCode::OK);

        stop_server(&mut server).await;
        server = start_open_server_with_config(bind, &server_data_dir, &node_id, 1).await?;

        let session_after_restart = http
            .get(format!("{base_url}/store/uploads/{upload_id}"))
            .send()
            .await?;
        assert_eq!(session_after_restart.status(), reqwest::StatusCode::OK);
        let session_json = session_after_restart
            .json::<serde_json::Value>()
            .await
            .context("failed to decode upload session after restart")?;
        assert_eq!(
            session_json
                .get("received_indexes")
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_default(),
            vec![serde_json::Value::from(0_u64)]
        );

        for (index, chunk) in payload
            .chunks(CHUNK_UPLOAD_THRESHOLD_BYTES)
            .enumerate()
            .skip(1)
        {
            let response = http
                .put(format!(
                    "{base_url}/store/uploads/{upload_id}/chunk/{index}"
                ))
                .body(chunk.to_vec())
                .send()
                .await?;
            assert_eq!(response.status(), reqwest::StatusCode::OK);
        }

        let complete_response = http
            .post(format!("{base_url}/store/uploads/{upload_id}/complete"))
            .send()
            .await?;
        assert_eq!(complete_response.status(), reqwest::StatusCode::OK);

        let sdk = IronMeshClient::from_direct_base_url(&base_url);
        let fetched = sdk.get("resumable/upload.bin").await?;
        assert_eq!(fetched, Bytes::from(payload));

        stop_server(&mut server).await;
        Ok(())
    }

    #[tokio::test]
    async fn ironmesh_client_resumable_file_helpers_roundtrip_large_files() -> Result<()> {
        let bind = "127.0.0.1:19239";
        let (mut server, enrolled) = start_authenticated_test_client(
            bind,
            "resumable-file-helpers-server",
            "resumable-file-helpers-client",
        )
        .await?;
        let working_dir = fresh_data_dir("resumable-file-helpers-work");
        fs::create_dir_all(&working_dir)?;

        let sdk = enrolled.build_client_async().await?;
        let upload_source = working_dir.join("source.bin");
        let upload_state = working_dir.join("upload.state.json");
        let download_target = working_dir.join("downloaded.bin");
        let download_temp = working_dir.join("downloaded.part");
        let download_state = working_dir.join("download.state.json");
        let payload = vec![b'F'; (CHUNK_UPLOAD_THRESHOLD_BYTES * 2) + 517];
        fs::write(&upload_source, &payload)?;

        let upload_client = sdk.clone();
        let upload_source_clone = upload_source.clone();
        let upload_state_clone = upload_state.clone();
        let upload_report = tokio::task::spawn_blocking(move || {
            upload_client.put_file_resumable(
                "resumable/file.bin",
                &upload_source_clone,
                &upload_state_clone,
            )
        })
        .await
        .context("resumable file upload task join failed")??;
        assert!(matches!(upload_report.upload_mode, UploadMode::Chunked));
        assert!(!upload_state.exists());

        let head = sdk.head_object("resumable/file.bin", None, None).await?;
        let etag = head
            .etag
            .context("missing etag on resumable download head response")?;

        fs::write(&download_temp, &payload[..CHUNK_UPLOAD_THRESHOLD_BYTES])?;
        fs::write(
            &download_state,
            serde_json::to_vec_pretty(&json!({
                "key": "resumable/file.bin",
                "snapshot": null,
                "version": null,
                "expected_size_bytes": payload.len(),
                "etag": etag,
            }))?,
        )?;

        let download_client = sdk.clone();
        let download_target_clone = download_target.clone();
        let download_temp_clone = download_temp.clone();
        let download_state_clone = download_state.clone();
        tokio::task::spawn_blocking(move || {
            download_client.download_file_resumable(
                "resumable/file.bin",
                None,
                None,
                &download_target_clone,
                &download_temp_clone,
                &download_state_clone,
            )
        })
        .await
        .context("resumable file download task join failed")??;

        assert_eq!(fs::read(&download_target)?, payload);
        assert!(!download_temp.exists());
        assert!(!download_state.exists());

        stop_server(&mut server).await;
        Ok(())
    }

    #[tokio::test]
    async fn ironmesh_client_staged_writer_download_roundtrip() -> Result<()> {
        let bind = "127.0.0.1:19240";
        let (mut server, enrolled) = start_authenticated_test_client(
            bind,
            "staged-writer-download-server",
            "staged-writer-download-client",
        )
        .await?;
        let working_dir = fresh_data_dir("staged-writer-download-work");
        fs::create_dir_all(&working_dir)?;

        let sdk = enrolled.build_client_async().await?;
        let payload = vec![b'S'; (CHUNK_UPLOAD_THRESHOLD_BYTES * 2) + 211];
        sdk.put_large_aware("staged-writer/file.bin", Bytes::from(payload.clone()))
            .await?;

        let staged_client = sdk.clone();
        let working_dir_clone = working_dir.clone();
        let downloaded = tokio::task::spawn_blocking(move || {
            let mut buffer = Vec::new();
            staged_client.download_to_writer_resumable_staged(
                "staged-writer/file.bin",
                None,
                None,
                &mut buffer,
                &working_dir_clone,
            )?;
            Ok::<Vec<u8>, anyhow::Error>(buffer)
        })
        .await
        .context("staged writer download task join failed")??;

        assert_eq!(downloaded, payload);

        stop_server(&mut server).await;
        Ok(())
    }

}
