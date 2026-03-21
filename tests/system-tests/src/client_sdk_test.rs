#[cfg(test)]
mod tests {
    const CHUNK_UPLOAD_THRESHOLD_BYTES: usize = 1024 * 1024;

    use std::io::Cursor;

    use anyhow::{Context, Result};
    use bytes::Bytes;
    use client_sdk::{ClientNode, ContentAddressedClientCache, UploadMode};
    use uuid::Uuid;

    use crate::framework::{
        EnrolledTestClient, TEST_ADMIN_TOKEN, fresh_data_dir,
        issue_bootstrap_bundle_and_enroll_client, latest_snapshot_id_for_client,
        start_authenticated_server, stop_server,
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
            let blocking_client = client.clone();
            tokio::task::spawn_blocking(move || -> Result<()> {
                let mut reader = Cursor::new(chunked_payload);
                let report = blocking_client.put_chunked_reader(chunked_key, &mut reader)?;
                assert!(matches!(report.upload_mode, UploadMode::Chunked));
                Ok(())
            })
            .await
            .context("put_chunked_reader task join failed")??;

            let entries = client.cache_entries().await;
            assert!(
                !entries.iter().any(|entry| entry.key == chunked_key),
                "put_chunked_reader should invalidate cached entry for the key"
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
                let mut reader = Cursor::new(payload);
                chunked_reader_sdk.put_chunked_reader("reader/chunked", &mut reader)
            })
            .await
            .context("put_chunked_reader task join failed")??;

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
}
