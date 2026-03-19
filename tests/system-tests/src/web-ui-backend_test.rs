#![cfg(test)]

#[cfg(test)]
mod tests {
    use crate::framework::{
        ChildGuard, binary_path, start_server, stop_server, wait_for_url_status,
    };
    use anyhow::{Context, Result};
    use reqwest::StatusCode;
    use std::process::Stdio;
    use tokio::process::Command;

    const CHUNK_UPLOAD_THRESHOLD_BYTES: usize = 1024 * 1024;

    async fn start_web_backend(bind: &str, server_url: &str) -> Result<ChildGuard> {
        let cli_bin = binary_path("cli-client")?;
        let child = Command::new(cli_bin)
            .arg("--server-url")
            .arg(server_url)
            .arg("serve-web")
            .arg("--bind")
            .arg(bind)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("failed to spawn cli-client serve-web")?;

        wait_for_url_status(&format!("http://{bind}/api/ping"), StatusCode::OK, 40).await?;
        Ok(ChildGuard::new(child))
    }

    #[tokio::test]
    async fn web_ui_backend_serves_react_client_ui_assets() -> Result<()> {
        let server_bind = "127.0.0.1:19378";
        let web_bind = "127.0.0.1:19379";
        let server_base = format!("http://{server_bind}");
        let web_base = format!("http://{web_bind}");
        let client = reqwest::Client::new();

        let mut server = start_server(server_bind).await?;
        let mut web = start_web_backend(web_bind, &server_base).await?;

        let result = async {
            let html = client
                .get(format!("{web_base}/"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert!(html.contains("Client UI"));
            assert!(html.contains("/app.js"));
            assert!(html.contains("/app.css"));

            let js = client
                .get(format!("{web_base}/app.js"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert!(js.contains("Transport-aware"));

            let css = client
                .get(format!("{web_base}/app.css"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert!(css.contains("radial-gradient"));

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut web).await;
        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn web_ui_backend_text_store_roundtrip() -> Result<()> {
        let server_bind = "127.0.0.1:19380";
        let web_bind = "127.0.0.1:19381";
        let server_base = format!("http://{server_bind}");
        let web_base = format!("http://{web_bind}");
        let key = "ui-text.txt";
        let value = "hello-from-web-ui-backend";
        let client = reqwest::Client::new();

        let mut server = start_server(server_bind).await?;
        let mut web = start_web_backend(web_bind, &server_base).await?;

        let result = async {
            let put_payload = serde_json::json!({
                "key": key,
                "value": value
            });

            let put_resp: serde_json::Value = client
                .post(format!("{web_base}/api/store/put"))
                .json(&put_payload)
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            assert_eq!(put_resp.get("key").and_then(|v| v.as_str()), Some(key));
            assert_eq!(
                put_resp.get("size_bytes").and_then(|v| v.as_u64()),
                Some(value.len() as u64)
            );

            let get_resp: serde_json::Value = client
                .get(format!("{web_base}/api/store/get"))
                .query(&[("key", key)])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            assert_eq!(get_resp.get("key").and_then(|v| v.as_str()), Some(key));
            assert_eq!(get_resp.get("value").and_then(|v| v.as_str()), Some(value));

            let upstream = client
                .get(format!("{server_base}/store/{key}"))
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;
            assert_eq!(upstream, value);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut web).await;
        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn web_ui_backend_binary_chunked_roundtrip() -> Result<()> {
        let server_bind = "127.0.0.1:19382";
        let web_bind = "127.0.0.1:19383";
        let server_base = format!("http://{server_bind}");
        let web_base = format!("http://{web_bind}");
        let key = "ui-large.bin";
        let mut payload = vec![b'B'; CHUNK_UPLOAD_THRESHOLD_BYTES + 128];
        payload[0..6].copy_from_slice(b"BEGIN:");
        let payload_len = payload.len();
        let client = reqwest::Client::new();

        let mut server = start_server(server_bind).await?;
        let mut web = start_web_backend(web_bind, &server_base).await?;

        let result = async {
            let put_resp: serde_json::Value = client
                .post(format!("{web_base}/api/store/put-binary"))
                .query(&[("key", key)])
                .body(payload.clone())
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            assert_eq!(put_resp.get("key").and_then(|v| v.as_str()), Some(key));
            assert_eq!(
                put_resp.get("size_bytes").and_then(|v| v.as_u64()),
                Some(payload_len as u64)
            );
            assert_eq!(
                put_resp.get("upload_mode").and_then(|v| v.as_str()),
                Some("chunked")
            );

            let response = client
                .get(format!("{web_base}/api/store/get-binary"))
                .query(&[("key", key)])
                .send()
                .await?
                .error_for_status()?;

            assert_eq!(
                response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/octet-stream")
            );

            let disposition = response
                .headers()
                .get(reqwest::header::CONTENT_DISPOSITION)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            assert!(disposition.contains("attachment;"));
            assert!(disposition.contains("filename=\"ui-large.bin\""));

            let body = response.bytes().await?;
            assert_eq!(body.as_ref(), payload.as_slice());

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut web).await;
        stop_server(&mut server).await;
        result
    }

    #[tokio::test]
    async fn web_ui_backend_store_list_and_delete_flow() -> Result<()> {
        let server_bind = "127.0.0.1:19384";
        let web_bind = "127.0.0.1:19385";
        let server_base = format!("http://{server_bind}");
        let web_base = format!("http://{web_bind}");
        let client = reqwest::Client::new();

        let mut server = start_server(server_bind).await?;
        let mut web = start_web_backend(web_bind, &server_base).await?;

        let result = async {
            for (key, value) in [
                ("docs/guide/intro.md", "intro"),
                ("docs/guide/setup.md", "setup"),
                ("docs/api/v1.json", "api"),
            ] {
                let payload = serde_json::json!({
                    "key": key,
                    "value": value,
                });
                client
                    .post(format!("{web_base}/api/store/put"))
                    .json(&payload)
                    .send()
                    .await?
                    .error_for_status()?;
            }

            let list_resp: serde_json::Value = client
                .get(format!("{web_base}/api/store/list"))
                .query(&[("prefix", "docs"), ("depth", "1")])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;

            let paths = list_resp
                .get("entries")
                .and_then(|v| v.as_array())
                .map(|entries| {
                    entries
                        .iter()
                        .filter_map(|entry| entry.get("path").and_then(|v| v.as_str()))
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                })
                .context("missing entries in /api/store/list response")?;
            assert!(paths.contains(&"docs/api/".to_string()));
            assert!(paths.contains(&"docs/guide/".to_string()));

            let delete_key = "web-delete.txt";
            let delete_payload = serde_json::json!({
                "key": delete_key,
                "value": "to-delete",
            });
            client
                .post(format!("{web_base}/api/store/put"))
                .json(&delete_payload)
                .send()
                .await?
                .error_for_status()?;

            let delete_resp: serde_json::Value = client
                .delete(format!("{web_base}/api/store/delete"))
                .query(&[("key", delete_key)])
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            assert_eq!(
                delete_resp.get("deleted").and_then(|v| v.as_bool()),
                Some(true)
            );
            assert_eq!(
                delete_resp.get("key").and_then(|v| v.as_str()),
                Some(delete_key)
            );

            let get_deleted = client
                .get(format!("{web_base}/api/store/get"))
                .query(&[("key", delete_key)])
                .send()
                .await?;
            assert_eq!(get_deleted.status(), StatusCode::BAD_GATEWAY);

            let upstream_deleted = client
                .get(format!("{server_base}/store/{delete_key}"))
                .send()
                .await?;
            assert_eq!(upstream_deleted.status(), StatusCode::NOT_FOUND);

            Ok::<(), anyhow::Error>(())
        }
        .await;

        stop_server(&mut web).await;
        stop_server(&mut server).await;
        result
    }
}
