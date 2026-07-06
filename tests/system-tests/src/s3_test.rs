#![cfg(test)]

#[cfg(test)]
mod tests {
    use crate::framework::{
        TEST_ADMIN_TOKEN, fresh_data_dir, start_authenticated_server_with_env_options, stop_server,
    };
    use anyhow::{Context, Result, bail};
    use hmac::{Hmac, Mac};
    use reqwest::{Method, StatusCode};
    use sha2::{Digest, Sha256};
    use std::time::Duration;
    use tokio::time::sleep;

    type TestHmacSha256 = Hmac<Sha256>;

    fn s3_test_hex_encode(bytes: &[u8]) -> String {
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push_str(&format!("{byte:02x}"));
        }
        encoded
    }

    fn s3_test_sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        s3_test_hex_encode(&hasher.finalize())
    }

    fn s3_test_hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
        let mut mac = TestHmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary keys");
        mac.update(data);
        let bytes = mac.finalize().into_bytes();
        let mut output = [0_u8; 32];
        output.copy_from_slice(&bytes);
        output
    }

    fn s3_test_derive_signing_key(
        secret_material: &str,
        date_scope: &str,
        region: &str,
        service: &str,
    ) -> Vec<u8> {
        let secret_key = format!("AWS4{secret_material}");
        let date_key = s3_test_hmac_sha256(secret_key.as_bytes(), date_scope.as_bytes());
        let region_key = s3_test_hmac_sha256(&date_key, region.as_bytes());
        let service_key = s3_test_hmac_sha256(&region_key, service.as_bytes());
        s3_test_hmac_sha256(&service_key, b"aws4_request").to_vec()
    }

    fn s3_canonical_query(url: &reqwest::Url) -> String {
        let mut pairs = url
            .query()
            .unwrap_or_default()
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                (name.to_string(), value.to_string())
            })
            .collect::<Vec<_>>();
        pairs.sort();
        pairs
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("&")
    }

    async fn send_signed_s3_request(
        client: &reqwest::Client,
        s3_base_url: &str,
        method: Method,
        path_and_query: &str,
        access_key_id: &str,
        secret_material: &str,
        extra_headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<reqwest::Response> {
        let host = s3_base_url
            .trim_end_matches('/')
            .strip_prefix("http://")
            .or_else(|| {
                s3_base_url
                    .trim_end_matches('/')
                    .strip_prefix("https://")
            })
            .context("S3 base URL must start with http:// or https://")?;
        let url = format!("{}{path_and_query}", s3_base_url.trim_end_matches('/'));
        let parsed_url = reqwest::Url::parse(&url)
            .with_context(|| format!("failed parsing signed S3 request URL {url}"))?;
        let amz_date = "20260706T120000Z";
        let date_scope = "20260706";
        let region = "us-east-1";
        let service = "s3";
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let payload_hash = s3_test_sha256_hex(&body);
        let canonical_request = format!(
            "{}\n{}\n{}\nhost:{host}\nx-amz-content-sha256:{payload_hash}\nx-amz-date:{amz_date}\n\n{signed_headers}\n{payload_hash}",
            method.as_str(),
            parsed_url.path(),
            s3_canonical_query(&parsed_url),
        );
        let credential_scope = format!("{date_scope}/{region}/{service}/aws4_request");
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            s3_test_sha256_hex(canonical_request.as_bytes())
        );
        let signing_key = s3_test_derive_signing_key(secret_material, date_scope, region, service);
        let signature = s3_test_hex_encode(&s3_test_hmac_sha256(
            &signing_key,
            string_to_sign.as_bytes(),
        ));
        let authorization = format!(
            "AWS4-HMAC-SHA256 Credential={access_key_id}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}"
        );

        let mut request = client
            .request(method, parsed_url)
            .header("host", host)
            .header("x-amz-date", amz_date)
            .header("x-amz-content-sha256", &payload_hash)
            .header("authorization", authorization);
        for (name, value) in extra_headers {
            request = request.header(*name, *value);
        }

        request
            .body(body)
            .send()
            .await
            .context("signed S3 request failed")
    }

    async fn wait_for_signed_s3_status(
        client: &reqwest::Client,
        s3_base_url: &str,
        method: Method,
        path_and_query: &str,
        access_key_id: &str,
        secret_material: &str,
        expected_status: StatusCode,
    ) -> Result<()> {
        let mut last_error = None;
        for _ in 0..60 {
            match send_signed_s3_request(
                client,
                s3_base_url,
                method.clone(),
                path_and_query,
                access_key_id,
                secret_material,
                &[],
                Vec::new(),
            )
            .await
            {
                Ok(response) if response.status() == expected_status => return Ok(()),
                Ok(response) => {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    last_error =
                        Some(format!("unexpected status {status} while waiting for listener: {body}"));
                }
                Err(err) => last_error = Some(err.to_string()),
            }
            sleep(Duration::from_millis(250)).await;
        }

        bail!(
            "dedicated S3 listener at {s3_base_url} did not become ready: {}",
            last_error.unwrap_or_else(|| "unknown error".to_string())
        );
    }

    fn json_bool(value: &serde_json::Value, key: &str) -> Result<bool> {
        value
            .get(key)
            .and_then(|value| value.as_bool())
            .with_context(|| format!("JSON field {key} missing or not a boolean"))
    }

    fn json_string(value: &serde_json::Value, key: &str) -> Result<String> {
        value
            .get(key)
            .and_then(|value| value.as_str())
            .map(ToString::to_string)
            .with_context(|| format!("JSON field {key} missing or not a string"))
    }

    #[tokio::test]
    async fn dedicated_s3_listener_serves_signed_crud_and_listing() -> Result<()> {
        let public_bind = "127.0.0.1:19460";
        let s3_bind = "127.0.0.1:19461";
        let data_dir = fresh_data_dir("s3-listener-runtime");
        let mut server = start_authenticated_server_with_env_options(
            public_bind,
            &data_dir,
            "s3-runtime-node",
            1,
            None,
            None,
            &[("IRONMESH_S3_BIND", s3_bind)],
        )
        .await?;

        let http = reqwest::Client::builder()
            .build()
            .context("failed building system test HTTP client")?;
        let public_base = format!("http://{public_bind}");
        let s3_base = format!("http://{s3_bind}");

        let result: Result<()> = async {
            let status_response = http
                .get(format!("{public_base}/auth/s3/status"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .send()
                .await?
                .error_for_status()?;
            let status_json: serde_json::Value = status_response.json().await?;
            assert!(json_bool(&status_json, "listener_enabled")?);
            assert!(!json_bool(&status_json, "tls_enabled")?);
            assert_eq!(json_string(&status_json, "public_url")?, s3_base);

            let create_bucket_response = http
                .post(format!("{public_base}/auth/s3/buckets"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "bucket_name": "photos.example",
                    "root_prefix": "tenant/photos",
                    "versioning_status": "enabled",
                    "read_only": false
                }))
                .send()
                .await?;
            assert_eq!(create_bucket_response.status(), StatusCode::CREATED);

            let create_access_key_response = http
                .post(format!("{public_base}/auth/s3/access-keys"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "description": "system-test-s3-listener",
                    "bucket_scope": ["photos.example"],
                    "prefix_scope": ["tenant/photos/"],
                    "allow_list": true,
                    "allow_read": true,
                    "allow_write": true,
                    "allow_delete": true,
                    "allow_manage": false
                }))
                .send()
                .await?;
            assert_eq!(create_access_key_response.status(), StatusCode::CREATED);
            let create_access_key_json: serde_json::Value =
                create_access_key_response.json().await?;
            let access_key_id = json_string(&create_access_key_json, "access_key_id")?;
            let secret_access_key = json_string(&create_access_key_json, "secret_access_key")?;

            wait_for_signed_s3_status(
                &http,
                &s3_base,
                Method::GET,
                "/",
                &access_key_id,
                &secret_access_key,
                StatusCode::OK,
            )
            .await?;

            let list_buckets = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(list_buckets.status(), StatusCode::OK);
            let list_buckets_xml = list_buckets.text().await?;
            assert!(list_buckets_xml.contains("<Name>photos.example</Name>"));

            let payload = b"hello from the networked S3 listener".to_vec();
            let put_object = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/photos.example/docs/hello.txt",
                &access_key_id,
                &secret_access_key,
                &[
                    ("content-type", "text/plain"),
                    ("cache-control", "max-age=60"),
                    ("x-amz-meta-color", "blue"),
                ],
                payload.clone(),
            )
            .await?;
            assert_eq!(put_object.status(), StatusCode::OK);
            let put_etag = put_object
                .headers()
                .get(reqwest::header::ETAG)
                .and_then(|value| value.to_str().ok())
                .context("PUT response missing ETag")?
                .to_string();
            let put_version_id = put_object
                .headers()
                .get("x-amz-version-id")
                .and_then(|value| value.to_str().ok())
                .context("PUT response missing x-amz-version-id")?
                .to_string();
            assert!(put_etag.starts_with('"'));
            assert!(!put_version_id.is_empty());

            let put_nested = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/photos.example/docs/nested/world.txt",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "text/plain")],
                b"nested payload".to_vec(),
            )
            .await?;
            assert_eq!(put_nested.status(), StatusCode::OK);

            let head_object = send_signed_s3_request(
                &http,
                &s3_base,
                Method::HEAD,
                "/photos.example/docs/hello.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(head_object.status(), StatusCode::OK);
            assert_eq!(
                head_object
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("text/plain")
            );
            assert_eq!(
                head_object
                    .headers()
                    .get(reqwest::header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some("max-age=60")
            );
            assert_eq!(
                head_object
                    .headers()
                    .get("x-amz-meta-color")
                    .and_then(|value| value.to_str().ok()),
                Some("blue")
            );
            assert_eq!(
                head_object
                    .headers()
                    .get(reqwest::header::ETAG)
                    .and_then(|value| value.to_str().ok()),
                Some(put_etag.as_str())
            );

            let get_object = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/photos.example/docs/hello.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_object.status(), StatusCode::OK);
            assert_eq!(
                get_object
                    .headers()
                    .get("x-amz-version-id")
                    .and_then(|value| value.to_str().ok()),
                Some(put_version_id.as_str())
            );
            assert_eq!(get_object.bytes().await?.as_ref(), payload.as_slice());

            let list_objects = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/photos.example?list-type=2&prefix=docs/&delimiter=/",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(list_objects.status(), StatusCode::OK);
            let list_objects_xml = list_objects.text().await?;
            assert!(list_objects_xml.contains("<Key>docs/hello.txt</Key>"));
            assert!(list_objects_xml.contains(
                "<CommonPrefixes><Prefix>docs/nested/</Prefix></CommonPrefixes>"
            ));

            let delete_object = send_signed_s3_request(
                &http,
                &s3_base,
                Method::DELETE,
                "/photos.example/docs/hello.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(delete_object.status(), StatusCode::NO_CONTENT);
            let delete_version_id = delete_object
                .headers()
                .get("x-amz-version-id")
                .and_then(|value| value.to_str().ok())
                .context("DELETE response missing x-amz-version-id")?
                .to_string();
            assert_ne!(delete_version_id, put_version_id);

            let get_deleted = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/photos.example/docs/hello.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_deleted.status(), StatusCode::NOT_FOUND);
            let deleted_xml = get_deleted.text().await?;
            assert!(deleted_xml.contains("<Code>NoSuchKey</Code>"));

            Ok(())
        }
        .await;

        stop_server(&mut server).await;
        result?;
        Ok(())
    }
}
