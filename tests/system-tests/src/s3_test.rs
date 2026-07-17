#![cfg(test)]

#[cfg(test)]
mod tests {
    use crate::framework::{
        ChildGuard, TEST_ADMIN_TOKEN, binary_path, default_client_identity_path, fresh_data_dir,
        issue_bootstrap_bundle_and_enroll_client, lock_test_resources, register_node,
        start_authenticated_server_with_env_options, start_rendezvous_service, stop_server,
        tcp_resource_key, wait_for_online_nodes, wait_for_rendezvous_registered_endpoints,
    };
    use anyhow::{Context, Result, bail};
    use aws_credential_types::Credentials;
    use aws_sdk_s3::{
        Client as AwsS3Client,
        config::{BehaviorVersion, RequestChecksumCalculation, ResponseChecksumValidation},
        primitives::ByteStream,
    };
    use aws_types::region::Region;
    use hmac::{Hmac, Mac};
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
    use reqwest::{Method, StatusCode};
    use sha2::{Digest, Sha256};
    use std::process::Stdio;
    use std::time::Duration;
    use time::OffsetDateTime;
    use tokio::process::Command;
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

    fn sigv4_timestamp_components(unix_ts: i64) -> (String, String) {
        let timestamp = OffsetDateTime::from_unix_timestamp(unix_ts)
            .unwrap_or(OffsetDateTime::UNIX_EPOCH)
            .to_offset(time::UtcOffset::UTC);
        let year = timestamp.year();
        let month = timestamp.month() as u8;
        let day = timestamp.day();
        let hour = timestamp.hour();
        let minute = timestamp.minute();
        let second = timestamp.second();
        (
            format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}Z"),
            format!("{year:04}{month:02}{day:02}"),
        )
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
            .or_else(|| s3_base_url.trim_end_matches('/').strip_prefix("https://"))
            .context("S3 base URL must start with http:// or https://")?;
        send_signed_s3_request_with_host(
            client,
            s3_base_url,
            host,
            method,
            path_and_query,
            access_key_id,
            secret_material,
            extra_headers,
            body,
        )
        .await
    }

    async fn send_signed_s3_request_with_host(
        client: &reqwest::Client,
        s3_base_url: &str,
        host: &str,
        method: Method,
        path_and_query: &str,
        access_key_id: &str,
        secret_material: &str,
        extra_headers: &[(&str, &str)],
        body: Vec<u8>,
    ) -> Result<reqwest::Response> {
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
        let signing_key = s3_test_derive_signing_key(secret_material, &date_scope, region, service);
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

    fn build_presigned_s3_url(
        s3_base_url: &str,
        method: &Method,
        path_and_query: &str,
        access_key_id: &str,
        secret_material: &str,
    ) -> Result<String> {
        let host = s3_base_url
            .trim_end_matches('/')
            .strip_prefix("http://")
            .or_else(|| s3_base_url.trim_end_matches('/').strip_prefix("https://"))
            .context("S3 base URL must start with http:// or https://")?;
        let url = format!("{}{path_and_query}", s3_base_url.trim_end_matches('/'));
        let parsed_url = reqwest::Url::parse(&url)
            .with_context(|| format!("failed parsing presigned S3 request URL {url}"))?;
        let (amz_date, date_scope) =
            sigv4_timestamp_components(OffsetDateTime::now_utc().unix_timestamp());
        let region = "us-east-1";
        let service = "s3";
        let expires = "900";
        let signed_headers = "host";
        let payload_hash = "UNSIGNED-PAYLOAD";
        let credential_scope = format!("{date_scope}/{region}/{service}/aws4_request");
        let credential_value = utf8_percent_encode(
            &format!("{access_key_id}/{credential_scope}"),
            NON_ALPHANUMERIC,
        )
        .to_string();

        let mut pairs = parsed_url
            .query()
            .unwrap_or_default()
            .split('&')
            .filter(|pair| !pair.is_empty())
            .map(|pair| {
                let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                (name.to_string(), value.to_string())
            })
            .collect::<Vec<_>>();
        pairs.push((
            "X-Amz-Algorithm".to_string(),
            "AWS4-HMAC-SHA256".to_string(),
        ));
        pairs.push(("X-Amz-Credential".to_string(), credential_value));
        pairs.push(("X-Amz-Date".to_string(), amz_date.clone()));
        pairs.push(("X-Amz-Expires".to_string(), expires.to_string()));
        pairs.push((
            "X-Amz-SignedHeaders".to_string(),
            signed_headers.to_string(),
        ));
        pairs.sort();

        let canonical_query = pairs
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("&");
        let canonical_request = format!(
            "{}\n{}\n{}\nhost:{host}\n\n{signed_headers}\n{payload_hash}",
            method.as_str(),
            parsed_url.path(),
            canonical_query,
        );
        let string_to_sign = format!(
            "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
            s3_test_sha256_hex(canonical_request.as_bytes())
        );
        let signing_key = s3_test_derive_signing_key(secret_material, &date_scope, region, service);
        let signature = s3_test_hex_encode(&s3_test_hmac_sha256(
            &signing_key,
            string_to_sign.as_bytes(),
        ));

        Ok(format!(
            "{}{}?{}&X-Amz-Signature={signature}",
            s3_base_url.trim_end_matches('/'),
            parsed_url.path(),
            canonical_query
        ))
    }

    async fn send_presigned_s3_request(
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
            .or_else(|| s3_base_url.trim_end_matches('/').strip_prefix("https://"))
            .context("S3 base URL must start with http:// or https://")?;
        let presigned_url = build_presigned_s3_url(
            s3_base_url,
            &method,
            path_and_query,
            access_key_id,
            secret_material,
        )?;

        let mut request = client.request(method, presigned_url).header("host", host);
        for (name, value) in extra_headers {
            request = request.header(*name, *value);
        }
        request
            .body(body)
            .send()
            .await
            .context("presigned S3 request failed")
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
                    last_error = Some(format!(
                        "unexpected status {status} while waiting for listener: {body}"
                    ));
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

    fn xml_tag_text(xml: &str, tag: &str) -> Option<String> {
        let start_tag = format!("<{tag}>");
        let end_tag = format!("</{tag}>");
        let start = xml.find(&start_tag)? + start_tag.len();
        let end = start + xml[start..].find(&end_tag)?;
        Some(xml[start..end].to_string())
    }

    async fn start_cli_s3_gateway(bind: &str, cli_args: &[&str]) -> Result<ChildGuard> {
        let cli_bin = binary_path("cli-client")?;
        let resource_guards = lock_test_resources([tcp_resource_key(bind)]).await;
        let child = Command::new(cli_bin)
            .args(cli_args)
            .arg("serve-s3")
            .arg("--bind")
            .arg(bind)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .context("failed to spawn cli-client serve-s3")?;
        Ok(ChildGuard::with_resources(child, resource_guards))
    }

    async fn wait_for_s3_control_plane_status(
        http: &reqwest::Client,
        base_url: &str,
        expected_bucket_count: u64,
        expected_access_key_count: u64,
        expected_last_source_node_id: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut last_payload = None;
        for _ in 0..120 {
            if let Ok(response) = http
                .get(format!("{base_url}/auth/s3/status"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .send()
                .await
                && let Ok(ok_response) = response.error_for_status()
                && let Ok(payload) = ok_response.json::<serde_json::Value>().await
            {
                let bucket_count = payload
                    .get("bucket_count")
                    .and_then(|value| value.as_u64())
                    .unwrap_or_default();
                let access_key_count = payload
                    .get("access_key_count")
                    .and_then(|value| value.as_u64())
                    .unwrap_or_default();
                let last_source_node_id = payload
                    .get("last_source_node_id")
                    .and_then(|value| value.as_str());

                last_payload = Some(payload.clone());
                if bucket_count == expected_bucket_count
                    && access_key_count == expected_access_key_count
                    && expected_last_source_node_id
                        .is_none_or(|expected| last_source_node_id == Some(expected))
                {
                    return Ok(payload);
                }
            }

            sleep(Duration::from_millis(250)).await;
        }

        bail!(
            "S3 control-plane status at {base_url}/auth/s3/status did not reach bucket_count={}, access_key_count={}, last_source_node_id={:?}; last payload: {:?}",
            expected_bucket_count,
            expected_access_key_count,
            expected_last_source_node_id,
            last_payload
        );
    }

    fn build_aws_sdk_s3_client(
        endpoint_url: &str,
        access_key_id: &str,
        secret_access_key: &str,
    ) -> AwsS3Client {
        let config = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(Credentials::new(
                access_key_id,
                secret_access_key,
                None,
                None,
                "system-tests",
            ))
            .endpoint_url(endpoint_url)
            .force_path_style(true)
            .region(Region::new("us-east-1"))
            .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
            .response_checksum_validation(ResponseChecksumValidation::WhenRequired)
            .build();
        AwsS3Client::from_conf(config)
    }

    async fn exercise_aws_sdk_s3_crud(
        endpoint_url: &str,
        access_key_id: &str,
        secret_access_key: &str,
        bucket_name: &str,
        object_key: &str,
        body: Vec<u8>,
    ) -> Result<()> {
        let client = build_aws_sdk_s3_client(endpoint_url, access_key_id, secret_access_key);

        let list_buckets = match client.list_buckets().send().await {
            Ok(output) => output,
            Err(error) => {
                let raw_summary = error.raw_response().map(|response| {
                    let body = response
                        .body()
                        .bytes()
                        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                        .unwrap_or_else(|| "<streaming body unavailable>".to_string());
                    format!("status={} body={body:?}", response.status())
                });
                bail!("AWS SDK list_buckets failed: {error:#}; raw_response={raw_summary:?}");
            }
        };
        assert!(
            list_buckets
                .buckets()
                .iter()
                .any(|bucket| bucket.name().is_some_and(|name| name == bucket_name))
        );

        client
            .put_object()
            .bucket(bucket_name)
            .key(object_key)
            .content_type("application/octet-stream")
            .body(ByteStream::from(body.clone()))
            .send()
            .await
            .context("AWS SDK put_object failed")?;

        let head_object = client
            .head_object()
            .bucket(bucket_name)
            .key(object_key)
            .send()
            .await
            .context("AWS SDK head_object failed")?;
        assert_eq!(head_object.content_length(), Some(body.len() as i64));
        assert!(head_object.e_tag().is_some_and(|etag| !etag.is_empty()));
        assert!(
            head_object
                .version_id()
                .is_some_and(|version_id| !version_id.is_empty())
        );

        let get_object = client
            .get_object()
            .bucket(bucket_name)
            .key(object_key)
            .send()
            .await
            .context("AWS SDK get_object failed")?;
        let get_object_body = get_object
            .body
            .collect()
            .await
            .context("AWS SDK get_object body collection failed")?
            .into_bytes();
        assert_eq!(get_object_body.as_ref(), body.as_slice());

        let list_objects = match client
            .list_objects_v2()
            .bucket(bucket_name)
            .prefix(object_key)
            .send()
            .await
        {
            Ok(output) => output,
            Err(error) => {
                let raw_summary = error.raw_response().map(|response| {
                    let body = response
                        .body()
                        .bytes()
                        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                        .unwrap_or_else(|| "<streaming body unavailable>".to_string());
                    format!("status={} body={body:?}", response.status())
                });
                bail!(
                    "AWS SDK list_objects_v2 after put failed: {error:#}; raw_response={raw_summary:?}"
                );
            }
        };
        assert!(
            list_objects
                .contents()
                .iter()
                .any(|object| object.key().is_some_and(|key| key == object_key))
        );

        client
            .delete_object()
            .bucket(bucket_name)
            .key(object_key)
            .send()
            .await
            .context("AWS SDK delete_object failed")?;

        let list_objects_after_delete = match client
            .list_objects_v2()
            .bucket(bucket_name)
            .prefix(object_key)
            .send()
            .await
        {
            Ok(output) => output,
            Err(error) => {
                let raw_summary = error.raw_response().map(|response| {
                    let body = response
                        .body()
                        .bytes()
                        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
                        .unwrap_or_else(|| "<streaming body unavailable>".to_string());
                    format!("status={} body={body:?}", response.status())
                });
                bail!(
                    "AWS SDK list_objects_v2 after delete failed: {error:#}; raw_response={raw_summary:?}"
                );
            }
        };
        assert!(
            list_objects_after_delete
                .contents()
                .iter()
                .all(|object| object.key() != Some(object_key))
        );

        Ok(())
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
            assert!(
                list_objects_xml
                    .contains("<CommonPrefixes><Prefix>docs/nested/</Prefix></CommonPrefixes>")
            );

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

    #[tokio::test]
    async fn dedicated_s3_listener_serves_virtual_hosted_signed_crud_and_listing() -> Result<()> {
        let public_bind = "127.0.0.1:19464";
        let s3_bind = "127.0.0.1:19465";
        let s3_public_url = "http://s3.localhost:19465";
        let data_dir = fresh_data_dir("s3-virtual-hosted-runtime");
        let mut server = start_authenticated_server_with_env_options(
            public_bind,
            &data_dir,
            "s3-virtual-hosted-runtime-node",
            1,
            None,
            None,
            &[
                ("IRONMESH_S3_BIND", s3_bind),
                ("IRONMESH_S3_PUBLIC_URL", s3_public_url),
            ],
        )
        .await?;

        let http = reqwest::Client::builder()
            .build()
            .context("failed building system test HTTP client")?;
        let public_base = format!("http://{public_bind}");
        let s3_request_base = format!("http://{s3_bind}");

        let result: Result<()> = async {
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
                    "description": "system-test-s3-virtual-hosted",
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
                &s3_request_base,
                Method::GET,
                "/",
                &access_key_id,
                &secret_access_key,
                StatusCode::OK,
            )
            .await?;

            let virtual_host = "photos.example.s3.localhost:19465";

            let head_bucket = send_signed_s3_request_with_host(
                &http,
                &s3_request_base,
                virtual_host,
                Method::HEAD,
                "/",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(head_bucket.status(), StatusCode::OK);

            let list_objects = send_signed_s3_request_with_host(
                &http,
                &s3_request_base,
                virtual_host,
                Method::GET,
                "/?list-type=2",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(list_objects.status(), StatusCode::OK);
            let list_objects_xml = list_objects.text().await?;
            assert!(list_objects_xml.contains("<Name>photos.example</Name>"));

            let payload = b"virtual hosted system payload".to_vec();
            let put_object = send_signed_s3_request_with_host(
                &http,
                &s3_request_base,
                virtual_host,
                Method::PUT,
                "/hello.txt",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "text/plain")],
                payload.clone(),
            )
            .await?;
            assert_eq!(put_object.status(), StatusCode::OK);

            let get_object = send_signed_s3_request_with_host(
                &http,
                &s3_request_base,
                virtual_host,
                Method::GET,
                "/hello.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_object.status(), StatusCode::OK);
            assert_eq!(get_object.bytes().await?.as_ref(), payload.as_slice());

            let list_after_put = send_signed_s3_request_with_host(
                &http,
                &s3_request_base,
                virtual_host,
                Method::GET,
                "/?list-type=2&prefix=hello",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(list_after_put.status(), StatusCode::OK);
            let list_after_put_xml = list_after_put.text().await?;
            assert!(list_after_put_xml.contains("<Key>hello.txt</Key>"));

            Ok(())
        }
        .await;

        stop_server(&mut server).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_s3_listener_supports_aws_sdk_client() -> Result<()> {
        let public_bind = "127.0.0.1:19596";
        let s3_bind = "127.0.0.1:19597";
        let data_dir = fresh_data_dir("s3-listener-aws-sdk-runtime");
        let mut server = start_authenticated_server_with_env_options(
            public_bind,
            &data_dir,
            "s3-aws-sdk-runtime-node",
            1,
            None,
            None,
            &[("IRONMESH_S3_BIND", s3_bind)],
        )
        .await?;

        let http = reqwest::Client::new();
        let public_base = format!("http://{public_bind}");
        let s3_base = format!("http://{s3_bind}");

        let result: Result<()> = async {
            let create_bucket_response = http
                .post(format!("{public_base}/auth/s3/buckets"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "bucket_name": "sdk-listener.example",
                    "root_prefix": "tenant/sdk-listener",
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
                    "description": "system-test-s3-listener-aws-sdk",
                    "bucket_scope": ["sdk-listener.example"],
                    "prefix_scope": ["tenant/sdk-listener/"],
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

            let sdk_payload = (0..((256 * 1024) + 137))
                .map(|index| (index % 239) as u8)
                .collect::<Vec<_>>();
            exercise_aws_sdk_s3_crud(
                &s3_base,
                &access_key_id,
                &secret_access_key,
                "sdk-listener.example",
                "sdk/native-listener.bin",
                sdk_payload,
            )
            .await?;

            Ok(())
        }
        .await;

        stop_server(&mut server).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_s3_listener_serves_multipart_uploads() -> Result<()> {
        let public_bind = "127.0.0.1:19462";
        let s3_bind = "127.0.0.1:19463";
        let data_dir = fresh_data_dir("s3-listener-multipart-runtime");
        let mut server = start_authenticated_server_with_env_options(
            public_bind,
            &data_dir,
            "s3-multipart-runtime-node",
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
            let create_bucket_response = http
                .post(format!("{public_base}/auth/s3/buckets"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "bucket_name": "media.example",
                    "root_prefix": "tenant/media",
                    "versioning_status": "disabled",
                    "read_only": false
                }))
                .send()
                .await?;
            assert_eq!(create_bucket_response.status(), StatusCode::CREATED);

            let create_access_key_response = http
                .post(format!("{public_base}/auth/s3/access-keys"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "description": "system-test-s3-multipart",
                    "bucket_scope": ["media.example"],
                    "prefix_scope": ["tenant/media/"],
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

            let create_upload = send_signed_s3_request(
                &http,
                &s3_base,
                Method::POST,
                "/media.example/archive/movie.bin?uploads=",
                &access_key_id,
                &secret_access_key,
                &[
                    ("content-type", "application/octet-stream"),
                    ("x-amz-meta-origin", "camera"),
                ],
                Vec::new(),
            )
            .await?;
            assert_eq!(create_upload.status(), StatusCode::OK);
            let create_upload_xml = create_upload.text().await?;
            let upload_id = xml_tag_text(&create_upload_xml, "UploadId")
                .context("multipart initiation response missing UploadId")?;

            let part1_payload = vec![b'a'; 5 * 1024 * 1024];
            let part2_payload = b"tail".to_vec();

            let upload_part1 = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                &format!("/media.example/archive/movie.bin?partNumber=1&uploadId={upload_id}"),
                &access_key_id,
                &secret_access_key,
                &[],
                part1_payload.clone(),
            )
            .await?;
            assert_eq!(upload_part1.status(), StatusCode::OK);
            let part1_etag = upload_part1
                .headers()
                .get(reqwest::header::ETAG)
                .and_then(|value| value.to_str().ok())
                .context("multipart part 1 response missing ETag")?
                .to_string();

            let upload_part2 = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                &format!("/media.example/archive/movie.bin?partNumber=2&uploadId={upload_id}"),
                &access_key_id,
                &secret_access_key,
                &[],
                part2_payload.clone(),
            )
            .await?;
            assert_eq!(upload_part2.status(), StatusCode::OK);
            let part2_etag = upload_part2
                .headers()
                .get(reqwest::header::ETAG)
                .and_then(|value| value.to_str().ok())
                .context("multipart part 2 response missing ETag")?
                .to_string();

            let list_parts = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                &format!("/media.example/archive/movie.bin?max-parts=1&uploadId={upload_id}"),
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(list_parts.status(), StatusCode::OK);
            let list_parts_xml = list_parts.text().await?;
            assert!(list_parts_xml.contains("<PartNumber>1</PartNumber>"));
            assert!(!list_parts_xml.contains("<PartNumber>2</PartNumber>"));
            assert!(list_parts_xml.contains("<NextPartNumberMarker>1</NextPartNumberMarker>"));

            let complete_upload = send_signed_s3_request(
                &http,
                &s3_base,
                Method::POST,
                &format!("/media.example/archive/movie.bin?uploadId={upload_id}"),
                &access_key_id,
                &secret_access_key,
                &[("content-type", "application/xml")],
                format!(
                    concat!(
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
                        "<CompleteMultipartUpload>",
                        "<Part><PartNumber>1</PartNumber><ETag>{}</ETag></Part>",
                        "<Part><PartNumber>2</PartNumber><ETag>{}</ETag></Part>",
                        "</CompleteMultipartUpload>"
                    ),
                    part1_etag, part2_etag
                )
                .into_bytes(),
            )
            .await?;
            assert_eq!(complete_upload.status(), StatusCode::OK);
            let complete_etag = complete_upload
                .headers()
                .get(reqwest::header::ETAG)
                .and_then(|value| value.to_str().ok())
                .context("multipart complete response missing ETag")?
                .to_string();
            assert!(complete_etag.ends_with("-2\""));
            let complete_upload_xml = complete_upload.text().await?;
            assert_eq!(
                xml_tag_text(&complete_upload_xml, "ETag").as_deref(),
                Some(complete_etag.as_str())
            );

            let get_completed = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/media.example/archive/movie.bin",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_completed.status(), StatusCode::OK);
            assert_eq!(
                get_completed
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("application/octet-stream")
            );
            assert_eq!(
                get_completed
                    .headers()
                    .get("x-amz-meta-origin")
                    .and_then(|value| value.to_str().ok()),
                Some("camera")
            );
            let completed_body = get_completed.bytes().await?;
            let mut expected_payload = part1_payload.clone();
            expected_payload.extend_from_slice(&part2_payload);
            assert_eq!(completed_body.as_ref(), expected_payload.as_slice());

            let create_abort_upload = send_signed_s3_request(
                &http,
                &s3_base,
                Method::POST,
                "/media.example/archive/abort.bin?uploads=",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(create_abort_upload.status(), StatusCode::OK);
            let create_abort_upload_xml = create_abort_upload.text().await?;
            let abort_upload_id = xml_tag_text(&create_abort_upload_xml, "UploadId")
                .context("abort multipart initiation response missing UploadId")?;

            let upload_abort_part = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                &format!(
                    "/media.example/archive/abort.bin?partNumber=1&uploadId={abort_upload_id}"
                ),
                &access_key_id,
                &secret_access_key,
                &[],
                b"abort-me".to_vec(),
            )
            .await?;
            assert_eq!(upload_abort_part.status(), StatusCode::OK);

            let abort_upload = send_signed_s3_request(
                &http,
                &s3_base,
                Method::DELETE,
                &format!("/media.example/archive/abort.bin?uploadId={abort_upload_id}"),
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(abort_upload.status(), StatusCode::NO_CONTENT);

            let list_aborted_parts = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                &format!("/media.example/archive/abort.bin?uploadId={abort_upload_id}"),
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(list_aborted_parts.status(), StatusCode::NOT_FOUND);
            let list_aborted_parts_xml = list_aborted_parts.text().await?;
            assert!(list_aborted_parts_xml.contains("<Code>NoSuchUpload</Code>"));

            Ok(())
        }
        .await;

        stop_server(&mut server).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_s3_listener_serves_versioning_and_delete_markers() -> Result<()> {
        let public_bind = "127.0.0.1:19464";
        let s3_bind = "127.0.0.1:19465";
        let data_dir = fresh_data_dir("s3-listener-versioning-runtime");
        let mut server = start_authenticated_server_with_env_options(
            public_bind,
            &data_dir,
            "s3-versioning-runtime-node",
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
            let create_bucket_response = http
                .post(format!("{public_base}/auth/s3/buckets"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "bucket_name": "versions.example",
                    "root_prefix": "tenant/versions",
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
                    "description": "system-test-s3-versioning",
                    "bucket_scope": ["versions.example"],
                    "prefix_scope": ["tenant/versions/"],
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

            let get_versioning = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/versions.example?versioning=",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_versioning.status(), StatusCode::OK);
            let get_versioning_xml = get_versioning.text().await?;
            assert!(get_versioning_xml.contains("<Status>Enabled</Status>"));

            let put_v1 = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/versions.example/docs/versioned.txt",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "text/plain")],
                b"version one".to_vec(),
            )
            .await?;
            assert_eq!(put_v1.status(), StatusCode::OK);
            let v1_version_id = put_v1
                .headers()
                .get("x-amz-version-id")
                .and_then(|value| value.to_str().ok())
                .context("versioned PUT v1 missing x-amz-version-id")?
                .to_string();

            let put_v2 = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/versions.example/docs/versioned.txt",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "text/plain")],
                b"version two".to_vec(),
            )
            .await?;
            assert_eq!(put_v2.status(), StatusCode::OK);
            let v2_version_id = put_v2
                .headers()
                .get("x-amz-version-id")
                .and_then(|value| value.to_str().ok())
                .context("versioned PUT v2 missing x-amz-version-id")?
                .to_string();

            let delete_current = send_signed_s3_request(
                &http,
                &s3_base,
                Method::DELETE,
                "/versions.example/docs/versioned.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(delete_current.status(), StatusCode::NO_CONTENT);
            assert_eq!(
                delete_current
                    .headers()
                    .get("x-amz-delete-marker")
                    .and_then(|value| value.to_str().ok()),
                Some("true")
            );
            let delete_marker_version_id = delete_current
                .headers()
                .get("x-amz-version-id")
                .and_then(|value| value.to_str().ok())
                .context("delete marker response missing x-amz-version-id")?
                .to_string();

            let get_deleted_current = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/versions.example/docs/versioned.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_deleted_current.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                get_deleted_current
                    .headers()
                    .get("x-amz-delete-marker")
                    .and_then(|value| value.to_str().ok()),
                Some("true")
            );

            let get_v1 = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                &format!("/versions.example/docs/versioned.txt?versionId={v1_version_id}"),
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_v1.status(), StatusCode::OK);
            assert_eq!(get_v1.bytes().await?.as_ref(), b"version one");

            let get_delete_marker_version = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                &format!(
                    "/versions.example/docs/versioned.txt?versionId={delete_marker_version_id}"
                ),
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(
                get_delete_marker_version.status(),
                StatusCode::METHOD_NOT_ALLOWED
            );
            assert_eq!(
                get_delete_marker_version
                    .headers()
                    .get("x-amz-delete-marker")
                    .and_then(|value| value.to_str().ok()),
                Some("true")
            );

            let list_versions = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/versions.example?versions=&prefix=docs/",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(list_versions.status(), StatusCode::OK);
            let list_versions_xml = list_versions.text().await?;
            assert!(list_versions_xml.contains("<DeleteMarker>"));
            assert!(list_versions_xml.contains(&delete_marker_version_id));
            assert!(list_versions_xml.contains(&v2_version_id));
            assert!(list_versions_xml.contains(&v1_version_id));

            Ok(())
        }
        .await;

        stop_server(&mut server).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_s3_listener_serves_presigned_requests() -> Result<()> {
        let public_bind = "127.0.0.1:19466";
        let s3_bind = "127.0.0.1:19467";
        let data_dir = fresh_data_dir("s3-listener-presigned-runtime");
        let mut server = start_authenticated_server_with_env_options(
            public_bind,
            &data_dir,
            "s3-presigned-runtime-node",
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
                    "description": "system-test-s3-presigned",
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

            let put_object = send_presigned_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/photos.example/docs/presigned.txt",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "text/plain")],
                b"presigned body".to_vec(),
            )
            .await?;
            assert_eq!(put_object.status(), StatusCode::OK);

            let list_objects = send_presigned_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/photos.example?list-type=2&prefix=docs/",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(list_objects.status(), StatusCode::OK);
            let list_objects_xml = list_objects.text().await?;
            assert!(list_objects_xml.contains("<Key>docs/presigned.txt</Key>"));

            let get_object = send_presigned_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/photos.example/docs/presigned.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_object.status(), StatusCode::OK);
            assert_eq!(get_object.bytes().await?.as_ref(), b"presigned body");

            let tampered_url = {
                let presigned_url = build_presigned_s3_url(
                    &s3_base,
                    &Method::GET,
                    "/photos.example/docs/presigned.txt",
                    &access_key_id,
                    &secret_access_key,
                )?;
                let (prefix, last_char) = presigned_url.split_at(presigned_url.len() - 1);
                let replacement = if last_char == "0" { "1" } else { "0" };
                format!("{prefix}{replacement}")
            };
            let tampered_get_object = http
                .get(&tampered_url)
                .header("host", s3_bind)
                .send()
                .await?;
            assert_eq!(tampered_get_object.status(), StatusCode::FORBIDDEN);
            let tampered_get_object_xml = tampered_get_object.text().await?;
            assert!(tampered_get_object_xml.contains("<Code>SignatureDoesNotMatch</Code>"));

            let delete_object = send_presigned_s3_request(
                &http,
                &s3_base,
                Method::DELETE,
                "/photos.example/docs/presigned.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(delete_object.status(), StatusCode::NO_CONTENT);

            let get_missing_object = send_presigned_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/photos.example/docs/presigned.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_missing_object.status(), StatusCode::NOT_FOUND);

            Ok(())
        }
        .await;

        stop_server(&mut server).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_s3_listener_serves_bucket_create_and_delete() -> Result<()> {
        let public_bind = "127.0.0.1:19468";
        let s3_bind = "127.0.0.1:19469";
        let data_dir = fresh_data_dir("s3-listener-bucket-manage-runtime");
        let mut server = start_authenticated_server_with_env_options(
            public_bind,
            &data_dir,
            "s3-bucket-manage-runtime-node",
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
            let create_access_key_response = http
                .post(format!("{public_base}/auth/s3/access-keys"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "description": "system-test-s3-bucket-manage",
                    "bucket_scope": ["managed.example", "managed-body.example"],
                    "prefix_scope": [],
                    "allow_list": true,
                    "allow_read": true,
                    "allow_write": true,
                    "allow_delete": true,
                    "allow_manage": true
                }))
                .send()
                .await?;
            assert_eq!(create_access_key_response.status(), StatusCode::CREATED);
            let create_access_key_json: serde_json::Value =
                create_access_key_response.json().await?;
            let access_key_id = json_string(&create_access_key_json, "access_key_id")?;
            let secret_access_key = json_string(&create_access_key_json, "secret_access_key")?;
            let allow_manage = create_access_key_json
                .get("view")
                .and_then(|view| view.get("allow_manage"))
                .and_then(|value| value.as_bool())
                .context("created manage-capable access key missing view.allow_manage")?;
            assert!(allow_manage);

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

            let create_bucket = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/managed.example",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(create_bucket.status(), StatusCode::OK);
            assert_eq!(
                create_bucket
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok()),
                Some("/managed.example")
            );

            let head_bucket = send_signed_s3_request(
                &http,
                &s3_base,
                Method::HEAD,
                "/managed.example",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(head_bucket.status(), StatusCode::OK);

            let put_object = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/managed.example/docs/hello.txt",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "text/plain")],
                b"hello".to_vec(),
            )
            .await?;
            assert_eq!(put_object.status(), StatusCode::OK);

            let delete_nonempty_bucket = send_signed_s3_request(
                &http,
                &s3_base,
                Method::DELETE,
                "/managed.example",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(delete_nonempty_bucket.status(), StatusCode::CONFLICT);
            let delete_nonempty_bucket_xml = delete_nonempty_bucket.text().await?;
            assert!(delete_nonempty_bucket_xml.contains("<Code>BucketNotEmpty</Code>"));

            let delete_object = send_signed_s3_request(
                &http,
                &s3_base,
                Method::DELETE,
                "/managed.example/docs/hello.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(delete_object.status(), StatusCode::NO_CONTENT);

            let delete_bucket = send_signed_s3_request(
                &http,
                &s3_base,
                Method::DELETE,
                "/managed.example",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(delete_bucket.status(), StatusCode::NO_CONTENT);

            let head_deleted_bucket = send_signed_s3_request(
                &http,
                &s3_base,
                Method::HEAD,
                "/managed.example",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(head_deleted_bucket.status(), StatusCode::NOT_FOUND);

            let create_bucket_with_body = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/managed-body.example",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "application/xml")],
                br#"<?xml version="1.0" encoding="UTF-8"?>
<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <LocationConstraint>eu-central-1</LocationConstraint>
</CreateBucketConfiguration>"#
                    .to_vec(),
            )
            .await?;
            assert_eq!(create_bucket_with_body.status(), StatusCode::OK);
            assert_eq!(
                create_bucket_with_body
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok()),
                Some("/managed-body.example")
            );

            let head_bucket_with_body = send_signed_s3_request(
                &http,
                &s3_base,
                Method::HEAD,
                "/managed-body.example",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(head_bucket_with_body.status(), StatusCode::OK);

            Ok(())
        }
        .await;

        stop_server(&mut server).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_s3_listener_serves_copy_object_flows() -> Result<()> {
        let public_bind = "127.0.0.1:19470";
        let s3_bind = "127.0.0.1:19471";
        let data_dir = fresh_data_dir("s3-listener-copy-runtime");
        let mut server = start_authenticated_server_with_env_options(
            public_bind,
            &data_dir,
            "s3-copy-runtime-node",
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
            for (bucket_name, root_prefix) in [
                ("source.example", "tenant/source"),
                ("dest.example", "tenant/dest"),
            ] {
                let create_bucket_response = http
                    .post(format!("{public_base}/auth/s3/buckets"))
                    .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                    .json(&serde_json::json!({
                        "bucket_name": bucket_name,
                        "root_prefix": root_prefix,
                        "versioning_status": "enabled",
                        "read_only": false
                    }))
                    .send()
                    .await?;
                assert_eq!(create_bucket_response.status(), StatusCode::CREATED);
            }

            let create_access_key_response = http
                .post(format!("{public_base}/auth/s3/access-keys"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "description": "system-test-s3-copy",
                    "bucket_scope": ["source.example", "dest.example"],
                    "prefix_scope": ["tenant/source/", "tenant/dest/"],
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

            let source_payload = b"hello from source".to_vec();
            let put_source = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/source.example/docs/hello.txt",
                &access_key_id,
                &secret_access_key,
                &[
                    ("content-type", "text/plain"),
                    ("cache-control", "max-age=60"),
                    ("x-amz-meta-color", "blue"),
                ],
                source_payload.clone(),
            )
            .await?;
            assert_eq!(put_source.status(), StatusCode::OK);

            let put_existing_dest = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/dest.example/docs/copied.txt",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "text/plain")],
                b"old target".to_vec(),
            )
            .await?;
            assert_eq!(put_existing_dest.status(), StatusCode::OK);

            let copy_overwrite = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/dest.example/docs/copied.txt",
                &access_key_id,
                &secret_access_key,
                &[("x-amz-copy-source", "/source.example/docs/hello.txt")],
                Vec::new(),
            )
            .await?;
            assert_eq!(copy_overwrite.status(), StatusCode::OK);
            let overwrite_version_id = copy_overwrite
                .headers()
                .get("x-amz-version-id")
                .and_then(|value| value.to_str().ok())
                .context("copy overwrite missing x-amz-version-id")?
                .to_string();
            let copy_overwrite_xml = copy_overwrite.text().await?;
            assert!(copy_overwrite_xml.contains("<CopyObjectResult"));
            assert!(!overwrite_version_id.is_empty());

            let get_copied = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/dest.example/docs/copied.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_copied.status(), StatusCode::OK);
            assert_eq!(
                get_copied
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("text/plain")
            );
            assert_eq!(
                get_copied
                    .headers()
                    .get(reqwest::header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok()),
                Some("max-age=60")
            );
            assert_eq!(
                get_copied
                    .headers()
                    .get("x-amz-meta-color")
                    .and_then(|value| value.to_str().ok()),
                Some("blue")
            );
            assert_eq!(
                get_copied.bytes().await?.as_ref(),
                source_payload.as_slice()
            );

            let copy_replace = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/dest.example/docs/replaced.txt",
                &access_key_id,
                &secret_access_key,
                &[
                    ("x-amz-copy-source", "/source.example/docs/hello.txt"),
                    ("x-amz-metadata-directive", "REPLACE"),
                    ("content-type", "text/markdown"),
                    ("x-amz-meta-color", "green"),
                ],
                Vec::new(),
            )
            .await?;
            assert_eq!(copy_replace.status(), StatusCode::OK);

            let get_replaced = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/dest.example/docs/replaced.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_replaced.status(), StatusCode::OK);
            assert_eq!(
                get_replaced
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok()),
                Some("text/markdown")
            );
            assert_eq!(
                get_replaced
                    .headers()
                    .get("x-amz-meta-color")
                    .and_then(|value| value.to_str().ok()),
                Some("green")
            );
            assert!(
                get_replaced
                    .headers()
                    .get(reqwest::header::CACHE_CONTROL)
                    .is_none(),
                "metadata replacement should drop omitted cache-control headers"
            );
            assert_eq!(
                get_replaced.bytes().await?.as_ref(),
                source_payload.as_slice()
            );

            Ok(())
        }
        .await;

        stop_server(&mut server).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_s3_listener_serves_delete_objects_batches() -> Result<()> {
        let public_bind = "127.0.0.1:19472";
        let s3_bind = "127.0.0.1:19473";
        let data_dir = fresh_data_dir("s3-listener-delete-objects-runtime");
        let mut server = start_authenticated_server_with_env_options(
            public_bind,
            &data_dir,
            "s3-delete-objects-runtime-node",
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
            let create_bucket_response = http
                .post(format!("{public_base}/auth/s3/buckets"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "bucket_name": "batch.example",
                    "root_prefix": "tenant/batch",
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
                    "description": "system-test-s3-delete-objects",
                    "bucket_scope": ["batch.example"],
                    "prefix_scope": ["tenant/batch/"],
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

            let put_v1 = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/batch.example/docs/versioned.txt",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "text/plain")],
                b"version one".to_vec(),
            )
            .await?;
            assert_eq!(put_v1.status(), StatusCode::OK);
            let v1_version_id = put_v1
                .headers()
                .get("x-amz-version-id")
                .and_then(|value| value.to_str().ok())
                .context("delete-objects fixture missing v1 version id")?
                .to_string();

            let put_v2 = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/batch.example/docs/versioned.txt",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "text/plain")],
                b"version two".to_vec(),
            )
            .await?;
            assert_eq!(put_v2.status(), StatusCode::OK);

            let put_current = send_signed_s3_request(
                &http,
                &s3_base,
                Method::PUT,
                "/batch.example/docs/current.txt",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "text/plain")],
                b"current payload".to_vec(),
            )
            .await?;
            assert_eq!(put_current.status(), StatusCode::OK);

            let delete_body = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Object><Key>docs/versioned.txt</Key><VersionId>{v1_version_id}</VersionId></Object>
  <Object><Key>docs/current.txt</Key></Object>
  <Object><Key>docs/missing.txt</Key></Object>
  <Object><Key>docs/versioned.txt</Key><VersionId>missing-version</VersionId></Object>
</Delete>"#
            );
            let delete_objects = send_signed_s3_request(
                &http,
                &s3_base,
                Method::POST,
                "/batch.example?delete=",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "application/xml")],
                delete_body.into_bytes(),
            )
            .await?;
            assert_eq!(delete_objects.status(), StatusCode::OK);
            let delete_objects_xml = delete_objects.text().await?;
            assert!(delete_objects_xml.contains(&format!(
                "<Deleted><Key>docs/versioned.txt</Key><VersionId>{v1_version_id}</VersionId>"
            )));
            assert!(delete_objects_xml.contains(
                "<Deleted><Key>docs/current.txt</Key><DeleteMarker>true</DeleteMarker><DeleteMarkerVersionId>"
            ));
            assert!(delete_objects_xml.contains("<Deleted><Key>docs/missing.txt</Key>"));
            assert!(delete_objects_xml.contains(
                "<Error><Key>docs/versioned.txt</Key><VersionId>missing-version</VersionId><Code>NoSuchVersion</Code>"
            ));

            let get_deleted_current = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/batch.example/docs/current.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_deleted_current.status(), StatusCode::NOT_FOUND);
            assert_eq!(
                get_deleted_current
                    .headers()
                    .get("x-amz-delete-marker")
                    .and_then(|value| value.to_str().ok()),
                Some("true")
            );

            let get_deleted_old_version = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                &format!("/batch.example/docs/versioned.txt?versionId={v1_version_id}"),
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_deleted_old_version.status(), StatusCode::NOT_FOUND);

            let quiet_delete = send_signed_s3_request(
                &http,
                &s3_base,
                Method::POST,
                "/batch.example?delete=",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "application/xml")],
                br#"<?xml version="1.0" encoding="UTF-8"?>
<Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Quiet>true</Quiet>
  <Object><Key>docs/versioned.txt</Key></Object>
</Delete>"#
                    .to_vec(),
            )
            .await?;
            assert_eq!(quiet_delete.status(), StatusCode::OK);
            let quiet_delete_xml = quiet_delete.text().await?;
            assert!(!quiet_delete_xml.contains("<Deleted>"));
            assert!(!quiet_delete_xml.contains("<Error>"));

            Ok(())
        }
        .await;

        stop_server(&mut server).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_s3_listener_lists_folder_markers_and_common_prefixes() -> Result<()> {
        let public_bind = "127.0.0.1:19474";
        let s3_bind = "127.0.0.1:19475";
        let data_dir = fresh_data_dir("s3-listener-folder-marker-runtime");
        let mut server = start_authenticated_server_with_env_options(
            public_bind,
            &data_dir,
            "s3-folder-marker-runtime-node",
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
                    "description": "system-test-s3-folder-marker",
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

            for path in ["/photos.example/docs/", "/photos.example/docs/hello.txt"] {
                let put_response = send_signed_s3_request(
                    &http,
                    &s3_base,
                    Method::PUT,
                    path,
                    &access_key_id,
                    &secret_access_key,
                    &[],
                    Vec::new(),
                )
                .await?;
                assert_eq!(put_response.status(), StatusCode::OK);
            }

            let list_response = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/photos.example?list-type=2&delimiter=/",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(list_response.status(), StatusCode::OK);
            let list_xml = list_response.text().await?;
            assert!(list_xml.contains("<Key>docs/</Key>"));
            assert!(list_xml.contains("<CommonPrefixes><Prefix>docs/</Prefix></CommonPrefixes>"));

            Ok(())
        }
        .await;

        stop_server(&mut server).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_s3_listener_pages_continuation_tokens() -> Result<()> {
        let public_bind = "127.0.0.1:19476";
        let s3_bind = "127.0.0.1:19477";
        let data_dir = fresh_data_dir("s3-listener-continuation-runtime");
        let mut server = start_authenticated_server_with_env_options(
            public_bind,
            &data_dir,
            "s3-continuation-runtime-node",
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
                    "description": "system-test-s3-continuation",
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

            for path in ["/photos.example/docs/a.txt", "/photos.example/docs/b.txt"] {
                let put_response = send_signed_s3_request(
                    &http,
                    &s3_base,
                    Method::PUT,
                    path,
                    &access_key_id,
                    &secret_access_key,
                    &[],
                    b"payload".to_vec(),
                )
                .await?;
                assert_eq!(put_response.status(), StatusCode::OK);
            }

            let first_response = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/photos.example?list-type=2&max-keys=1",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(first_response.status(), StatusCode::OK);
            let first_xml = first_response.text().await?;
            assert!(first_xml.contains("<Key>docs/a.txt</Key>"));
            let next_token = xml_tag_text(&first_xml, "NextContinuationToken")
                .context("paginated S3 listing should expose NextContinuationToken")?;

            let second_response = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                &format!("/photos.example?list-type=2&max-keys=1&continuation-token={next_token}"),
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(second_response.status(), StatusCode::OK);
            let second_xml = second_response.text().await?;
            assert!(second_xml.contains("<Key>docs/b.txt</Key>"));
            assert!(!second_xml.contains("<NextContinuationToken>"));

            Ok(())
        }
        .await;

        stop_server(&mut server).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_s3_listener_lists_versions_with_delimiter() -> Result<()> {
        let public_bind = "127.0.0.1:19478";
        let s3_bind = "127.0.0.1:19479";
        let data_dir = fresh_data_dir("s3-listener-version-delimiter-runtime");
        let mut server = start_authenticated_server_with_env_options(
            public_bind,
            &data_dir,
            "s3-version-delimiter-runtime-node",
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
            let create_bucket_response = http
                .post(format!("{public_base}/auth/s3/buckets"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "bucket_name": "versions.example",
                    "root_prefix": "tenant/versions",
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
                    "description": "system-test-s3-version-delimiter",
                    "bucket_scope": ["versions.example"],
                    "prefix_scope": ["tenant/versions/"],
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

            for (path, body) in [
                ("/versions.example/root.txt", b"root version".to_vec()),
                ("/versions.example/docs/a.txt", b"docs a version".to_vec()),
                ("/versions.example/docs/sub/b.txt", b"docs sub b version".to_vec()),
            ] {
                let put_response = send_signed_s3_request(
                    &http,
                    &s3_base,
                    Method::PUT,
                    path,
                    &access_key_id,
                    &secret_access_key,
                    &[("content-type", "text/plain")],
                    body,
                )
                .await?;
                assert_eq!(put_response.status(), StatusCode::OK);
            }

            let root_versions = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/versions.example?versions=&delimiter=/",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(root_versions.status(), StatusCode::OK);
            let root_versions_xml = root_versions.text().await?;
            assert!(root_versions_xml.contains("<Delimiter>/</Delimiter>"));
            assert!(root_versions_xml.contains("<Key>root.txt</Key>"));
            assert!(
                root_versions_xml
                    .contains("<CommonPrefixes><Prefix>docs/</Prefix></CommonPrefixes>")
            );
            assert!(!root_versions_xml.contains("<Key>docs/a.txt</Key>"));
            assert!(!root_versions_xml.contains("<Key>docs/sub/b.txt</Key>"));

            let first_root_page = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/versions.example?versions=&delimiter=/&max-keys=1",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(first_root_page.status(), StatusCode::OK);
            let first_root_page_xml = first_root_page.text().await?;
            assert!(first_root_page_xml.contains("<IsTruncated>true</IsTruncated>"));
            assert!(
                first_root_page_xml
                    .contains("<CommonPrefixes><Prefix>docs/</Prefix></CommonPrefixes>")
            );
            assert_eq!(
                xml_tag_text(&first_root_page_xml, "NextKeyMarker").as_deref(),
                Some("root.txt")
            );
            let root_version_id = xml_tag_text(&first_root_page_xml, "NextVersionIdMarker")
                .context("truncated version listing should expose NextVersionIdMarker")?;

            let second_root_page = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                &format!(
                    "/versions.example?versions=&delimiter=/&max-keys=1&key-marker=root.txt&version-id-marker={root_version_id}"
                ),
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(second_root_page.status(), StatusCode::OK);
            let second_root_page_xml = second_root_page.text().await?;
            assert!(second_root_page_xml.contains("<Key>root.txt</Key>"));
            assert!(
                !second_root_page_xml
                    .contains("<CommonPrefixes><Prefix>docs/</Prefix></CommonPrefixes>")
            );

            let docs_versions = send_signed_s3_request(
                &http,
                &s3_base,
                Method::GET,
                "/versions.example?versions=&prefix=docs/&delimiter=/",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(docs_versions.status(), StatusCode::OK);
            let docs_versions_xml = docs_versions.text().await?;
            assert!(docs_versions_xml.contains("<Key>docs/a.txt</Key>"));
            assert!(
                docs_versions_xml
                    .contains("<CommonPrefixes><Prefix>docs/sub/</Prefix></CommonPrefixes>")
            );
            assert!(!docs_versions_xml.contains("<Key>docs/sub/b.txt</Key>"));

            Ok(())
        }
        .await;

        stop_server(&mut server).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_s3_listener_accepts_fanout_replicated_control_plane() -> Result<()> {
        let bind_a = "127.0.0.1:19580";
        let bind_b = "127.0.0.1:19582";
        let s3_bind_a = "127.0.0.1:19581";
        let s3_bind_b = "127.0.0.1:19583";
        let node_id_a = "00000000-0000-0000-0000-00000000f0a1";
        let node_id_b = "00000000-0000-0000-0000-00000000f0b2";
        let data_a = fresh_data_dir("s3-fanout-node-a");
        let data_b = fresh_data_dir("s3-fanout-node-b");

        let mut node_a = start_authenticated_server_with_env_options(
            bind_a,
            &data_a,
            node_id_a,
            2,
            None,
            None,
            &[("IRONMESH_S3_BIND", s3_bind_a)],
        )
        .await?;
        let mut node_b = start_authenticated_server_with_env_options(
            bind_b,
            &data_b,
            node_id_b,
            2,
            None,
            None,
            &[("IRONMESH_S3_BIND", s3_bind_b)],
        )
        .await?;

        let http = reqwest::Client::new();
        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let s3_base_b = format!("http://{s3_bind_b}");

        let result: Result<()> = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-b").await?;
            register_node(&http, &base_b, node_id_a, &base_a, "dc-a", "rack-a").await?;

            wait_for_online_nodes(&http, &base_a, 2, 120).await?;
            wait_for_online_nodes(&http, &base_b, 2, 120).await?;

            let create_bucket_response = http
                .post(format!("{base_a}/auth/s3/buckets"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "bucket_name": "fanout.example",
                    "root_prefix": "tenant/fanout",
                    "versioning_status": "enabled",
                    "read_only": false
                }))
                .send()
                .await?;
            assert_eq!(create_bucket_response.status(), StatusCode::CREATED);

            let create_access_key_response = http
                .post(format!("{base_a}/auth/s3/access-keys"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "description": "system-test-s3-fanout",
                    "bucket_scope": ["fanout.example"],
                    "prefix_scope": ["tenant/fanout/uploads/"],
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

            let status_b =
                wait_for_s3_control_plane_status(&http, &base_b, 1, 1, Some(node_id_a)).await?;
            assert_eq!(
                status_b
                    .get("last_source_node_id")
                    .and_then(|value| value.as_str()),
                Some(node_id_a)
            );

            wait_for_signed_s3_status(
                &http,
                &s3_base_b,
                Method::GET,
                "/",
                &access_key_id,
                &secret_access_key,
                StatusCode::OK,
            )
            .await?;

            let put_object = send_signed_s3_request(
                &http,
                &s3_base_b,
                Method::PUT,
                "/fanout.example/uploads/fanout.txt",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "text/plain")],
                b"fanout replicated".to_vec(),
            )
            .await?;
            assert_eq!(put_object.status(), StatusCode::OK);

            let get_object = send_signed_s3_request(
                &http,
                &s3_base_b,
                Method::GET,
                "/fanout.example/uploads/fanout.txt",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(get_object.status(), StatusCode::OK);
            assert_eq!(get_object.bytes().await?.as_ref(), b"fanout replicated");

            Ok(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn dedicated_s3_listener_rejects_peer_revoked_access_keys() -> Result<()> {
        let bind_a = "127.0.0.1:19590";
        let bind_b = "127.0.0.1:19592";
        let s3_bind_a = "127.0.0.1:19591";
        let s3_bind_b = "127.0.0.1:19593";
        let node_id_a = "00000000-0000-0000-0000-00000000f1a1";
        let node_id_b = "00000000-0000-0000-0000-00000000f1b2";
        let data_a = fresh_data_dir("s3-revoke-node-a");
        let data_b = fresh_data_dir("s3-revoke-node-b");

        let mut node_a = start_authenticated_server_with_env_options(
            bind_a,
            &data_a,
            node_id_a,
            2,
            None,
            None,
            &[("IRONMESH_S3_BIND", s3_bind_a)],
        )
        .await?;
        let mut node_b = start_authenticated_server_with_env_options(
            bind_b,
            &data_b,
            node_id_b,
            2,
            None,
            None,
            &[("IRONMESH_S3_BIND", s3_bind_b)],
        )
        .await?;

        let http = reqwest::Client::new();
        let base_a = format!("http://{bind_a}");
        let base_b = format!("http://{bind_b}");
        let s3_base_a = format!("http://{s3_bind_a}");

        let result: Result<()> = async {
            register_node(&http, &base_a, node_id_b, &base_b, "dc-b", "rack-b").await?;
            register_node(&http, &base_b, node_id_a, &base_a, "dc-a", "rack-a").await?;

            wait_for_online_nodes(&http, &base_a, 2, 120).await?;
            wait_for_online_nodes(&http, &base_b, 2, 120).await?;

            let create_bucket_response = http
                .post(format!("{base_a}/auth/s3/buckets"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "bucket_name": "revoke.example",
                    "root_prefix": "tenant/revoke",
                    "versioning_status": "enabled",
                    "read_only": false
                }))
                .send()
                .await?;
            assert_eq!(create_bucket_response.status(), StatusCode::CREATED);

            let create_access_key_response = http
                .post(format!("{base_a}/auth/s3/access-keys"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "description": "system-test-s3-peer-revoke",
                    "bucket_scope": ["revoke.example"],
                    "prefix_scope": ["tenant/revoke/"],
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

            wait_for_s3_control_plane_status(&http, &base_b, 1, 1, Some(node_id_a)).await?;

            let put_object = send_signed_s3_request(
                &http,
                &s3_base_a,
                Method::PUT,
                "/revoke.example/docs/peer.txt",
                &access_key_id,
                &secret_access_key,
                &[("content-type", "text/plain")],
                b"accepted before revoke".to_vec(),
            )
            .await?;
            assert_eq!(put_object.status(), StatusCode::OK);

            let revoke_access_key_response = http
                .post(format!(
                    "{base_b}/auth/s3/access-keys/{access_key_id}/revoke"
                ))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .send()
                .await?;
            assert_eq!(revoke_access_key_response.status(), StatusCode::NO_CONTENT);

            let status_a =
                wait_for_s3_control_plane_status(&http, &base_a, 1, 1, Some(node_id_b)).await?;
            assert_eq!(
                status_a
                    .get("last_source_node_id")
                    .and_then(|value| value.as_str()),
                Some(node_id_b)
            );

            wait_for_signed_s3_status(
                &http,
                &s3_base_a,
                Method::GET,
                "/",
                &access_key_id,
                &secret_access_key,
                StatusCode::FORBIDDEN,
            )
            .await?;

            let rejected = send_signed_s3_request(
                &http,
                &s3_base_a,
                Method::GET,
                "/",
                &access_key_id,
                &secret_access_key,
                &[],
                Vec::new(),
            )
            .await?;
            assert_eq!(rejected.status(), StatusCode::FORBIDDEN);
            let rejected_xml = rejected.text().await?;
            assert!(rejected_xml.contains("<Code>InvalidAccessKeyId</Code>"));

            Ok(())
        }
        .await;

        stop_server(&mut node_a).await;
        stop_server(&mut node_b).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn serve_s3_gateway_transports_signed_s3_requests() -> Result<()> {
        let server_bind = "127.0.0.1:19484";
        let gateway_bind = "127.0.0.1:19485";
        let data_dir = fresh_data_dir("s3-gateway-server");
        let client_dir = fresh_data_dir("s3-gateway-client");
        let mut server = start_authenticated_server_with_env_options(
            server_bind,
            &data_dir,
            "s3-gateway-runtime-node",
            1,
            None,
            None,
            &[],
        )
        .await?;

        let http = reqwest::Client::new();
        let base_url = format!("http://{server_bind}");
        let gateway_base = format!("http://{gateway_bind}");

        let result: Result<()> = async {
            let create_bucket_response = http
                .post(format!("{base_url}/auth/s3/buckets"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "bucket_name": "gateway.example",
                    "root_prefix": "tenant/gateway",
                    "versioning_status": "enabled",
                    "read_only": false
                }))
                .send()
                .await?;
            assert_eq!(create_bucket_response.status(), StatusCode::CREATED);

            let create_access_key_response = http
                .post(format!("{base_url}/auth/s3/access-keys"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "description": "system-test-s3-gateway",
                    "bucket_scope": ["gateway.example"],
                    "prefix_scope": ["tenant/gateway/"],
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

            let enrolled = issue_bootstrap_bundle_and_enroll_client(
                &http,
                &base_url,
                TEST_ADMIN_TOKEN,
                &client_dir,
                "s3-gateway.bootstrap.json",
                Some("s3-gateway"),
                Some(3600),
            )
            .await?;
            let identity_path = default_client_identity_path(&enrolled.bootstrap_path);
            let bootstrap_arg = enrolled.bootstrap_path.to_string_lossy().into_owned();
            let identity_arg = identity_path.to_string_lossy().into_owned();
            let cli_args = [
                "--bootstrap-file",
                bootstrap_arg.as_str(),
                "--client-identity-file",
                identity_arg.as_str(),
            ];
            let mut gateway = start_cli_s3_gateway(gateway_bind, &cli_args).await?;

            let gateway_result: Result<()> = async {
                wait_for_signed_s3_status(
                    &http,
                    &gateway_base,
                    Method::GET,
                    "/",
                    &access_key_id,
                    &secret_access_key,
                    StatusCode::OK,
                )
                .await?;

                let list_buckets = send_signed_s3_request(
                    &http,
                    &gateway_base,
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
                assert!(list_buckets_xml.contains("<Name>gateway.example</Name>"));

                let put_object = send_signed_s3_request(
                    &http,
                    &gateway_base,
                    Method::PUT,
                    "/gateway.example/docs/transport.txt",
                    &access_key_id,
                    &secret_access_key,
                    &[("content-type", "text/plain")],
                    b"transported through gateway".to_vec(),
                )
                .await?;
                assert_eq!(put_object.status(), StatusCode::OK);

                let get_object = send_signed_s3_request(
                    &http,
                    &gateway_base,
                    Method::GET,
                    "/gateway.example/docs/transport.txt",
                    &access_key_id,
                    &secret_access_key,
                    &[],
                    Vec::new(),
                )
                .await?;
                assert_eq!(get_object.status(), StatusCode::OK);
                assert!(
                    get_object
                        .headers()
                        .get("x-amz-version-id")
                        .and_then(|value| value.to_str().ok())
                        .is_some_and(|value| !value.is_empty())
                );
                assert_eq!(
                    get_object.bytes().await?.as_ref(),
                    b"transported through gateway"
                );

                exercise_aws_sdk_s3_crud(
                    &gateway_base,
                    &access_key_id,
                    &secret_access_key,
                    "gateway.example",
                    "sdk/direct-gateway.txt",
                    b"official aws rust sdk through direct gateway".to_vec(),
                )
                .await?;

                Ok(())
            }
            .await;

            stop_server(&mut gateway).await;
            gateway_result
        }
        .await;

        stop_server(&mut server).await;
        result?;
        Ok(())
    }

    #[tokio::test]
    async fn serve_s3_gateway_transports_signed_s3_requests_over_relay() -> Result<()> {
        let server_bind = "127.0.0.1:19584";
        let rendezvous_bind = "127.0.0.1:19585";
        let gateway_bind = "127.0.0.1:19586";
        let rendezvous_url = format!("http://{rendezvous_bind}");
        let data_dir = fresh_data_dir("s3-gateway-relay-server");
        let client_dir = fresh_data_dir("s3-gateway-relay-client");
        let node_env = [
            ("IRONMESH_RENDEZVOUS_URLS", rendezvous_url.as_str()),
            ("IRONMESH_RELAY_MODE", "fallback"),
            ("IRONMESH_PUBLIC_PEER_API_ENABLED", "true"),
        ];

        let mut rendezvous = start_rendezvous_service(rendezvous_bind).await?;
        let mut server = start_authenticated_server_with_env_options(
            server_bind,
            &data_dir,
            "s3-gateway-relay-node",
            1,
            None,
            None,
            &node_env,
        )
        .await?;

        let http = reqwest::Client::new();
        let base_url = format!("http://{server_bind}");
        let gateway_base = format!("http://{gateway_bind}");

        let result: Result<()> = async {
            wait_for_rendezvous_registered_endpoints(&rendezvous_url, 1, 120).await?;

            let create_bucket_response = http
                .post(format!("{base_url}/auth/s3/buckets"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "bucket_name": "relay-gateway.example",
                    "root_prefix": "tenant/relay-gateway",
                    "versioning_status": "enabled",
                    "read_only": false
                }))
                .send()
                .await?;
            assert_eq!(create_bucket_response.status(), StatusCode::CREATED);

            let create_access_key_response = http
                .post(format!("{base_url}/auth/s3/access-keys"))
                .header("x-ironmesh-admin-token", TEST_ADMIN_TOKEN)
                .json(&serde_json::json!({
                    "description": "system-test-s3-gateway-relay",
                    "bucket_scope": ["relay-gateway.example"],
                    "prefix_scope": ["tenant/relay-gateway/"],
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

            let enrolled = issue_bootstrap_bundle_and_enroll_client(
                &http,
                &base_url,
                TEST_ADMIN_TOKEN,
                &client_dir,
                "s3-gateway-relay.bootstrap.json",
                Some("s3-gateway-relay"),
                Some(3600),
            )
            .await?;
            let identity_path = default_client_identity_path(&enrolled.bootstrap_path);

            let mut relay_bootstrap = enrolled.bootstrap.clone();
            for endpoint in &mut relay_bootstrap.direct_endpoints {
                if endpoint.usage == Some(client_sdk::BootstrapEndpointUse::PublicApi) {
                    endpoint.url = "http://127.0.0.1:9".to_string();
                }
            }
            let relay_bootstrap_path = client_dir.join("s3-gateway-relay-forced.bootstrap.json");
            relay_bootstrap.write_to_path(&relay_bootstrap_path)?;

            let bootstrap_arg = relay_bootstrap_path.to_string_lossy().into_owned();
            let identity_arg = identity_path.to_string_lossy().into_owned();
            let cli_args = [
                "--bootstrap-file",
                bootstrap_arg.as_str(),
                "--client-identity-file",
                identity_arg.as_str(),
            ];
            let mut gateway = start_cli_s3_gateway(gateway_bind, &cli_args).await?;

            let gateway_result: Result<()> = async {
                wait_for_signed_s3_status(
                    &http,
                    &gateway_base,
                    Method::GET,
                    "/",
                    &access_key_id,
                    &secret_access_key,
                    StatusCode::OK,
                )
                .await?;

                let list_buckets = send_signed_s3_request(
                    &http,
                    &gateway_base,
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
                assert!(list_buckets_xml.contains("<Name>relay-gateway.example</Name>"));

                let put_object = send_signed_s3_request(
                    &http,
                    &gateway_base,
                    Method::PUT,
                    "/relay-gateway.example/docs/relay.txt",
                    &access_key_id,
                    &secret_access_key,
                    &[("content-type", "text/plain")],
                    b"transported through relay".to_vec(),
                )
                .await?;
                assert_eq!(put_object.status(), StatusCode::OK);

                let get_object = send_signed_s3_request(
                    &http,
                    &gateway_base,
                    Method::GET,
                    "/relay-gateway.example/docs/relay.txt",
                    &access_key_id,
                    &secret_access_key,
                    &[],
                    Vec::new(),
                )
                .await?;
                assert_eq!(get_object.status(), StatusCode::OK);
                assert!(
                    get_object
                        .headers()
                        .get("x-amz-version-id")
                        .and_then(|value| value.to_str().ok())
                        .is_some_and(|value| !value.is_empty())
                );
                assert_eq!(
                    get_object.bytes().await?.as_ref(),
                    b"transported through relay"
                );

                let large_payload = (0..((2 * 1024 * 1024) + 257))
                    .map(|index| (index % 251) as u8)
                    .collect::<Vec<_>>();
                let put_large_object = send_signed_s3_request(
                    &http,
                    &gateway_base,
                    Method::PUT,
                    "/relay-gateway.example/docs/large.bin",
                    &access_key_id,
                    &secret_access_key,
                    &[("content-type", "application/octet-stream")],
                    large_payload.clone(),
                )
                .await?;
                assert_eq!(put_large_object.status(), StatusCode::OK);

                let get_large_object = send_signed_s3_request(
                    &http,
                    &gateway_base,
                    Method::GET,
                    "/relay-gateway.example/docs/large.bin",
                    &access_key_id,
                    &secret_access_key,
                    &[],
                    Vec::new(),
                )
                .await?;
                assert_eq!(get_large_object.status(), StatusCode::OK);
                assert_eq!(
                    get_large_object.bytes().await?.as_ref(),
                    large_payload.as_slice()
                );

                let sdk_large_payload = (0..((1024 * 1024) + 511))
                    .map(|index| (255 - (index % 251)) as u8)
                    .collect::<Vec<_>>();
                exercise_aws_sdk_s3_crud(
                    &gateway_base,
                    &access_key_id,
                    &secret_access_key,
                    "relay-gateway.example",
                    "sdk/relay-gateway.bin",
                    sdk_large_payload,
                )
                .await?;

                Ok(())
            }
            .await;

            stop_server(&mut gateway).await;
            gateway_result
        }
        .await;

        stop_server(&mut server).await;
        stop_server(&mut rendezvous).await;
        result?;
        Ok(())
    }
}
