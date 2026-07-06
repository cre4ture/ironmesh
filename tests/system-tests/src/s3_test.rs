#![cfg(test)]

#[cfg(test)]
mod tests {
    use crate::framework::{
        TEST_ADMIN_TOKEN, fresh_data_dir, start_authenticated_server_with_env_options, stop_server,
    };
    use anyhow::{Context, Result, bail};
    use hmac::{Hmac, Mac};
    use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
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
            .or_else(|| s3_base_url.trim_end_matches('/').strip_prefix("https://"))
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
        let amz_date = "20260706T120000Z";
        let date_scope = "20260706";
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
        pairs.push(("X-Amz-Date".to_string(), amz_date.to_string()));
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
        let signing_key = s3_test_derive_signing_key(secret_material, date_scope, region, service);
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
}
