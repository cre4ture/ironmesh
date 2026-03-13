use anyhow::{Context, Result, anyhow, bail};
use reqwest::Client;
use reqwest::StatusCode;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::connection::build_blocking_http_client;
use crate::connection::load_root_certificate;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEnrollmentRequest {
    pub pairing_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEnrollmentResponse {
    pub device_id: String,
    pub device_token: String,
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_unix: Option<u64>,
}

pub async fn enroll_device(
    base_url: &Url,
    server_ca_cert: Option<&Path>,
    request: &DeviceEnrollmentRequest,
) -> Result<DeviceEnrollmentResponse> {
    let enroll_url = base_url
        .join("auth/device/enroll")
        .with_context(|| format!("failed to build enroll URL from {base_url}"))?;
    let mut builder = Client::builder();
    if let Some(ca_cert_path) = server_ca_cert {
        builder = builder.add_root_certificate(load_root_certificate(ca_cert_path)?);
    } else if base_url.scheme() == "https" {
        bail!("server-ca-cert needed for HTTPS server");
    }
    let response = builder
        .build()?
        .post(enroll_url)
        .json(request)
        .send()
        .await
        .context("failed to call /auth/device/enroll")?;
    parse_enrollment_response(response.status(), response.text().await?)
}

pub fn enroll_device_blocking(
    base_url: &Url,
    server_ca_cert: Option<&Path>,
    request: &DeviceEnrollmentRequest,
) -> Result<DeviceEnrollmentResponse> {
    let enroll_url = base_url
        .join("auth/device/enroll")
        .with_context(|| format!("failed to build enroll URL from {base_url}"))?;
    let client = build_blocking_http_client(server_ca_cert)?;
    let response = client
        .post(enroll_url)
        .json(request)
        .send()
        .context("failed to call /auth/device/enroll")?;
    let status = response.status();
    let body = response
        .text()
        .unwrap_or_else(|_| "<failed to read response body>".to_string());
    parse_enrollment_response(status, body)
}

fn parse_enrollment_response(status: StatusCode, body: String) -> Result<DeviceEnrollmentResponse> {
    if !status.is_success() {
        bail!("device enrollment failed with HTTP {status}: {body}");
    }

    let enrolled = serde_json::from_str::<DeviceEnrollmentResponse>(&body)
        .context("failed to parse /auth/device/enroll response")?;
    if enrolled.device_id.trim().is_empty() || enrolled.device_token.trim().is_empty() {
        return Err(anyhow!(
            "device enrollment returned an incomplete credential"
        ));
    }
    Ok(enrolled)
}
