use anyhow::{Context, Result, anyhow, bail};
use common::ClusterId;
use reqwest::Client;
use reqwest::StatusCode;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::path::Path;
use transport_sdk::IssuedClientIdentity;

use crate::connection::{
    build_blocking_http_client, build_blocking_reqwest_client_from_pem, load_root_certificate,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEnrollmentRequest {
    pub cluster_id: ClusterId,
    pub pairing_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub public_key_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEnrollmentResponse {
    pub cluster_id: ClusterId,
    pub device_id: String,
    pub label: Option<String>,
    pub public_key_pem: String,
    pub credential_pem: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rendezvous_client_identity_pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_unix: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
}

impl DeviceEnrollmentResponse {
    pub fn issued_identity(&self) -> Result<IssuedClientIdentity> {
        Ok(IssuedClientIdentity {
            cluster_id: self.cluster_id,
            device_id: self
                .device_id
                .parse()
                .with_context(|| format!("invalid device_id {}", self.device_id))?,
            label: self.label.clone(),
            public_key_pem: self.public_key_pem.clone(),
            credential_pem: self.credential_pem.clone(),
            issued_at_unix: self.created_at_unix.unwrap_or_default(),
            expires_at_unix: self.expires_at_unix,
        })
    }
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

pub fn enroll_device_blocking_from_pem(
    base_url: &Url,
    server_ca_pem: Option<&str>,
    request: &DeviceEnrollmentRequest,
) -> Result<DeviceEnrollmentResponse> {
    let enroll_url = base_url
        .join("auth/device/enroll")
        .with_context(|| format!("failed to build enroll URL from {base_url}"))?;
    let client = build_blocking_reqwest_client_from_pem(server_ca_pem)?;
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
    if enrolled.cluster_id.is_nil()
        || enrolled.device_id.trim().is_empty()
        || enrolled.public_key_pem.trim().is_empty()
        || enrolled.credential_pem.trim().is_empty()
        || enrolled
            .rendezvous_client_identity_pem
            .as_deref()
            .is_some_and(|value| value.trim().is_empty())
    {
        return Err(anyhow!(
            "device enrollment returned an incomplete credential"
        ));
    }
    Ok(enrolled)
}
