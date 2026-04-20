use anyhow::{Context, Result, anyhow, bail};
use common::ClusterId;
use reqwest::StatusCode;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use transport_sdk::IssuedClientIdentity;

use crate::ironmesh_client::CLIENT_API_V1_PREFIX;

use crate::connection::{
    build_blocking_http_client, build_blocking_reqwest_client_from_pem_for_url,
    build_reqwest_client_from_pem_for_url,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEnrollmentRequest {
    pub cluster_id: ClusterId,
    pub pairing_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    #[serde(
        rename = "device_label",
        alias = "label",
        skip_serializing_if = "Option::is_none"
    )]
    pub label: Option<String>,
    pub public_key_pem: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceEnrollmentResponse {
    pub cluster_id: ClusterId,
    pub device_id: String,
    #[serde(rename = "device_label", alias = "label")]
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
        .join(&format!("{CLIENT_API_V1_PREFIX}/auth/device/enroll"))
        .with_context(|| format!("failed to build enroll URL from {base_url}"))?;
    let server_ca_pem = if let Some(ca_cert_path) = server_ca_cert {
        Some(fs::read_to_string(ca_cert_path).with_context(|| {
            format!(
                "failed to read server CA certificate {}",
                ca_cert_path.display()
            )
        })?)
    } else if base_url.scheme() == "https" {
        bail!("server-ca-pem-file needed for HTTPS server");
    } else {
        None
    };
    let response = build_reqwest_client_from_pem_for_url(server_ca_pem.as_deref(), &enroll_url)?
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
        .join(&format!("{CLIENT_API_V1_PREFIX}/auth/device/enroll"))
        .with_context(|| format!("failed to build enroll URL from {base_url}"))?;
    let client = if let Some(ca_cert_path) = server_ca_cert {
        let server_ca_pem = fs::read_to_string(ca_cert_path).with_context(|| {
            format!(
                "failed to read server CA certificate {}",
                ca_cert_path.display()
            )
        })?;
        build_blocking_reqwest_client_from_pem_for_url(Some(&server_ca_pem), &enroll_url)?
    } else {
        build_blocking_http_client(server_ca_cert)?
    };
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
        .join(&format!("{CLIENT_API_V1_PREFIX}/auth/device/enroll"))
        .with_context(|| format!("failed to build enroll URL from {base_url}"))?;
    let client = build_blocking_reqwest_client_from_pem_for_url(server_ca_pem, &enroll_url)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn sample_response() -> DeviceEnrollmentResponse {
        DeviceEnrollmentResponse {
            cluster_id: Uuid::now_v7(),
            device_id: Uuid::now_v7().to_string(),
            label: Some("phone".to_string()),
            public_key_pem: "public-key".to_string(),
            credential_pem: "credential".to_string(),
            rendezvous_client_identity_pem: Some("rendezvous-identity".to_string()),
            created_at_unix: Some(11),
            expires_at_unix: Some(22),
        }
    }

    #[test]
    fn issued_identity_rejects_invalid_device_id() {
        let mut response = sample_response();
        response.device_id = "not-a-uuid".to_string();

        let error = response
            .issued_identity()
            .expect_err("invalid device_id should fail");
        assert!(error.to_string().contains("invalid device_id"));
    }

    #[test]
    fn parse_enrollment_response_accepts_complete_success_payload() {
        let response = sample_response();
        let body = serde_json::to_string(&response).expect("response should serialize");

        let parsed = parse_enrollment_response(StatusCode::CREATED, body)
            .expect("complete success payload should parse");
        assert_eq!(parsed.device_id, response.device_id);
        assert_eq!(
            parsed.rendezvous_client_identity_pem,
            response.rendezvous_client_identity_pem
        );
    }

    #[test]
    fn parse_enrollment_response_rejects_http_errors() {
        let error = parse_enrollment_response(StatusCode::FORBIDDEN, "denied".to_string())
            .expect_err("HTTP errors should fail");
        assert!(
            error
                .to_string()
                .contains("device enrollment failed with HTTP 403 Forbidden: denied")
        );
    }

    #[test]
    fn parse_enrollment_response_rejects_invalid_json() {
        let error = parse_enrollment_response(StatusCode::OK, "{".to_string())
            .expect_err("invalid JSON should fail");
        assert!(
            error
                .to_string()
                .contains("failed to parse /auth/device/enroll response")
        );
    }

    #[test]
    fn device_enrollment_request_serializes_device_label_and_accepts_legacy_label() {
        let request = DeviceEnrollmentRequest {
            cluster_id: Uuid::now_v7(),
            pairing_token: "pairing-token".to_string(),
            device_id: Some(Uuid::now_v7().to_string()),
            label: Some("Tablet".to_string()),
            public_key_pem: "public-key".to_string(),
        };

        let json = serde_json::to_value(&request).expect("request should serialize");
        let object = json
            .as_object()
            .expect("request should serialize as an object");
        assert_eq!(
            object
                .get("device_label")
                .and_then(serde_json::Value::as_str),
            Some("Tablet")
        );
        assert!(!object.contains_key("label"));

        let mut legacy = serde_json::to_value(&request).expect("request should serialize");
        let legacy_object = legacy
            .as_object_mut()
            .expect("request should serialize as an object");
        legacy_object.remove("device_label");
        legacy_object.insert(
            "label".to_string(),
            serde_json::Value::String("Phone".to_string()),
        );

        let parsed: DeviceEnrollmentRequest =
            serde_json::from_value(legacy).expect("legacy request should deserialize");

        assert_eq!(parsed.label.as_deref(), Some("Phone"));
    }

    #[test]
    fn device_enrollment_response_serializes_device_label_and_accepts_legacy_label() {
        let response = sample_response();
        let json = serde_json::to_value(&response).expect("response should serialize");
        let object = json
            .as_object()
            .expect("response should serialize as an object");
        assert_eq!(
            object
                .get("device_label")
                .and_then(serde_json::Value::as_str),
            Some("phone")
        );
        assert!(!object.contains_key("label"));

        let mut legacy = serde_json::to_value(&response).expect("response should serialize");
        let legacy_object = legacy
            .as_object_mut()
            .expect("response should serialize as an object");
        legacy_object.remove("device_label");
        legacy_object.insert(
            "label".to_string(),
            serde_json::Value::String("desktop".to_string()),
        );

        let parsed: DeviceEnrollmentResponse =
            serde_json::from_value(legacy).expect("legacy response should deserialize");

        assert_eq!(parsed.label.as_deref(), Some("desktop"));
    }

    #[test]
    fn parse_enrollment_response_rejects_incomplete_credentials() {
        let mut response = sample_response();
        response.credential_pem.clear();
        let body = serde_json::to_string(&response).expect("response should serialize");

        let error = parse_enrollment_response(StatusCode::OK, body)
            .expect_err("incomplete credential should fail");
        assert!(
            error
                .to_string()
                .contains("device enrollment returned an incomplete credential")
        );
    }
}
