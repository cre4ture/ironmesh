use anyhow::{Context, Result, bail};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use blake3::Hash;
use common::ClusterId;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pkcs8::{DecodePrivateKey, DecodePublicKey};
use reqwest::RequestBuilder;
use serde::{Deserialize, Serialize};

use crate::identity::ClientIdentityMaterial;

pub const HEADER_CLUSTER_ID: &str = "x-ironmesh-cluster-id";
pub const HEADER_DEVICE_ID: &str = "x-ironmesh-device-id";
pub const HEADER_CREDENTIAL_FINGERPRINT: &str = "x-ironmesh-credential-fingerprint";
pub const HEADER_AUTH_TIMESTAMP: &str = "x-ironmesh-auth-timestamp";
pub const HEADER_AUTH_NONCE: &str = "x-ironmesh-auth-nonce";
pub const HEADER_AUTH_SIGNATURE: &str = "x-ironmesh-auth-signature";

const REQUEST_AUTH_CONTEXT: &str = "ironmesh-client-request-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedRequestHeaders {
    pub cluster_id: ClusterId,
    pub device_id: String,
    pub credential_fingerprint: String,
    pub timestamp_unix: u64,
    pub nonce: String,
    pub signature_base64: String,
}

impl SignedRequestHeaders {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("signed request headers must include a non-nil cluster_id");
        }
        if self.device_id.trim().is_empty() {
            bail!("signed request headers must include a device_id");
        }
        if self.credential_fingerprint.trim().is_empty() {
            bail!("signed request headers must include a credential_fingerprint");
        }
        if self.nonce.trim().is_empty() {
            bail!("signed request headers must include a nonce");
        }
        if self.signature_base64.trim().is_empty() {
            bail!("signed request headers must include a signature");
        }
        Ok(())
    }

    pub fn apply_to_reqwest(&self, request: RequestBuilder) -> RequestBuilder {
        request
            .header(HEADER_CLUSTER_ID, self.cluster_id.to_string())
            .header(HEADER_DEVICE_ID, self.device_id.as_str())
            .header(
                HEADER_CREDENTIAL_FINGERPRINT,
                self.credential_fingerprint.as_str(),
            )
            .header(HEADER_AUTH_TIMESTAMP, self.timestamp_unix.to_string())
            .header(HEADER_AUTH_NONCE, self.nonce.as_str())
            .header(HEADER_AUTH_SIGNATURE, self.signature_base64.as_str())
    }

    pub fn from_header_lookup<F>(mut lookup: F) -> Result<Self>
    where
        F: FnMut(&str) -> Option<String>,
    {
        let cluster_id = lookup(HEADER_CLUSTER_ID)
            .context("missing cluster_id request header")?
            .parse()
            .context("invalid cluster_id request header")?;
        let timestamp_unix = lookup(HEADER_AUTH_TIMESTAMP)
            .context("missing auth timestamp request header")?
            .parse::<u64>()
            .context("invalid auth timestamp request header")?;
        let headers = Self {
            cluster_id,
            device_id: lookup(HEADER_DEVICE_ID).context("missing device_id request header")?,
            credential_fingerprint: lookup(HEADER_CREDENTIAL_FINGERPRINT)
                .context("missing credential_fingerprint request header")?,
            timestamp_unix,
            nonce: lookup(HEADER_AUTH_NONCE).context("missing auth nonce request header")?,
            signature_base64: lookup(HEADER_AUTH_SIGNATURE)
                .context("missing auth signature request header")?,
        };
        headers.validate()?;
        Ok(headers)
    }
}

pub fn next_auth_nonce() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

pub fn credential_fingerprint(credential_pem: &str) -> Result<String> {
    let credential_pem = credential_pem.trim();
    if credential_pem.is_empty() {
        bail!("credential fingerprint requires a non-empty credential");
    }
    Ok(hash_hex(blake3::hash(credential_pem.as_bytes())))
}

pub fn build_signed_request_headers(
    identity: &ClientIdentityMaterial,
    method: &str,
    path_and_query: &str,
    timestamp_unix: u64,
    nonce: Option<String>,
) -> Result<SignedRequestHeaders> {
    identity.validate()?;
    let credential_pem = identity
        .credential_pem
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("signed request auth requires issued client credential"))?;
    let signing_key = SigningKey::from_pkcs8_pem(&identity.private_key_pem)
        .context("failed to parse client private key PEM")?;
    let nonce = nonce.unwrap_or_else(next_auth_nonce);
    let headers = SignedRequestHeaders {
        cluster_id: identity.cluster_id,
        device_id: identity.device_id.to_string(),
        credential_fingerprint: credential_fingerprint(credential_pem)?,
        timestamp_unix,
        nonce,
        signature_base64: String::new(),
    };
    let message = canonical_request_message(&headers, method, path_and_query);
    let signature = signing_key.sign(message.as_bytes());
    Ok(SignedRequestHeaders {
        signature_base64: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        ..headers
    })
}

pub fn verify_signed_request_headers(
    headers: &SignedRequestHeaders,
    public_key_pem: &str,
    method: &str,
    path_and_query: &str,
) -> Result<()> {
    headers.validate()?;
    if public_key_pem.trim().is_empty() {
        bail!("signed request verification requires a public key");
    }
    let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem)
        .context("failed to parse client public key PEM")?;
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(headers.signature_base64.as_bytes())
        .context("failed to decode request signature")?;
    let signature = Signature::try_from(signature_bytes.as_slice())
        .context("request signature had invalid length")?;
    let message = canonical_request_message(headers, method, path_and_query);
    verifying_key
        .verify(message.as_bytes(), &signature)
        .context("request signature verification failed")
}

fn canonical_request_message(
    headers: &SignedRequestHeaders,
    method: &str,
    path_and_query: &str,
) -> String {
    let method = method.trim().to_ascii_uppercase();
    let path_and_query = normalize_path_and_query(path_and_query);
    format!(
        "{REQUEST_AUTH_CONTEXT}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        headers.cluster_id,
        headers.device_id.trim(),
        headers.credential_fingerprint.trim(),
        headers.timestamp_unix,
        headers.nonce.trim(),
        method,
        path_and_query
    )
}

fn normalize_path_and_query(path_and_query: &str) -> String {
    let trimmed = path_and_query.trim();
    if trimmed.is_empty() || trimmed == "*" {
        "/".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}

fn hash_hex(hash: Hash) -> String {
    hash.to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::ClientIdentityMaterial;

    #[test]
    fn signed_request_headers_roundtrip_sign_and_verify() {
        let mut identity =
            ClientIdentityMaterial::generate(uuid::Uuid::now_v7(), None, Some("Pixel".to_string()))
                .expect("identity should generate");
        identity.credential_pem = Some("issued-credential".to_string());

        let headers = build_signed_request_headers(
            &identity,
            "get",
            "/store/index?depth=8",
            1_730_000_000,
            Some("nonce-1".to_string()),
        )
        .expect("request headers should sign");

        verify_signed_request_headers(
            &headers,
            &identity.public_key_pem,
            "GET",
            "/store/index?depth=8",
        )
        .expect("request headers should verify");
    }

    #[test]
    fn signed_request_headers_reject_mismatched_path() {
        let mut identity =
            ClientIdentityMaterial::generate(uuid::Uuid::now_v7(), None, None).unwrap();
        identity.credential_pem = Some("issued-credential".to_string());
        let headers = build_signed_request_headers(
            &identity,
            "POST",
            "/store/delete?key=alpha",
            1_730_000_000,
            Some("nonce-2".to_string()),
        )
        .unwrap();

        let error = verify_signed_request_headers(
            &headers,
            &identity.public_key_pem,
            "POST",
            "/store/delete?key=beta",
        )
        .unwrap_err();
        assert!(error.to_string().contains("verification failed"));
    }
}
