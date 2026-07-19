//! Versioned wire protocol for self-service global rendezvous cluster registration.
//!
//! This module deliberately contains no HTTP client/server code and never handles CA private
//! keys. The registry service issues challenges and verifies the proof; clients only need the
//! public request/response types and the canonical proof-message builder below.

use std::io::Cursor;

use anyhow::{Context, Result, bail};
use base64::Engine;
use common::ClusterId;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use x509_parser::parse_x509_certificate;

/// The only currently supported cluster-registration wire protocol version.
pub const CLUSTER_REGISTRATION_PROTOCOL_VERSION: u16 = 1;

const PROOF_MESSAGE_DOMAIN: &[u8] = b"ironmesh.cluster-registration-proof\0";
const SHA256_FINGERPRINT_HEX_LENGTH: usize = 64;
const MAX_CA_PEM_BYTES: usize = 32 * 1024;
const MIN_CHALLENGE_NONCE_BYTES: usize = 16;
const MAX_CHALLENGE_NONCE_BYTES: usize = 64;
const MIN_ECDSA_P256_ASN1_SIGNATURE_BYTES: usize = 8;
const MAX_ECDSA_P256_ASN1_SIGNATURE_BYTES: usize = 80;
const MAX_SUSPEND_REASON_BYTES: usize = 1024;

/// Supported proof algorithm for the MVP cluster CA.
///
/// IronMesh currently creates P-256 CA keys. The proof signature uses the ASN.1 DER encoding
/// produced and verified by the corresponding P-256 SHA-256 implementation. New algorithms
/// require a new enum variant and explicit verifier support; APIs must not accept free-form
/// algorithm names.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClusterRegistrationProofAlgorithm {
    EcdsaP256Sha256Asn1,
}

/// Starts a registration by submitting one cluster CA and the intended proof algorithm.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterRegistrationChallengeRequest {
    pub protocol_version: u16,
    pub cluster_id: ClusterId,
    pub cluster_ca_pem: String,
    pub proof_algorithm: ClusterRegistrationProofAlgorithm,
}

/// Challenge issued by a registry service for a single cluster-registration attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterRegistrationChallengeResponse {
    pub protocol_version: u16,
    pub cluster_id: ClusterId,
    /// Lowercase hexadecimal SHA-256 over the single submitted CA's DER bytes.
    pub cluster_ca_fingerprint_sha256: String,
    pub proof_algorithm: ClusterRegistrationProofAlgorithm,
    pub challenge_id: Uuid,
    /// Unpadded base64url of 16 through 64 random bytes.
    pub challenge_nonce_b64u: String,
    pub expires_at_unix: u64,
}

/// Completes a registration by returning a proof over the exact challenge fields.
///
/// The service must compare the echoed challenge fields to the challenge it issued and enforce
/// single use. Keeping the complete request self-describing makes the signed bytes auditable and
/// avoids ambiguities between HTTP implementations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterRegistrationCompleteRequest {
    pub protocol_version: u16,
    pub cluster_id: ClusterId,
    pub cluster_ca_fingerprint_sha256: String,
    pub proof_algorithm: ClusterRegistrationProofAlgorithm,
    pub challenge_id: Uuid,
    pub challenge_nonce_b64u: String,
    pub expires_at_unix: u64,
    /// Unpadded base64url ASN.1 DER ECDSA P-256 signature over the canonical v1 proof message.
    pub proof_signature_b64u: String,
}

/// The suspension state shown in operator and registry-status APIs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClusterSuspendStatus {
    #[serde(default)]
    pub suspended: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspended_at_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Public, non-secret registry representation for one registered cluster.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterRegistrationRecord {
    pub cluster_id: ClusterId,
    pub cluster_ca_fingerprint_sha256: String,
    pub proof_algorithm: ClusterRegistrationProofAlgorithm,
    pub created_at_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at_unix: Option<u64>,
    #[serde(default)]
    pub suspension: ClusterSuspendStatus,
}

/// Snapshot returned by a public registry-status or operator list endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterRegistrationRegistryStatus {
    pub protocol_version: u16,
    pub generated_at_unix: u64,
    pub records: Vec<ClusterRegistrationRecord>,
}

impl ClusterRegistrationChallengeRequest {
    pub fn validate(&self) -> Result<()> {
        validate_protocol_version(self.protocol_version)?;
        validate_cluster_id(self.cluster_id)?;
        let certificate_der = parse_single_cluster_ca_pem(&self.cluster_ca_pem)?;
        self.proof_algorithm
            .validate_cluster_ca(certificate_der.as_slice())
    }

    /// Returns the normalized SHA-256 DER fingerprint after validating the request CA.
    pub fn cluster_ca_fingerprint_sha256(&self) -> Result<String> {
        self.validate()?;
        cluster_ca_fingerprint_sha256(&self.cluster_ca_pem)
    }
}

impl ClusterRegistrationChallengeResponse {
    pub fn validate(&self) -> Result<()> {
        validate_proof_fields(
            self.protocol_version,
            self.cluster_id,
            &self.cluster_ca_fingerprint_sha256,
            self.challenge_id,
            &self.challenge_nonce_b64u,
            self.expires_at_unix,
        )
    }

    /// Validates this challenge against a caller-supplied current UNIX timestamp.
    pub fn validate_at(&self, now_unix: u64) -> Result<()> {
        self.validate()?;
        if self.expires_at_unix <= now_unix {
            bail!("cluster registration challenge has expired");
        }
        Ok(())
    }

    /// Builds the exact byte sequence the cluster CA must sign for protocol v1.
    pub fn canonical_proof_message_v1(&self) -> Result<Vec<u8>> {
        self.validate()?;
        cluster_registration_proof_message_v1(
            self.cluster_id,
            &self.cluster_ca_fingerprint_sha256,
            self.challenge_id,
            &self.challenge_nonce_b64u,
            self.expires_at_unix,
        )
    }
}

impl ClusterRegistrationCompleteRequest {
    pub fn validate(&self) -> Result<()> {
        validate_proof_fields(
            self.protocol_version,
            self.cluster_id,
            &self.cluster_ca_fingerprint_sha256,
            self.challenge_id,
            &self.challenge_nonce_b64u,
            self.expires_at_unix,
        )?;
        self.proof_algorithm
            .validate_signature_b64u(&self.proof_signature_b64u)
    }

    /// Validates this completion request against a caller-supplied current UNIX timestamp.
    pub fn validate_at(&self, now_unix: u64) -> Result<()> {
        self.validate()?;
        if self.expires_at_unix <= now_unix {
            bail!("cluster registration completion challenge has expired");
        }
        Ok(())
    }

    /// Builds the exact byte sequence whose signature is carried by this request.
    pub fn canonical_proof_message_v1(&self) -> Result<Vec<u8>> {
        self.validate()?;
        cluster_registration_proof_message_v1(
            self.cluster_id,
            &self.cluster_ca_fingerprint_sha256,
            self.challenge_id,
            &self.challenge_nonce_b64u,
            self.expires_at_unix,
        )
    }
}

impl ClusterSuspendStatus {
    pub fn validate(&self) -> Result<()> {
        match (
            self.suspended,
            self.suspended_at_unix,
            self.reason.as_deref(),
        ) {
            (false, None, None) => Ok(()),
            (false, _, _) => {
                bail!("active cluster suspension status must not include suspension metadata")
            }
            (true, Some(suspended_at_unix), reason) if suspended_at_unix > 0 => {
                if reason.is_some_and(|value| value.len() > MAX_SUSPEND_REASON_BYTES) {
                    bail!("cluster suspension reason exceeds {MAX_SUSPEND_REASON_BYTES} bytes");
                }
                Ok(())
            }
            (true, _, _) => {
                bail!("suspended cluster status must include a non-zero suspended_at_unix")
            }
        }
    }
}

impl ClusterRegistrationRecord {
    pub fn validate(&self) -> Result<()> {
        validate_cluster_id(self.cluster_id)?;
        validate_normalized_sha256_fingerprint(&self.cluster_ca_fingerprint_sha256)?;
        if self.created_at_unix == 0 {
            bail!("cluster registration record must include a non-zero created_at_unix");
        }
        if self
            .last_seen_at_unix
            .is_some_and(|value| value < self.created_at_unix)
        {
            bail!("cluster registration record last_seen_at_unix precedes created_at_unix");
        }
        self.suspension.validate()
    }
}

impl ClusterRegistrationRegistryStatus {
    pub fn validate(&self) -> Result<()> {
        validate_protocol_version(self.protocol_version)?;
        if self.generated_at_unix == 0 {
            bail!("cluster registration registry status must include a non-zero generated_at_unix");
        }

        let mut cluster_ids = std::collections::HashSet::new();
        for record in &self.records {
            record.validate()?;
            if !cluster_ids.insert(record.cluster_id) {
                bail!("cluster registration registry status contains duplicate cluster_id");
            }
        }
        Ok(())
    }
}

impl ClusterRegistrationProofAlgorithm {
    fn validate_cluster_ca(self, certificate_der: &[u8]) -> Result<()> {
        let (_, certificate) = parse_x509_certificate(certificate_der)
            .context("failed parsing cluster registration CA certificate")?;

        match self {
            Self::EcdsaP256Sha256Asn1 => {
                let public_key_algorithm =
                    certificate.public_key().algorithm.algorithm.to_id_string();
                let curve = certificate
                    .public_key()
                    .algorithm
                    .parameters
                    .as_ref()
                    .and_then(|parameters| parameters.as_oid().ok())
                    .map(|oid| oid.to_id_string());
                if public_key_algorithm != "1.2.840.10045.2.1"
                    || curve.as_deref() != Some("1.2.840.10045.3.1.7")
                {
                    bail!(
                        "cluster registration proof algorithm ecdsa_p256_sha256_asn1 requires a P-256 EC CA public key"
                    );
                }
            }
        }
        Ok(())
    }

    fn validate_signature_b64u(self, proof_signature_b64u: &str) -> Result<()> {
        let signature = decode_base64url(proof_signature_b64u, "proof_signature_b64u")?;
        match self {
            Self::EcdsaP256Sha256Asn1 => {
                if !(MIN_ECDSA_P256_ASN1_SIGNATURE_BYTES..=MAX_ECDSA_P256_ASN1_SIGNATURE_BYTES)
                    .contains(&signature.len())
                {
                    bail!(
                        "ecdsa_p256_sha256_asn1 proof_signature_b64u must decode to {MIN_ECDSA_P256_ASN1_SIGNATURE_BYTES} through {MAX_ECDSA_P256_ASN1_SIGNATURE_BYTES} bytes"
                    );
                }
                validate_ecdsa_p256_asn1_signature(&signature)?;
            }
        }
        Ok(())
    }
}

/// Computes the normalized lowercase hexadecimal SHA-256 fingerprint of exactly one CA PEM.
///
/// Fingerprints are over the DER certificate bytes, never over PEM text. Different whitespace
/// or line-ending formatting therefore produces the same fingerprint.
pub fn cluster_ca_fingerprint_sha256(cluster_ca_pem: &str) -> Result<String> {
    let certificate_der = parse_single_cluster_ca_pem(cluster_ca_pem)?;
    Ok(format!("{:x}", Sha256::digest(certificate_der.as_slice())))
}

/// Builds the canonical protocol-v1 proof message without serializing JSON.
///
/// Its byte layout is `domain || version:u16be || cluster_id:16 || ca_fingerprint:32 ||
/// challenge_id:16 || nonce_length:u16be || nonce || expires_at_unix:u64be`, where `domain` is
/// the ASCII string `ironmesh.cluster-registration-proof` followed by one NUL byte. All UUIDs
/// use their RFC 4122 network byte order and the fingerprint is decoded from normalized lowercase
/// hexadecimal before it is appended.
pub fn cluster_registration_proof_message_v1(
    cluster_id: ClusterId,
    cluster_ca_fingerprint_sha256: &str,
    challenge_id: Uuid,
    challenge_nonce_b64u: &str,
    expires_at_unix: u64,
) -> Result<Vec<u8>> {
    validate_proof_fields(
        CLUSTER_REGISTRATION_PROTOCOL_VERSION,
        cluster_id,
        cluster_ca_fingerprint_sha256,
        challenge_id,
        challenge_nonce_b64u,
        expires_at_unix,
    )?;

    let fingerprint = decode_normalized_sha256_fingerprint(cluster_ca_fingerprint_sha256)?;
    let nonce = decode_challenge_nonce(challenge_nonce_b64u)?;
    let nonce_len = u16::try_from(nonce.len()).context("challenge nonce is too large")?;

    let mut message = Vec::with_capacity(
        PROOF_MESSAGE_DOMAIN.len() + 2 + 16 + fingerprint.len() + 16 + 2 + nonce.len() + 8,
    );
    message.extend_from_slice(PROOF_MESSAGE_DOMAIN);
    message.extend_from_slice(&CLUSTER_REGISTRATION_PROTOCOL_VERSION.to_be_bytes());
    message.extend_from_slice(cluster_id.as_bytes());
    message.extend_from_slice(&fingerprint);
    message.extend_from_slice(challenge_id.as_bytes());
    message.extend_from_slice(&nonce_len.to_be_bytes());
    message.extend_from_slice(&nonce);
    message.extend_from_slice(&expires_at_unix.to_be_bytes());
    Ok(message)
}

/// Alias retained for callers that use the protocol-v1 function name in documentation.
pub fn canonical_cluster_registration_proof_message_v1(
    cluster_id: ClusterId,
    cluster_ca_fingerprint_sha256: &str,
    challenge_id: Uuid,
    challenge_nonce_b64u: &str,
    expires_at_unix: u64,
) -> Result<Vec<u8>> {
    cluster_registration_proof_message_v1(
        cluster_id,
        cluster_ca_fingerprint_sha256,
        challenge_id,
        challenge_nonce_b64u,
        expires_at_unix,
    )
}

fn validate_proof_fields(
    protocol_version: u16,
    cluster_id: ClusterId,
    cluster_ca_fingerprint_sha256: &str,
    challenge_id: Uuid,
    challenge_nonce_b64u: &str,
    expires_at_unix: u64,
) -> Result<()> {
    validate_protocol_version(protocol_version)?;
    validate_cluster_id(cluster_id)?;
    validate_normalized_sha256_fingerprint(cluster_ca_fingerprint_sha256)?;
    if challenge_id.is_nil() {
        bail!("cluster registration challenge_id must be a non-nil UUID");
    }
    decode_challenge_nonce(challenge_nonce_b64u)?;
    if expires_at_unix == 0 {
        bail!("cluster registration challenge must include a non-zero expires_at_unix");
    }
    Ok(())
}

fn validate_protocol_version(protocol_version: u16) -> Result<()> {
    if protocol_version != CLUSTER_REGISTRATION_PROTOCOL_VERSION {
        bail!("unsupported cluster registration protocol version {protocol_version}");
    }
    Ok(())
}

fn validate_cluster_id(cluster_id: ClusterId) -> Result<()> {
    if cluster_id.is_nil() {
        bail!("cluster registration must include a non-nil cluster_id UUID");
    }
    Ok(())
}

fn parse_single_cluster_ca_pem(cluster_ca_pem: &str) -> Result<Vec<u8>> {
    if cluster_ca_pem.trim().is_empty() {
        bail!("cluster registration requires a non-empty cluster_ca_pem");
    }
    if cluster_ca_pem.len() > MAX_CA_PEM_BYTES {
        bail!("cluster registration cluster_ca_pem exceeds {MAX_CA_PEM_BYTES} bytes");
    }

    let lines = cluster_ca_pem
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    if lines.first() != Some(&"-----BEGIN CERTIFICATE-----")
        || lines.last() != Some(&"-----END CERTIFICATE-----")
        || lines
            .iter()
            .filter(|line| line.starts_with("-----BEGIN ") || line.starts_with("-----END "))
            .count()
            != 2
    {
        bail!("cluster registration cluster_ca_pem must contain exactly one certificate PEM block");
    }

    let mut reader = Cursor::new(cluster_ca_pem.as_bytes());
    let certificates = CertificateDer::pem_reader_iter(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed parsing cluster registration CA PEM")?;
    let [certificate] = certificates.as_slice() else {
        bail!("cluster registration cluster_ca_pem must contain exactly one certificate");
    };
    let certificate_der = certificate.as_ref().to_vec();

    let (remaining, certificate) = parse_x509_certificate(&certificate_der)
        .context("failed parsing cluster registration CA certificate")?;
    if !remaining.is_empty() {
        bail!("cluster registration CA certificate contains trailing DER data");
    }
    let basic_constraints = certificate
        .basic_constraints()
        .context("failed reading cluster registration CA basic constraints")?
        .ok_or_else(|| {
            anyhow::anyhow!("cluster registration certificate is missing basic constraints")
        })?;
    if !basic_constraints.value.ca {
        bail!("cluster registration certificate is not a CA");
    }

    Ok(certificate_der)
}

fn decode_challenge_nonce(challenge_nonce_b64u: &str) -> Result<Vec<u8>> {
    let nonce = decode_base64url(challenge_nonce_b64u, "challenge_nonce_b64u")?;
    if !(MIN_CHALLENGE_NONCE_BYTES..=MAX_CHALLENGE_NONCE_BYTES).contains(&nonce.len()) {
        bail!(
            "challenge_nonce_b64u must decode to {MIN_CHALLENGE_NONCE_BYTES} through {MAX_CHALLENGE_NONCE_BYTES} bytes"
        );
    }
    Ok(nonce)
}

fn validate_ecdsa_p256_asn1_signature(signature: &[u8]) -> Result<()> {
    if signature.first() != Some(&0x30)
        || signature.get(1).copied() != Some((signature.len() - 2) as u8)
    {
        bail!("ecdsa_p256_sha256_asn1 proof signature must be a definite-length DER sequence");
    }

    let mut offset = 2;
    for _ in 0..2 {
        if signature.get(offset) != Some(&0x02) {
            bail!("ecdsa_p256_sha256_asn1 proof signature must contain two DER integers");
        }
        let integer_len = *signature
            .get(offset + 1)
            .ok_or_else(|| anyhow::anyhow!("ECDSA proof signature is truncated"))?
            as usize;
        if integer_len == 0 || integer_len > 33 {
            bail!("ecdsa_p256_sha256_asn1 proof signature integer has an invalid length");
        }
        let integer_start = offset + 2;
        let integer_end = integer_start + integer_len;
        let integer = signature
            .get(integer_start..integer_end)
            .ok_or_else(|| anyhow::anyhow!("ECDSA proof signature is truncated"))?;
        if integer[0] & 0x80 != 0
            || (integer_len > 1 && integer[0] == 0 && integer[1] & 0x80 == 0)
            || integer.iter().all(|byte| *byte == 0)
        {
            bail!("ecdsa_p256_sha256_asn1 proof signature integer is not canonical");
        }
        offset = integer_end;
    }
    if offset != signature.len() {
        bail!("ecdsa_p256_sha256_asn1 proof signature has trailing DER data");
    }
    Ok(())
}

fn decode_base64url(value: &str, field_name: &str) -> Result<Vec<u8>> {
    if value.is_empty() {
        bail!("{field_name} must not be empty");
    }
    if value.trim() != value || value.contains('=') {
        bail!("{field_name} must be unpadded base64url without surrounding whitespace");
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("{field_name} must be valid unpadded base64url"))?;
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != value {
        bail!("{field_name} is not canonical base64url");
    }
    Ok(decoded)
}

fn validate_normalized_sha256_fingerprint(value: &str) -> Result<()> {
    if value.len() != SHA256_FINGERPRINT_HEX_LENGTH
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!(
            "cluster_ca_fingerprint_sha256 must be {SHA256_FINGERPRINT_HEX_LENGTH} lowercase hexadecimal characters"
        );
    }
    Ok(())
}

fn decode_normalized_sha256_fingerprint(value: &str) -> Result<[u8; 32]> {
    validate_normalized_sha256_fingerprint(value)?;
    let mut fingerprint = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        fingerprint[index] = (hex_value(pair[0])? << 4) | hex_value(pair[1])?;
    }
    Ok(fingerprint)
}

fn hex_value(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => bail!("invalid lowercase hexadecimal fingerprint character"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

    fn test_cluster_ca_pem() -> String {
        let key_pair = KeyPair::generate().expect("test CA key should generate");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "ironmesh-cluster-registration-test-ca");
        params
            .self_signed(&key_pair)
            .expect("test CA certificate should issue")
            .pem()
    }

    fn challenge_response() -> ClusterRegistrationChallengeResponse {
        ClusterRegistrationChallengeResponse {
            protocol_version: CLUSTER_REGISTRATION_PROTOCOL_VERSION,
            cluster_id: Uuid::parse_str("123e4567-e89b-12d3-a456-426614174000")
                .expect("test UUID should parse"),
            cluster_ca_fingerprint_sha256: "11".repeat(32),
            proof_algorithm: ClusterRegistrationProofAlgorithm::EcdsaP256Sha256Asn1,
            challenge_id: Uuid::parse_str("87654321-4321-4abc-8def-1234567890ab")
                .expect("test UUID should parse"),
            challenge_nonce_b64u: "AQIDBAUGBwgJCgsMDQ4PEA".to_string(),
            expires_at_unix: 1_800_000_000,
        }
    }

    fn structurally_valid_signature_b64u() -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
    }

    #[test]
    fn canonical_v1_proof_message_is_stable_and_not_json() {
        let response = challenge_response();
        let message = response
            .canonical_proof_message_v1()
            .expect("proof message should build");

        let mut expected = Vec::new();
        expected.extend_from_slice(b"ironmesh.cluster-registration-proof\0");
        expected.extend_from_slice(&1_u16.to_be_bytes());
        expected.extend_from_slice(&[
            0x12, 0x3e, 0x45, 0x67, 0xe8, 0x9b, 0x12, 0xd3, 0xa4, 0x56, 0x42, 0x66, 0x14, 0x17,
            0x40, 0x00,
        ]);
        expected.extend_from_slice(&[0x11; 32]);
        expected.extend_from_slice(&[
            0x87, 0x65, 0x43, 0x21, 0x43, 0x21, 0x4a, 0xbc, 0x8d, 0xef, 0x12, 0x34, 0x56, 0x78,
            0x90, 0xab,
        ]);
        expected.extend_from_slice(&16_u16.to_be_bytes());
        expected.extend_from_slice(&(1_u8..=16).collect::<Vec<_>>());
        expected.extend_from_slice(&1_800_000_000_u64.to_be_bytes());

        assert_eq!(message, expected);
        assert!(!message.starts_with(b"{"));
        assert_eq!(
            message,
            cluster_registration_proof_message_v1(
                response.cluster_id,
                &response.cluster_ca_fingerprint_sha256,
                response.challenge_id,
                &response.challenge_nonce_b64u,
                response.expires_at_unix,
            )
            .expect("free function should build identical message")
        );
    }

    #[test]
    fn ca_fingerprint_is_independent_of_pem_whitespace() {
        let pem = test_cluster_ca_pem();
        let reformatted = format!("\n\r\n{}\r\n\r\n", pem.replace('\n', "\r\n"));

        assert_eq!(
            cluster_ca_fingerprint_sha256(&pem).expect("original PEM should fingerprint"),
            cluster_ca_fingerprint_sha256(&reformatted)
                .expect("whitespace-formatted PEM should fingerprint")
        );
    }

    #[test]
    fn validation_rejects_invalid_protocol_inputs() {
        let pem = test_cluster_ca_pem();
        let mut request = ClusterRegistrationChallengeRequest {
            protocol_version: CLUSTER_REGISTRATION_PROTOCOL_VERSION,
            cluster_id: Uuid::now_v7(),
            cluster_ca_pem: pem.clone(),
            proof_algorithm: ClusterRegistrationProofAlgorithm::EcdsaP256Sha256Asn1,
        };
        request
            .validate()
            .expect("P-256 CA request should validate");

        request.cluster_id = Uuid::nil();
        assert!(request.validate().is_err());
        request.cluster_id = Uuid::now_v7();
        request.cluster_ca_pem = format!("{pem}\n{pem}");
        assert!(request.validate().is_err());

        let mut response = challenge_response();
        response.challenge_nonce_b64u = "AQIDBAUGBwgJCgsMDQ4PEA=".to_string();
        assert!(response.validate().is_err());
        response.challenge_nonce_b64u = "AQIDBAUGBwgJCgsMDQ4PEA".to_string();
        response.cluster_ca_fingerprint_sha256 = "AA".repeat(32);
        assert!(response.validate().is_err());
        response.cluster_ca_fingerprint_sha256 = "11".repeat(32);
        assert!(response.validate_at(response.expires_at_unix).is_err());

        let mut complete = ClusterRegistrationCompleteRequest {
            protocol_version: CLUSTER_REGISTRATION_PROTOCOL_VERSION,
            cluster_id: response.cluster_id,
            cluster_ca_fingerprint_sha256: response.cluster_ca_fingerprint_sha256.clone(),
            proof_algorithm: response.proof_algorithm,
            challenge_id: response.challenge_id,
            challenge_nonce_b64u: response.challenge_nonce_b64u.clone(),
            expires_at_unix: response.expires_at_unix,
            proof_signature_b64u: structurally_valid_signature_b64u(),
        };
        complete
            .validate()
            .expect("properly sized signature should validate structurally");
        complete.proof_signature_b64u = "AQI".to_string();
        assert!(complete.validate().is_err());
    }

    #[test]
    fn public_protocol_types_round_trip_through_json() {
        let request = ClusterRegistrationChallengeRequest {
            protocol_version: CLUSTER_REGISTRATION_PROTOCOL_VERSION,
            cluster_id: Uuid::now_v7(),
            cluster_ca_pem: test_cluster_ca_pem(),
            proof_algorithm: ClusterRegistrationProofAlgorithm::EcdsaP256Sha256Asn1,
        };
        request.validate().expect("request should validate");
        let response = challenge_response();
        response.validate().expect("response should validate");
        let complete = ClusterRegistrationCompleteRequest {
            protocol_version: response.protocol_version,
            cluster_id: response.cluster_id,
            cluster_ca_fingerprint_sha256: response.cluster_ca_fingerprint_sha256.clone(),
            proof_algorithm: response.proof_algorithm,
            challenge_id: response.challenge_id,
            challenge_nonce_b64u: response.challenge_nonce_b64u.clone(),
            expires_at_unix: response.expires_at_unix,
            proof_signature_b64u: structurally_valid_signature_b64u(),
        };
        complete
            .validate()
            .expect("complete request should validate");
        let status = ClusterRegistrationRegistryStatus {
            protocol_version: CLUSTER_REGISTRATION_PROTOCOL_VERSION,
            generated_at_unix: 1_700_000_100,
            records: vec![ClusterRegistrationRecord {
                cluster_id: response.cluster_id,
                cluster_ca_fingerprint_sha256: response.cluster_ca_fingerprint_sha256.clone(),
                proof_algorithm: response.proof_algorithm,
                created_at_unix: 1_700_000_000,
                last_seen_at_unix: Some(1_700_000_050),
                suspension: ClusterSuspendStatus {
                    suspended: true,
                    suspended_at_unix: Some(1_700_000_075),
                    reason: Some("rate limit review".to_string()),
                },
            }],
        };
        status.validate().expect("status should validate");

        let request_round_trip: ClusterRegistrationChallengeRequest = serde_json::from_str(
            &serde_json::to_string(&request).expect("request should serialize"),
        )
        .expect("request should deserialize");
        let response_round_trip: ClusterRegistrationChallengeResponse = serde_json::from_str(
            &serde_json::to_string(&response).expect("response should serialize"),
        )
        .expect("response should deserialize");
        let complete_round_trip: ClusterRegistrationCompleteRequest = serde_json::from_str(
            &serde_json::to_string(&complete).expect("complete should serialize"),
        )
        .expect("complete should deserialize");
        let status_round_trip: ClusterRegistrationRegistryStatus =
            serde_json::from_str(&serde_json::to_string(&status).expect("status should serialize"))
                .expect("status should deserialize");

        assert_eq!(request_round_trip, request);
        assert_eq!(response_round_trip, response);
        assert_eq!(complete_round_trip, complete);
        assert_eq!(status_round_trip, status);
    }
}
