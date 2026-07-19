use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use base64::Engine;
use common::ClusterId;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use rand::RngCore;
use rand::rngs::OsRng;
use rustls::pki_types::pem::PemObject;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use transport_sdk::{
    CLUSTER_REGISTRATION_PROTOCOL_VERSION, ClusterRegistrationChallengeRequest,
    ClusterRegistrationChallengeResponse, ClusterRegistrationCompleteRequest,
    ClusterRegistrationProofAlgorithm, ClusterRegistrationRecord,
    ClusterRegistrationRegistryStatus, ClusterSuspendStatus,
};
use uuid::Uuid;
use x509_parser::parse_x509_certificate;

use crate::{
    ClusterCaRecord, ClusterCaRegistry, GlobalClusterRegistrationConfig, MaybeObservedPeerAddr,
    RendezvousAppState,
};

type ApiResult<T> = std::result::Result<T, (StatusCode, String)>;

#[derive(Clone)]
pub(crate) struct GlobalRegistrationState {
    registry: ClusterCaRegistry,
    config: GlobalClusterRegistrationConfig,
    challenges: Arc<Mutex<ChallengeStore>>,
    registrations: Arc<Mutex<()>>,
}

impl GlobalRegistrationState {
    pub(crate) fn new(
        registry: ClusterCaRegistry,
        config: GlobalClusterRegistrationConfig,
    ) -> Result<Self> {
        config.validate()?;
        Ok(Self {
            registry,
            config,
            challenges: Arc::new(Mutex::new(ChallengeStore::default())),
            // The persistent registry makes each write atomic. This lock also prevents two
            // simultaneous completion requests in this service instance from rotating a CA.
            registrations: Arc::new(Mutex::new(())),
        })
    }

    fn challenge(
        &self,
        request: ClusterRegistrationChallengeRequest,
        source_ip: IpAddr,
    ) -> Result<ClusterRegistrationChallengeResponse> {
        request.validate()?;
        let now = now_unix_secs()?;
        let ttl_secs = self.config.challenge_ttl.as_secs();
        let expires_at_unix = now
            .checked_add(ttl_secs)
            .context("global registration challenge expiry overflows Unix time")?;
        let mut nonce = [0_u8; 32];
        OsRng.fill_bytes(&mut nonce);
        let response = ClusterRegistrationChallengeResponse {
            protocol_version: CLUSTER_REGISTRATION_PROTOCOL_VERSION,
            cluster_id: request.cluster_id,
            cluster_ca_fingerprint_sha256: request.cluster_ca_fingerprint_sha256()?,
            proof_algorithm: request.proof_algorithm,
            challenge_id: Uuid::new_v4(),
            challenge_nonce_b64u: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce),
            expires_at_unix,
        };
        response.validate()?;

        let mut store = lock(&self.challenges);
        store.cleanup(now);
        if store.entries.len() >= self.config.max_pending_challenges {
            bail!("global registration challenge store is full");
        }
        store.entries.insert(
            response.challenge_id,
            PendingChallenge {
                source_ip,
                cluster_ca_pem: request.cluster_ca_pem,
                response: response.clone(),
            },
        );
        Ok(response)
    }

    fn complete(
        &self,
        request: ClusterRegistrationCompleteRequest,
        source_ip: IpAddr,
    ) -> Result<ClusterRegistrationRecord> {
        request.validate()?;
        let now = now_unix_secs()?;
        let challenge = {
            let mut store = lock(&self.challenges);
            store.cleanup(now);
            let challenge = store
                .entries
                .get(&request.challenge_id)
                .cloned()
                .context("unknown or expired global registration challenge")?;
            if challenge.source_ip != source_ip {
                bail!("global registration challenge source IP does not match");
            }
            if challenge.response.expires_at_unix <= now {
                store.entries.remove(&request.challenge_id);
                bail!("global registration challenge has expired");
            }
            // Completion attempts are one-shot after their source IP is authenticated. This
            // prevents an invalid proof from becoming a reusable signing oracle.
            store.entries.remove(&request.challenge_id);
            challenge
        };

        ensure_challenge_matches(&challenge.response, &request)?;
        verify_proof(&challenge.cluster_ca_pem, &request)?;

        let _registration_guard = lock(&self.registrations);
        if let Some(existing) = self.registry.registered_ca(request.cluster_id) {
            if existing.ca_fingerprint != request.cluster_ca_fingerprint_sha256 {
                bail!("cluster ID is already registered with a different CA");
            }
            info!(
                cluster_id = %request.cluster_id,
                ca_fingerprint = %existing.ca_fingerprint,
                source_ip = %source_ip,
                "global cluster registration completed idempotently"
            );
            return Ok(record_from_registry(&existing));
        }

        let proof_fingerprint = format!(
            "{:x}",
            Sha256::digest(
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(&request.proof_signature_b64u)
                    .context("failed decoding validated global registration proof")?,
            )
        );
        let registered = self.registry.register_or_update(
            request.cluster_id,
            challenge.cluster_ca_pem,
            proof_fingerprint,
        )?;
        info!(
            cluster_id = %registered.cluster_id,
            ca_fingerprint = %registered.ca_fingerprint,
            source_ip = %source_ip,
            "global cluster registered"
        );
        Ok(record_from_registry(&registered))
    }

    fn registry_status(&self) -> Result<ClusterRegistrationRegistryStatus> {
        let status = ClusterRegistrationRegistryStatus {
            protocol_version: CLUSTER_REGISTRATION_PROTOCOL_VERSION,
            generated_at_unix: now_unix_secs()?,
            records: self
                .registry
                .list()
                .iter()
                .map(record_from_registry)
                .collect(),
        };
        status.validate()?;
        Ok(status)
    }

    fn set_suspension(
        &self,
        cluster_id: ClusterId,
        suspended: bool,
    ) -> Result<ClusterRegistrationRecord> {
        let record = self.registry.set_suspended(cluster_id, suspended)?;
        info!(
            cluster_id = %cluster_id,
            suspended,
            ca_fingerprint = %record.ca_fingerprint,
            "global cluster suspension changed"
        );
        Ok(record_from_registry(&record))
    }

    fn rate_limit(&self, source_ip: IpAddr, operation: RateLimitOperation) -> Result<()> {
        let mut store = lock(&self.challenges);
        store.allow(source_ip, operation, self.config.rate_limit_per_minute)
    }

    fn authorize_operator(&self, headers: &HeaderMap) -> bool {
        let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
            return false;
        };
        let Ok(value) = value.to_str() else {
            return false;
        };
        let Some(token) = value.strip_prefix("Bearer ") else {
            return false;
        };
        bool::from(token.as_bytes().ct_eq(self.config.admin_token.as_bytes()))
    }
}

#[derive(Default)]
struct ChallengeStore {
    entries: HashMap<Uuid, PendingChallenge>,
    rates: HashMap<(IpAddr, RateLimitOperation), RateWindow>,
}

impl ChallengeStore {
    fn cleanup(&mut self, now_unix: u64) {
        self.entries
            .retain(|_, challenge| challenge.response.expires_at_unix > now_unix);
        self.rates
            .retain(|_, window| window.started_at.elapsed() < Duration::from_secs(60));
    }

    fn allow(
        &mut self,
        source_ip: IpAddr,
        operation: RateLimitOperation,
        limit: u32,
    ) -> Result<()> {
        let now = Instant::now();
        self.rates
            .retain(|_, window| now.duration_since(window.started_at) < Duration::from_secs(60));
        let window = self
            .rates
            .entry((source_ip, operation))
            .or_insert(RateWindow {
                started_at: now,
                requests: 0,
            });
        if now.duration_since(window.started_at) >= Duration::from_secs(60) {
            *window = RateWindow {
                started_at: now,
                requests: 0,
            };
        }
        if window.requests >= limit {
            bail!("global registration rate limit exceeded");
        }
        window.requests += 1;
        Ok(())
    }
}

#[derive(Clone)]
struct PendingChallenge {
    source_ip: IpAddr,
    cluster_ca_pem: String,
    response: ClusterRegistrationChallengeResponse,
}

struct RateWindow {
    started_at: Instant,
    requests: u32,
}

#[derive(Clone, Copy, Hash, PartialEq, Eq)]
enum RateLimitOperation {
    Challenge,
    Complete,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClusterSuspensionRequest {
    suspended: bool,
}

pub(crate) async fn issue_challenge(
    State(state): State<RendezvousAppState>,
    observed_peer_addr: MaybeObservedPeerAddr,
    Json(request): Json<ClusterRegistrationChallengeRequest>,
) -> ApiResult<Json<ClusterRegistrationChallengeResponse>> {
    let registration = global_registration(&state)?;
    let source_ip = source_ip(observed_peer_addr)?;
    registration
        .rate_limit(source_ip, RateLimitOperation::Challenge)
        .map_err(rate_limited)?;
    registration
        .challenge(request, source_ip)
        .map(Json)
        .map_err(|error| {
            if error.to_string().contains("challenge store is full") {
                rate_limited(error)
            } else {
                bad_request(error)
            }
        })
}

pub(crate) async fn complete_registration(
    State(state): State<RendezvousAppState>,
    observed_peer_addr: MaybeObservedPeerAddr,
    Json(request): Json<ClusterRegistrationCompleteRequest>,
) -> ApiResult<Json<ClusterRegistrationRecord>> {
    let registration = global_registration(&state)?;
    let source_ip = source_ip(observed_peer_addr)?;
    registration
        .rate_limit(source_ip, RateLimitOperation::Complete)
        .map_err(rate_limited)?;
    registration
        .complete(request, source_ip)
        .map(Json)
        .map_err(|error| {
            let status = if error
                .to_string()
                .contains("already registered with a different CA")
            {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_REQUEST
            };
            (status, error.to_string())
        })
}

pub(crate) async fn list_clusters(
    State(state): State<RendezvousAppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ClusterRegistrationRegistryStatus>> {
    let registration = global_registration(&state)?;
    require_operator(registration, &headers)?;
    registration
        .registry_status()
        .map(Json)
        .map_err(internal_error)
}

pub(crate) async fn set_cluster_suspension(
    State(state): State<RendezvousAppState>,
    headers: HeaderMap,
    Path(cluster_id): Path<ClusterId>,
    Json(request): Json<ClusterSuspensionRequest>,
) -> ApiResult<Json<ClusterRegistrationRecord>> {
    let registration = global_registration(&state)?;
    require_operator(registration, &headers)?;
    registration
        .set_suspension(cluster_id, request.suspended)
        .map(Json)
        .map_err(|error| (StatusCode::NOT_FOUND, error.to_string()))
}

fn global_registration(state: &RendezvousAppState) -> ApiResult<&GlobalRegistrationState> {
    state.global_registration.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "global cluster registration is not enabled".to_string(),
        )
    })
}

fn source_ip(observed_peer_addr: MaybeObservedPeerAddr) -> ApiResult<IpAddr> {
    observed_peer_addr
        .socket_addr()
        .map(|address| address.ip())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "global registration source IP is unavailable".to_string(),
            )
        })
}

fn require_operator(registration: &GlobalRegistrationState, headers: &HeaderMap) -> ApiResult<()> {
    if registration.authorize_operator(headers) {
        Ok(())
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            "global cluster registration operator authorization is required".to_string(),
        ))
    }
}

fn ensure_challenge_matches(
    challenge: &ClusterRegistrationChallengeResponse,
    completion: &ClusterRegistrationCompleteRequest,
) -> Result<()> {
    if completion.protocol_version != challenge.protocol_version
        || completion.cluster_id != challenge.cluster_id
        || completion.cluster_ca_fingerprint_sha256 != challenge.cluster_ca_fingerprint_sha256
        || completion.proof_algorithm != challenge.proof_algorithm
        || completion.challenge_id != challenge.challenge_id
        || completion.challenge_nonce_b64u != challenge.challenge_nonce_b64u
        || completion.expires_at_unix != challenge.expires_at_unix
    {
        bail!("global registration completion does not match its issued challenge");
    }
    Ok(())
}

fn verify_proof(ca_pem: &str, completion: &ClusterRegistrationCompleteRequest) -> Result<()> {
    let message = completion.canonical_proof_message_v1()?;
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&completion.proof_signature_b64u)
        .context("failed decoding global registration proof signature")?;
    let signature = Signature::from_der(&signature)
        .context("global registration proof signature is not ASN.1 ECDSA P-256")?;
    let verifying_key = verifying_key_from_ca(ca_pem, completion.proof_algorithm)?;
    verifying_key
        .verify(&message, &signature)
        .context("global registration proof signature does not verify")
}

fn verifying_key_from_ca(
    ca_pem: &str,
    algorithm: ClusterRegistrationProofAlgorithm,
) -> Result<VerifyingKey> {
    match algorithm {
        ClusterRegistrationProofAlgorithm::EcdsaP256Sha256Asn1 => {}
    }
    let certificate = pem_certificate_der(ca_pem)?;
    let (_, parsed) = parse_x509_certificate(&certificate)
        .context("failed parsing global registration CA certificate")?;
    VerifyingKey::from_sec1_bytes(parsed.public_key().subject_public_key.data.as_ref())
        .context("global registration CA does not contain a valid P-256 public key")
}

fn pem_certificate_der(ca_pem: &str) -> Result<Vec<u8>> {
    let mut reader = std::io::Cursor::new(ca_pem.as_bytes());
    let certificates = rustls::pki_types::CertificateDer::pem_reader_iter(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed parsing global registration CA PEM")?;
    let [certificate] = certificates.as_slice() else {
        bail!("global registration CA PEM must contain exactly one certificate");
    };
    Ok(certificate.as_ref().to_vec())
}

fn record_from_registry(record: &ClusterCaRecord) -> ClusterRegistrationRecord {
    ClusterRegistrationRecord {
        cluster_id: record.cluster_id,
        cluster_ca_fingerprint_sha256: record.ca_fingerprint.clone(),
        proof_algorithm: ClusterRegistrationProofAlgorithm::EcdsaP256Sha256Asn1,
        created_at_unix: record.created_at_unix_secs,
        last_seen_at_unix: Some(record.last_seen_at_unix_secs),
        // P2-C persists suspension as an active/inactive trust decision. Its latest
        // persisted observation time is the stable audit timestamp available to P2-D.
        suspension: if record.suspended {
            ClusterSuspendStatus {
                suspended: true,
                suspended_at_unix: Some(record.last_seen_at_unix_secs),
                reason: None,
            }
        } else {
            ClusterSuspendStatus::default()
        },
    }
}

fn now_unix_secs() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")
        .map(|duration| duration.as_secs())
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn bad_request(error: anyhow::Error) -> (StatusCode, String) {
    warn!(error = %error, "global cluster registration request rejected");
    (StatusCode::BAD_REQUEST, error.to_string())
}

fn rate_limited(error: anyhow::Error) -> (StatusCode, String) {
    warn!(error = %error, "global cluster registration request rate limited");
    (StatusCode::TOO_MANY_REQUESTS, error.to_string())
}

fn internal_error(error: anyhow::Error) -> (StatusCode, String) {
    warn!(error = %error, "global cluster registration internal error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "global cluster registration failed".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::{HeaderValue, Request, header};
    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};
    use tower::ServiceExt;

    use super::*;
    use crate::{
        RendezvousClientCa, RendezvousMtlsConfig, RendezvousServerConfig,
        RendezvousServerTlsIdentity, build_router,
    };

    struct TestCa {
        pem: String,
        signing_key: p256::ecdsa::SigningKey,
    }

    fn test_ca() -> TestCa {
        let key_pair = KeyPair::generate().expect("test P-256 CA key should generate");
        let signing_key = p256::ecdsa::SigningKey::from_pkcs8_der(&key_pair.serialize_der())
            .expect("rcgen P-256 key should decode for proof signing");
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];
        let pem = params
            .self_signed(&key_pair)
            .expect("test P-256 CA certificate should self-sign")
            .pem();
        TestCa { pem, signing_key }
    }

    fn registry_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "ironmesh-global-registration-{name}-{}.json",
            ClusterId::now_v7()
        ))
    }

    fn global_state(rate_limit_per_minute: u32) -> (RendezvousAppState, TestCa, PathBuf) {
        global_state_with_capacity(rate_limit_per_minute, 16)
    }

    fn global_state_with_capacity(
        rate_limit_per_minute: u32,
        max_pending_challenges: usize,
    ) -> (RendezvousAppState, TestCa, PathBuf) {
        let ca = test_ca();
        let path = registry_path("state");
        let registry = ClusterCaRegistry::open(&path).expect("registry should open");
        let state = RendezvousAppState::new(RendezvousServerConfig {
            bind_addr: "127.0.0.1:0".parse().expect("bind address should parse"),
            public_url: "https://rendezvous.example".to_string(),
            relay_public_urls: vec!["https://rendezvous.example".to_string()],
            peer_rendezvous_urls: Vec::new(),
            mtls: Some(RendezvousMtlsConfig {
                client_ca: RendezvousClientCa::Global {
                    cluster_registry: registry,
                    registration: GlobalClusterRegistrationConfig {
                        admin_token: "operator-token".to_string(),
                        rate_limit_per_minute,
                        challenge_ttl: Duration::from_secs(60),
                        max_pending_challenges,
                    },
                },
                server_identity: RendezvousServerTlsIdentity::InlinePem {
                    cert_pem: String::new(),
                    key_pem: String::new(),
                },
            }),
        })
        .expect("global rendezvous state should build");
        (state, ca, path)
    }

    fn source(ip: &str) -> MaybeObservedPeerAddr {
        MaybeObservedPeerAddr(Some(
            format!("{ip}:44042")
                .parse()
                .expect("test source address should parse"),
        ))
    }

    fn challenge_request(
        ca: &TestCa,
        cluster_id: ClusterId,
    ) -> ClusterRegistrationChallengeRequest {
        ClusterRegistrationChallengeRequest {
            protocol_version: CLUSTER_REGISTRATION_PROTOCOL_VERSION,
            cluster_id,
            cluster_ca_pem: ca.pem.clone(),
            proof_algorithm: ClusterRegistrationProofAlgorithm::EcdsaP256Sha256Asn1,
        }
    }

    fn completion(
        challenge: &ClusterRegistrationChallengeResponse,
        signing_key: &p256::ecdsa::SigningKey,
    ) -> ClusterRegistrationCompleteRequest {
        let message = challenge
            .canonical_proof_message_v1()
            .expect("challenge proof message should build");
        let signature: Signature = signing_key.sign(&message);
        ClusterRegistrationCompleteRequest {
            protocol_version: challenge.protocol_version,
            cluster_id: challenge.cluster_id,
            cluster_ca_fingerprint_sha256: challenge.cluster_ca_fingerprint_sha256.clone(),
            proof_algorithm: challenge.proof_algorithm,
            challenge_id: challenge.challenge_id,
            challenge_nonce_b64u: challenge.challenge_nonce_b64u.clone(),
            expires_at_unix: challenge.expires_at_unix,
            proof_signature_b64u: base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(signature.to_der().as_bytes()),
        }
    }

    async fn issue(
        state: &RendezvousAppState,
        ca: &TestCa,
        cluster_id: ClusterId,
        ip: &str,
    ) -> ClusterRegistrationChallengeResponse {
        issue_challenge(
            State(state.clone()),
            source(ip),
            Json(challenge_request(ca, cluster_id)),
        )
        .await
        .expect("challenge should succeed")
        .0
    }

    #[tokio::test]
    async fn challenge_proof_completion_and_registry_reuse_succeed() {
        let (state, ca, path) = global_state(10);
        let cluster_id = ClusterId::now_v7();
        let challenge = issue(&state, &ca, cluster_id, "203.0.113.10").await;
        let record = complete_registration(
            State(state.clone()),
            source("203.0.113.10"),
            Json(completion(&challenge, &ca.signing_key)),
        )
        .await
        .expect("valid proof should register the cluster")
        .0;
        assert_eq!(record.cluster_id, cluster_id);
        assert!(!record.suspension.suspended);

        let reloaded = ClusterCaRegistry::open(&path).expect("registry should reload");
        assert_eq!(
            reloaded
                .registered_ca(cluster_id)
                .map(|entry| entry.ca_fingerprint),
            Some(record.cluster_ca_fingerprint_sha256.clone())
        );

        let restarted = RendezvousAppState::new(RendezvousServerConfig {
            bind_addr: "127.0.0.1:0".parse().expect("bind address should parse"),
            public_url: "https://rendezvous.example".to_string(),
            relay_public_urls: vec!["https://rendezvous.example".to_string()],
            peer_rendezvous_urls: Vec::new(),
            mtls: Some(RendezvousMtlsConfig {
                client_ca: RendezvousClientCa::Global {
                    cluster_registry: reloaded,
                    registration: GlobalClusterRegistrationConfig {
                        admin_token: "operator-token".to_string(),
                        rate_limit_per_minute: 10,
                        challenge_ttl: Duration::from_secs(60),
                        max_pending_challenges: 16,
                    },
                },
                server_identity: RendezvousServerTlsIdentity::InlinePem {
                    cert_pem: String::new(),
                    key_pem: String::new(),
                },
            }),
        })
        .expect("restarted global rendezvous state should build");
        let retry_challenge = issue(&restarted, &ca, cluster_id, "203.0.113.10").await;
        let retry = complete_registration(
            State(restarted),
            source("203.0.113.10"),
            Json(completion(&retry_challenge, &ca.signing_key)),
        )
        .await
        .expect("same CA registration should be idempotent")
        .0;
        assert_eq!(retry, record);
    }

    #[tokio::test]
    async fn completion_rejects_replay_expiry_ip_mismatch_and_invalid_signature() {
        let (state, ca, _) = global_state(10);
        let cluster_id = ClusterId::now_v7();
        let challenge = issue(&state, &ca, cluster_id, "203.0.113.10").await;
        let valid_completion = completion(&challenge, &ca.signing_key);

        let wrong_ip = complete_registration(
            State(state.clone()),
            source("203.0.113.11"),
            Json(valid_completion.clone()),
        )
        .await
        .expect_err("another source IP must not complete the challenge");
        assert_eq!(wrong_ip.0, StatusCode::BAD_REQUEST);

        let _ = complete_registration(
            State(state.clone()),
            source("203.0.113.10"),
            Json(valid_completion.clone()),
        )
        .await
        .expect("bound source IP should still complete the challenge");
        let replay = complete_registration(
            State(state.clone()),
            source("203.0.113.10"),
            Json(valid_completion),
        )
        .await
        .expect_err("consumed challenge must not replay");
        assert_eq!(replay.0, StatusCode::BAD_REQUEST);

        let expired = issue(&state, &ca, ClusterId::now_v7(), "203.0.113.12").await;
        lock(
            &state
                .global_registration
                .as_ref()
                .expect("registration state")
                .challenges,
        )
        .entries
        .get_mut(&expired.challenge_id)
        .expect("challenge should exist")
        .response
        .expires_at_unix = 1;
        let expired_result = complete_registration(
            State(state.clone()),
            source("203.0.113.12"),
            Json(completion(&expired, &ca.signing_key)),
        )
        .await
        .expect_err("expired challenge must be rejected");
        assert_eq!(expired_result.0, StatusCode::BAD_REQUEST);

        let invalid = issue(&state, &ca, ClusterId::now_v7(), "203.0.113.13").await;
        let foreign_signer = test_ca();
        let invalid_result = complete_registration(
            State(state),
            source("203.0.113.13"),
            Json(completion(&invalid, &foreign_signer.signing_key)),
        )
        .await
        .expect_err("proof from another CA key must be rejected");
        assert_eq!(invalid_result.0, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn foreign_ca_conflicts_and_rate_limits_are_enforced_per_operation() {
        let (state, ca_a, _) = global_state(1);
        let cluster_id = ClusterId::now_v7();
        let challenge = issue(&state, &ca_a, cluster_id, "203.0.113.20").await;
        let _ = complete_registration(
            State(state.clone()),
            source("203.0.113.20"),
            Json(completion(&challenge, &ca_a.signing_key)),
        )
        .await
        .expect("first CA should register");

        let ca_b = test_ca();
        let foreign_challenge = issue(&state, &ca_b, cluster_id, "203.0.113.21").await;
        let conflict = complete_registration(
            State(state.clone()),
            source("203.0.113.21"),
            Json(completion(&foreign_challenge, &ca_b.signing_key)),
        )
        .await
        .expect_err("CA rotation is outside the MVP");
        assert_eq!(conflict.0, StatusCode::CONFLICT);

        let rate_limited = issue_challenge(
            State(state.clone()),
            source("203.0.113.20"),
            Json(challenge_request(&ca_a, ClusterId::now_v7())),
        )
        .await
        .expect_err("second challenge from one IP should hit its limit");
        assert_eq!(rate_limited.0, StatusCode::TOO_MANY_REQUESTS);

        let registration = state
            .global_registration
            .as_ref()
            .expect("registration state");
        let ip: IpAddr = "203.0.113.22".parse().expect("IP should parse");
        registration
            .rate_limit(ip, RateLimitOperation::Complete)
            .expect("first completion slot should be allowed");
        assert!(
            registration
                .rate_limit(ip, RateLimitOperation::Complete)
                .is_err()
        );
    }

    #[tokio::test]
    async fn bounded_challenge_store_returns_too_many_requests() {
        let (state, ca, _) = global_state_with_capacity(10, 1);
        issue(&state, &ca, ClusterId::now_v7(), "203.0.113.23").await;
        let full = issue_challenge(
            State(state),
            source("203.0.113.24"),
            Json(challenge_request(&ca, ClusterId::now_v7())),
        )
        .await
        .expect_err("bounded challenge store must reject new challenges");
        assert_eq!(full.0, StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn operator_auth_suspension_and_global_route_auth_boundaries_are_enforced() {
        let (state, ca, _) = global_state(10);
        let cluster_id = ClusterId::now_v7();
        let challenge = issue(&state, &ca, cluster_id, "203.0.113.30").await;
        let _ = complete_registration(
            State(state.clone()),
            source("203.0.113.30"),
            Json(completion(&challenge, &ca.signing_key)),
        )
        .await
        .expect("cluster should register");

        let unauthorized = list_clusters(State(state.clone()), HeaderMap::new())
            .await
            .expect_err("registry status requires an operator token");
        assert_eq!(unauthorized.0, StatusCode::UNAUTHORIZED);

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer operator-token"),
        );
        let status = list_clusters(State(state.clone()), headers.clone())
            .await
            .expect("operator should list registered clusters")
            .0;
        assert_eq!(status.records.len(), 1);
        assert_eq!(status.records[0].cluster_id, cluster_id);
        let suspended = set_cluster_suspension(
            State(state.clone()),
            headers.clone(),
            Path(cluster_id),
            Json(ClusterSuspensionRequest { suspended: true }),
        )
        .await
        .expect("operator should suspend cluster")
        .0;
        assert!(suspended.suspension.suspended);
        assert!(
            state
                .global_registration
                .as_ref()
                .expect("registration state")
                .registry
                .active_ca(cluster_id)
                .is_none()
        );

        let resumed = set_cluster_suspension(
            State(state.clone()),
            headers,
            Path(cluster_id),
            Json(ClusterSuspensionRequest { suspended: false }),
        )
        .await
        .expect("operator should resume cluster")
        .0;
        assert!(!resumed.suspension.suspended);

        let router = build_router(state.clone());
        let control = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/control/mesh")
                    .body(Body::empty())
                    .expect("control request should build"),
            )
            .await
            .expect("control route should respond");
        assert_eq!(control.status(), StatusCode::UNAUTHORIZED);

        assert!(
            crate::ensure_relay_websocket_authenticated(
                &state,
                &crate::MaybeAuthenticatedPeer::default(),
            )
            .is_err()
        );

        let request = serde_json::to_vec(&challenge_request(&ca, ClusterId::now_v7()))
            .expect("challenge request should serialize");
        let registration = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/global/cluster-registration/challenge")
                    .header(header::CONTENT_TYPE, "application/json")
                    .extension(ConnectInfo(
                        "203.0.113.31:44042"
                            .parse::<std::net::SocketAddr>()
                            .expect("source should parse"),
                    ))
                    .body(Body::from(request))
                    .expect("registration request should build"),
            )
            .await
            .expect("registration route should respond");
        assert_eq!(registration.status(), StatusCode::OK);
    }
}
