use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use rendezvous_server::{
    ClusterCaRegistry, GlobalClusterRegistrationConfig, RendezvousAppState, RendezvousClientCa,
    RendezvousMtlsConfig, RendezvousServerConfig, RendezvousServerTlsIdentity,
};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};
use transport_sdk::{
    CLUSTER_REGISTRATION_PROTOCOL_VERSION, CandidateKind, ClusterRegistrationChallengeRequest,
    ClusterRegistrationChallengeResponse, ClusterRegistrationCompleteRequest,
    ClusterRegistrationProofAlgorithm, ClusterRegistrationRecord, ConnectionCandidate,
    PeerIdentity, PresenceRegistration, RelayMode, RendezvousClientConfig, RendezvousControlClient,
    TransportCapability,
};
use uuid::Uuid;

const ADMIN_TOKEN: &str = "global-rendezvous-system-test-operator-token";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const SERVER_START_TIMEOUT: Duration = Duration::from_secs(10);
const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
const SYSTEM_TEST_TIMEOUT: Duration = Duration::from_secs(45);

struct TestCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
    proof_signing_key: SigningKey,
}

struct TemporaryRegistry {
    path: PathBuf,
}

impl TemporaryRegistry {
    fn new() -> Self {
        Self {
            path: std::env::temp_dir().join(format!(
                "ironmesh-global-rendezvous-system-test-{}.json",
                Uuid::new_v4()
            )),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TemporaryRegistry {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct TestServer {
    task: JoinHandle<Result<()>>,
}

impl TestServer {
    async fn shutdown(mut self) -> Result<()> {
        self.task.abort();
        match timeout(SERVER_SHUTDOWN_TIMEOUT, &mut self.task).await {
            Ok(Err(error)) if error.is_cancelled() => Ok(()),
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(error.context("rendezvous server stopped with an error")),
            Ok(Err(error)) => Err(anyhow!("failed joining rendezvous server task: {error}")),
            Err(_) => bail!("timed out shutting down rendezvous server"),
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn global_rendezvous_https_registry_mtls_tenancy_and_suspend_survive_restart() -> Result<()> {
    timeout(SYSTEM_TEST_TIMEOUT, global_rendezvous_system_test())
        .await
        .context("global rendezvous system test timed out")?
}

async fn global_rendezvous_system_test() -> Result<()> {
    let registry = TemporaryRegistry::new();
    let bind_addr = unused_loopback_address()?;
    let base_url = format!("https://{bind_addr}");
    let server_ca = p256_ca("ironmesh-global-rendezvous-server-ca")?;
    let server_identity = server_identity(&server_ca)?;
    let mut server = start_global_rendezvous(
        bind_addr,
        &base_url,
        registry.path(),
        &server_ca.cert_pem,
        server_identity.clone(),
    )
    .await?;

    let cluster_a = Uuid::new_v4();
    let cluster_b = Uuid::new_v4();
    let cluster_ca_a = p256_ca("ironmesh-global-rendezvous-cluster-a-ca")?;
    let cluster_ca_b = p256_ca("ironmesh-global-rendezvous-cluster-b-ca")?;

    // This client deliberately has no client identity: registration precedes mTLS enrollment.
    let registration_http = strict_https_client(&server_ca.cert_pem)?;
    let record_a =
        register_cluster(&registration_http, &base_url, cluster_a, &cluster_ca_a).await?;
    let record_b =
        register_cluster(&registration_http, &base_url, cluster_b, &cluster_ca_b).await?;
    assert_eq!(record_a.cluster_id, cluster_a);
    assert_eq!(record_b.cluster_id, cluster_b);

    let shared_node_id = Uuid::new_v4();
    let shared_identity = PeerIdentity::Node(shared_node_id);
    let client_identity_a = client_identity(&cluster_ca_a, cluster_a, &shared_identity)?;
    let client_identity_b = client_identity(&cluster_ca_b, cluster_b, &shared_identity)?;
    let control_a = rendezvous_control(
        cluster_a,
        &base_url,
        &server_ca.cert_pem,
        &client_identity_a,
    )?;
    let control_b = rendezvous_control(
        cluster_b,
        &base_url,
        &server_ca.cert_pem,
        &client_identity_b,
    )?;
    let presence_a = presence(
        cluster_a,
        shared_identity.clone(),
        "https://127.0.0.1:42001",
    );
    let presence_b = presence(
        cluster_b,
        shared_identity.clone(),
        "https://127.0.0.1:42002",
    );

    control_a
        .register_presence(&presence_a)
        .await
        .context("cluster A mTLS presence registration failed")?;
    control_b
        .register_presence(&presence_b)
        .await
        .context("cluster B mTLS presence registration failed")?;

    assert_cluster_namespace(&control_a, &presence_a, shared_node_id).await?;
    assert_cluster_namespace(&control_b, &presence_b, shared_node_id).await?;

    let mismatched_identity = client_identity(&cluster_ca_a, cluster_b, &shared_identity)?;
    let mismatched_control = rendezvous_control(
        cluster_b,
        &base_url,
        &server_ca.cert_pem,
        &mismatched_identity,
    )?;
    assert!(
        mismatched_control.list_presence().await.is_err(),
        "a cluster B SAN signed by cluster A CA must not reach cluster B control"
    );

    server.shutdown().await?;
    server = start_global_rendezvous(
        bind_addr,
        &base_url,
        registry.path(),
        &server_ca.cert_pem,
        server_identity,
    )
    .await?;

    let restarted_control_a = rendezvous_control(
        cluster_a,
        &base_url,
        &server_ca.cert_pem,
        &client_identity_a,
    )?;
    let restarted_a_presence = restarted_control_a
        .list_presence()
        .await
        .context("cluster A was not authenticated after registry-backed restart")?;
    assert_eq!(restarted_a_presence.registered_endpoints, 0);

    let operator_http = strict_https_client(&server_ca.cert_pem)?;
    suspend_cluster(&operator_http, &base_url, cluster_a).await?;

    let suspended_control_a = rendezvous_control(
        cluster_a,
        &base_url,
        &server_ca.cert_pem,
        &client_identity_a,
    )?;
    assert!(
        suspended_control_a.list_presence().await.is_err(),
        "suspended cluster A must not complete a new mTLS control connection"
    );

    let active_control_b = rendezvous_control(
        cluster_b,
        &base_url,
        &server_ca.cert_pem,
        &client_identity_b,
    )?;
    active_control_b
        .register_presence(&presence_b)
        .await
        .context("cluster B must remain usable after cluster A suspension")?;
    assert_cluster_namespace(&active_control_b, &presence_b, shared_node_id).await?;

    server.shutdown().await
}

fn p256_ca(common_name: &str) -> Result<TestCa> {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .context("failed generating P-256 test CA key")?;
    let proof_signing_key = SigningKey::from_pkcs8_der(&key_pair.serialize_der())
        .context("failed loading P-256 test CA proof key")?;
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let cert_pem = params
        .self_signed(&key_pair)
        .context("failed self-signing P-256 test CA")?
        .pem();

    Ok(TestCa {
        cert_pem,
        issuer: Issuer::new(params, key_pair),
        proof_signing_key,
    })
}

fn server_identity(ca: &TestCa) -> Result<RendezvousServerTlsIdentity> {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .context("failed generating rendezvous server key")?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, "ironmesh-global-rendezvous-system-test");
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let cert_pem = params
        .signed_by(&key_pair, &ca.issuer)
        .context("failed signing rendezvous server certificate")?
        .pem();

    Ok(RendezvousServerTlsIdentity::InlinePem {
        cert_pem,
        key_pem: key_pair.serialize_pem(),
    })
}

fn client_identity(ca: &TestCa, cluster_id: Uuid, identity: &PeerIdentity) -> Result<Vec<u8>> {
    let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
        .context("failed generating rendezvous client key")?;
    let mut params = CertificateParams::default();
    params.distinguished_name.push(
        DnType::CommonName,
        "ironmesh-global-rendezvous-system-client",
    );
    params.subject_alt_names = vec![
        SanType::URI(
            rcgen::string::Ia5String::try_from(peer_identity_san(identity))
                .context("invalid peer identity SAN")?,
        ),
        SanType::URI(
            rcgen::string::Ia5String::try_from(format!("urn:ironmesh:cluster:{cluster_id}"))
                .context("invalid cluster SAN")?,
        ),
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let cert_pem = params
        .signed_by(&key_pair, &ca.issuer)
        .context("failed signing rendezvous client certificate")?
        .pem();

    let mut identity_pem = cert_pem.into_bytes();
    identity_pem.extend_from_slice(key_pair.serialize_pem().as_bytes());
    Ok(identity_pem)
}

fn peer_identity_san(identity: &PeerIdentity) -> String {
    match identity {
        PeerIdentity::Node(node_id) => format!("urn:ironmesh:node:{node_id}"),
        PeerIdentity::Device(device_id) => format!("urn:ironmesh:device:{device_id}"),
    }
}

fn presence(cluster_id: Uuid, identity: PeerIdentity, endpoint: &str) -> PresenceRegistration {
    PresenceRegistration {
        cluster_id,
        identity,
        public_api_url: None,
        public_direct_urls: Vec::new(),
        peer_api_url: None,
        direct_candidates: vec![ConnectionCandidate {
            kind: CandidateKind::DirectHttps,
            endpoint: endpoint.to_string(),
            rtt_ms: Some(1),
            transport_hints: None,
        }],
        labels: HashMap::new(),
        capacity_bytes: None,
        free_bytes: None,
        capabilities: vec![TransportCapability::DirectHttps],
        relay_mode: RelayMode::Disabled,
        connected_at_unix: unix_timestamp(),
    }
}

fn unused_loopback_address() -> Result<SocketAddr> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .context("failed reserving a loopback port for rendezvous server")?;
    let address = listener
        .local_addr()
        .context("failed reading reserved rendezvous server address")?;
    drop(listener);
    Ok(address)
}

async fn start_global_rendezvous(
    bind_addr: SocketAddr,
    base_url: &str,
    registry_path: &Path,
    server_ca_pem: &str,
    server_identity: RendezvousServerTlsIdentity,
) -> Result<TestServer> {
    let registry = ClusterCaRegistry::open(registry_path)
        .context("failed opening persistent global rendezvous registry")?;
    let state = RendezvousAppState::new(RendezvousServerConfig {
        bind_addr,
        public_url: base_url.to_string(),
        relay_public_urls: vec![base_url.to_string()],
        peer_rendezvous_urls: Vec::new(),
        mtls: Some(RendezvousMtlsConfig {
            client_ca: RendezvousClientCa::Global {
                cluster_registry: registry,
                registration: GlobalClusterRegistrationConfig {
                    admin_token: ADMIN_TOKEN.to_string(),
                    rate_limit_per_minute: 100,
                    challenge_ttl: Duration::from_secs(30),
                    max_pending_challenges: 32,
                },
            },
            server_identity,
        }),
    })
    .context("failed constructing global rendezvous application state")?;
    let server = TestServer {
        task: tokio::spawn(rendezvous_server::serve(state)),
    };
    wait_for_server_ready(base_url, server_ca_pem).await?;
    Ok(server)
}

fn strict_https_client(server_ca_pem: &str) -> Result<reqwest::Client> {
    let server_ca = reqwest::Certificate::from_pem(server_ca_pem.as_bytes())
        .context("failed parsing local rendezvous server CA")?;
    reqwest::Client::builder()
        .https_only(true)
        .tls_built_in_root_certs(false)
        .add_root_certificate(server_ca)
        .connect_timeout(REQUEST_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed building strict local HTTPS client")
}

async fn wait_for_server_ready(base_url: &str, server_ca_pem: &str) -> Result<()> {
    let client = strict_https_client(server_ca_pem)?;
    let health_url = endpoint_url(base_url, "/health");
    let deadline = Instant::now() + SERVER_START_TIMEOUT;
    let last_error = loop {
        let error = match client.get(&health_url).send().await {
            Ok(response) if response.status().is_success() => return Ok(()),
            Ok(response) => format!("HTTP {}", response.status()),
            Err(error) => error.to_string(),
        };

        if Instant::now() >= deadline {
            break error;
        }
        sleep(Duration::from_millis(50)).await;
    };
    bail!("global rendezvous server did not become ready at {health_url}: {last_error}")
}

async fn register_cluster(
    http: &reqwest::Client,
    base_url: &str,
    cluster_id: Uuid,
    cluster_ca: &TestCa,
) -> Result<ClusterRegistrationRecord> {
    let request = ClusterRegistrationChallengeRequest {
        protocol_version: CLUSTER_REGISTRATION_PROTOCOL_VERSION,
        cluster_id,
        cluster_ca_pem: cluster_ca.cert_pem.clone(),
        proof_algorithm: ClusterRegistrationProofAlgorithm::EcdsaP256Sha256Asn1,
    };
    request
        .validate()
        .context("test P-256 cluster registration request is invalid")?;
    let expected_fingerprint = request
        .cluster_ca_fingerprint_sha256()
        .context("failed calculating test P-256 CA fingerprint")?;

    let challenge_url = endpoint_url(base_url, "/global/cluster-registration/challenge");
    let challenge: ClusterRegistrationChallengeResponse = http
        .post(&challenge_url)
        .json(&request)
        .send()
        .await
        .with_context(|| format!("failed sending HTTPS request to {challenge_url}"))?
        .error_for_status()
        .with_context(|| format!("global rendezvous request to {challenge_url} returned an error"))?
        .json()
        .await
        .with_context(|| {
            format!("failed decoding global rendezvous response from {challenge_url}")
        })?;
    challenge
        .validate_at(unix_timestamp())
        .context("global rendezvous returned an invalid registration challenge")?;
    assert_eq!(challenge.cluster_id, cluster_id);
    assert_eq!(
        challenge.cluster_ca_fingerprint_sha256,
        expected_fingerprint
    );
    assert_eq!(
        challenge.proof_algorithm,
        ClusterRegistrationProofAlgorithm::EcdsaP256Sha256Asn1
    );

    let proof_message = challenge
        .canonical_proof_message_v1()
        .context("failed generating canonical P2-D proof message")?;
    let proof_signature: Signature = cluster_ca.proof_signing_key.sign(&proof_message);
    let completion = ClusterRegistrationCompleteRequest {
        protocol_version: challenge.protocol_version,
        cluster_id: challenge.cluster_id,
        cluster_ca_fingerprint_sha256: challenge.cluster_ca_fingerprint_sha256.clone(),
        proof_algorithm: challenge.proof_algorithm,
        challenge_id: challenge.challenge_id,
        challenge_nonce_b64u: challenge.challenge_nonce_b64u.clone(),
        expires_at_unix: challenge.expires_at_unix,
        proof_signature_b64u: URL_SAFE_NO_PAD.encode(proof_signature.to_der().as_bytes()),
    };
    completion
        .validate_at(unix_timestamp())
        .context("test P2-D registration completion is invalid")?;

    let completion_url = endpoint_url(base_url, "/global/cluster-registration/complete");
    let record: ClusterRegistrationRecord = http
        .post(&completion_url)
        .json(&completion)
        .send()
        .await
        .with_context(|| format!("failed sending HTTPS request to {completion_url}"))?
        .error_for_status()
        .with_context(|| {
            format!("global rendezvous request to {completion_url} returned an error")
        })?
        .json()
        .await
        .with_context(|| {
            format!("failed decoding global rendezvous response from {completion_url}")
        })?;
    record
        .validate()
        .context("global rendezvous returned an invalid registration record")?;
    assert_eq!(record.cluster_id, cluster_id);
    assert_eq!(record.cluster_ca_fingerprint_sha256, expected_fingerprint);
    Ok(record)
}

fn rendezvous_control(
    cluster_id: Uuid,
    base_url: &str,
    server_ca_pem: &str,
    client_identity_pem: &[u8],
) -> Result<RendezvousControlClient> {
    RendezvousControlClient::new(
        RendezvousClientConfig {
            cluster_id,
            rendezvous_urls: vec![base_url.to_string()],
            heartbeat_interval_secs: 15,
        },
        Some(server_ca_pem),
        Some(client_identity_pem),
    )
}

async fn assert_cluster_namespace(
    control: &RendezvousControlClient,
    expected_presence: &PresenceRegistration,
    shared_node_id: Uuid,
) -> Result<()> {
    let listed = control
        .list_presence()
        .await
        .context("cluster-scoped presence list failed")?;
    assert_eq!(listed.registered_endpoints, 1);
    assert_eq!(listed.entries.len(), 1);
    assert_eq!(listed.entries[0].registration, *expected_presence);

    let discovery = control
        .fetch_discovery(Some(shared_node_id))
        .await
        .context("cluster-scoped discovery failed")?;
    assert_eq!(
        discovery.node_candidates,
        Some(expected_presence.direct_candidates.clone())
    );
    assert!(!discovery.node_relay_capable);
    Ok(())
}

async fn suspend_cluster(http: &reqwest::Client, base_url: &str, cluster_id: Uuid) -> Result<()> {
    let response = http
        .post(endpoint_url(
            base_url,
            &format!("/global/cluster-registration/clusters/{cluster_id}/suspension"),
        ))
        .bearer_auth(ADMIN_TOKEN)
        .json(&serde_json::json!({ "suspended": true }))
        .send()
        .await
        .context("failed calling global rendezvous cluster suspension endpoint")?
        .error_for_status()
        .context("global rendezvous cluster suspension endpoint rejected operator bearer token")?;
    let record = response
        .json::<ClusterRegistrationRecord>()
        .await
        .context("failed parsing global rendezvous suspension response")?;
    assert_eq!(record.cluster_id, cluster_id);
    assert!(record.suspension.suspended);
    Ok(())
}

fn endpoint_url(base_url: &str, path: &str) -> String {
    format!("{}{}", base_url.trim_end_matches('/'), path)
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_secs()
}
