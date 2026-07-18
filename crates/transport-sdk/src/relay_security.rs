use std::fmt;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use common::{ClusterId, NodeId};
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::WebPkiClientVerifier;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error as RustlsError,
    RootCertStore, ServerConfig, SignatureScheme,
};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use crate::peer::PeerIdentity;

const RELAY_TLS_SERVER_NAME: &str = "relay-tunnel.ironmesh.invalid";

/// PEM certificate-chain and private-key material for an inner relay TLS endpoint.
///
/// [`Self::new`] accepts the separate PEM fields used by cluster-issued node material.
/// [`Self::from_combined_pem`] accepts the certificate-plus-key form issued to devices.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayTunnelTlsIdentity {
    certificate_chain_pem: Vec<u8>,
    private_key_pem: Vec<u8>,
}

impl RelayTunnelTlsIdentity {
    pub fn new(
        certificate_chain_pem: impl Into<Vec<u8>>,
        private_key_pem: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            certificate_chain_pem: certificate_chain_pem.into(),
            private_key_pem: private_key_pem.into(),
        }
    }

    pub fn from_combined_pem(pem: impl Into<Vec<u8>>) -> Self {
        let pem = pem.into();
        Self::new(pem.clone(), pem)
    }

    pub fn certificate_chain_pem(&self) -> &[u8] {
        &self.certificate_chain_pem
    }

    pub fn private_key_pem(&self) -> &[u8] {
        &self.private_key_pem
    }

    fn validate(&self) -> Result<()> {
        if self.certificate_chain_pem.is_empty() {
            bail!("relay TLS identity certificate chain PEM must not be empty");
        }
        if self.private_key_pem.is_empty() {
            bail!("relay TLS identity private key PEM must not be empty");
        }
        Ok(())
    }
}

impl fmt::Debug for RelayTunnelTlsIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayTunnelTlsIdentity")
            .field("certificate_chain_pem", &"[redacted]")
            .field("private_key_pem", &"[redacted]")
            .finish()
    }
}

/// Security requirements for the source side of an inner relay tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTunnelSourceSecurityConfig {
    pub cluster_id: ClusterId,
    pub expected_target_node_id: NodeId,
    pub cluster_ca_pem: Vec<u8>,
    pub identity: RelayTunnelTlsIdentity,
}

impl RelayTunnelSourceSecurityConfig {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_id.is_nil() {
            bail!("relay TLS source config must include a non-nil cluster_id");
        }
        if self.expected_target_node_id.is_nil() {
            bail!("relay TLS source config must include a non-nil expected target node ID");
        }
        if self.cluster_ca_pem.is_empty() {
            bail!("relay TLS source config must include a cluster CA certificate");
        }
        self.identity.validate()
    }
}

/// Security requirements for the target side of an inner relay tunnel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTunnelTargetSecurityConfig {
    pub expected_source: PeerIdentity,
    pub cluster_ca_pem: Vec<u8>,
    pub identity: RelayTunnelTlsIdentity,
}

impl RelayTunnelTargetSecurityConfig {
    pub fn validate(&self) -> Result<()> {
        if self.cluster_ca_pem.is_empty() {
            bail!("relay TLS target config must include a cluster CA certificate");
        }
        self.identity.validate()
    }
}

pub(crate) fn build_source_tls_config(
    config: &RelayTunnelSourceSecurityConfig,
) -> Result<ClientConfig> {
    config.validate()?;
    let _ = rustls::crypto::ring::default_provider().install_default();

    let roots = Arc::new(root_store_from_pem(
        &config.cluster_ca_pem,
        "relay TLS source cluster CA",
    )?);
    let signature_verifier = WebPkiServerVerifier::builder(Arc::clone(&roots))
        .build()
        .context("failed creating relay TLS server signature verifier")?;
    let verifier = RelayServerCertVerifier {
        roots,
        signature_verifier,
        expected_target_node_id: config.expected_target_node_id,
        expected_cluster_id: config.cluster_id,
    };
    let (cert_chain, key) = parse_identity(&config.identity)?;

    ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(cert_chain, key)
        .context("failed building relay TLS source configuration")
}

pub(crate) fn build_target_tls_config(
    config: &RelayTunnelTargetSecurityConfig,
) -> Result<ServerConfig> {
    config.validate()?;
    let _ = rustls::crypto::ring::default_provider().install_default();

    let roots = Arc::new(root_store_from_pem(
        &config.cluster_ca_pem,
        "relay TLS target cluster CA",
    )?);
    let chain_verifier = WebPkiClientVerifier::builder(roots)
        .build()
        .context("failed creating relay TLS client certificate verifier")?;
    let verifier = ExpectedPeerClientVerifier {
        chain_verifier,
        expected_source: config.expected_source.clone(),
    };
    let (cert_chain, key) = parse_identity(&config.identity)?;

    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(cert_chain, key)
        .context("failed building relay TLS target configuration")
}

pub(crate) fn relay_tls_server_name() -> Result<ServerName<'static>> {
    ServerName::try_from(RELAY_TLS_SERVER_NAME.to_string())
        .context("failed building inner relay TLS server name")
}

fn root_store_from_pem(pem: &[u8], field_name: &str) -> Result<RootCertStore> {
    let mut reader = std::io::Cursor::new(pem);
    let mut roots = RootCertStore::empty();
    let mut count = 0_usize;
    for cert in CertificateDer::pem_reader_iter(&mut reader) {
        let cert = cert.with_context(|| format!("failed parsing {field_name} certificate"))?;
        roots
            .add(cert)
            .with_context(|| format!("failed adding {field_name} certificate to trust store"))?;
        count += 1;
    }
    if count == 0 {
        bail!("{field_name} PEM is missing certificates");
    }
    Ok(roots)
}

fn parse_identity(
    identity: &RelayTunnelTlsIdentity,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let mut cert_reader = std::io::Cursor::new(identity.certificate_chain_pem());
    let cert_chain = CertificateDer::pem_reader_iter(&mut cert_reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed parsing relay TLS identity certificate chain")?;
    if cert_chain.is_empty() {
        bail!("relay TLS identity PEM is missing a certificate chain");
    }

    let mut key_reader = std::io::Cursor::new(identity.private_key_pem());
    let key = PrivateKeyDer::from_pem_reader(&mut key_reader)
        .context("failed parsing relay TLS identity private key")?;
    Ok((cert_chain, key))
}

#[derive(Debug)]
struct RelayServerCertVerifier {
    roots: Arc<RootCertStore>,
    signature_verifier: Arc<WebPkiServerVerifier>,
    expected_target_node_id: NodeId,
    expected_cluster_id: ClusterId,
}

impl ServerCertVerifier for RelayServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        let cert = webpki::EndEntityCert::try_from(end_entity)
            .map_err(|_| certificate_verification_error())?;
        cert.verify_for_usage(
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .all,
            &self.roots.roots,
            intermediates,
            now,
            webpki::KeyUsage::server_auth(),
            None,
            None,
        )
        .map_err(|_| certificate_verification_error())?;
        verify_target_certificate_sans(
            end_entity,
            self.expected_target_node_id,
            self.expected_cluster_id,
        )
        .map_err(|_| certificate_verification_error())?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.signature_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.signature_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_verifier.supported_verify_schemes()
    }
}

#[derive(Debug)]
struct ExpectedPeerClientVerifier {
    chain_verifier: Arc<dyn ClientCertVerifier>,
    expected_source: PeerIdentity,
}

impl ClientCertVerifier for ExpectedPeerClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.chain_verifier.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, RustlsError> {
        self.chain_verifier
            .verify_client_cert(end_entity, intermediates, now)?;
        verify_peer_certificate_san(end_entity, &self.expected_source)
            .map_err(|_| certificate_verification_error())?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.chain_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        self.chain_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.chain_verifier.supported_verify_schemes()
    }
}

fn certificate_verification_error() -> RustlsError {
    RustlsError::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
}

fn verify_target_certificate_sans(
    certificate: &CertificateDer<'_>,
    expected_node_id: NodeId,
    expected_cluster_id: ClusterId,
) -> Result<()> {
    let san_uris = certificate_san_uris(certificate)?;
    let expected_node = node_san_uri(expected_node_id);
    let expected_cluster = cluster_san_uri(expected_cluster_id);
    if !san_uris.iter().any(|uri| uri == &expected_node) {
        bail!("relay TLS server certificate does not contain expected node URI SAN");
    }
    if !san_uris.iter().any(|uri| uri == &expected_cluster) {
        bail!("relay TLS server certificate does not contain expected cluster URI SAN");
    }
    Ok(())
}

fn verify_peer_certificate_san(
    certificate: &CertificateDer<'_>,
    expected_peer: &PeerIdentity,
) -> Result<()> {
    let expected = peer_san_uri(expected_peer);
    if certificate_san_uris(certificate)?
        .iter()
        .any(|uri| uri == &expected)
    {
        Ok(())
    } else {
        bail!("relay TLS client certificate does not contain the expected peer URI SAN")
    }
}

fn certificate_san_uris(certificate: &CertificateDer<'_>) -> Result<Vec<String>> {
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(certificate.as_ref())
        .context("failed parsing relay TLS certificate")?;
    let mut uris = Vec::new();
    for extension in parsed.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for name in &san.general_names {
                if let GeneralName::URI(uri) = name {
                    uris.push((*uri).to_string());
                }
            }
        }
    }
    Ok(uris)
}

fn node_san_uri(node_id: NodeId) -> String {
    format!("urn:ironmesh:node:{node_id}")
}

fn cluster_san_uri(cluster_id: ClusterId) -> String {
    format!("urn:ironmesh:cluster:{cluster_id}")
}

fn peer_san_uri(peer: &PeerIdentity) -> String {
    match peer {
        PeerIdentity::Node(node_id) => node_san_uri(*node_id),
        PeerIdentity::Device(device_id) => format!("urn:ironmesh:device:{device_id}"),
    }
}
