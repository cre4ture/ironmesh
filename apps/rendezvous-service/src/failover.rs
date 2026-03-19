use std::path::{Path, PathBuf};

use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::{Aes256GcmSiv, KeyInit, Nonce};
use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use common::{ClusterId, NodeId};
use pbkdf2::pbkdf2_hmac;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const MANAGED_RENDEZVOUS_FAILOVER_VERSION: u32 = 1;
const MANAGED_RENDEZVOUS_FAILOVER_SALT_LEN: usize = 16;
const MANAGED_RENDEZVOUS_FAILOVER_NONCE_LEN: usize = 12;
const MANAGED_RENDEZVOUS_FAILOVER_KEY_LEN: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ManagedRendezvousFailoverPackage {
    pub version: u32,
    pub cluster_id: ClusterId,
    pub source_node_id: NodeId,
    pub target_node_id: NodeId,
    pub exported_at_unix: u64,
    pub public_url: String,
    pub pbkdf2_rounds: u32,
    pub salt_b64: String,
    pub nonce_b64: String,
    pub ciphertext_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ManagedRendezvousFailoverPlaintext {
    cluster_id: ClusterId,
    source_node_id: NodeId,
    target_node_id: NodeId,
    exported_at_unix: u64,
    public_url: String,
    cert_pem: String,
    key_pem: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DecryptedRendezvousFailoverPackage {
    pub package_path: PathBuf,
    pub package: ManagedRendezvousFailoverPackage,
    pub cert_pem: String,
    pub key_pem: String,
}

pub(crate) fn load_rendezvous_failover_package(
    package_path: &Path,
    passphrase: &str,
) -> Result<DecryptedRendezvousFailoverPackage> {
    let raw = std::fs::read_to_string(package_path)
        .with_context(|| format!("failed reading {}", package_path.display()))?;
    let package = serde_json::from_str::<ManagedRendezvousFailoverPackage>(&raw)
        .with_context(|| format!("failed parsing {}", package_path.display()))?;
    decrypt_rendezvous_failover_package(package_path, package, passphrase)
}

fn decrypt_rendezvous_failover_package(
    package_path: &Path,
    package: ManagedRendezvousFailoverPackage,
    passphrase: &str,
) -> Result<DecryptedRendezvousFailoverPackage> {
    if package.version != MANAGED_RENDEZVOUS_FAILOVER_VERSION {
        bail!(
            "unsupported managed rendezvous failover package version {}",
            package.version
        );
    }

    let salt = BASE64_STANDARD
        .decode(package.salt_b64.as_bytes())
        .context("failed decoding managed rendezvous failover salt")?;
    if salt.len() != MANAGED_RENDEZVOUS_FAILOVER_SALT_LEN {
        bail!("invalid managed rendezvous failover salt length");
    }

    let nonce = BASE64_STANDARD
        .decode(package.nonce_b64.as_bytes())
        .context("failed decoding managed rendezvous failover nonce")?;
    if nonce.len() != MANAGED_RENDEZVOUS_FAILOVER_NONCE_LEN {
        bail!("invalid managed rendezvous failover nonce length");
    }

    let ciphertext = BASE64_STANDARD
        .decode(package.ciphertext_b64.as_bytes())
        .context("failed decoding managed rendezvous failover ciphertext")?;

    let key = derive_rendezvous_failover_key(passphrase, &salt, package.pbkdf2_rounds);
    let cipher = Aes256GcmSiv::new_from_slice(&key)
        .context("failed initializing managed rendezvous failover cipher")?;
    let plaintext_json = cipher
        .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|_| anyhow!("failed decrypting managed rendezvous failover package"))?;
    let plaintext = serde_json::from_slice::<ManagedRendezvousFailoverPlaintext>(&plaintext_json)
        .context("failed parsing managed rendezvous failover payload")?;

    if plaintext.cluster_id != package.cluster_id {
        bail!("managed rendezvous failover cluster ID mismatch");
    }
    if plaintext.source_node_id != package.source_node_id {
        bail!("managed rendezvous failover source node ID mismatch");
    }
    if plaintext.target_node_id != package.target_node_id {
        bail!("managed rendezvous failover target node ID mismatch");
    }
    if normalize_public_url(&plaintext.public_url) != normalize_public_url(&package.public_url) {
        bail!("managed rendezvous failover public URL mismatch");
    }

    Ok(DecryptedRendezvousFailoverPackage {
        package_path: package_path.to_path_buf(),
        package,
        cert_pem: plaintext.cert_pem,
        key_pem: plaintext.key_pem,
    })
}

fn derive_rendezvous_failover_key(passphrase: &str, salt: &[u8], rounds: u32) -> [u8; 32] {
    let mut key = [0u8; MANAGED_RENDEZVOUS_FAILOVER_KEY_LEN];
    pbkdf2_hmac::<Sha256>(passphrase.as_bytes(), salt, rounds, &mut key);
    key
}

pub(crate) fn normalize_public_url(value: &str) -> String {
    value.trim().trim_end_matches('/').to_string()
}

#[cfg(test)]
pub(crate) fn build_test_failover_package_json(
    public_url: &str,
    cert_pem: &str,
    key_pem: &str,
    passphrase: &str,
) -> String {
    let package = build_test_failover_package(public_url, cert_pem, key_pem, passphrase);
    serde_json::to_string(&package).expect("test failover package should serialize")
}

#[cfg(test)]
fn build_test_failover_package(
    public_url: &str,
    cert_pem: &str,
    key_pem: &str,
    passphrase: &str,
) -> ManagedRendezvousFailoverPackage {
    let cluster_id = uuid::Uuid::now_v7();
    let source_node_id = uuid::Uuid::now_v7();
    let target_node_id = uuid::Uuid::now_v7();
    let exported_at_unix = 1_773_904_240;
    let pbkdf2_rounds = 600_000;
    let salt = [7u8; MANAGED_RENDEZVOUS_FAILOVER_SALT_LEN];
    let nonce = [9u8; MANAGED_RENDEZVOUS_FAILOVER_NONCE_LEN];
    let plaintext = ManagedRendezvousFailoverPlaintext {
        cluster_id,
        source_node_id,
        target_node_id,
        exported_at_unix,
        public_url: public_url.to_string(),
        cert_pem: cert_pem.to_string(),
        key_pem: key_pem.to_string(),
    };
    let plaintext_json =
        serde_json::to_vec(&plaintext).expect("test failover plaintext should serialize");
    let key = derive_rendezvous_failover_key(passphrase, &salt, pbkdf2_rounds);
    let cipher = Aes256GcmSiv::new_from_slice(&key).expect("test cipher should initialize");
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext_json.as_ref())
        .expect("test failover plaintext should encrypt");

    ManagedRendezvousFailoverPackage {
        version: MANAGED_RENDEZVOUS_FAILOVER_VERSION,
        cluster_id,
        source_node_id,
        target_node_id,
        exported_at_unix,
        public_url: public_url.to_string(),
        pbkdf2_rounds,
        salt_b64: BASE64_STANDARD.encode(salt),
        nonce_b64: BASE64_STANDARD.encode(nonce),
        ciphertext_b64: BASE64_STANDARD.encode(ciphertext),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_rendezvous_failover_package_decrypts_payload() {
        let dir = std::env::temp_dir().join(format!(
            "ironmesh-rendezvous-failover-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should create");
        let path = dir.join("failover.json");

        let public_url = "https://creax.de:44042";
        let cert_pem = "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n";
        let key_pem = "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----\n";
        let passphrase = "correct horse battery staple";
        std::fs::write(
            &path,
            build_test_failover_package_json(public_url, cert_pem, key_pem, passphrase),
        )
        .expect("test failover package should write");

        let decrypted =
            load_rendezvous_failover_package(&path, passphrase).expect("package should decrypt");

        assert_eq!(decrypted.package_path, path);
        assert_eq!(decrypted.package.public_url, public_url);
        assert_eq!(decrypted.cert_pem, cert_pem);
        assert_eq!(decrypted.key_pem, key_pem);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_rendezvous_failover_package_rejects_wrong_passphrase() {
        let dir = std::env::temp_dir().join(format!(
            "ironmesh-rendezvous-failover-{}",
            uuid::Uuid::now_v7()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should create");
        let path = dir.join("failover.json");

        std::fs::write(
            &path,
            build_test_failover_package_json(
                "https://creax.de:44042",
                "cert",
                "key",
                "correct horse battery staple",
            ),
        )
        .expect("test failover package should write");

        let err = load_rendezvous_failover_package(&path, "wrong passphrase")
            .expect_err("wrong passphrase should fail");
        assert!(err.to_string().contains("failed decrypting"));

        let _ = std::fs::remove_dir_all(dir);
    }
}
