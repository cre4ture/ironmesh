use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use cap_std::ambient_authority;
use cap_std::fs::{Dir, OpenOptions};
use common::ClusterId;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use transport_sdk::ClusterSuspendStatus;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::FromDer;

const REGISTRY_FORMAT_VERSION: u32 = 1;
const LEGACY_SUSPENSION_REASON: &str = "Suspended by a legacy registry caller";
const LEGACY_SUSPENSION_MIGRATION_REASON: &str = "Suspension state migrated from a legacy registry";
static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// The single active trust anchor for one globally registered IronMesh cluster.
///
/// `created_at_unix_secs` tracks the lifetime of this CA binding. Re-registering
/// an unchanged CA preserves it, while replacing a CA starts a new binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterCaRecord {
    pub cluster_id: ClusterId,
    pub ca_pem: String,
    pub ca_fingerprint: String,
    pub created_at_unix_secs: u64,
    pub last_seen_at_unix_secs: u64,
    pub registration_proof_fingerprint: String,
    pub suspended: bool,
    #[serde(default)]
    pub suspended_at_unix_secs: Option<u64>,
    #[serde(default)]
    pub suspension_reason: Option<String>,
}

impl ClusterCaRecord {
    fn validate_suspension(&self) -> Result<()> {
        match (
            self.suspended,
            self.suspended_at_unix_secs,
            self.suspension_reason.as_deref(),
        ) {
            (false, None, None) => Ok(()),
            (false, _, _) => bail!("active cluster record must not include suspension metadata"),
            (true, Some(suspended_at_unix_secs), Some(reason)) => {
                if suspended_at_unix_secs == 0 {
                    bail!("suspended cluster record must include a non-zero suspension timestamp");
                }
                validate_suspension_reason(reason)
            }
            (true, _, None) => {
                bail!("suspended cluster record must include a suspension reason");
            }
            (true, None, Some(_)) => {
                bail!("suspended cluster record must include a non-zero suspension timestamp");
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedClusterCaRegistry {
    format_version: u32,
    clusters: BTreeMap<ClusterId, ClusterCaRecord>,
}

/// The registry's pre-opened storage boundary.
///
/// All registry operations below are relative to this directory capability, so
/// a configured registry filename cannot make a later write escape the
/// canonical directory selected during service startup.
#[derive(Debug)]
struct RegistryStorage {
    path: PathBuf,
    directory: Dir,
    file_name: PathBuf,
}

impl RegistryStorage {
    fn open(path: PathBuf) -> Result<Self> {
        let path = normalize_registry_path(path)?;
        let parent = path
            .parent()
            .expect("normalized cluster CA registry path must have a parent");
        let file_name = path
            .file_name()
            .expect("normalized cluster CA registry path must name a file");
        let file_name = PathBuf::from(file_name);
        let directory = Dir::open_ambient_dir(parent, ambient_authority()).with_context(|| {
            format!(
                "failed opening cluster CA registry directory {}",
                parent.display()
            )
        })?;
        Ok(Self {
            path,
            directory,
            file_name,
        })
    }
}

#[derive(Debug)]
struct ClusterCaRegistryInner {
    storage: RegistryStorage,
    clusters: RwLock<BTreeMap<ClusterId, ClusterCaRecord>>,
}

/// Thread-safe persistent registry for the Option-1 global rendezvous trust model.
///
/// It intentionally has no fallback trust store: a cluster can have exactly one
/// active CA and callers must select it by the authenticated certificate's
/// cluster URI SAN.
#[derive(Debug, Clone)]
pub struct ClusterCaRegistry {
    inner: Arc<ClusterCaRegistryInner>,
}

impl ClusterCaRegistry {
    /// Opens an existing registry, or creates an empty in-memory registry that
    /// is persisted on its first mutation.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let storage = RegistryStorage::open(path.into())?;
        let clusters = load_registry(&storage)?;
        Ok(Self {
            inner: Arc::new(ClusterCaRegistryInner {
                storage,
                clusters: RwLock::new(clusters),
            }),
        })
    }

    pub fn path(&self) -> &Path {
        &self.inner.storage.path
    }

    /// Registers a cluster CA or atomically replaces the existing active CA.
    pub fn register_or_update(
        &self,
        cluster_id: ClusterId,
        ca_pem: String,
        registration_proof_fingerprint: String,
    ) -> Result<ClusterCaRecord> {
        if registration_proof_fingerprint.trim().is_empty() {
            bail!("registration proof fingerprint must not be empty");
        }

        let ca_fingerprint = cluster_ca_fingerprint(&ca_pem)?;
        let now = now_unix_secs()?;
        let mut clusters = self.write_clusters();
        let existing = clusters.get(&cluster_id);
        let created_at_unix_secs = existing
            .filter(|record| record.ca_fingerprint == ca_fingerprint)
            .map(|record| record.created_at_unix_secs)
            .unwrap_or(now);
        let record = ClusterCaRecord {
            cluster_id,
            ca_pem,
            ca_fingerprint,
            created_at_unix_secs,
            last_seen_at_unix_secs: now,
            registration_proof_fingerprint,
            suspended: false,
            suspended_at_unix_secs: None,
            suspension_reason: None,
        };

        let mut updated = clusters.clone();
        updated.insert(cluster_id, record.clone());
        persist_registry(&self.inner.storage, &updated)?;
        *clusters = updated;
        Ok(record)
    }

    /// Suspends a registered cluster and persists the reason supplied by its caller.
    pub fn suspend(&self, cluster_id: ClusterId, reason: String) -> Result<ClusterCaRecord> {
        validate_suspension_reason(&reason)?;
        let suspended_at_unix_secs = now_unix_secs()?;
        self.update_record(cluster_id, |record| {
            record.suspended = true;
            record.suspended_at_unix_secs = Some(suspended_at_unix_secs);
            record.suspension_reason = Some(reason);
            record.validate_suspension()
        })
    }

    /// Resumes a registered cluster and removes its suspension audit metadata.
    pub fn resume(&self, cluster_id: ClusterId) -> Result<ClusterCaRecord> {
        self.update_record(cluster_id, |record| {
            record.suspended = false;
            record.suspended_at_unix_secs = None;
            record.suspension_reason = None;
            record.validate_suspension()
        })
    }

    /// Suspends or re-enables a registered cluster without deleting its audit data.
    ///
    /// New callers should use [`Self::suspend`] so operator-provided audit data is
    /// retained. This wrapper keeps the existing programmatic API compatible.
    pub fn set_suspended(&self, cluster_id: ClusterId, suspended: bool) -> Result<ClusterCaRecord> {
        if suspended {
            self.suspend(cluster_id, LEGACY_SUSPENSION_REASON.to_string())
        } else {
            self.resume(cluster_id)
        }
    }

    /// Returns every record, including suspended clusters, for a future admin handler.
    pub fn list(&self) -> Vec<ClusterCaRecord> {
        self.read_clusters().values().cloned().collect()
    }

    /// Returns the registered CA record, including suspension state.
    pub fn registered_ca(&self, cluster_id: ClusterId) -> Option<ClusterCaRecord> {
        self.read_clusters().get(&cluster_id).cloned()
    }

    /// Updates the access timestamp for a currently active cluster.
    pub fn observe_access(&self, cluster_id: ClusterId) -> Result<ClusterCaRecord> {
        self.update_record(cluster_id, |record| {
            if record.suspended {
                return Err(anyhow::anyhow!("cluster {cluster_id} is suspended"));
            }
            record.last_seen_at_unix_secs = now_unix_secs()?;
            Ok(())
        })
    }

    /// Returns the active CA only. Suspended clusters are deliberately invisible
    /// to the TLS verifier and have no fallback to another registered CA.
    pub(crate) fn active_ca(&self, cluster_id: ClusterId) -> Option<ClusterCaRecord> {
        self.read_clusters()
            .get(&cluster_id)
            .filter(|record| !record.suspended)
            .cloned()
    }

    fn update_record<F>(&self, cluster_id: ClusterId, update: F) -> Result<ClusterCaRecord>
    where
        F: FnOnce(&mut ClusterCaRecord) -> Result<()>,
    {
        let mut clusters = self.write_clusters();
        let mut updated = clusters.clone();
        let record = updated
            .get_mut(&cluster_id)
            .with_context(|| format!("cluster {cluster_id} is not registered"))?;
        update(record)?;
        let record = record.clone();
        persist_registry(&self.inner.storage, &updated)?;
        *clusters = updated;
        Ok(record)
    }

    fn read_clusters(
        &self,
    ) -> std::sync::RwLockReadGuard<'_, BTreeMap<ClusterId, ClusterCaRecord>> {
        self.inner
            .clusters
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn write_clusters(
        &self,
    ) -> std::sync::RwLockWriteGuard<'_, BTreeMap<ClusterId, ClusterCaRecord>> {
        self.inner
            .clusters
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

pub(crate) fn cluster_ca_root_store(ca_pem: &str) -> Result<RootCertStore> {
    let certificate = parse_single_cluster_ca(ca_pem)?;
    let mut roots = RootCertStore::empty();
    roots
        .add(certificate)
        .context("failed adding cluster CA certificate to trust store")?;
    Ok(roots)
}

pub fn cluster_ca_fingerprint(ca_pem: &str) -> Result<String> {
    let certificate = parse_single_cluster_ca(ca_pem)?;
    Ok(hex_digest(Sha256::digest(certificate.as_ref())))
}

fn load_registry(storage: &RegistryStorage) -> Result<BTreeMap<ClusterId, ClusterCaRecord>> {
    let bytes = match storage.directory.read(&storage.file_name) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed reading cluster CA registry {}",
                    storage.path.display()
                )
            });
        }
    };
    let registry: PersistedClusterCaRegistry =
        serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "failed parsing cluster CA registry {}",
                storage.path.display()
            )
        })?;
    if registry.format_version != REGISTRY_FORMAT_VERSION {
        bail!(
            "unsupported cluster CA registry format version {}",
            registry.format_version
        );
    }

    let mut clusters = registry.clusters;
    let mut migrated_legacy_suspension = false;
    for (cluster_id, record) in &mut clusters {
        if record.cluster_id != *cluster_id {
            bail!("cluster CA registry key does not match record cluster_id");
        }
        if record.registration_proof_fingerprint.trim().is_empty() {
            bail!("cluster CA registry contains an empty registration proof fingerprint");
        }
        if record.suspended
            && record.suspended_at_unix_secs.is_none()
            && record.suspension_reason.is_none()
        {
            record.suspended_at_unix_secs = Some(now_unix_secs()?);
            record.suspension_reason = Some(LEGACY_SUSPENSION_MIGRATION_REASON.to_string());
            migrated_legacy_suspension = true;
        }
        record.validate_suspension()?;
        let actual_fingerprint = cluster_ca_fingerprint(&record.ca_pem)?;
        if actual_fingerprint != record.ca_fingerprint {
            bail!("cluster CA registry contains a CA fingerprint mismatch");
        }
    }

    if migrated_legacy_suspension {
        persist_registry(storage, &clusters)?;
    }
    Ok(clusters)
}

pub(crate) fn validate_suspension_reason(reason: &str) -> Result<()> {
    if reason.trim().is_empty() {
        bail!("cluster suspension reason must not be empty");
    }
    ClusterSuspendStatus {
        suspended: true,
        suspended_at_unix: Some(1),
        reason: Some(reason.to_string()),
    }
    .validate()
}

fn persist_registry(
    storage: &RegistryStorage,
    clusters: &BTreeMap<ClusterId, ClusterCaRecord>,
) -> Result<()> {
    let serialized = serde_json::to_vec_pretty(&PersistedClusterCaRegistry {
        format_version: REGISTRY_FORMAT_VERSION,
        clusters: clusters.clone(),
    })
    .context("failed serializing cluster CA registry")?;
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary_name = format!(
        ".ironmesh-cluster-ca-registry.{}.{}.tmp",
        std::process::id(),
        sequence
    );
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    let mut temporary = storage
        .directory
        .open_with(&temporary_name, &options)
        .with_context(|| {
            format!(
                "failed creating temporary registry for {}",
                storage.path.display()
            )
        })?;
    temporary
        .write_all(&serialized)
        .context("failed writing temporary cluster CA registry")?;
    temporary
        .write_all(b"\n")
        .context("failed finalizing temporary cluster CA registry")?;
    temporary
        .sync_all()
        .context("failed syncing temporary cluster CA registry")?;
    drop(temporary);

    storage
        .directory
        .rename(&temporary_name, &storage.directory, &storage.file_name)
        .with_context(|| {
            format!(
                "failed atomically replacing cluster CA registry {}",
                storage.path.display()
            )
        })?;
    // The replacement file is fully synced before this atomic rename, so an
    // interrupted write cannot leave a partially written registry behind.
    Ok(())
}

fn normalize_registry_path(path: PathBuf) -> Result<PathBuf> {
    // The registry is configured by the service operator, but reject traversal
    // components before it reaches any filesystem API.
    let path = path
        .to_str()
        .context("cluster CA registry path must be valid UTF-8")?
        .to_owned();
    if path.contains("..") {
        bail!("cluster CA registry path must not contain '..'");
    }
    let path = PathBuf::from(path);
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .canonicalize()
        .context("cluster CA registry parent directory must already exist")?;
    if !parent.is_dir() {
        bail!(
            "cluster CA registry parent {} is not a directory",
            parent.display()
        );
    }
    let file_name = path
        .file_name()
        .filter(|name| !name.is_empty())
        .context("cluster CA registry path must name a file")?;
    let normalized = parent.join(file_name);
    // Keep the configured file inside its canonical parent. This guards both
    // the persistent registry and the fixed-name temporary replacement file.
    if !normalized.starts_with(&parent) {
        bail!(
            "cluster CA registry {} escapes its parent directory {}",
            normalized.display(),
            parent.display()
        );
    }
    if fs::symlink_metadata(&normalized)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        bail!(
            "cluster CA registry {} must not be a symbolic link",
            normalized.display()
        );
    }
    Ok(normalized)
}

fn parse_single_cluster_ca(ca_pem: &str) -> Result<CertificateDer<'static>> {
    let mut reader = std::io::Cursor::new(ca_pem.as_bytes());
    let certificates = CertificateDer::pem_reader_iter(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed parsing cluster CA PEM")?;
    let [certificate] = certificates.as_slice() else {
        bail!("cluster CA PEM must contain exactly one certificate");
    };

    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(certificate.as_ref())
        .context("failed parsing cluster CA certificate")?;
    let is_ca = parsed.extensions().iter().any(|extension| {
        matches!(
            extension.parsed_extension(),
            ParsedExtension::BasicConstraints(constraints) if constraints.ca
        )
    });
    if !is_ca {
        bail!("registered cluster certificate is not a CA");
    }
    Ok(certificate.clone())
}

fn now_unix_secs() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")
        .map(|duration| duration.as_secs())
}

fn hex_digest(digest: impl AsRef<[u8]>) -> String {
    let mut fingerprint = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        use std::fmt::Write as _;
        write!(fingerprint, "{byte:02x}").expect("writing to String cannot fail");
    }
    fingerprint
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};

    fn test_registry_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("ironmesh-{name}-{}.json", ClusterId::now_v7()))
    }

    fn test_ca(common_name: &str) -> String {
        let key = KeyPair::generate().expect("test CA key generation should succeed");
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
        params
            .self_signed(&key)
            .expect("test CA certificate generation should succeed")
            .pem()
    }

    fn write_legacy_registry(path: &Path, cluster_id: ClusterId, suspended: bool) {
        let ca_pem = test_ca("legacy-cluster");
        let ca_fingerprint =
            cluster_ca_fingerprint(&ca_pem).expect("legacy test CA fingerprint should calculate");
        let cluster_id = cluster_id.to_string();
        let mut clusters = serde_json::Map::new();
        clusters.insert(
            cluster_id.clone(),
            serde_json::json!({
                "cluster_id": cluster_id,
                "ca_pem": ca_pem,
                "ca_fingerprint": ca_fingerprint,
                "created_at_unix_secs": 1,
                "last_seen_at_unix_secs": 1,
                "registration_proof_fingerprint": "legacy-proof",
                "suspended": suspended,
            }),
        );
        fs::write(
            path,
            serde_json::to_vec(&serde_json::json!({
                "format_version": REGISTRY_FORMAT_VERSION,
                "clusters": clusters,
            }))
            .expect("legacy registry JSON should serialize"),
        )
        .expect("legacy registry should write");
    }

    #[test]
    fn registry_persists_and_reloads_records() {
        let path = test_registry_path("registry-restart");
        let cluster_id = ClusterId::now_v7();
        let registry = ClusterCaRegistry::open(&path).expect("registry should open");
        let registered = registry
            .register_or_update(cluster_id, test_ca("cluster-a"), "proof-a".to_string())
            .expect("cluster registration should persist");
        let observed = registry
            .observe_access(cluster_id)
            .expect("active cluster access should persist");
        drop(registry);

        let reloaded = ClusterCaRegistry::open(&path).expect("registry should reload");
        assert_eq!(reloaded.list().len(), 1);
        assert_eq!(reloaded.registered_ca(cluster_id), Some(observed));
        assert_eq!(registered.ca_fingerprint, reloaded.list()[0].ca_fingerprint);
        fs::remove_file(path).expect("test registry should be removable");
    }

    #[test]
    fn registry_rejects_parent_directory_components() {
        let error = ClusterCaRegistry::open(PathBuf::from("../cluster-ca-registry.json"))
            .expect_err("registry path traversal must be rejected");
        assert!(error.to_string().contains("must not contain '..'"));
    }

    #[test]
    fn registry_keeps_one_active_ca_per_cluster() {
        let path = test_registry_path("single-ca");
        let cluster_id = ClusterId::now_v7();
        let registry = ClusterCaRegistry::open(&path).expect("registry should open");
        let first = registry
            .register_or_update(
                cluster_id,
                test_ca("cluster-a-first"),
                "proof-a".to_string(),
            )
            .expect("first registration should succeed");
        let second = registry
            .register_or_update(
                cluster_id,
                test_ca("cluster-a-second"),
                "proof-b".to_string(),
            )
            .expect("CA replacement should succeed");

        assert_ne!(first.ca_fingerprint, second.ca_fingerprint);
        assert_eq!(registry.list(), vec![second]);
        fs::remove_file(path).expect("test registry should be removable");
    }

    #[test]
    fn suspended_clusters_are_not_active() {
        let path = test_registry_path("suspend");
        let cluster_id = ClusterId::now_v7();
        let registry = ClusterCaRegistry::open(&path).expect("registry should open");
        registry
            .register_or_update(cluster_id, test_ca("cluster-a"), "proof-a".to_string())
            .expect("registration should succeed");
        let suspended = registry
            .suspend(cluster_id, "operator review".to_string())
            .expect("suspension should persist");

        assert!(suspended.suspended);
        assert!(suspended.suspended_at_unix_secs.is_some());
        assert_eq!(
            suspended.suspension_reason.as_deref(),
            Some("operator review")
        );
        assert_eq!(registry.active_ca(cluster_id), None);
        assert!(registry.observe_access(cluster_id).is_err());
        fs::remove_file(path).expect("test registry should be removable");
    }

    #[test]
    fn suspension_audit_data_persists_and_is_cleared_when_resumed() {
        let path = test_registry_path("suspension-audit");
        let cluster_id = ClusterId::now_v7();
        let registry = ClusterCaRegistry::open(&path).expect("registry should open");
        registry
            .register_or_update(cluster_id, test_ca("cluster-a"), "proof-a".to_string())
            .expect("registration should succeed");
        let suspended = registry
            .suspend(cluster_id, "compromised credentials".to_string())
            .expect("suspension should persist");
        drop(registry);

        let reloaded = ClusterCaRegistry::open(&path).expect("registry should reload");
        assert_eq!(reloaded.registered_ca(cluster_id), Some(suspended));
        let resumed = reloaded.resume(cluster_id).expect("resume should persist");
        assert!(!resumed.suspended);
        assert_eq!(resumed.suspended_at_unix_secs, None);
        assert_eq!(resumed.suspension_reason, None);
        drop(reloaded);

        let reloaded = ClusterCaRegistry::open(&path).expect("resumed registry should reload");
        assert_eq!(reloaded.registered_ca(cluster_id), Some(resumed));
        fs::remove_file(path).expect("test registry should be removable");
    }

    #[test]
    fn legacy_active_records_without_suspension_metadata_load() {
        let path = test_registry_path("legacy-active");
        let cluster_id = ClusterId::now_v7();
        write_legacy_registry(&path, cluster_id, false);

        let registry = ClusterCaRegistry::open(&path).expect("legacy active registry should load");
        let record = registry
            .registered_ca(cluster_id)
            .expect("legacy record should be present");
        assert_eq!(record.suspended_at_unix_secs, None);
        assert_eq!(record.suspension_reason, None);
        fs::remove_file(path).expect("test registry should be removable");
    }

    #[test]
    fn legacy_suspended_records_without_suspension_metadata_are_migrated() {
        let path = test_registry_path("legacy-suspended");
        let cluster_id = ClusterId::now_v7();
        write_legacy_registry(&path, cluster_id, true);

        let registry =
            ClusterCaRegistry::open(&path).expect("legacy suspended registry should migrate");
        let record = registry
            .registered_ca(cluster_id)
            .expect("legacy suspended record should be present");
        assert!(record.suspended);
        assert!(record.suspended_at_unix_secs.is_some());
        assert_ne!(record.suspended_at_unix_secs, Some(1));
        assert_eq!(
            record.suspension_reason.as_deref(),
            Some(LEGACY_SUSPENSION_MIGRATION_REASON)
        );
        drop(registry);

        let reloaded = ClusterCaRegistry::open(&path).expect("migrated registry should reload");
        assert_eq!(reloaded.registered_ca(cluster_id), Some(record));
        fs::remove_file(path).expect("test registry should be removable");
    }

    #[test]
    fn suspended_records_with_partial_audit_metadata_are_rejected() {
        let path = test_registry_path("partial-suspension-audit");
        write_legacy_registry(&path, ClusterId::now_v7(), true);
        let mut persisted: serde_json::Value = serde_json::from_slice(
            &fs::read(&path).expect("legacy registry should be readable for mutation"),
        )
        .expect("legacy registry JSON should parse");
        persisted["clusters"]
            .as_object_mut()
            .expect("clusters should be an object")
            .values_mut()
            .next()
            .expect("legacy registry should have one record")
            .as_object_mut()
            .expect("record should be an object")
            .insert(
                "suspended_at_unix_secs".to_string(),
                serde_json::Value::from(2),
            );
        fs::write(
            &path,
            serde_json::to_vec(&persisted).expect("partial registry JSON should serialize"),
        )
        .expect("partial registry should write");

        let error = ClusterCaRegistry::open(&path)
            .expect_err("suspended records require complete audit metadata");
        assert!(
            error
                .to_string()
                .contains("must include a suspension reason")
        );
        fs::remove_file(path).expect("test registry should be removable");
    }
}
