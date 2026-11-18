//! Archive Only prototype. Original bytes are canonical; JSON metadata is UTF-8.
//! SHA-256 provides local fixity, never authenticity or rollback protection.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub const FORMAT_VERSION: &str = "0.1-archive-only";
mod model;
pub use model::*;
const JSON_LIMIT: u64 = 1024 * 1024;
const MANIFEST_LIMIT: u64 = 16 * JSON_LIMIT;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    oiaf_version: String,
    /// Object ID -> SHA-256 of the exact envelope JSON bytes.
    envelopes: BTreeMap<String, String>,
}

/// Validate a portable, slash-separated archive-relative path before joining it.
/// Rejects traversal, platform prefixes, ADS, Windows device names, and aliases.
pub fn validate_relative_path(value: &str) -> Result<()> {
    if value.is_empty() || value.contains(['\\', ':']) || value.chars().any(char::is_control) {
        return Err(Error::Invalid("unsafe archive-relative path".into()));
    }
    for part in value.split('/') {
        let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
        let numbered_device = stem.len() == 4
            && (stem.starts_with("COM") || stem.starts_with("LPT"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9');
        if part.is_empty()
            || part == "."
            || part == ".."
            || part.ends_with(['.', ' '])
            || part.contains(['<', '>', '"', '|', '?', '*'])
            || matches!(
                stem.as_str(),
                "CON"
                    | "PRN"
                    | "AUX"
                    | "NUL"
                    | "CONIN$"
                    | "CONOUT$"
                    | "COM¹"
                    | "COM²"
                    | "COM³"
                    | "LPT¹"
                    | "LPT²"
                    | "LPT³"
            )
            || numbered_device
        {
            return Err(Error::Invalid("unsafe archive-relative component".into()));
        }
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid(
            "expected 64 lowercase SHA-256 hex digits".into(),
        ));
    }
    Ok(())
}

/// CAS locations are derived only from a validated lowercase digest.
pub fn blob_relative_path(digest: &str) -> Result<String> {
    validate_digest(digest)?;
    Ok(format!(
        "objects/sha256/{}/{}/{digest}.blob",
        &digest[..2],
        &digest[2..4]
    ))
}

fn envelope_relative_path(id: &str) -> Result<String> {
    validate_digest(id)?;
    Ok(format!("objects/envelopes/{id}.json"))
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Deterministic struct order / BTreeMap order, compact UTF-8 JSON and one LF.
pub fn json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Invalid("clock precedes Unix epoch".into()))?
        .as_millis()
        .try_into()
        .map_err(|_| Error::Invalid("clock exceeds supported range".into()))
}

fn hash_reader(reader: &mut impl Read, mut output: Option<&mut File>) -> Result<(String, u64)> {
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        size = size
            .checked_add(count as u64)
            .ok_or_else(|| Error::Invalid("blob too large".into()))?;
        if let Some(file) = output.as_deref_mut() {
            file.write_all(&buffer[..count])?;
        }
    }
    Ok((format!("{:x}", hasher.finalize()), size))
}

/// Reject symlinks/junctions in archive-owned paths. The root is canonicalized
/// once; concurrent hostile filesystem replacement by the host is out of scope.
fn safe_path(root: &Path, relative: &str) -> Result<PathBuf> {
    validate_relative_path(relative)?;
    let mut path = root.to_path_buf();
    for part in relative.split('/') {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                #[cfg(windows)]
                let linked = {
                    use std::os::windows::fs::MetadataExt;
                    metadata.file_attributes() & 0x400 != 0
                };
                #[cfg(not(windows))]
                let linked = metadata.file_type().is_symlink();
                if linked {
                    return Err(Error::Invalid("archive paths cannot contain links".into()));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e.into()),
        }
    }
    Ok(path)
}

fn read_json_snapshot<T: DeserializeOwned + Serialize>(
    path: &Path,
    limit: u64,
) -> Result<(T, Vec<u8>)> {
    let file = open_regular(path)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(Error::Invalid("JSON size limit exceeded".into()));
    }
    let value: T = serde_json::from_slice(&bytes)?;
    if json_bytes(&value)? != bytes {
        return Err(Error::Invalid("invalid metadata: noncanonical JSON".into()));
    }
    Ok((value, bytes))
}

fn open_regular(path: &Path) -> Result<File> {
    if !fs::symlink_metadata(path)?.is_file() {
        return Err(Error::Invalid("expected regular archive file".into()));
    }
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(Error::Invalid("expected regular archive file".into()));
    }
    Ok(file)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    // Windows std cannot open a directory for fsync. Files are still synced
    // before rename; sudden-power-loss durability depends on the filesystem.
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn sync_parents(mut path: &Path, root: &Path) -> Result<()> {
    if !path.starts_with(root) {
        return Err(Error::Invalid("directory escapes archive".into()));
    }
    loop {
        sync_dir(path)?;
        if path == root {
            break;
        }
        path = path.parent().expect("directory is beneath root");
    }
    Ok(())
}

/// A temporary directory on the same filesystem as its publication target.
struct Stage(PathBuf);
impl Stage {
    fn new(parent: &Path) -> Result<Self> {
        for _ in 0..100 {
            let path = parent.join(format!(
                ".oiaf-stage-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Ok(Self(path)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error::Invalid("cannot allocate staging directory".into()))
    }
}
impl Drop for Stage {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Open readers never create locks, directories, repair records, or timestamps.
#[derive(Debug, Clone)]
pub struct Archive {
    root: PathBuf,
}

impl Archive {
    /// Initialize a new directory. Existing paths are never adopted or overwritten.
    pub fn init(root: impl AsRef<Path>) -> Result<Self> {
        let (parent, target) = new_target(root.as_ref())?;
        let stage = Stage::new(&parent)?;
        fs::create_dir_all(stage.0.join("objects/envelopes"))?;
        fs::create_dir_all(stage.0.join("objects/sha256"))?;
        write_new(
            &stage.0.join("OIAF-VERSION"),
            format!("{FORMAT_VERSION}\n").as_bytes(),
        )?;
        write_new(
            &stage.0.join("manifest.json"),
            &json_bytes(&Manifest {
                oiaf_version: FORMAT_VERSION.into(),
                envelopes: BTreeMap::new(),
            })?,
        )?;
        write_new(&stage.0.join(".writer.lock"), b"")?;
        sync_parents(&stage.0.join("objects/envelopes"), &stage.0)?;
        sync_parents(&stage.0.join("objects/sha256"), &stage.0)?;
        fs::rename(&stage.0, &target)?;
        sync_dir(&parent)?;
        Self::open(target)
    }

    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = fs::canonicalize(root)?;
        if !root.is_dir() {
            return Err(Error::Invalid("archive root is not a directory".into()));
        }
        let archive = Self { root };
        archive.manifest()?;
        Ok(archive)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn summary(&self) -> ArchiveSummary {
        ArchiveSummary {
            root: self.root.clone(),
            oiaf_version: FORMAT_VERSION,
            fixity_only: true,
        }
    }

    fn manifest_snapshot(&self) -> Result<(Manifest, Vec<u8>)> {
        let mut version = String::new();
        open_regular(&safe_path(&self.root, "OIAF-VERSION")?)?
            .take(128)
            .read_to_string(&mut version)?;
        if version != format!("{FORMAT_VERSION}\n") {
            return Err(Error::Invalid("unsupported OIAF version".into()));
        }
        let manifest_path = safe_path(&self.root, "manifest.json")?;
        let (manifest, bytes) = read_json_snapshot::<Manifest>(&manifest_path, MANIFEST_LIMIT)?;
        if manifest.oiaf_version != FORMAT_VERSION {
            return Err(Error::Invalid("unsupported manifest version".into()));
        }
        for (id, hash) in &manifest.envelopes {
            validate_digest(id)?;
            validate_digest(hash)?;
        }
        Ok((manifest, bytes))
    }

    fn manifest(&self) -> Result<Manifest> {
        self.manifest_snapshot().map(|(manifest, _)| manifest)
    }

    fn writer_lock(&self) -> Result<File> {
        // Persistent inode: unlinking lock files would permit two independent locks.
        let path = safe_path(&self.root, ".writer.lock")?;
        if !fs::symlink_metadata(&path)?.is_file() {
            return Err(Error::Invalid("writer lock is not a regular file".into()));
        }
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => Err(Error::Locked),
            Err(std::fs::TryLockError::Error(e)) => Err(e.into()),
        }
    }

    fn envelope(&self, id: &str, expected_hash: &str) -> Result<Envelope> {
        let path = safe_path(&self.root, &envelope_relative_path(id)?)?;
        let mut bytes = Vec::new();
        open_regular(&path)?
            .take(JSON_LIMIT + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > JSON_LIMIT || digest(&bytes) != expected_hash {
            return Err(Error::Integrity(format!("envelope {id}")));
        }
        let envelope: Envelope = serde_json::from_slice(&bytes)?;
        envelope.source.validate()?;
        validate_digest(&envelope.blob.digest)?;
        if envelope.oiaf_version != FORMAT_VERSION
            || envelope.object_id != id
            || envelope.source.object_id()? != id
            || envelope.blob.algorithm != "sha256"
            || json_bytes(&envelope)? != bytes
        {
            return Err(Error::Integrity(format!("inconsistent envelope {id}")));
        }
        Ok(envelope)
    }

    pub fn list_objects(&self) -> Result<Vec<Envelope>> {
        self.manifest()?
            .envelopes
            .iter()
            .map(|(id, hash)| self.envelope(id, hash))
            .collect()
    }

    pub fn provenance(&self, object_id: &str) -> Result<Envelope> {
        validate_digest(object_id)?;
        let manifest = self.manifest()?;
        let hash = manifest
            .envelopes
            .get(object_id)
            .ok_or_else(|| Error::Invalid("unknown object ID".into()))?;
        self.envelope(object_id, hash)
    }

    /// Import a regular file with bounded memory, two content passes, and metadata
    /// checks before publication. The caller must provide a stable source revision.
    pub fn import_source_file(
        &self,
        path: impl AsRef<Path>,
        source: Source,
    ) -> Result<ImportResult> {
        self.import_file_inner(path.as_ref(), Some(source), || {})
    }

    /// Filesystem convenience: canonical UTF-8 path identifies the source, and
    /// content digest identifies its revision. Connectors should use explicit IDs
    /// through `import_source_file` to distinguish equal-byte source revisions.
    pub fn import_file(&self, path: impl AsRef<Path>) -> Result<ImportResult> {
        self.import_file_inner(path.as_ref(), None, || {})
    }

    fn import_file_inner(
        &self,
        path: &Path,
        source: Option<Source>,
        after_copy: impl FnOnce(),
    ) -> Result<ImportResult> {
        if let Some(source) = &source {
            source.validate()?;
        }
        let _lock = self.writer_lock()?;
        let observed = now_ms()?;
        let before = fs::symlink_metadata(path)?;
        if !before.is_file() || before.file_type().is_symlink() {
            return Err(Error::Invalid("source must be a regular file".into()));
        }
        let mut input = File::open(path)?;
        if !same_file_state(&before, &input.metadata()?) {
            return Err(Error::SourceChanged);
        }
        let stage = Stage::new(&self.root)?;
        let staged_blob = stage.0.join("payload");
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged_blob)?;
        let (hash, size) = hash_reader(&mut input, Some(&mut output))?;
        output.sync_all()?;
        drop(output);
        after_copy();
        input.rewind()?;
        let second = hash_reader(&mut input, None)?;
        if second != (hash.clone(), size)
            || size != before.len()
            || !same_file_state(&before, &input.metadata()?)
            || !same_file_state(&before, &fs::symlink_metadata(path)?)
        {
            return Err(Error::SourceChanged);
        }
        let source = match source {
            Some(source) => source,
            None => {
                let canonical = fs::canonicalize(path)?;
                let locator = canonical.to_str().ok_or_else(|| {
                    Error::Invalid(
                        "source path is not UTF-8; supply explicit Source metadata".into(),
                    )
                })?;
                Source::filesystem("local-filesystem", locator, &hash)
            }
        };
        source.validate()?;
        self.commit(
            &stage,
            source,
            Blob {
                algorithm: "sha256".into(),
                digest: hash,
                size,
                domain: None,
            },
            observed,
        )
    }

    pub fn import_bytes(&self, bytes: &[u8], source: Source) -> Result<ImportResult> {
        source.validate()?;
        let _lock = self.writer_lock()?;
        let observed = now_ms()?;
        let stage = Stage::new(&self.root)?;
        write_new(&stage.0.join("payload"), bytes)?;
        self.commit(
            &stage,
            source,
            Blob {
                algorithm: "sha256".into(),
                digest: digest(bytes),
                size: bytes.len() as u64,
                domain: None,
            },
            observed,
        )
    }

    /// Encrypt and import bytes under a canonical domain key. The domain is
    /// recorded in the blob metadata and authenticated as AEAD associated data.
    pub fn import_bytes_in_domain(
        &self,
        bytes: &[u8],
        source: Source,
        domain: ArchiveDomain,
        domain_key: &[u8],
    ) -> Result<ImportResult> {
        source.validate()?;
        let _lock = self.writer_lock()?;
        let id = source.object_id()?;
        let manifest = self.manifest()?;
        if let Some(hash) = manifest.envelopes.get(&id) {
            let envelope = self.envelope(&id, hash)?;
            if envelope.source != source || envelope.blob.domain != Some(domain) {
                return Err(Error::SourceConflict);
            }
            let existing = self.read_domain_bytes(&id, domain, domain_key)?;
            if existing != bytes {
                return Err(Error::SourceConflict);
            }
            return Ok(ImportResult {
                envelope,
                created: false,
            });
        }

        let sealed = sc_crypto::seal_domain(domain_key, bytes, domain.as_str())?;
        let payload = serde_json::to_vec(&sealed)?;
        let stage = Stage::new(&self.root)?;
        write_new(&stage.0.join("payload"), &payload)?;
        self.commit(
            &stage,
            source,
            Blob {
                algorithm: "sha256".into(),
                digest: digest(&payload),
                size: payload.len() as u64,
                domain: Some(domain),
            },
            now_ms()?,
        )
    }

    /// Read and authenticate a domain-encrypted object using its expected domain.
    pub fn read_domain_bytes(
        &self,
        object_id: &str,
        expected_domain: ArchiveDomain,
        domain_key: &[u8],
    ) -> Result<Vec<u8>> {
        validate_digest(object_id)?;
        let manifest = self.manifest()?;
        let hash = manifest
            .envelopes
            .get(object_id)
            .ok_or_else(|| Error::Invalid("unknown object ID".into()))?;
        let envelope = self.envelope(object_id, hash)?;
        if envelope.blob.domain != Some(expected_domain) {
            return Err(Error::Integrity("blob domain mismatch".into()));
        }

        let path = safe_path(&self.root, &blob_relative_path(&envelope.blob.digest)?)?;
        let mut file = open_regular(&path)?;
        let mut payload = Vec::new();
        file.read_to_end(&mut payload)?;
        if payload.len() as u64 != envelope.blob.size || digest(&payload) != envelope.blob.digest {
            return Err(Error::Integrity(format!("blob {}", envelope.blob.digest)));
        }
        let sealed: sc_crypto::DomainSealedEnvelope = serde_json::from_slice(&payload)?;
        if sealed.domain != expected_domain.as_str() {
            return Err(Error::Integrity("sealed payload domain mismatch".into()));
        }
        Ok(sc_crypto::open_domain(
            domain_key,
            &sealed,
            expected_domain.as_str(),
        )?)
    }

    fn commit(
        &self,
        stage: &Stage,
        source: Source,
        blob: Blob,
        observed: u64,
    ) -> Result<ImportResult> {
        let mut manifest = self.manifest()?;
        let id = source.object_id()?;
        if let Some(hash) = manifest.envelopes.get(&id) {
            let envelope = self.envelope(&id, hash)?;
            if envelope.source != source || envelope.blob != blob {
                return Err(Error::SourceConflict);
            }
            self.verify_blob(&blob)?;
            return Ok(ImportResult {
                envelope,
                created: false,
            });
        }
        let envelope = Envelope {
            oiaf_version: FORMAT_VERSION.into(),
            object_id: id.clone(),
            blob,
            source,
            time: EvidenceTime {
                event_time_unix_ms: None,
                observed_time_unix_ms: observed,
                ingested_time_unix_ms: now_ms()?,
                processed_time_unix_ms: None,
            },
        };
        let envelope_bytes = json_bytes(&envelope)?;
        manifest
            .envelopes
            .insert(id.clone(), digest(&envelope_bytes));
        let manifest_bytes = json_bytes(&manifest)?;
        if manifest_bytes.len() as u64 > MANIFEST_LIMIT {
            return Err(Error::Invalid("manifest size limit exceeded".into()));
        }
        write_new(&stage.0.join("envelope.json"), &envelope_bytes)?;
        write_new(&stage.0.join("manifest.json"), &manifest_bytes)?;
        let target = safe_path(&self.root, &blob_relative_path(&envelope.blob.digest)?)?;
        let parent = target.parent().expect("CAS path has parent");
        fs::create_dir_all(parent)?;
        if target.try_exists()? {
            self.verify_blob(&envelope.blob)?;
        } else {
            fs::rename(stage.0.join("payload"), &target)?;
            sync_parents(parent, &self.root)?;
        }
        let target = safe_path(&self.root, &envelope_relative_path(&id)?)?;
        // A crash may leave an unreferenced envelope. Replacing it is safe while
        // holding the writer lock because only manifest entries are committed.
        fs::rename(stage.0.join("envelope.json"), target)?;
        sync_dir(&self.root.join("objects/envelopes"))?;
        fs::rename(
            stage.0.join("manifest.json"),
            safe_path(&self.root, "manifest.json")?,
        )?;
        sync_dir(&self.root)?;
        Ok(ImportResult {
            envelope,
            created: true,
        })
    }

    fn verify_blob(&self, blob: &Blob) -> Result<()> {
        let path = safe_path(&self.root, &blob_relative_path(&blob.digest)?)?;
        let mut file = open_regular(&path)?;
        if !file.metadata()?.is_file() {
            return Err(Error::Integrity("blob is not a regular file".into()));
        }
        let (hash, size) = hash_reader(&mut file, None)?;
        if hash != blob.digest || size != blob.size {
            return Err(Error::Integrity(format!("blob {}", blob.digest)));
        }
        Ok(())
    }

    /// Read-only local fixity verification. Never repairs, locks, or writes.
    /// This first slice always hashes all blobs, including without `--full`.
    pub fn verify(&self, _full: bool) -> Result<VerificationReport> {
        let entries = self.list_objects()?;
        let mut blobs = BTreeSet::new();
        let mut bytes = 0_u64;
        for envelope in &entries {
            // Check every reference's size, including duplicate blob references.
            self.verify_blob(&envelope.blob)?;
            if blobs.insert(&envelope.blob.digest) {
                bytes = bytes
                    .checked_add(envelope.blob.size)
                    .ok_or_else(|| Error::Invalid("total size overflow".into()))?;
            }
        }
        Ok(VerificationReport {
            objects: entries.len(),
            blobs: blobs.len(),
            bytes,
            fixity_only: true,
        })
    }

    /// Deterministic envelope JSONL, sorted by object ID. Source bytes stay in CAS.
    pub fn export_jsonl(&self, mut output: impl Write) -> Result<()> {
        for envelope in self.list_objects()? {
            output.write_all(&json_bytes(&envelope)?)?;
        }
        Ok(())
    }

    /// Deterministic backup manifest snapshot sorted by object ID.
    pub fn generate_backup_manifest(&self) -> Result<BackupManifest> {
        let (manifest, manifest_bytes) = self.manifest_snapshot()?;
        let root_manifest_hash = digest(&manifest_bytes);
        let mut blob_digests = BTreeSet::new();
        let mut total_blob_bytes = 0_u64;
        for (id, hash) in &manifest.envelopes {
            let envelope = self.envelope(id, hash)?;
            self.verify_blob(&envelope.blob)?;
            if blob_digests.insert(envelope.blob.digest) {
                total_blob_bytes = total_blob_bytes
                    .checked_add(envelope.blob.size)
                    .ok_or_else(|| Error::Invalid("total size overflow".into()))?;
            }
        }

        Ok(BackupManifest {
            oiaf_version: FORMAT_VERSION.into(),
            timestamp_unix_ms: now_ms()?,
            total_objects: manifest.envelopes.len(),
            total_blob_bytes,
            root_manifest_hash,
            envelopes: manifest.envelopes,
        })
    }

    pub fn verify_backup_manifest(&self, manifest: &BackupManifest) -> Result<bool> {
        let (live_manifest, manifest_bytes) = self.manifest_snapshot()?;
        if digest(&manifest_bytes) != manifest.root_manifest_hash
            || manifest.oiaf_version != live_manifest.oiaf_version
            || manifest.envelopes != live_manifest.envelopes
            || manifest.total_objects != live_manifest.envelopes.len()
        {
            return Ok(false);
        }

        let mut total_blob_bytes = 0_u64;
        let mut blob_digests = BTreeSet::new();
        for (id, hash) in &live_manifest.envelopes {
            let envelope = match self.envelope(id, hash) {
                Ok(env) => env,
                Err(_) => return Ok(false),
            };
            if self.verify_blob(&envelope.blob).is_err() {
                return Ok(false);
            }
            if blob_digests.insert(envelope.blob.digest) {
                total_blob_bytes = match total_blob_bytes.checked_add(envelope.blob.size) {
                    Some(sum) => sum,
                    None => return Ok(false),
                };
            }
        }

        Ok(total_blob_bytes == manifest.total_blob_bytes)
    }

    /// Publish a self-contained, verified directory copy at a previously absent
    /// destination. Only committed data is copied; export never mutates this archive.
    pub fn export(
        &self,
        destination: impl AsRef<Path>,
        object_id: Option<&str>,
    ) -> Result<VerificationReport> {
        let (parent, target) = new_target(destination.as_ref())?;
        if parent.starts_with(&self.root) {
            return Err(Error::Invalid(
                "export destination is inside archive".into(),
            ));
        }
        let stage = Stage::new(&parent)?;
        let mut manifest = self.manifest()?;
        if let Some(id) = object_id {
            validate_digest(id)?;
            if !manifest.envelopes.contains_key(id) {
                return Err(Error::Invalid("unknown object ID".into()));
            }
            manifest.envelopes.retain(|key, _| key == id);
        }
        fs::create_dir_all(stage.0.join("objects/envelopes"))?;
        fs::create_dir_all(stage.0.join("objects/sha256"))?;
        let mut copied = BTreeSet::new();
        for (id, hash) in &manifest.envelopes {
            let envelope = self.envelope(id, hash)?;
            let relative = envelope_relative_path(id)?;
            write_new(&stage.0.join(relative), &json_bytes(&envelope)?)?;
            if copied.insert(envelope.blob.digest.clone()) {
                let relative = blob_relative_path(&envelope.blob.digest)?;
                let target = stage.0.join(&relative);
                fs::create_dir_all(target.parent().expect("CAS path has parent"))?;
                let mut input = open_regular(&safe_path(&self.root, &relative)?)?;
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&target)?;
                let (actual, size) = hash_reader(&mut input, Some(&mut output))?;
                if actual != envelope.blob.digest || size != envelope.blob.size {
                    return Err(Error::Integrity("export blob changed".into()));
                }
                output.sync_all()?;
                sync_parents(target.parent().expect("CAS path has parent"), &stage.0)?;
            }
        }
        write_new(
            &stage.0.join("OIAF-VERSION"),
            format!("{FORMAT_VERSION}\n").as_bytes(),
        )?;
        write_new(&stage.0.join("manifest.json"), &json_bytes(&manifest)?)?;
        write_new(&stage.0.join(".writer.lock"), b"")?;
        let report = Self::open(&stage.0)?.verify(true)?;
        sync_parents(&stage.0.join("objects/envelopes"), &stage.0)?;
        sync_parents(&stage.0.join("objects/sha256"), &stage.0)?;
        fs::rename(&stage.0, target)?;
        sync_dir(&parent)?;
        Ok(report)
    }
}

fn new_target(path: &Path) -> Result<(PathBuf, PathBuf)> {
    let name = path
        .file_name()
        .ok_or_else(|| Error::Invalid("destination needs a directory name".into()))?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = fs::canonicalize(parent)?;
    let target = parent.join(name);
    match fs::symlink_metadata(&target) {
        Ok(_) => Err(Error::Invalid("destination already exists".into())),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok((parent, target)),
        Err(e) => Err(e.into()),
    }
}

fn same_file_state(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    let same = a.is_file()
        && b.is_file()
        && a.len() == b.len()
        && a.modified().ok() == b.modified().ok()
        && a.created().ok() == b.created().ok();
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        same && a.dev() == b.dev()
            && a.ino() == b.ino()
            && a.ctime() == b.ctime()
            && a.ctime_nsec() == b.ctime_nsec()
    }
    #[cfg(not(unix))]
    {
        same
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
