//! Archive Only prototype. Original bytes are canonical; JSON metadata is UTF-8.
//! SHA-256 provides local fixity, never authenticity or rollback protection.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

pub const FORMAT_VERSION: &str = "0.1-archive-only";
const JSON_LIMIT: u64 = 1024 * 1024;
const MANIFEST_LIMIT: u64 = 16 * JSON_LIMIT;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Json(serde_json::Error),
    Invalid(String),
    Integrity(String),
    Locked,
    SourceChanged,
    SourceConflict,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::Json(e) => write!(f, "JSON: {e}"),
            Self::Invalid(e) => write!(f, "invalid archive input: {e}"),
            Self::Integrity(e) => write!(f, "local fixity failure: {e}"),
            Self::Locked => f.write_str("archive writer is already locked"),
            Self::SourceChanged => f.write_str("source changed during import"),
            Self::SourceConflict => {
                f.write_str("source revision already records different content or metadata")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

/// Stable source occurrence. A retry MUST reuse the same revision. A new
/// occurrence/version MUST use a different identity or revision, even for equal bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    pub connector: String,
    pub source_instance: String,
    pub external_id: String,
    pub revision: String,
    /// Opaque provenance, never interpreted as an archive path.
    pub source_locator: String,
}

impl Source {
    pub fn filesystem(instance: &str, locator: &str, revision: &str) -> Self {
        Self {
            connector: "filesystem".into(),
            source_instance: instance.into(),
            external_id: locator.into(),
            revision: revision.into(),
            source_locator: locator.into(),
        }
    }

    fn validate(&self) -> Result<()> {
        for value in [
            &self.connector,
            &self.source_instance,
            &self.external_id,
            &self.revision,
            &self.source_locator,
        ] {
            if value.is_empty() || value.len() > 16 * 1024 || value.chars().any(char::is_control) {
                return Err(Error::Invalid(
                    "source fields must be nonempty, bounded text without control characters"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    fn object_id(&self) -> Result<String> {
        // JSON tuple encoding prevents ambiguous concatenation and excludes locator changes.
        Ok(digest(&json_bytes(&(
            &self.connector,
            &self.source_instance,
            &self.external_id,
            &self.revision,
        ))?))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    pub algorithm: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceTime {
    pub event_time_unix_ms: Option<u64>,
    pub observed_time_unix_ms: u64,
    pub ingested_time_unix_ms: u64,
    pub processed_time_unix_ms: Option<u64>,
}

/// The envelope is also the provenance record for this untransformed source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub oiaf_version: String,
    pub object_id: String,
    pub blob: Blob,
    pub source: Source,
    pub time: EvidenceTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    oiaf_version: String,
    /// Object ID -> SHA-256 of the exact envelope JSON bytes.
    envelopes: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ImportResult {
    pub envelope: Envelope,
    pub created: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationReport {
    pub objects: usize,
    pub blobs: usize,
    /// Unique canonical blob bytes.
    pub bytes: u64,
    pub fixity_only: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveSummary {
    pub root: PathBuf,
    pub oiaf_version: &'static str,
    pub fixity_only: bool,
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

fn read_json<T: DeserializeOwned + Serialize>(path: &Path, limit: u64) -> Result<T> {
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
    Ok(value)
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

    fn manifest(&self) -> Result<Manifest> {
        let mut version = String::new();
        open_regular(&safe_path(&self.root, "OIAF-VERSION")?)?
            .take(128)
            .read_to_string(&mut version)?;
        if version != format!("{FORMAT_VERSION}\n") {
            return Err(Error::Invalid("unsupported OIAF version".into()));
        }
        let manifest: Manifest =
            read_json(&safe_path(&self.root, "manifest.json")?, MANIFEST_LIMIT)?;
        if manifest.oiaf_version != FORMAT_VERSION {
            return Err(Error::Invalid("unsupported manifest version".into()));
        }
        for (id, hash) in &manifest.envelopes {
            validate_digest(id)?;
            validate_digest(hash)?;
        }
        Ok(manifest)
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
            },
            observed,
        )
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
mod tests {
    use super::*;

    fn test_dir() -> Stage {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/unit-data");
        fs::create_dir_all(&parent).unwrap();
        Stage::new(&fs::canonicalize(parent).unwrap()).unwrap()
    }

    #[test]
    fn sha256_vectors_and_digest_validation() {
        assert_eq!(
            digest(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        assert_eq!(digest(b"abc"), abc);
        assert_eq!(
            blob_relative_path(abc).unwrap(),
            format!("objects/sha256/ba/78/{abc}.blob")
        );
        for invalid in [
            "",
            "../escape",
            &"a".repeat(63),
            &"A".repeat(64),
            &"g".repeat(64),
            &"é".repeat(32),
        ] {
            assert!(blob_relative_path(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn strict_portable_relative_paths() {
        for path in [
            "",
            "/root",
            "//server/share",
            "a//b",
            "a/",
            ".",
            "..",
            "a/../b",
            "a/./b",
            "C:/x",
            "C:x",
            "a\\b",
            "a\0b",
            "a\nb",
            "a:b",
            "a?b",
            "a*b",
            "a|b",
            "a<",
            "a>",
            "a\"",
            "a.",
            "a ",
            "a/NUL.txt",
            "con",
            "COM1",
            "lpt9.txt",
            "COM¹.txt",
        ] {
            assert!(validate_relative_path(path).is_err(), "accepted {path:?}");
        }
        for path in [
            "objects/sha256/ab/cd/file.blob",
            "żółw/文.json",
            "normal-file.txt",
        ] {
            validate_relative_path(path).unwrap();
        }
    }

    #[test]
    fn deterministic_json_has_utf8_and_one_lf() {
        let values = BTreeMap::from([("z", "文"), ("a", "ż")]);
        assert_eq!(
            json_bytes(&values).unwrap(),
            "{\"a\":\"ż\",\"z\":\"文\"}\n".as_bytes()
        );
    }

    #[test]
    fn writer_lock_excludes_other_writers_but_allows_readers() {
        let dir = test_dir();
        let archive = Archive::init(dir.0.join("archive")).unwrap();
        let lock = archive.writer_lock().unwrap();
        let second = Archive::open(archive.root()).unwrap();
        assert!(matches!(
            second.import_bytes(b"x", Source::filesystem("test", "x", "1")),
            Err(Error::Locked)
        ));
        assert_eq!(second.verify(true).unwrap().objects, 0);
        drop(lock);
        second
            .import_bytes(b"x", Source::filesystem("test", "x", "1"))
            .unwrap();
    }

    #[test]
    fn source_mutation_is_rejected_before_canonical_publication() {
        let dir = test_dir();
        let archive = Archive::init(dir.0.join("archive")).unwrap();
        let input = dir.0.join("input");
        fs::write(&input, b"before").unwrap();
        let old_modified = fs::metadata(&input).unwrap().modified().unwrap();
        let result = archive.import_file_inner(
            &input,
            Some(Source::filesystem("test", "input", "1")),
            || {
                fs::write(&input, b"after!").unwrap();
                // Equal length and restored mtime still fail the second content pass.
                File::options()
                    .write(true)
                    .open(&input)
                    .unwrap()
                    .set_times(fs::FileTimes::new().set_modified(old_modified))
                    .unwrap();
            },
        );
        assert!(matches!(result, Err(Error::SourceChanged)));
        assert!(archive.list_objects().unwrap().is_empty());
        assert_eq!(
            fs::read_dir(archive.root().join("objects/sha256"))
                .unwrap()
                .count(),
            0
        );
        assert_eq!(fs::read_dir(archive.root()).unwrap().count(), 4);
    }

    #[test]
    fn interrupted_publication_is_invisible_and_retry_recovers_orphans() {
        let dir = test_dir();
        let archive = Archive::init(dir.0.join("archive")).unwrap();
        let initial_manifest = fs::read(archive.root().join("manifest.json")).unwrap();
        let source = Source::filesystem("test", "x", "1");
        let committed = archive.import_bytes(b"x", source.clone()).unwrap();
        // Simulate crash after blob/envelope publication but before manifest rename.
        fs::write(archive.root().join("manifest.json"), initial_manifest).unwrap();
        assert_eq!(archive.verify(true).unwrap().objects, 0);
        assert!(archive.import_bytes(b"x", source.clone()).unwrap().created);
        let retry = archive.import_bytes(b"x", source).unwrap();
        assert!(!retry.created);
        assert_eq!(retry.envelope.object_id, committed.envelope.object_id);
        assert_eq!(archive.verify(true).unwrap().objects, 1);
    }

    #[test]
    fn untrusted_manifest_keys_and_inconsistent_envelopes_are_rejected() {
        let dir = test_dir();
        let archive = Archive::init(dir.0.join("archive")).unwrap();
        let imported = archive
            .import_bytes(b"x", Source::filesystem("test", "x", "1"))
            .unwrap();
        let mut manifest = archive.manifest().unwrap();
        manifest
            .envelopes
            .insert("../outside".into(), "a".repeat(64));
        fs::write(
            archive.root().join("manifest.json"),
            json_bytes(&manifest).unwrap(),
        )
        .unwrap();
        assert!(archive.verify(true).is_err());
        manifest.envelopes.remove("../outside");
        let mut envelope = imported.envelope;
        envelope.blob.digest = "A".repeat(64);
        let bytes = json_bytes(&envelope).unwrap();
        manifest
            .envelopes
            .insert(envelope.object_id.clone(), digest(&bytes));
        fs::write(
            archive
                .root()
                .join(envelope_relative_path(&envelope.object_id).unwrap()),
            bytes,
        )
        .unwrap();
        fs::write(
            archive.root().join("manifest.json"),
            json_bytes(&manifest).unwrap(),
        )
        .unwrap();
        assert!(archive.verify(true).is_err());
    }

    #[test]
    fn manifest_parser_rejects_noncanonical_duplicate_keys_and_oversized_json() {
        let dir = test_dir();
        let path = dir.0.join("manifest.json");
        fs::write(
            &path,
            format!(
                "{{\"oiaf_version\":\"{FORMAT_VERSION}\",\"envelopes\":{{}},\"envelopes\":{{}}}}\n"
            ),
        )
        .unwrap();
        assert!(read_json::<Manifest>(&path, MANIFEST_LIMIT).is_err());
        fs::write(&path, vec![b' '; 129]).unwrap();
        assert!(read_json::<Manifest>(&path, 128).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn archive_symlinks_cannot_escape_root() {
        let dir = test_dir();
        let archive = Archive::init(dir.0.join("archive")).unwrap();
        fs::remove_dir(archive.root().join("objects/sha256")).unwrap();
        let outside = dir.0.join("outside");
        fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, archive.root().join("objects/sha256")).unwrap();
        assert!(
            archive
                .import_bytes(b"x", Source::filesystem("test", "x", "1"))
                .is_err()
        );
        assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
    }
}
