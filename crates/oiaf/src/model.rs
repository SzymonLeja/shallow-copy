//! Stable OIAF data model and public error contract.

use std::{collections::BTreeMap, fmt, io, path::PathBuf};

use serde::{Deserialize, Serialize};

use crate::{digest, json_bytes};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    pub oiaf_version: String,
    pub timestamp_unix_ms: u64,
    pub total_objects: usize,
    pub total_blob_bytes: u64,
    pub root_manifest_hash: String,
    pub envelopes: BTreeMap<String, String>,
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Json(serde_json::Error),
    Crypto(sc_crypto::Error),
    Invalid(String),
    Integrity(String),
    Locked,
    SourceChanged,
    SourceConflict,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O: {error}"),
            Self::Json(error) => write!(f, "JSON: {error}"),
            Self::Crypto(error) => write!(f, "domain encryption: {error}"),
            Self::Invalid(error) => write!(f, "invalid archive input: {error}"),
            Self::Integrity(error) => write!(f, "local fixity failure: {error}"),
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
            Self::Io(error) => Some(error),
            Self::Json(error) => Some(error),
            Self::Crypto(error) => Some(error),
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
impl From<sc_crypto::Error> for Error {
    fn from(value: sc_crypto::Error) -> Self {
        Self::Crypto(value)
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

    pub(crate) fn validate(&self) -> Result<()> {
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

    pub(crate) fn object_id(&self) -> Result<String> {
        Ok(digest(&json_bytes(&(
            &self.connector,
            &self.source_instance,
            &self.external_id,
            &self.revision,
        ))?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ArchiveDomain {
    Public,
    Private,
    Restricted,
    Legacy,
    Secrets,
}

impl ArchiveDomain {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Restricted => "restricted",
            Self::Legacy => "legacy",
            Self::Secrets => "secrets",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blob {
    pub algorithm: String,
    pub digest: String,
    pub size: u64,
    /// Absent for legacy plaintext blobs; included in the object envelope hash otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<ArchiveDomain>,
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
