//! Bounded ingestion gateway for Archive Only sources.
#![forbid(unsafe_code)]

use oiaf::{Archive, Envelope, Source};
use sc_storage::Catalog;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

const MAX_TEXT_BYTES: usize = 16 * 1024;
const MAX_MEDIA_TYPE_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestEnvelope {
    pub source_instance: String,
    pub cursor: Option<String>,
    pub items: Vec<IngestItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngestItem {
    pub external_id: String,
    pub revision: String,
    pub media_type: String,
    pub event_time_unix_ms: Option<u64>,
    pub content_ref: String,
    pub suggested_domain: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IngestOutcome {
    pub ingest_fingerprint: String,
    pub object_id: String,
    pub created: bool,
    pub envelope: Envelope,
}

#[derive(Debug)]
pub enum Error {
    Invalid(String),
    Archive(oiaf::Error),
    Storage(sc_storage::Error),
    Encoding(serde_json::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(formatter, "invalid ingest envelope: {message}"),
            Self::Archive(error) => write!(formatter, "archive: {error}"),
            Self::Storage(error) => write!(formatter, "storage: {error}"),
            Self::Encoding(error) => write!(formatter, "ingest encoding: {error}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<oiaf::Error> for Error {
    fn from(error: oiaf::Error) -> Self {
        Self::Archive(error)
    }
}

impl From<sc_storage::Error> for Error {
    fn from(error: sc_storage::Error) -> Self {
        Self::Storage(error)
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        Self::Encoding(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Compute the stable retry identity for one source occurrence.
pub fn ingest_fingerprint(
    source_instance: &str,
    external_id: &str,
    revision: &str,
) -> Result<String> {
    validate_text("source_instance", source_instance, MAX_TEXT_BYTES)?;
    validate_text("external_id", external_id, MAX_TEXT_BYTES)?;
    validate_text("revision", revision, MAX_TEXT_BYTES)?;

    let bytes = serde_json::to_vec(&(source_instance, external_id, revision))?;
    Ok(hex_digest(&bytes))
}

pub struct IngestGateway<'a> {
    archive: &'a Archive,
    catalog: &'a mut Catalog,
}

impl<'a> IngestGateway<'a> {
    pub fn new(archive: &'a Archive, catalog: &'a mut Catalog) -> Self {
        Self { archive, catalog }
    }

    /// Validate and commit one filesystem item through OIAF, then index its
    /// committed envelope in the derived operational catalog.
    pub fn ingest_file(
        &mut self,
        source_instance: &str,
        item: &IngestItem,
        path: impl AsRef<Path>,
    ) -> Result<IngestOutcome> {
        validate_item(source_instance, item)?;
        let fingerprint = ingest_fingerprint(source_instance, &item.external_id, &item.revision)?;
        if let Some(existing) = self.catalog.get_object_by_fingerprint(&fingerprint)? {
            if existing.media_type.as_deref() != Some(item.media_type.as_str())
                || existing.suggested_domain.as_deref() != item.suggested_domain.as_deref()
            {
                return Err(Error::Invalid(
                    "ingest fingerprint already has different metadata".into(),
                ));
            }
            let envelope = self.archive.provenance(&existing.object_id)?;
            return Ok(IngestOutcome {
                ingest_fingerprint: fingerprint,
                object_id: envelope.object_id.clone(),
                created: false,
                envelope,
            });
        }
        let source = Source {
            connector: "filesystem".into(),
            source_instance: source_instance.into(),
            external_id: item.external_id.clone(),
            revision: item.revision.clone(),
            source_locator: item.content_ref.clone(),
        };
        let result = self.archive.import_source_file(path, source)?;
        self.catalog.upsert_object(
            &result.envelope,
            Some(&fingerprint),
            Some(&item.media_type),
            item.suggested_domain.as_deref(),
        )?;

        Ok(IngestOutcome {
            ingest_fingerprint: fingerprint,
            object_id: result.envelope.object_id.clone(),
            created: result.created,
            envelope: result.envelope,
        })
    }
}

fn validate_item(source_instance: &str, item: &IngestItem) -> Result<()> {
    validate_text("source_instance", source_instance, MAX_TEXT_BYTES)?;
    validate_text("external_id", &item.external_id, MAX_TEXT_BYTES)?;
    validate_text("revision", &item.revision, MAX_TEXT_BYTES)?;
    validate_text("content_ref", &item.content_ref, MAX_TEXT_BYTES)?;
    validate_text("media_type", &item.media_type, MAX_MEDIA_TYPE_BYTES)?;
    if let Some(domain) = &item.suggested_domain {
        validate_text("suggested_domain", domain, MAX_TEXT_BYTES)?;
    }
    Ok(())
}

fn validate_text(name: &str, value: &str, max_bytes: usize) -> Result<()> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(Error::Invalid(format!(
            "{name} must be nonempty, bounded text without control characters"
        )));
    }
    Ok(())
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
