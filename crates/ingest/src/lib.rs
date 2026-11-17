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
mod tests {
    use super::*;
    use std::fs;

    fn item(external_id: &str, revision: &str) -> IngestItem {
        IngestItem {
            external_id: external_id.into(),
            revision: revision.into(),
            media_type: "application/octet-stream".into(),
            event_time_unix_ms: None,
            content_ref: external_id.into(),
            suggested_domain: Some("private".into()),
        }
    }

    #[test]
    fn fingerprint_is_deterministic_and_changes_with_revision() {
        let first = ingest_fingerprint("source", "item", "v1").unwrap();
        let retry = ingest_fingerprint("source", "item", "v1").unwrap();
        let next = ingest_fingerprint("source", "item", "v2").unwrap();

        assert_eq!(first, retry);
        assert_ne!(first, next);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn rejects_untrusted_control_characters() {
        let result = ingest_fingerprint("source\n", "item", "v1");

        assert!(matches!(result, Err(Error::Invalid(_))));
    }

    #[test]
    fn envelope_parser_rejects_unknown_fields() {
        let json = r#"{
            "source_instance": "source",
            "cursor": null,
            "items": [],
            "unexpected": true
        }"#;

        assert!(serde_json::from_str::<IngestEnvelope>(json).is_err());
    }

    #[test]
    fn retry_returns_existing_commit_metadata() {
        let temp = tempfile::tempdir().unwrap();
        let archive = Archive::init(temp.path().join("archive")).unwrap();
        let source_path = temp.path().join("payload.bin");
        fs::write(&source_path, [0, 1, 2, 255]).unwrap();
        let mut catalog = Catalog::open_in_memory().unwrap();
        let mut gateway = IngestGateway::new(&archive, &mut catalog);
        let source = item("record-1", "revision-1");

        let first = gateway
            .ingest_file("connector-1", &source, &source_path)
            .unwrap();
        let retry = gateway
            .ingest_file("connector-1", &source, &source_path)
            .unwrap();

        assert!(first.created);
        assert!(!retry.created);
        assert_eq!(first.object_id, retry.object_id);
        assert_eq!(first.ingest_fingerprint, retry.ingest_fingerprint);
        assert_eq!(catalog.object_count().unwrap(), 1);
    }

    #[test]
    fn changed_revision_creates_new_occurrence() {
        let temp = tempfile::tempdir().unwrap();
        let archive = Archive::init(temp.path().join("archive")).unwrap();
        let source_path = temp.path().join("payload.bin");
        fs::write(&source_path, b"payload").unwrap();
        let mut catalog = Catalog::open_in_memory().unwrap();
        let mut gateway = IngestGateway::new(&archive, &mut catalog);

        let first = gateway
            .ingest_file("connector-1", &item("record-1", "revision-1"), &source_path)
            .unwrap();
        let second = gateway
            .ingest_file("connector-1", &item("record-1", "revision-2"), &source_path)
            .unwrap();

        assert!(first.created);
        assert!(second.created);
        assert_ne!(first.object_id, second.object_id);
        assert_eq!(catalog.object_count().unwrap(), 2);
    }

    #[test]
    fn metadata_preserved_and_retrievable_from_catalog() {
        let temp = tempfile::tempdir().unwrap();
        let archive = Archive::init(temp.path().join("archive")).unwrap();
        let source_path = temp.path().join("doc.txt");
        fs::write(&source_path, b"hello text").unwrap();
        let mut catalog = Catalog::open_in_memory().unwrap();
        let mut gateway = IngestGateway::new(&archive, &mut catalog);

        let mut ingest_item = item("note-1", "rev-1");
        ingest_item.media_type = "text/plain".into();
        ingest_item.suggested_domain = Some("restricted".into());

        let outcome = gateway
            .ingest_file("connector-1", &ingest_item, &source_path)
            .unwrap();

        let obj = catalog.get_object(&outcome.object_id).unwrap().unwrap();
        assert_eq!(obj.media_type.as_deref(), Some("text/plain"));
        assert_eq!(obj.suggested_domain.as_deref(), Some("restricted"));
        assert_eq!(
            obj.ingest_fingerprint.as_deref(),
            Some(outcome.ingest_fingerprint.as_str())
        );

        let by_fp = catalog
            .get_object_by_fingerprint(&outcome.ingest_fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(by_fp.object_id, outcome.object_id);
    }

    #[test]
    fn duplicate_fingerprint_behavior_is_idempotent() {
        let temp = tempfile::tempdir().unwrap();
        let archive = Archive::init(temp.path().join("archive")).unwrap();
        let source_path = temp.path().join("doc.txt");
        fs::write(&source_path, b"idempotent payload").unwrap();
        let mut catalog = Catalog::open_in_memory().unwrap();
        let mut gateway = IngestGateway::new(&archive, &mut catalog);

        let ingest_item = item("note-dup", "rev-1");

        let first = gateway
            .ingest_file("connector-1", &ingest_item, &source_path)
            .unwrap();
        let second = gateway
            .ingest_file("connector-1", &ingest_item, &source_path)
            .unwrap();

        assert_eq!(first.ingest_fingerprint, second.ingest_fingerprint);
        assert_eq!(catalog.object_count().unwrap(), 1);
        let by_fp = catalog
            .get_object_by_fingerprint(&first.ingest_fingerprint)
            .unwrap()
            .unwrap();
        assert_eq!(by_fp.object_id, first.object_id);
    }
}
