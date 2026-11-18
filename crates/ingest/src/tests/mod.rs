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
