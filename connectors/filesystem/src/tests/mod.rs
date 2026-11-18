use super::*;

#[test]
fn scans_directory_and_produces_ingest_envelope() {
    let dir = tempfile::tempdir().unwrap();
    let sub = dir.path().join("sub");
    fs::create_dir_all(&sub).unwrap();

    let f1 = dir.path().join("file1.txt");
    let f2 = sub.join("file2.log");
    fs::write(&f1, b"hello").unwrap();
    fs::write(&f2, b"world").unwrap();

    let connector = FilesystemConnector::new(FilesystemConnectorConfig {
        source_instance: "test-box".into(),
        root_dir: dir.path().to_path_buf(),
    });

    let envelope = connector.scan().unwrap();
    assert_eq!(envelope.source_instance, "test-box");
    assert_eq!(envelope.items.len(), 2);

    let ids: Vec<_> = envelope
        .items
        .iter()
        .map(|i| i.external_id.as_str())
        .collect();
    assert_eq!(ids, ["file1.txt", "sub/file2.log"]);
}

#[test]
fn fails_on_nonexistent_root() {
    let connector = FilesystemConnector::new(FilesystemConnectorConfig {
        source_instance: "test-box".into(),
        root_dir: PathBuf::from("nonexistent-path-abc-123"),
    });
    assert!(connector.scan().is_err());
}

#[test]
fn fails_on_walkdir_traversal_error() {
    let dir = tempfile::tempdir().unwrap();
    let connector = FilesystemConnector::new(FilesystemConnectorConfig {
        source_instance: "test-box".into(),
        root_dir: dir.path().to_path_buf(),
    });

    let missing = dir.path().join("missing");
    let result = connector.scan_entries(walkdir::WalkDir::new(missing));

    assert!(matches!(
        result,
        Err(Error::Invalid(message)) if message.contains("walkdir traversal failed")
    ));
}
