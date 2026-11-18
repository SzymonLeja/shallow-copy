use super::*;

#[test]
fn scans_mock_db_with_urls_table() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("History");
    let stage_dir = temp.path().join("stage");
    create_mock_urls_db(&db_path).unwrap();

    let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
        source_instance: "chrome-laptop".into(),
        history_db_path: db_path,
        staging_dir: Some(stage_dir),
    });

    let envelope = connector.scan().unwrap();
    assert_eq!(envelope.source_instance, "chrome-laptop");
    assert_eq!(envelope.items.len(), 2);

    let first = &envelope.items[0];
    assert_eq!(first.external_id, "history:1");
    assert_eq!(
        first.media_type,
        "application/vnd.shallowcopy.browser-visit+json"
    );
    assert_eq!(first.suggested_domain.as_deref(), Some("private"));
    assert!(first.event_time_unix_ms.is_some());
    assert!(Path::new(&first.content_ref).is_file());

    let content_str = fs::read_to_string(&first.content_ref).unwrap();
    let record: BrowserVisitRecord = serde_json::from_str(&content_str).unwrap();
    assert_eq!(record.visit_id, 1);
    assert_eq!(record.url, "https://example.com");
    assert_eq!(record.title.as_deref(), Some("Example Domain"));
    assert!(record.transition_type.is_none());
}

#[test]
fn scans_mock_db_with_visits_and_urls_table_with_transitions() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("History");
    create_mock_history_db(&db_path).unwrap();

    let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
        source_instance: "chrome-desktop".into(),
        history_db_path: db_path,
        staging_dir: None,
    });

    let envelope = connector.scan().unwrap();
    assert_eq!(envelope.items.len(), 2);
    assert_eq!(envelope.items[0].external_id, "history:100");
    assert_eq!(envelope.items[1].external_id, "history:101");

    let content_0 = fs::read_to_string(&envelope.items[0].content_ref).unwrap();
    let record_0: BrowserVisitRecord = serde_json::from_str(&content_0).unwrap();
    assert_eq!(record_0.visit_id, 100);
    assert_eq!(record_0.url, "https://shallow-copy.org");
    assert_eq!(record_0.title.as_deref(), Some("Shallow Copy Project"));
    assert_eq!(record_0.transition_raw, Some(1));
    assert_eq!(record_0.transition_type.as_deref(), Some("typed"));

    let content_1 = fs::read_to_string(&envelope.items[1].content_ref).unwrap();
    let record_1: BrowserVisitRecord = serde_json::from_str(&content_1).unwrap();
    assert_eq!(record_1.visit_id, 101);
    assert_eq!(record_1.transition_raw, Some(0));
    assert_eq!(record_1.transition_type.as_deref(), Some("link"));
}

#[test]
fn extracts_bookmarks_with_nested_folder_hierarchy() {
    let temp = tempfile::tempdir().unwrap();
    let bpath = temp.path().join("Bookmarks");
    create_mock_bookmarks_file(&bpath).unwrap();

    let db_path = temp.path().join("History");
    create_mock_urls_db(&db_path).unwrap();

    let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
        source_instance: "chrome-test".into(),
        history_db_path: db_path,
        staging_dir: None,
    })
    .with_bookmarks_path(bpath);

    let bookmarks = connector.scan_bookmarks().unwrap();
    assert_eq!(bookmarks.len(), 4);

    // Bookmark 1: in "Bookmarks bar"
    let b1 = bookmarks.iter().find(|b| b.bookmark_id == "1").unwrap();
    assert_eq!(b1.title, "Rust Language");
    assert_eq!(b1.url, "https://www.rust-lang.org/");
    assert_eq!(b1.folder_path, vec!["Bookmarks bar"]);
    assert_eq!(b1.folder, "Bookmarks bar");
    assert!(b1.date_added_unix_ms.is_some());

    // Bookmark 3: in "Bookmarks bar/Engineering"
    let b3 = bookmarks.iter().find(|b| b.bookmark_id == "3").unwrap();
    assert_eq!(b3.title, "DeepMind");
    assert_eq!(b3.url, "https://deepmind.google/");
    assert_eq!(b3.folder_path, vec!["Bookmarks bar", "Engineering"]);
    assert_eq!(b3.folder, "Bookmarks bar/Engineering");

    // Bookmark 5: in "Bookmarks bar/Engineering/Projects"
    let b5 = bookmarks.iter().find(|b| b.bookmark_id == "5").unwrap();
    assert_eq!(b5.title, "Shallow Copy");
    assert_eq!(b5.url, "https://github.com/shallow-copy");
    assert_eq!(
        b5.folder_path,
        vec!["Bookmarks bar", "Engineering", "Projects"]
    );
    assert_eq!(b5.folder, "Bookmarks bar/Engineering/Projects");

    // Bookmark 6: in "Other bookmarks"
    let b6 = bookmarks.iter().find(|b| b.bookmark_id == "6").unwrap();
    assert_eq!(b6.title, "Documentation");
    assert_eq!(b6.url, "https://docs.rs/");
    assert_eq!(b6.folder_path, vec!["Other bookmarks"]);
    assert_eq!(b6.folder, "Other bookmarks");
}

#[test]
fn scan_combines_visits_and_bookmarks_into_single_envelope() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("History");
    let bpath = temp.path().join("Bookmarks");
    create_mock_history_db(&db_path).unwrap();
    create_mock_bookmarks_file(&bpath).unwrap();

    let stage_dir = temp.path().join("stage");

    let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
        source_instance: "chrome-full".into(),
        history_db_path: db_path,
        staging_dir: Some(stage_dir),
    })
    .with_bookmarks_path(bpath);

    let envelope = connector.scan().unwrap();
    // 2 visits + 4 bookmarks = 6 items
    assert_eq!(envelope.items.len(), 6);

    let visit_items: Vec<_> = envelope
        .items
        .iter()
        .filter(|i| i.media_type == "application/vnd.shallowcopy.browser-visit+json")
        .collect();
    assert_eq!(visit_items.len(), 2);

    let bookmark_items: Vec<_> = envelope
        .items
        .iter()
        .filter(|i| i.media_type == "application/vnd.shallowcopy.browser-bookmark+json")
        .collect();
    assert_eq!(bookmark_items.len(), 4);

    // Verify bookmark item content
    let b_item = bookmark_items
        .iter()
        .find(|i| i.external_id == "bookmark:1")
        .unwrap();
    let b_content = fs::read_to_string(&b_item.content_ref).unwrap();
    let b_record: BrowserBookmarkRecord = serde_json::from_str(&b_content).unwrap();
    assert_eq!(b_record.title, "Rust Language");
    assert_eq!(b_record.folder, "Bookmarks bar");
}

#[test]
fn snapshot_scan_is_deterministic_and_does_not_mutate_source() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("History");
    let bpath = temp.path().join("Bookmarks");
    let stage_dir = temp.path().join("stage");
    create_mock_history_db(&db_path).unwrap();
    create_mock_bookmarks_file(&bpath).unwrap();

    let history_before = fs::read(&db_path).unwrap();
    let bookmarks_before = fs::read(&bpath).unwrap();

    let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
        source_instance: "chrome-laptop".into(),
        history_db_path: db_path.clone(),
        staging_dir: Some(stage_dir),
    })
    .with_bookmarks_path(bpath.clone());

    let first = connector.scan().unwrap();
    let second = connector.scan().unwrap();

    assert_eq!(first.items, second.items);
    assert_eq!(fs::read(&db_path).unwrap(), history_before);
    assert_eq!(fs::read(&bpath).unwrap(), bookmarks_before);
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_history_database_and_sidecar() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let real_db = temp.path().join("real-History");
    let db_path = temp.path().join("History");
    create_mock_urls_db(&real_db).unwrap();
    symlink(&real_db, &db_path).unwrap();

    let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
        source_instance: "chrome-laptop".into(),
        history_db_path: db_path,
        staging_dir: None,
    });
    assert!(connector.scan().is_err());

    let regular_db = temp.path().join("regular-History");
    create_mock_urls_db(&regular_db).unwrap();
    let sidecar = temp.path().join("History-wal");
    symlink(&real_db, &sidecar).unwrap();
    let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
        source_instance: "chrome-laptop".into(),
        history_db_path: regular_db,
        staging_dir: None,
    });
    assert!(connector.scan().is_err());
}

#[cfg(unix)]
#[test]
fn rejects_symlinked_bookmarks_file() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("History");
    create_mock_urls_db(&db_path).unwrap();

    let real_b = temp.path().join("real-Bookmarks");
    create_mock_bookmarks_file(&real_b).unwrap();
    let sym_b = temp.path().join("Bookmarks");
    symlink(&real_b, &sym_b).unwrap();

    let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
        source_instance: "chrome-laptop".into(),
        history_db_path: db_path,
        staging_dir: None,
    })
    .with_bookmarks_path(sym_b);

    assert!(connector.scan().is_err());
}

#[test]
fn propagates_sidecar_copy_failure() {
    let temp = tempfile::tempdir().unwrap();
    let sidecar = temp.path().join("History-wal");
    fs::write(&sidecar, b"wal").unwrap();

    assert!(copy_sidecar(&sidecar, temp.path()).is_err());
}

#[test]
fn fails_on_nonexistent_history_db() {
    let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
        source_instance: "chrome-desktop".into(),
        history_db_path: PathBuf::from("nonexistent_path_history.db"),
        staging_dir: None,
    });
    assert!(connector.scan().is_err());
}

#[test]
fn fails_on_nonexistent_bookmarks_file() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("History");
    create_mock_urls_db(&db_path).unwrap();

    let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
        source_instance: "chrome-desktop".into(),
        history_db_path: db_path,
        staging_dir: None,
    })
    .with_bookmarks_path(PathBuf::from("nonexistent_bookmarks.json"));

    assert!(connector.scan().is_err());
}

#[test]
fn scans_history_with_wal_and_shm_sidecars_and_verifies_fixity() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("History");
    create_mock_history_db(&db_path).unwrap();

    let wal_path = temp.path().join("History-wal");
    let shm_path = temp.path().join("History-shm");
    fs::write(&wal_path, b"initial wal state content").unwrap();
    fs::write(&shm_path, b"initial shm state content").unwrap();

    let wal_before = fs::read(&wal_path).unwrap();
    let shm_before = fs::read(&shm_path).unwrap();

    let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
        source_instance: "chrome-wal-test".into(),
        history_db_path: db_path,
        staging_dir: None,
    });

    let envelope = connector.scan().unwrap();
    assert_eq!(envelope.items.len(), 2);

    let visits = connector.scan_visits().unwrap();
    assert_eq!(visits.len(), 2);

    assert_eq!(fs::read(&wal_path).unwrap(), wal_before);
    assert_eq!(fs::read(&shm_path).unwrap(), shm_before);
}

#[test]
fn sidecar_post_fixity_detects_mutation_removal_and_creation() {
    let temp = tempfile::tempdir().unwrap();
    let sidecar = temp.path().join("History-wal");

    // 1. Initial matching hash passes
    fs::write(&sidecar, b"original sidecar bytes").unwrap();
    let hash = file_sha256(&sidecar).unwrap();
    assert!(verify_sidecar_post_fixity(&sidecar, Some(&hash), "WAL").is_ok());

    // 2. Tampered content fails
    fs::write(&sidecar, b"tampered sidecar bytes").unwrap();
    let err = verify_sidecar_post_fixity(&sidecar, Some(&hash), "WAL").unwrap_err();
    assert!(err.to_string().contains("fixity violation"));

    // 3. Disappearing sidecar fails
    fs::remove_file(&sidecar).unwrap();
    let err = verify_sidecar_post_fixity(&sidecar, Some(&hash), "WAL").unwrap_err();
    assert!(err.to_string().contains("fixity violation"));

    // 4. Unexpected sidecar creation when none existed before fails
    fs::write(&sidecar, b"newly created sidecar").unwrap();
    let err = verify_sidecar_post_fixity(&sidecar, None, "WAL").unwrap_err();
    assert!(err.to_string().contains("fixity violation"));
}
