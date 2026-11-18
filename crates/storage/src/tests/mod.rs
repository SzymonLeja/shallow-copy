use super::*;
use oiaf::{Archive, Source};

fn test_archive(dir: &tempfile::TempDir) -> Archive {
    Archive::init(dir.path().join("archive")).unwrap()
}

fn test_source(name: &str, rev: &str) -> Source {
    Source::filesystem("test", name, rev)
}

#[test]
fn empty_catalog_has_zero_objects() {
    let cat = Catalog::open_in_memory().unwrap();
    assert_eq!(cat.object_count().unwrap(), 0);
    assert!(cat.list_objects().unwrap().is_empty());
}

#[test]
fn rebuild_from_archive_imports_all_objects() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = test_archive(&tmp);
    archive
        .import_bytes(b"alpha", test_source("alpha", "1"))
        .unwrap();
    archive
        .import_bytes(b"beta", test_source("beta", "1"))
        .unwrap();
    let mut cat = Catalog::open_in_memory().unwrap();
    let count = cat.rebuild_from_archive(&archive).unwrap();
    assert_eq!(count, 2);
    assert_eq!(cat.object_count().unwrap(), 2);
}

#[test]
fn rebuild_is_idempotent() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = test_archive(&tmp);
    archive.import_bytes(b"x", test_source("x", "1")).unwrap();
    let mut cat = Catalog::open_in_memory().unwrap();
    cat.rebuild_from_archive(&archive).unwrap();
    cat.rebuild_from_archive(&archive).unwrap();
    assert_eq!(cat.object_count().unwrap(), 1);
}

#[test]
fn get_object_returns_correct_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = test_archive(&tmp);
    let result = archive
        .import_bytes(b"payload", test_source("doc", "v1"))
        .unwrap();
    let mut cat = Catalog::open_in_memory().unwrap();
    cat.rebuild_from_archive(&archive).unwrap();
    let obj = cat.get_object(&result.envelope.object_id).unwrap().unwrap();
    assert_eq!(obj.object_id, result.envelope.object_id);
    assert_eq!(obj.blob_digest, result.envelope.blob.digest);
    assert_eq!(obj.blob_size, result.envelope.blob.size);
    assert_eq!(obj.connector, "filesystem");
    assert_eq!(obj.source_instance, "test");
    assert_eq!(obj.external_id, "doc");
    assert_eq!(obj.revision, "v1");
}

#[test]
fn get_object_returns_none_for_unknown_id() {
    let cat = Catalog::open_in_memory().unwrap();
    let missing = cat.get_object(&"a".repeat(64)).unwrap();
    assert!(missing.is_none());
}

#[test]
fn job_lifecycle_pending_to_completed() {
    let cat = Catalog::open_in_memory().unwrap();
    let job = CatalogJob {
        job_id: "01JFAKE000000000000000000A".into(),
        kind: "verify".into(),
        status: JobStatus::Pending,
        progress_pct: None,
        created_at_unix_ms: 1_000_000,
        updated_at_unix_ms: 1_000_000,
        error: None,
    };
    cat.insert_job(&job).unwrap();
    let pending = cat.list_jobs(Some(JobStatus::Pending)).unwrap();
    assert_eq!(pending.len(), 1);
    let changed = cat
        .update_job_status(
            &job.job_id,
            JobStatus::Completed,
            Some(100),
            None,
            2_000_000,
        )
        .unwrap();
    assert!(changed);
    assert!(cat.list_jobs(Some(JobStatus::Pending)).unwrap().is_empty());
    let done = cat.list_jobs(Some(JobStatus::Completed)).unwrap();
    assert_eq!(done.len(), 1);
    assert_eq!(done[0].progress_pct, Some(100));
}

#[test]
fn list_all_jobs_returns_all_statuses() {
    let cat = Catalog::open_in_memory().unwrap();
    for (id, status) in [
        ("A", JobStatus::Pending),
        ("B", JobStatus::Running),
        ("C", JobStatus::Completed),
    ] {
        cat.insert_job(&CatalogJob {
            job_id: id.into(),
            kind: "test".into(),
            status,
            progress_pct: None,
            created_at_unix_ms: 1000,
            updated_at_unix_ms: 1000,
            error: None,
        })
        .unwrap();
    }
    assert_eq!(cat.list_jobs(None).unwrap().len(), 3);
}

#[test]
fn upsert_object_with_metadata_stores_and_retrieves_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = test_archive(&tmp);
    let result = archive
        .import_bytes(b"metadata-test", test_source("meta-doc", "v1"))
        .unwrap();
    let cat = Catalog::open_in_memory().unwrap();

    cat.upsert_object(
        &result.envelope,
        Some("fingerprint-123"),
        Some("text/markdown"),
        Some("private"),
    )
    .unwrap();

    let obj = cat.get_object(&result.envelope.object_id).unwrap().unwrap();
    assert_eq!(obj.ingest_fingerprint.as_deref(), Some("fingerprint-123"));
    assert_eq!(obj.media_type.as_deref(), Some("text/markdown"));
    assert_eq!(obj.suggested_domain.as_deref(), Some("private"));

    let by_fp = cat
        .get_object_by_fingerprint("fingerprint-123")
        .unwrap()
        .unwrap();
    assert_eq!(by_fp.object_id, result.envelope.object_id);
}

#[test]
fn unique_index_prevents_duplicate_fingerprint_for_different_object() {
    let cat = Catalog::open_in_memory().unwrap();

    let obj1 = CatalogObject {
        object_id: "obj-1".into(),
        blob_digest: "digest-1".into(),
        blob_size: 10,
        connector: "filesystem".into(),
        source_instance: "node1".into(),
        external_id: "file1".into(),
        revision: "r1".into(),
        observed_time_unix_ms: 100,
        ingested_time_unix_ms: 100,
        ingest_fingerprint: Some("unique-fp".into()),
        media_type: None,
        suggested_domain: None,
    };

    let obj2 = CatalogObject {
        object_id: "obj-2".into(),
        blob_digest: "digest-2".into(),
        blob_size: 20,
        connector: "filesystem".into(),
        source_instance: "node1".into(),
        external_id: "file2".into(),
        revision: "r1".into(),
        observed_time_unix_ms: 200,
        ingested_time_unix_ms: 200,
        ingest_fingerprint: Some("unique-fp".into()),
        media_type: None,
        suggested_domain: None,
    };

    cat.upsert_catalog_object(&obj1).unwrap();
    assert!(cat.upsert_catalog_object(&obj2).is_err());

    assert_eq!(cat.object_count().unwrap(), 1);
    let by_fp = cat.get_object_by_fingerprint("unique-fp").unwrap().unwrap();
    assert_eq!(by_fp.object_id, "obj-1");
}

#[test]
fn idempotent_upsert_rejects_metadata_drift() {
    let cat = Catalog::open_in_memory().unwrap();
    let base = CatalogObject {
        object_id: "obj-1".into(),
        blob_digest: "digest-1".into(),
        blob_size: 10,
        connector: "filesystem".into(),
        source_instance: "node1".into(),
        external_id: "file1".into(),
        revision: "r1".into(),
        observed_time_unix_ms: 100,
        ingested_time_unix_ms: 100,
        ingest_fingerprint: Some("stable-fp".into()),
        media_type: Some("text/plain".into()),
        suggested_domain: Some("private".into()),
    };
    cat.upsert_catalog_object(&base).unwrap();

    let mut changed = base.clone();
    changed.media_type = Some("application/pdf".into());
    assert!(cat.upsert_catalog_object(&changed).is_err());
    assert_eq!(
        cat.get_object("obj-1")
            .unwrap()
            .unwrap()
            .media_type
            .as_deref(),
        Some("text/plain")
    );
}

#[test]
fn schema_version_enforced_and_rejects_unsupported() {
    let cat = Catalog::open_in_memory().unwrap();
    assert_eq!(cat.schema_version().unwrap(), SCHEMA_VERSION);
    assert_eq!(cat.schema_version().unwrap(), 1);

    let tmp = tempfile::tempdir().unwrap();
    let db_path = tmp.path().join("catalog.db");
    {
        let disk_cat = Catalog::open(&db_path).unwrap();
        assert_eq!(disk_cat.schema_version().unwrap(), 1);
    }
    {
        let disk_cat = Catalog::open(&db_path).unwrap();
        assert_eq!(disk_cat.schema_version().unwrap(), 1);
    }
    {
        let conn = Connection::open(&db_path).unwrap();
        conn.execute("PRAGMA user_version = 99", []).unwrap();
    }
    let err = match Catalog::open(&db_path) {
        Ok(_) => panic!("expected error opening database with unsupported user_version"),
        Err(e) => e,
    };
    assert!(matches!(err, Error::Invalid(_)));
}

#[test]
fn catalog_meta_get_and_set() {
    let cat = Catalog::open_in_memory().unwrap();
    assert_eq!(cat.get_meta("nonexistent").unwrap(), None);

    cat.set_meta("custom_key", "custom_val").unwrap();
    assert_eq!(
        cat.get_meta("custom_key").unwrap().as_deref(),
        Some("custom_val")
    );

    cat.set_meta("custom_key", "updated_val").unwrap();
    assert_eq!(
        cat.get_meta("custom_key").unwrap().as_deref(),
        Some("updated_val")
    );
}

#[test]
fn rebuild_from_archive_records_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = test_archive(&tmp);
    archive
        .import_bytes(b"test1", test_source("f1", "1"))
        .unwrap();
    archive
        .import_bytes(b"test2", test_source("f2", "1"))
        .unwrap();

    let mut cat = Catalog::open_in_memory().unwrap();
    let count = cat.rebuild_from_archive(&archive).unwrap();
    assert_eq!(count, 2);

    let last_rebuild = cat.get_meta("last_rebuild_unix_ms").unwrap();
    assert!(last_rebuild.is_some());
    let ts: u64 = last_rebuild.unwrap().parse().unwrap();
    assert!(ts > 0);

    assert_eq!(cat.get_meta("rebuilt_count").unwrap().as_deref(), Some("2"));
    assert_eq!(
        cat.get_meta("oiaf_version").unwrap().as_deref(),
        Some(oiaf::FORMAT_VERSION)
    );
}

#[test]
fn rebuild_purges_stale_orphan_objects() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = test_archive(&tmp);
    let res = archive
        .import_bytes(b"valid", test_source("valid_file", "1"))
        .unwrap();

    let mut cat = Catalog::open_in_memory().unwrap();

    let orphan = CatalogObject {
        object_id: "orphan-id-12345".into(),
        blob_digest: "stale-blob-digest".into(),
        blob_size: 999,
        connector: "filesystem".into(),
        source_instance: "old".into(),
        external_id: "old_external".into(),
        revision: "1".into(),
        observed_time_unix_ms: 100,
        ingested_time_unix_ms: 100,
        ingest_fingerprint: None,
        media_type: None,
        suggested_domain: None,
    };
    cat.upsert_catalog_object(&orphan).unwrap();
    assert_eq!(cat.object_count().unwrap(), 1);
    assert!(cat.get_object("orphan-id-12345").unwrap().is_some());

    let count = cat.rebuild_from_archive(&archive).unwrap();
    assert_eq!(count, 1);
    assert_eq!(cat.object_count().unwrap(), 1);

    assert!(cat.get_object("orphan-id-12345").unwrap().is_none());
    assert!(cat.get_object(&res.envelope.object_id).unwrap().is_some());
}

#[test]
fn rebuild_transaction_rollback_preserves_prior_state_on_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = test_archive(&tmp);
    let res = archive
        .import_bytes(b"valid-init", test_source("init_file", "1"))
        .unwrap();

    let mut cat = Catalog::open_in_memory().unwrap();
    cat.rebuild_from_archive(&archive).unwrap();
    assert_eq!(cat.object_count().unwrap(), 1);

    let manifest_path = tmp.path().join("archive/manifest.json");
    std::fs::write(&manifest_path, b"corrupted non-json manifest").unwrap();

    let err = cat.rebuild_from_archive(&archive).unwrap_err();
    assert!(matches!(err, Error::Archive(_)));

    assert_eq!(cat.object_count().unwrap(), 1);
    assert!(cat.get_object(&res.envelope.object_id).unwrap().is_some());
}

#[test]
fn record_and_list_audit_events() {
    let cat = Catalog::open_in_memory().unwrap();
    assert!(cat.list_audit_events(10).unwrap().is_empty());

    let evt1 = AuditEvent {
        id: "evt-001".into(),
        event_type: "auth.login".into(),
        actor: "user-alice".into(),
        object_id: None,
        details_json: Some(r#"{"ip":"127.0.0.1"}"#.into()),
        created_unix_ms: 1000,
    };
    let evt2 = AuditEvent {
        id: "evt-002".into(),
        event_type: "archive.delete".into(),
        actor: "guard-session".into(),
        object_id: Some("obj-999".into()),
        details_json: None,
        created_unix_ms: 2000,
    };

    cat.record_audit_event(&evt1).unwrap();
    cat.record_audit_event(&evt2).unwrap();

    let events = cat.list_audit_events(10).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0], evt2);
    assert_eq!(events[1], evt1);
}

#[test]
fn audit_events_ordered_by_created_desc_and_bounded_by_limit() {
    let cat = Catalog::open_in_memory().unwrap();
    for (id, ts) in [("e1", 1000), ("e3", 3000), ("e2", 2000), ("e4", 4000)] {
        cat.record_audit_event(&AuditEvent {
            id: id.into(),
            event_type: "test".into(),
            actor: "actor".into(),
            object_id: None,
            details_json: None,
            created_unix_ms: ts,
        })
        .unwrap();
    }

    let all = cat.list_audit_events(10).unwrap();
    assert_eq!(all.len(), 4);
    assert_eq!(all[0].id, "e4");
    assert_eq!(all[1].id, "e3");
    assert_eq!(all[2].id, "e2");
    assert_eq!(all[3].id, "e1");

    let top2 = cat.list_audit_events(2).unwrap();
    assert_eq!(top2.len(), 2);
    assert_eq!(top2[0].id, "e4");
    assert_eq!(top2[1].id, "e3");
}

#[test]
fn audit_events_rejects_duplicate_id() {
    let cat = Catalog::open_in_memory().unwrap();
    let evt = AuditEvent {
        id: "duplicate-id".into(),
        event_type: "test".into(),
        actor: "actor".into(),
        object_id: None,
        details_json: None,
        created_unix_ms: 1000,
    };
    cat.record_audit_event(&evt).unwrap();
    assert!(cat.record_audit_event(&evt).is_err());
}

#[test]
fn audit_events_transaction_rollback_safety() {
    let mut cat = Catalog::open_in_memory().unwrap();
    let evt = AuditEvent {
        id: "tx-evt".into(),
        event_type: "test".into(),
        actor: "actor".into(),
        object_id: None,
        details_json: None,
        created_unix_ms: 1000,
    };

    {
        let tx = cat.conn.transaction().unwrap();
        tx.execute(
                "INSERT INTO audit_events (id, event_type, actor, object_id, details_json, created_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    evt.id,
                    evt.event_type,
                    evt.actor,
                    evt.object_id,
                    evt.details_json,
                    evt.created_unix_ms as i64,
                ],
            )
            .unwrap();
    }
    assert!(cat.list_audit_events(10).unwrap().is_empty());

    cat.record_audit_event(&evt).unwrap();
    assert_eq!(cat.list_audit_events(10).unwrap().len(), 1);
}

#[test]
fn rebuild_from_archive_preserves_audit_events() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = test_archive(&tmp);
    archive
        .import_bytes(b"data", test_source("f", "1"))
        .unwrap();

    let mut cat = Catalog::open_in_memory().unwrap();
    cat.record_audit_event(&AuditEvent {
        id: "preserve-evt".into(),
        event_type: "audit.test".into(),
        actor: "admin".into(),
        object_id: None,
        details_json: None,
        created_unix_ms: 5000,
    })
    .unwrap();

    cat.rebuild_from_archive(&archive).unwrap();
    let events = cat.list_audit_events(10).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].id, "preserve-evt");
}

// new tests
#[test]
fn list_objects_by_domain_and_count() {
    let cat = Catalog::open_in_memory().unwrap();
    let obj1 = CatalogObject {
        object_id: "obj-1".into(),
        blob_digest: "d1".into(),
        blob_size: 10,
        connector: "c1".into(),
        source_instance: "s1".into(),
        external_id: "e1".into(),
        revision: "r1".into(),
        observed_time_unix_ms: 100,
        ingested_time_unix_ms: 100,
        ingest_fingerprint: None,
        media_type: None,
        suggested_domain: Some("alpha".into()),
    };
    let obj2 = CatalogObject {
        object_id: "obj-2".into(),
        blob_digest: "d2".into(),
        blob_size: 20,
        connector: "c2".into(),
        source_instance: "s2".into(),
        external_id: "e2".into(),
        revision: "r2".into(),
        observed_time_unix_ms: 200,
        ingested_time_unix_ms: 200,
        ingest_fingerprint: None,
        media_type: None,
        suggested_domain: Some("beta".into()),
    };
    let obj3 = CatalogObject {
        object_id: "obj-3".into(),
        blob_digest: "d3".into(),
        blob_size: 30,
        connector: "c3".into(),
        source_instance: "s3".into(),
        external_id: "e3".into(),
        revision: "r3".into(),
        observed_time_unix_ms: 300,
        ingested_time_unix_ms: 300,
        ingest_fingerprint: None,
        media_type: None,
        suggested_domain: Some("alpha".into()),
    };
    cat.upsert_catalog_object(&obj1).unwrap();
    cat.upsert_catalog_object(&obj2).unwrap();
    cat.upsert_catalog_object(&obj3).unwrap();

    let alpha_objs = cat.list_objects_by_domain("alpha").unwrap();
    assert_eq!(alpha_objs.len(), 2);
    assert_eq!(alpha_objs[0].object_id, "obj-1");
    assert_eq!(alpha_objs[1].object_id, "obj-3");

    let beta_objs = cat.list_objects_by_domain("beta").unwrap();
    assert_eq!(beta_objs.len(), 1);
    assert_eq!(beta_objs[0].object_id, "obj-2");

    assert_eq!(cat.domain_object_count("alpha").unwrap(), 2);
    assert_eq!(cat.domain_object_count("beta").unwrap(), 1);
    assert_eq!(cat.domain_object_count("gamma").unwrap(), 0);
}

#[test]
fn rebuild_preserves_domain_indexing() {
    let mut cat = Catalog::open_in_memory().unwrap();
    let foo = "foo";
    let obj = CatalogObject {
        object_id: "obj-1".into(),
        blob_digest: "d1".into(),
        blob_size: 10,
        connector: "c1".into(),
        source_instance: "s1".into(),
        external_id: "e1".into(),
        revision: "r1".into(),
        observed_time_unix_ms: 100,
        ingested_time_unix_ms: 100,
        ingest_fingerprint: None,
        media_type: None,
        suggested_domain: Some(foo.into()),
    };
    cat.upsert_catalog_object(&obj).unwrap();

    let tmp = tempfile::tempdir().unwrap();
    let archive = test_archive(&tmp);
    let env = archive
        .import_bytes(b"obj-1", test_source("file", "1"))
        .unwrap();
    cat.rebuild_from_archive(&archive).unwrap();
    cat.set_suggested_domain(&env.envelope.object_id, Some(foo))
        .unwrap();
    cat.rebuild_from_archive(&archive).unwrap();
    let domain_objs = cat.list_objects_by_domain(foo).unwrap();
    assert_eq!(domain_objs.len(), 1);
    assert_eq!(cat.domain_object_count(foo).unwrap(), 1);
    assert_eq!(cat.object_count().unwrap(), 1);
}

#[test]
fn provision_owner_credentials_fresh_and_legacy_predicates() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("catalog.sqlite");

    // 1. Fresh install on empty catalog
    let mut cat = Catalog::open(&db_path).unwrap();
    let fresh_cfg = FreshSetupConfig {
        archive_path: "/data/archive/store".into(),
        backup_path: Some("/data/backups".into()),
    };
    let committed = cat
        .provision_owner_credentials(
            OwnerProvisionMode::Fresh,
            "verifier_hash_1",
            Some(&fresh_cfg),
            1000,
        )
        .unwrap();
    assert!(committed);
    assert_eq!(
        cat.get_meta("setup.owner_verifier").unwrap().as_deref(),
        Some("verifier_hash_1")
    );
    assert_eq!(
        cat.get_meta("setup.owner_auth_version").unwrap().as_deref(),
        Some("1")
    );
    assert_eq!(
        cat.get_meta("setup.admin_provisioned").unwrap().as_deref(),
        Some("true")
    );
    assert_eq!(
        cat.get_meta("setup.prepared_unix_ms").unwrap().as_deref(),
        Some("1000")
    );
    assert_eq!(
        cat.get_meta("setup.completed_unix_ms").unwrap().as_deref(),
        Some("1000")
    );
    assert_eq!(
        cat.get_meta("setup.archive_path").unwrap().as_deref(),
        Some("/data/archive/store")
    );
    assert_eq!(
        cat.get_meta("setup.backup_path").unwrap().as_deref(),
        Some("/data/backups")
    );

    // Replay of fresh is rejected
    let replay = cat
        .provision_owner_credentials(
            OwnerProvisionMode::Fresh,
            "verifier_hash_2",
            Some(&fresh_cfg),
            2000,
        )
        .unwrap();
    assert!(!replay);

    // Claim on already-configured catalog is rejected
    let claim_attempt = cat
        .provision_owner_credentials(
            OwnerProvisionMode::LegacyClaim,
            "verifier_hash_3",
            None,
            3000,
        )
        .unwrap();
    assert!(!claim_attempt);
}

#[test]
fn legacy_admin_only_accepted_and_fresh_denied_preserves_data() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("catalog.sqlite");
    let mut cat = Catalog::open(&db_path).unwrap();

    // Simulate legacy unmigrated state (e.g. from prior login before setup was run)
    cat.set_meta("setup.admin_provisioned", "true").unwrap();
    cat.set_meta("setup.archive_path", "/legacy/archive")
        .unwrap();

    // Also add an object to verify preservation
    let obj = CatalogObject {
        object_id: "legacy-obj".into(),
        blob_digest: "digest123".into(),
        blob_size: 42,
        connector: "filesystem".into(),
        source_instance: "local".into(),
        external_id: "ext1".into(),
        revision: "1".into(),
        observed_time_unix_ms: 500,
        ingested_time_unix_ms: 500,
        ingest_fingerprint: None,
        media_type: None,
        suggested_domain: None,
    };
    cat.upsert_catalog_object(&obj).unwrap();

    // Fresh mode must be DENIED because legacy admin marker is present
    let fresh_cfg = FreshSetupConfig {
        archive_path: "/fresh/archive".into(),
        backup_path: None,
    };
    let fresh_res = cat
        .provision_owner_credentials(
            OwnerProvisionMode::Fresh,
            "fresh_verifier",
            Some(&fresh_cfg),
            1000,
        )
        .unwrap();
    assert!(!fresh_res);
    assert_eq!(
        cat.get_meta("setup.archive_path").unwrap().as_deref(),
        Some("/legacy/archive")
    );

    // Legacy claim mode must SUCCEED and preserve archive_path and catalog rows
    let claim_res = cat
        .provision_owner_credentials(
            OwnerProvisionMode::LegacyClaim,
            "claimed_verifier",
            None,
            1100,
        )
        .unwrap();
    assert!(claim_res);
    assert_eq!(
        cat.get_meta("setup.owner_verifier").unwrap().as_deref(),
        Some("claimed_verifier")
    );
    assert_eq!(
        cat.get_meta("setup.owner_auth_version").unwrap().as_deref(),
        Some("1")
    );
    assert_eq!(
        cat.get_meta("setup.archive_path").unwrap().as_deref(),
        Some("/legacy/archive")
    );
    assert_eq!(
        cat.get_object("legacy-obj").unwrap().unwrap().object_id,
        "legacy-obj"
    );
}

#[test]
fn two_connection_race_first_writer_wins_loser_cannot_alter_config() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("catalog.sqlite");

    // Initialize schema first so both threads connect to initialized catalog
    {
        let _init = Catalog::open(&db_path).unwrap();
    }

    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));

    let db_path_a = db_path.clone();
    let barrier_a = barrier.clone();
    let handle_a = std::thread::spawn(move || {
        let mut conn_a = Catalog::open(&db_path_a).unwrap();
        let cfg_a = FreshSetupConfig {
            archive_path: "/archive/A".into(),
            backup_path: Some("/backup/A".into()),
        };
        barrier_a.wait();
        conn_a.provision_owner_credentials(
            OwnerProvisionMode::Fresh,
            "verifier_A",
            Some(&cfg_a),
            1000,
        )
    });

    let db_path_b = db_path.clone();
    let barrier_b = barrier.clone();
    let handle_b = std::thread::spawn(move || {
        let mut conn_b = Catalog::open(&db_path_b).unwrap();
        let cfg_b = FreshSetupConfig {
            archive_path: "/archive/B".into(),
            backup_path: Some("/backup/B".into()),
        };
        barrier_b.wait();
        conn_b.provision_owner_credentials(
            OwnerProvisionMode::Fresh,
            "verifier_B",
            Some(&cfg_b),
            1001,
        )
    });

    let res_a = handle_a.join().unwrap();
    let res_b = handle_b.join().unwrap();

    // Exactly one commits successfully; the other conflicts (returns Ok(false) or locked Err which fails closed)
    let success_a = res_a.as_ref().copied().unwrap_or(false);
    let success_b = res_b.as_ref().copied().unwrap_or(false);
    assert_ne!(
        success_a, success_b,
        "exactly one concurrent connection must commit"
    );

    let reader = Catalog::open(&db_path).unwrap();
    let committed_verifier = reader.get_meta("setup.owner_verifier").unwrap().unwrap();
    let committed_archive = reader.get_meta("setup.archive_path").unwrap().unwrap();
    let committed_backup = reader.get_meta("setup.backup_path").unwrap().unwrap();

    if success_a {
        assert_eq!(committed_verifier, "verifier_A");
        assert_eq!(committed_archive, "/archive/A");
        assert_eq!(committed_backup, "/backup/A");
    } else {
        assert_eq!(committed_verifier, "verifier_B");
        assert_eq!(committed_archive, "/archive/B");
        assert_eq!(committed_backup, "/backup/B");
    }
}

#[test]
fn fresh_setup_with_no_backup_deletes_stale_backup_path() {
    let temp = tempfile::tempdir().unwrap();
    let db_path = temp.path().join("catalog.sqlite");
    let mut cat = Catalog::open(&db_path).unwrap();

    // Simulate stale backup_path from prior aborted state
    cat.set_meta("setup.backup_path", "/stale/legacy/backup")
        .unwrap();

    // Add a catalog object to verify catalog data remains completely intact
    let obj = CatalogObject {
        object_id: "intact-object".into(),
        blob_digest: "sha256:intact".into(),
        blob_size: 42,
        connector: "fs".into(),
        source_instance: "local".into(),
        external_id: "ext-1".into(),
        revision: "rev-1".into(),
        observed_time_unix_ms: 100,
        ingested_time_unix_ms: 200,
        ingest_fingerprint: None,
        media_type: None,
        suggested_domain: None,
    };
    cat.upsert_catalog_object(&obj).unwrap();

    // Fresh setup selecting NO backup path (backup_path: None)
    let cfg = FreshSetupConfig {
        archive_path: "/fresh/archive/target".into(),
        backup_path: None,
    };
    let committed = cat
        .provision_owner_credentials(
            OwnerProvisionMode::Fresh,
            "verifier_fresh",
            Some(&cfg),
            2000,
        )
        .unwrap();
    assert!(committed);

    // Stale backup_path is strictly absent
    assert!(cat.get_meta("setup.backup_path").unwrap().is_none());
    assert_eq!(
        cat.get_meta("setup.archive_path").unwrap().as_deref(),
        Some("/fresh/archive/target")
    );
    assert_eq!(
        cat.get_meta("setup.owner_verifier").unwrap().as_deref(),
        Some("verifier_fresh")
    );

    // Catalog data preserved
    assert_eq!(
        cat.get_object("intact-object").unwrap().unwrap().object_id,
        "intact-object"
    );
}
