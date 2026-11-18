use super::*;
use sc_storage::CatalogObject;

fn setup_mock_catalog() -> Catalog {
    let cat = Catalog::open_in_memory().unwrap();
    cat.upsert_catalog_object(&CatalogObject {
        object_id: "obj-100".into(),
        blob_digest: "digest-100".into(),
        blob_size: 4096,
        connector: "filesystem".into(),
        source_instance: "node1".into(),
        external_id: "doc1.pdf".into(),
        revision: "rev1".into(),
        observed_time_unix_ms: 1000,
        ingested_time_unix_ms: 1000,
        ingest_fingerprint: Some("fp-100".into()),
        media_type: Some("application/pdf".into()),
        suggested_domain: Some("private".into()),
    })
    .unwrap();
    cat
}

#[test]
fn state_transition_validation_dry_run_to_cancelled_vs_confirmed() {
    let cat = setup_mock_catalog();
    let op = GuardedOperation::DeleteCanonical {
        object_ids: vec!["obj-100".into()],
    };

    // Path A: Requested -> DryRunReady -> Cancelled
    let mut session_cancel = GuardSession::new("sess-1", op.clone());
    assert_eq!(session_cancel.state, GuardState::Requested);
    let report = session_cancel.run_impact_analysis(&cat, true).unwrap();
    assert_eq!(report.affected_objects, 1);
    assert_eq!(report.affected_bytes, 4096);
    assert_eq!(session_cancel.state, GuardState::DryRunReady);

    session_cancel.cancel().unwrap();
    assert_eq!(session_cancel.state, GuardState::Cancelled);

    // Path B: Requested -> DryRunReady -> Confirmed -> Quarantine -> Committed
    let mut session_confirm = GuardSession::new("sess-2", op);
    session_confirm.run_impact_analysis(&cat, true).unwrap();
    session_confirm
        .confirm_step_up("CONFIRM DESTRUCTIVE OPERATION", false)
        .unwrap();
    assert_eq!(session_confirm.state, GuardState::ExplicitConfirmation);

    session_confirm.enter_quarantine(60_000, 1_000_000).unwrap();
    assert_eq!(session_confirm.state, GuardState::QuarantineDelay);

    // Commit fails while quarantine is active
    assert!(session_confirm.commit(1_030_000).is_err());

    // Commit succeeds after quarantine window elapses
    session_confirm.commit(1_070_000).unwrap();
    assert_eq!(session_confirm.state, GuardState::Committed);
}

#[test]
fn unverified_backup_blocks_destructive_commit_without_override() {
    let cat = setup_mock_catalog();
    let op = GuardedOperation::DeleteCanonical {
        object_ids: vec!["obj-100".into()],
    };

    let mut session = GuardSession::new("sess-nobackup", op);
    let report = session.run_impact_analysis(&cat, false).unwrap();
    assert!(!report.has_verified_backup);

    // Confirm fails without override
    let err = session
        .confirm_step_up("CONFIRM DESTRUCTIVE OPERATION", false)
        .unwrap_err();
    assert!(matches!(err, Error::BackupRequirementUnmet(_)));

    // Confirm succeeds with explicit override
    session
        .confirm_step_up("CONFIRM DESTRUCTIVE OPERATION", true)
        .unwrap();
    assert_eq!(session.state, GuardState::ExplicitConfirmation);
}

#[test]
fn guard_execution_without_ai_dependencies() {
    let cat = setup_mock_catalog();
    let op = GuardedOperation::DestroyKey;

    let mut session = GuardSession::new("sess-no-ai", op);
    let impact = session.run_impact_analysis(&cat, true).unwrap();

    assert!(!impact.is_reversible);
    assert!(
        impact
            .warnings
            .iter()
            .any(|w| w.contains("Destroying master vault keys"))
    );
}

#[test]
fn quarantine_undo_transitions_to_restored() {
    let cat = setup_mock_catalog();
    let mut session = GuardSession::new("sess-undo", GuardedOperation::PurgeSnapshots);
    session.run_impact_analysis(&cat, true).unwrap();
    session
        .confirm_step_up("CONFIRM DESTRUCTIVE OPERATION", false)
        .unwrap();
    session.enter_quarantine(100_000, 1_000).unwrap();

    session.restore_from_quarantine().unwrap();
    assert_eq!(session.state, GuardState::Restored);
}

#[test]
fn policy_scope_verification_enforces_destructive_scope() {
    assert!(GuardSession::verify_policy_scope(&[]).is_err());
    assert!(GuardSession::verify_policy_scope(&[sc_policy::Scope::ArchiveRead]).is_err());
    assert!(GuardSession::verify_policy_scope(&[sc_policy::Scope::ArchiveDestructive]).is_ok());
}

#[test]
fn unknown_object_id_records_warning_and_real_checkpoint_preserved() {
    let cat = setup_mock_catalog();
    let op = GuardedOperation::DeleteCanonical {
        object_ids: vec!["obj-100".into(), "obj-unknown-999".into()],
    };

    let mut session = GuardSession::new("sess-unknown-check", op);
    let impact = session
        .run_impact_analysis_with_backup(&cat, true, Some(1_700_555_000_000))
        .unwrap();

    assert_eq!(impact.affected_objects, 1);
    assert_eq!(impact.affected_bytes, 4096);
    assert_eq!(impact.backup_checkpoint_timestamp, Some(1_700_555_000_000));
    assert!(
        impact
            .warnings
            .iter()
            .any(|w| w.contains("obj-unknown-999") && w.contains("undercounted"))
    );
}
