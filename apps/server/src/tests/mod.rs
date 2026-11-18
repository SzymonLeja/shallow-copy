use super::*;
use axum::Router;
use axum::body::Body;
use axum::http::Request;
use oiaf::BackupManifest;
use sc_policy::{ArchiveDomain, Scope};
use sc_preservation_guard::GuardState;
use sc_storage::Catalog;
use tower::ServiceExt;

fn setup_test_state_unprovisioned() -> (AppState, tempfile::TempDir) {
    let temp = tempfile::tempdir().unwrap();
    let archive_path = temp.path().join("archive");
    let archive = Archive::init(&archive_path).unwrap();

    let source = oiaf::Source::filesystem("node-test", "note.txt", "rev-1");
    archive.import_bytes(b"hello world", source).unwrap();

    let mut catalog = Catalog::open_in_memory().unwrap();
    catalog.rebuild_from_archive(&archive).unwrap();

    let state = AppState::new(catalog, archive);
    (state, temp)
}

fn setup_test_state() -> (AppState, tempfile::TempDir) {
    let (state, temp) = setup_test_state_unprovisioned();
    let envelope = sc_crypto::seal(b"secret-passphrase", OWNER_VERIFIER_SENTINEL).unwrap();
    let verifier_json = serde_json::to_string(&envelope).unwrap();
    state
        .catalog
        .lock()
        .unwrap()
        .set_meta("setup.owner_verifier", &verifier_json)
        .unwrap();
    state
        .catalog
        .lock()
        .unwrap()
        .set_meta("setup.owner_auth_version", "1")
        .unwrap();
    state
        .catalog
        .lock()
        .unwrap()
        .set_meta("setup.admin_provisioned", "true")
        .unwrap();
    state
        .catalog
        .lock()
        .unwrap()
        .set_meta("setup.completed_unix_ms", "1000")
        .unwrap();
    state.setup_state.lock().unwrap().admin_provisioned = true;
    state.setup_state.lock().unwrap().completed_unix_ms = Some(1000);
    (state, temp)
}

fn setup_test_app() -> (Router, tempfile::TempDir) {
    let (state, temp) = setup_test_state();
    let router = create_router(state);
    (router, temp)
}

fn setup_test_app_with_session(session: SessionToken) -> (Router, tempfile::TempDir) {
    let (state, temp) = setup_test_state();
    state.auth_tokens.lock().unwrap().push(session);
    (create_router(state), temp)
}

async fn login_token(app: &Router, device_id: &str) -> String {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/session")
                .header("content-type", "application/json")
                .header("x-device-id", device_id)
                .body(Body::from(r#"{"password":"secret-passphrase"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice::<SessionToken>(&body).unwrap().token
}

#[tokio::test]
async fn health_endpoint_reports_ready() {
    let (app, _temp) = setup_test_app();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn object_listing_and_provenance_endpoint() {
    let (app, _temp) = setup_test_app();
    let token = login_token(&app, "test-device").await;

    // 1. List objects
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/archive/objects")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "test-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let list: ObjectListResponse = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(list.items.len(), 1);
    let object_id = list.items[0].object_id.clone();

    // 2. Get object provenance
    let response = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/archive/objects/{object_id}"))
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "test-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let obj: SourceObject = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(obj.object_id, object_id);
    assert_eq!(obj.blob_size, 11);
    assert_eq!(obj.connector_id, "filesystem");
}

#[tokio::test]
async fn job_trigger_and_retrieval() {
    let (app, _temp) = setup_test_app();
    let token = login_token(&app, "test-device").await;

    // 1. Trigger verification job
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/verify")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "test-device")
                .body(Body::from(r#"{"full": true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let job: ApiJob = serde_json::from_slice(&body_bytes).unwrap();
    assert_eq!(job.kind, "verify");
    let job_id = job.job_id;

    // 2. Retrieve job by id
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/jobs/{job_id}"))
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "test-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 3. List all jobs
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/jobs")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "test-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn auth_session_lifecycle() {
    let (app, _temp) = setup_test_app();

    // 1. Login
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/session")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password": "secret-passphrase"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body_bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let session: SessionToken = serde_json::from_slice(&body_bytes).unwrap();
    assert!(session.token.starts_with("sess_"));
    assert_eq!(session.device_id, "local-device");
    assert!(session.scopes.contains(&Scope::ArchiveRead));

    // 2. Logout
    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/auth/session")
                .header("authorization", format!("Bearer {}", session.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn protected_routes_require_scoped_session_and_logout_revokes_token() {
    let (app, _temp) = setup_test_app();

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/archive/objects")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/archive/objects")
                .header("authorization", "Bearer invalid")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/session")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let device_id = "auth-test-device";
    let token = login_token(&app, device_id).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/archive/objects")
                .header("authorization", "Bearer expired")
                .header("x-device-id", device_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/archive/objects")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", device_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/auth/session")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", device_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/archive/objects")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", device_id)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn expired_session_token_is_rejected() {
    let (app, _temp) = setup_test_app_with_session(SessionToken {
        token: "expired-token".into(),
        device_id: "expired-device".into(),
        scopes: vec![Scope::ArchiveRead],
        expires_at: "1970-01-01T00:00:00Z".into(),
    });

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/archive/objects")
                .header("authorization", "Bearer expired-token")
                .header("x-device-id", "expired-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn filesystem_ingest_imports_indexes_retries_and_rejects_traversal() {
    let (mut state, temp) = setup_test_state();
    let source_root = temp.path().join("source");
    std::fs::create_dir_all(source_root.join("notes")).unwrap();
    std::fs::write(source_root.join("notes/note.txt"), b"filesystem payload").unwrap();
    std::fs::write(temp.path().join("outside.txt"), b"outside payload").unwrap();
    state.filesystem_ingest_root = Some(source_root);
    let catalog = state.catalog.clone();
    let app = create_router(state.clone());
    let token = login_token(&app, "ingest-device").await;

    let ingest_request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/archive/ingest/filesystem")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .header("x-device-id", "ingest-device")
            .body(Body::from(r#"{"path":"notes/note.txt"}"#))
            .unwrap()
    };
    let response = app.clone().oneshot(ingest_request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let first: FilesystemIngestResponse = serde_json::from_slice(&body).unwrap();
    assert!(first.created);
    assert_eq!(catalog.lock().unwrap().object_count().unwrap(), 2);

    let response = app.clone().oneshot(ingest_request()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let retry: FilesystemIngestResponse = serde_json::from_slice(&body).unwrap();
    assert!(!retry.created);
    assert_eq!(retry.object_id, first.object_id);
    assert_eq!(retry.ingest_fingerprint, first.ingest_fingerprint);
    assert_eq!(catalog.lock().unwrap().object_count().unwrap(), 2);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/archive/objects/{}", first.object_id))
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "ingest-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let object: SourceObject = serde_json::from_slice(&body).unwrap();
    assert_eq!(object.object_id, first.object_id);
    assert_eq!(object.connector_id, "filesystem");
    assert_eq!(object.external_id, "notes/note.txt");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/ingest/filesystem")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "ingest-device")
                .body(Body::from(r#"{"path":"../outside.txt"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(catalog.lock().unwrap().object_count().unwrap(), 2);
}

#[tokio::test]
async fn guarded_delete_analyzes_catalog_and_requires_step_up_token() {
    let (state, _temp) = setup_test_state();
    let object_id = state.catalog.lock().unwrap().list_objects().unwrap()[0]
        .object_id
        .clone();
    let app = create_router(state);
    let token = login_token(&app, "guard-device").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/guard/analyze")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "guard-device")
                .body(Body::from(
                    serde_json::json!({ "objectIds": [object_id] }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let analysis: GuardAnalyzeResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(analysis.impact.affected_objects, 1);
    assert_eq!(analysis.impact.affected_bytes, 11);
    assert!(!analysis.impact.is_reversible);

    let action_request = |confirmation_token: &str| {
        Request::builder()
            .method("POST")
            .uri("/v1/archive/guard/action")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .header("x-device-id", "guard-device")
            .body(Body::from(
                serde_json::json!({
                    "sessionId": analysis.session_id,
                    "confirmationToken": confirmation_token,
                    "typedConfirmation": "CONFIRM DESTRUCTIVE OPERATION",
                    "allowUnverifiedBackupOverride": true
                })
                .to_string(),
            ))
            .unwrap()
    };
    let response = app
        .clone()
        .oneshot(action_request("invalid-token"))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    let response = app
        .clone()
        .oneshot(action_request(&analysis.confirmation_token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let action: GuardActionResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(action.state, GuardState::QuarantineDelay);
    assert!(action.step_up_confirmed);
    assert!(action.quarantine_deadline_unix_ms.is_some());

    let response = app
        .oneshot(action_request(&analysis.confirmation_token))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn audit_endpoint_enforces_scope_and_retrieves_descending_events() {
    let (mut state, temp) = setup_test_state();

    // 1. Unauthorized when no bearer token is present
    let app = create_router(state.clone());
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/archive/audit")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 2. Unauthorized when token lacks Scope::ArchiveRead
    let write_only_session = SessionToken {
        token: "write-only-token".into(),
        device_id: "test-device".into(),
        scopes: vec![Scope::ArchiveWrite],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    };
    state.auth_tokens.lock().unwrap().push(write_only_session);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/archive/audit")
                .header("authorization", "Bearer write-only-token")
                .header("x-device-id", "test-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 3. Authorized request with ArchiveRead
    let read_token = login_token(&app, "audit-device").await;

    // Record events directly into catalog with distinct timestamps
    {
        let catalog = state.catalog.lock().unwrap();
        let evt1 = AuditEvent {
            id: "audit-test-1".into(),
            event_type: "ingest".into(),
            actor: "audit-device".into(),
            object_id: Some("obj-1".into()),
            details_json: Some(r#"{"seq":1}"#.into()),
            created_unix_ms: 10_000,
        };
        let evt2 = AuditEvent {
            id: "audit-test-2".into(),
            event_type: "guard_action".into(),
            actor: "audit-device".into(),
            object_id: Some("obj-2".into()),
            details_json: Some(r#"{"seq":2}"#.into()),
            created_unix_ms: 20_000,
        };
        let evt3 = AuditEvent {
            id: "audit-test-3".into(),
            event_type: "ingest".into(),
            actor: "audit-device".into(),
            object_id: Some("obj-3".into()),
            details_json: Some(r#"{"seq":3}"#.into()),
            created_unix_ms: 30_000,
        };
        catalog.record_audit_event(&evt1).unwrap();
        catalog.record_audit_event(&evt2).unwrap();
        catalog.record_audit_event(&evt3).unwrap();
    }

    // 4. Retrieve all events and verify DESC ordering
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/archive/audit")
                .header("authorization", format!("Bearer {read_token}"))
                .header("x-device-id", "audit-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let events: Vec<AuditEvent> = serde_json::from_slice(&body).unwrap();
    assert!(events.len() >= 3);
    assert_eq!(events[0].id, "audit-test-3");
    assert_eq!(events[1].id, "audit-test-2");
    assert_eq!(events[2].id, "audit-test-1");
    assert!(events[0].created_unix_ms > events[1].created_unix_ms);
    assert!(events[1].created_unix_ms > events[2].created_unix_ms);

    // 5. Query limit parameter
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/archive/audit?limit=2")
                .header("authorization", format!("Bearer {read_token}"))
                .header("x-device-id", "audit-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let limited_events: Vec<AuditEvent> = serde_json::from_slice(&body).unwrap();
    assert_eq!(limited_events.len(), 2);
    assert_eq!(limited_events[0].id, "audit-test-3");
    assert_eq!(limited_events[1].id, "audit-test-2");

    // 6. Test ingest_filesystem_file records an 'ingest' event
    let source_root = temp.path().join("source_audit");
    std::fs::create_dir_all(&source_root).unwrap();
    std::fs::write(source_root.join("audit.txt"), b"audit content").unwrap();
    state.filesystem_ingest_root = Some(source_root);
    let app = create_router(state);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/ingest/filesystem")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {read_token}"))
                .header("x-device-id", "audit-device")
                .body(Body::from(r#"{"path":"audit.txt"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/archive/audit?limit=1")
                .header("authorization", format!("Bearer {read_token}"))
                .header("x-device-id", "audit-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let newest: Vec<AuditEvent> = serde_json::from_slice(&body).unwrap();
    assert_eq!(newest.len(), 1);
    assert_eq!(newest[0].event_type, "ingest");
}

#[tokio::test]
async fn backup_manifest_lifecycle_requires_auth_and_proves_generate_verify() {
    let (state, _temp) = setup_test_state();
    let app = create_router(state.clone());

    // 1. Missing auth header rejected on both generate and verify
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/backup-manifest/generate")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/backup-manifest/verify")
                .header("content-type", "application/json")
                .body(Body::from(r#"{}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 2. Invalid or expired bearer token rejected
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/backup-manifest/generate")
                .header("authorization", "Bearer invalid-or-nonexistent-token")
                .header("x-device-id", "test-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 3. Token with insufficient scope: read-only token on POST route
    let read_only_session = SessionToken {
        token: "read-only-session-token".into(),
        device_id: "test-device".into(),
        scopes: vec![Scope::ArchiveRead],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    };
    state.auth_tokens.lock().unwrap().push(read_only_session);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/backup-manifest/generate")
                .header("authorization", "Bearer read-only-session-token")
                .header("x-device-id", "test-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // However, GET /v1/archive/backup-manifest succeeds with Scope::ArchiveRead
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/archive/backup-manifest")
                .header("authorization", "Bearer read-only-session-token")
                .header("x-device-id", "test-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 4. Valid authenticated session (with ArchiveWrite) generates backup manifest
    let valid_token = login_token(&app, "manifest-device").await;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/backup-manifest/generate")
                .header("authorization", format!("Bearer {valid_token}"))
                .header("x-device-id", "manifest-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let manifest: BackupManifest = serde_json::from_slice(&body).unwrap();
    assert_eq!(manifest.oiaf_version, oiaf::FORMAT_VERSION);
    assert_eq!(manifest.total_objects, 1);
    assert!(!manifest.root_manifest_hash.is_empty());

    // 5. Valid session verifies untampered manifest -> valid: true
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/backup-manifest/verify")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {valid_token}"))
                .header("x-device-id", "manifest-device")
                .body(Body::from(serde_json::to_vec(&manifest).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let verify_res: BackupManifestVerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(verify_res.valid);

    // 6. Valid session verifies tampered manifest -> valid: false
    let mut tampered = manifest.clone();
    tampered.root_manifest_hash = "0".repeat(64);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/backup-manifest/verify")
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {valid_token}"))
                .header("x-device-id", "manifest-device")
                .body(Body::from(serde_json::to_vec(&tampered).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let verify_res: BackupManifestVerifyResponse = serde_json::from_slice(&body).unwrap();
    assert!(!verify_res.valid);
}

#[tokio::test]
async fn backup_or_recovery_drill_requires_auth_and_proves_execution() {
    let (state, _temp) = setup_test_state();
    let app = create_router(state.clone());

    // 1. Missing auth header rejected
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/recovery/drill")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 2. Invalid or expired bearer token rejected
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/recovery/drill")
                .header("authorization", "Bearer invalid-or-nonexistent-token")
                .header("x-device-id", "drill-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 3. Token lacking Scope::ArchiveRead rejected
    let invalid_scope_session = SessionToken {
        token: "invalid-scope-token".into(),
        device_id: "drill-device".into(),
        scopes: vec![Scope::ArchiveDestructive],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    };
    state
        .auth_tokens
        .lock()
        .unwrap()
        .push(invalid_scope_session);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/recovery/drill")
                .header("authorization", "Bearer invalid-scope-token")
                .header("x-device-id", "drill-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 4. Valid session with Scope::ArchiveRead executes drill successfully
    let valid_read_session = SessionToken {
        token: "valid-read-token".into(),
        device_id: "drill-device".into(),
        scopes: vec![Scope::ArchiveRead],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    };
    state.auth_tokens.lock().unwrap().push(valid_read_session);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/recovery/drill")
                .header("authorization", "Bearer valid-read-token")
                .header("x-device-id", "drill-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let drill_res: RecoveryDrillResponse = serde_json::from_slice(&body).unwrap();
    assert!(drill_res.success);
    assert_eq!(drill_res.objects_tested, 1);
}

#[tokio::test]
async fn system_readiness_requires_auth_and_reports_status() {
    let (mut state, temp) = setup_test_state();

    // Configure filesystem ingest root
    let source_root = temp.path().join("source");
    std::fs::create_dir_all(&source_root).unwrap();
    state.filesystem_ingest_root = Some(source_root);

    // Insert 1 pending job and 1 failed job
    {
        let catalog = state.catalog.lock().unwrap();
        let pending_job = CatalogJob {
            job_id: "job-pending-1".into(),
            kind: "export".into(),
            status: JobStatus::Pending,
            progress_pct: Some(0),
            created_at_unix_ms: 1000,
            updated_at_unix_ms: 1000,
            error: None,
        };
        let failed_job = CatalogJob {
            job_id: "job-failed-1".into(),
            kind: "verify".into(),
            status: JobStatus::Failed,
            progress_pct: None,
            created_at_unix_ms: 2000,
            updated_at_unix_ms: 2000,
            error: Some("verification error".into()),
        };
        catalog.insert_job(&pending_job).unwrap();
        catalog.insert_job(&failed_job).unwrap();
    }

    let app = create_router(state.clone());

    // 1. Missing auth header rejected
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/system/readiness")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 2. Invalid bearer token rejected
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/system/readiness")
                .header("authorization", "Bearer invalid-token")
                .header("x-device-id", "readiness-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 3. Token lacking Scope::ArchiveRead rejected
    let invalid_scope_session = SessionToken {
        token: "invalid-scope-token".into(),
        device_id: "readiness-device".into(),
        scopes: vec![Scope::ArchiveDestructive],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    };
    state
        .auth_tokens
        .lock()
        .unwrap()
        .push(invalid_scope_session);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/system/readiness")
                .header("authorization", "Bearer invalid-scope-token")
                .header("x-device-id", "readiness-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 4. Valid session with Scope::ArchiveRead succeeds and reports aggregated metrics
    let valid_session = SessionToken {
        token: "valid-read-token".into(),
        device_id: "readiness-device".into(),
        scopes: vec![Scope::ArchiveRead],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    };
    state.auth_tokens.lock().unwrap().push(valid_session);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/system/readiness")
                .header("authorization", "Bearer valid-read-token")
                .header("x-device-id", "readiness-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let readiness: SystemReadinessResponse = serde_json::from_slice(&body).unwrap();
    assert!(readiness.archive_ready);
    assert_eq!(readiness.object_count, 1);
    assert_eq!(readiness.pending_jobs, 1);
    assert_eq!(readiness.failed_jobs, 1);
    assert!(readiness.filesystem_ingest_available);
}

#[tokio::test]
async fn static_assets_and_spa_fallback_serve_web_app_and_preserve_v1_semantics() {
    let (state, temp) = setup_test_state();

    // Create a test static directory with index.html and dist/index.js
    let static_dir = temp.path().join("static_web");
    let dist_dir = static_dir.join("dist");
    std::fs::create_dir_all(&dist_dir).unwrap();
    std::fs::write(
        static_dir.join("index.html"),
        b"<!DOCTYPE html><html><body>Test Web App</body></html>",
    )
    .unwrap();
    std::fs::write(dist_dir.join("index.js"), b"console.log('test bundle');").unwrap();

    let mut test_state = state.clone();
    test_state.static_dir = Some(static_dir);
    let app = create_router(test_state);

    // 1. Root path "/" returns index.html (200 OK)
    let response = app
        .clone()
        .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("Test Web App"));

    // 2. Specific file "/dist/index.js" returns the javascript asset (200 OK)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dist/index.js")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("test bundle"));

    // 3. SPA client-side route "/dashboard" falls back to index.html (200 OK)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/dashboard")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert!(String::from_utf8_lossy(&body).contains("Test Web App"));

    // 4. Unknown "/v1/*" path preserves API semantics and returns 404 (NOT index.html)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/unknown-endpoint")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert!(!String::from_utf8_lossy(&body).contains("Test Web App"));

    // 5. /health still returns "ok" (200 OK)
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    assert_eq!(&body[..], b"ok");
}

#[tokio::test]
async fn browser_history_ingest_requires_auth_and_archive_write_scope() {
    let (state, temp) = setup_test_state();
    let db_path = temp.path().join("History");
    sc_connector_browser_chromium::create_mock_history_db(&db_path).unwrap();

    let mut test_state = state.clone();
    test_state.browser_history_path = Some(db_path);
    let app = create_router(test_state.clone());

    // 1. Missing Authorization header -> 401 Unauthorized
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/ingest/browser-history")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 2. Bogus token -> 401 Unauthorized
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/ingest/browser-history")
                .header("authorization", "Bearer bogus-token")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 3. Token with only ArchiveRead scope -> 401 Unauthorized (ingest requires ArchiveWrite)
    let read_token = "sess_read_only";
    let read_session = SessionToken {
        token: read_token.into(),
        device_id: "local-device".into(),
        scopes: vec![Scope::ArchiveRead],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    };
    test_state.auth_tokens.lock().unwrap().push(read_session);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/ingest/browser-history")
                .header("authorization", format!("Bearer {read_token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn browser_history_ingest_returns_service_unavailable_when_unconfigured_or_missing() {
    let (state, _temp) = setup_test_state();
    let token = "sess_write_valid";
    let session = SessionToken {
        token: token.into(),
        device_id: "local-device".into(),
        scopes: vec![Scope::ArchiveWrite],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    };
    state.auth_tokens.lock().unwrap().push(session);

    // 1. When browser_history_path is None -> 503
    let mut test_state = state.clone();
    test_state.browser_history_path = None;
    let app = create_router(test_state);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/ingest/browser-history")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, "ingest.source_unavailable");

    // 2. When configured path points to non-existent file -> 503
    let mut test_state_missing = state.clone();
    test_state_missing.browser_history_path = Some(PathBuf::from("nonexistent_history_file.db"));
    let app_missing = create_router(test_state_missing);

    let resp = app_missing
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/ingest/browser-history")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, "ingest.source_unavailable");
}

#[tokio::test]
async fn browser_history_ingest_rejects_arbitrary_client_filesystem_paths() {
    let (state, temp) = setup_test_state();
    let db_path = temp.path().join("History");
    sc_connector_browser_chromium::create_mock_history_db(&db_path).unwrap();

    let token = "sess_write_valid_2";
    let session = SessionToken {
        token: token.into(),
        device_id: "local-device".into(),
        scopes: vec![Scope::ArchiveWrite],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    };
    state.auth_tokens.lock().unwrap().push(session);

    let mut test_state = state.clone();
    test_state.browser_history_path = Some(db_path);
    let app = create_router(test_state);

    // Attempting to supply a client filesystem path must be rejected with 400 Bad Request
    let payload = serde_json::json!({
        "path": "/etc/passwd",
        "historyDbPath": "C:\\Windows\\System32\\calc.exe"
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/ingest/browser-history")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.code, "request.invalid");
}

#[tokio::test]
async fn browser_history_ingest_proves_source_unmodified_idempotent_import_readback_and_provenance()
{
    let (state, temp) = setup_test_state();
    let db_path = temp.path().join("History");
    sc_connector_browser_chromium::create_mock_history_db(&db_path).unwrap();

    // 1. Calculate exact source database SHA-256 before any operations
    let source_bytes_initial = std::fs::read(&db_path).unwrap();
    let initial_hash = hex_digest(&Sha256::digest(&source_bytes_initial));

    let token = "sess_write_browser";
    let session = SessionToken {
        token: token.into(),
        device_id: "test-device-1".into(),
        scopes: vec![
            Scope::ArchiveRead,
            Scope::ArchiveWrite,
            Scope::ArchiveDestructive,
        ],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    };
    state.auth_tokens.lock().unwrap().push(session);

    let mut test_state = state.clone();
    test_state.browser_history_path = Some(db_path.clone());
    let app = create_router(test_state.clone());

    // 2. First Ingestion: POST /v1/archive/ingest/browser-history
    let req_body = serde_json::json!({
        "sourceInstance": "custom-chromium-test"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/ingest/browser-history")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "test-device-1")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let ingest_resp: BrowserHistoryIngestResponse = serde_json::from_slice(&body).unwrap();

    assert_eq!(ingest_resp.source_instance, "custom-chromium-test");
    assert_eq!(ingest_resp.total_visits, 2);
    assert_eq!(ingest_resp.imported_count, 2);
    assert_eq!(ingest_resp.skipped_count, 0);
    assert_eq!(ingest_resp.object_ids.len(), 2);

    // 3. Prove source database was NOT modified during first ingestion
    let source_bytes_after_first = std::fs::read(&db_path).unwrap();
    let hash_after_first = hex_digest(&Sha256::digest(&source_bytes_after_first));
    assert_eq!(initial_hash, hash_after_first);

    // 4. Idempotent Retry: Re-run ingestion against same database
    let resp_retry = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/ingest/browser-history")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "test-device-1")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&req_body).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_retry.status(), StatusCode::OK);
    let body_retry = axum::body::to_bytes(resp_retry.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let retry_resp: BrowserHistoryIngestResponse = serde_json::from_slice(&body_retry).unwrap();

    assert_eq!(retry_resp.source_instance, "custom-chromium-test");
    assert_eq!(retry_resp.total_visits, 2);
    assert_eq!(retry_resp.imported_count, 0); // 0 new imports
    assert_eq!(retry_resp.skipped_count, 2); // 2 skipped duplicates
    assert_eq!(retry_resp.object_ids, ingest_resp.object_ids);

    // 5. Prove source database was NOT modified during retry
    let source_bytes_after_retry = std::fs::read(&db_path).unwrap();
    let hash_after_retry = hex_digest(&Sha256::digest(&source_bytes_after_retry));
    assert_eq!(initial_hash, hash_after_retry);

    // 6. Object Readback via API: GET /v1/archive/objects/{objectId}
    let first_object_id = &ingest_resp.object_ids[0];
    let resp_get = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(format!("/v1/archive/objects/{first_object_id}"))
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "test-device-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_get.status(), StatusCode::OK);
    let body_get = axum::body::to_bytes(resp_get.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let obj: SourceObject = serde_json::from_slice(&body_get).unwrap();

    assert_eq!(&obj.object_id, first_object_id);
    assert_eq!(obj.domain, ArchiveDomain::Private);
    assert_eq!(obj.source_instance, "custom-chromium-test");
    assert_eq!(obj.external_id, "history:100");

    // 7. Provenance & Blob Integrity Verification directly in Archive
    let blob_bytes = {
        let archive = test_state.archive.read().unwrap();
        let provenance = archive.provenance(first_object_id).unwrap();
        assert_eq!(&provenance.object_id, first_object_id);
        assert_eq!(provenance.source.external_id, "history:100");

        let blob_path = archive
            .root()
            .join(oiaf::blob_relative_path(&provenance.blob.digest).unwrap());
        std::fs::read(&blob_path).unwrap()
    };
    let visit_record: sc_connector_browser_chromium::BrowserVisitRecord =
        serde_json::from_slice(&blob_bytes).unwrap();
    assert_eq!(visit_record.visit_id, 100);
    assert_eq!(visit_record.url, "https://shallow-copy.org");
    assert_eq!(visit_record.title.as_deref(), Some("Shallow Copy Project"));

    // 8. Audit Event Verification: GET /v1/archive/audit
    let resp_audit = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/archive/audit")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "test-device-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_audit.status(), StatusCode::OK);
    let body_audit = axum::body::to_bytes(resp_audit.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let audit_events: Vec<AuditEvent> = serde_json::from_slice(&body_audit).unwrap();
    let ingest_audit = audit_events
        .iter()
        .find(|e| e.event_type == "ingest_browser_history");
    assert!(ingest_audit.is_some());
    let audit = ingest_audit.unwrap();
    assert_eq!(audit.actor, "test-device-1");

    // 9. Route Alias Verification: POST /v1/archive/ingest/browser/chromium
    let resp_alias = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/archive/ingest/browser/chromium")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "test-device-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_alias.status(), StatusCode::OK);
}

#[tokio::test]
async fn system_setup_bootstrap_is_one_time_and_normal_login_cannot_replay() {
    let (state, _temp) = setup_test_state_unprovisioned();
    let app = create_router(state.clone());

    // 1. GET /v1/system/setup without auth -> 401
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/system/setup")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    let initial_token = "sess_preexisting";
    state.auth_tokens.lock().unwrap().push(SessionToken {
        token: initial_token.into(),
        device_id: "local-device".into(),
        scopes: vec![Scope::ArchiveRead, Scope::ArchiveWrite],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    });
    let ordinary_session_attempt = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("authorization", format!("Bearer {initial_token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"ownerPassword":"secret-passphrase","recoveryConfirmed": true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ordinary_session_attempt.status(), StatusCode::UNAUTHORIZED);

    // First-run bootstrap is unauthenticated, but consumes the one-time boundary.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"ownerPassword":"secret-passphrase","recoveryConfirmed": true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(state.setup_state.lock().unwrap().attempted);

    // Unauthenticated replay fails once the bootstrap marker is durable.
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"ownerPassword":"secret-passphrase","recoveryConfirmed": true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // A normal session can inspect state, but cannot replay setup.
    let token = login_token(&app, "local-device").await;
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"ownerPassword":"secret-passphrase","recoveryConfirmed": true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/system/setup")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn system_setup_lifecycle_replay_rejection_and_zero_secret_leakage() {
    let (state, temp) = setup_test_state_unprovisioned();
    let token = "sess_setup_admin";
    let session = SessionToken {
        token: token.into(),
        device_id: "admin-device".into(),
        scopes: vec![
            Scope::ArchiveRead,
            Scope::ArchiveWrite,
            Scope::ArchiveDestructive,
        ],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    };
    state.auth_tokens.lock().unwrap().push(session);

    let app = create_router(state.clone());

    // 1. Initial status query: unconfigured setup state
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/system/setup")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "admin-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(!body_str.contains("secret"));
    assert!(!body_str.contains("password"));
    assert!(!body_str.contains("recoveryKey"));

    let status: SystemSetupStatus = serde_json::from_slice(&body).unwrap();
    assert!(status.archive_initialized);
    assert!(!status.recovery_configured);
    assert!(!status.is_complete);

    // 2. Execute setup configuration
    let backup_dir = temp.path().join("local_backups");
    let configured_archive_dir = temp.path().join("configured_archive");
    let setup_payload = serde_json::json!({
        "backupPath": backup_dir.to_str().unwrap(),
        "archivePath": configured_archive_dir.to_str().unwrap(),
        "recoveryConfirmed": true,
        "ownerPassword": "setup-secret-password"
    });

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("x-device-id", "admin-device")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&setup_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(!body_str.contains("secret"));
    assert!(!body_str.contains("password"));
    assert!(!body_str.contains("recoveryKey"));

    let setup_resp: SystemSetupResponse = serde_json::from_slice(&body).unwrap();
    assert!(setup_resp.success);
    assert!(setup_resp.status.is_complete);
    assert!(setup_resp.status.recovery_configured);
    assert!(setup_resp.status.archive_initialized);
    assert!(setup_resp.status.backup_path.is_some());
    assert!(setup_resp.status.archive_path.is_some());
    let configured_archive = Archive::open(&configured_archive_dir).unwrap();
    assert_eq!(
        state.archive.read().unwrap().root(),
        configured_archive.root()
    );

    // 3. Status check after execution: is_complete is true, paths reflected safely
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/system/setup")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "admin-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let status_after: SystemSetupStatus = serde_json::from_slice(&body).unwrap();
    assert!(status_after.is_complete);
    assert!(status_after.backup_path.is_some());
    assert!(status_after.archive_path.is_some());

    // Also verify GET /v1/system/readiness reflects initialized paths safely
    let resp_readiness = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/system/readiness")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "admin-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_readiness.status(), StatusCode::OK);
    let body_readiness = axum::body::to_bytes(resp_readiness.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let readiness: SystemReadinessResponse = serde_json::from_slice(&body_readiness).unwrap();
    assert!(readiness.archive_ready);
    assert!(readiness.backup_path.is_some());
    assert!(readiness.archive_path.is_some());

    // 4. Replay Guard: Attempting to call POST /v1/system/setup again must be rejected with 409 Conflict
    let resp_replay = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "admin-device")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&setup_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_replay.status(), StatusCode::CONFLICT);
    let body_replay = axum::body::to_bytes(resp_replay.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body_replay).unwrap();
    assert_eq!(err.code, "setup.already_completed");

    // 5. Audit event verification: GET /v1/archive/audit
    let resp_audit = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/archive/audit")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "admin-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_audit.status(), StatusCode::OK);
    let body_audit = axum::body::to_bytes(resp_audit.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let events: Vec<AuditEvent> = serde_json::from_slice(&body_audit).unwrap();
    let setup_event = events.iter().find(|e| e.event_type == "system_setup");
    assert!(setup_event.is_some());
    assert_eq!(setup_event.unwrap().actor, "admin-device");
}

#[tokio::test]
async fn system_setup_validation_and_traversal_rejection() {
    let (state, _temp) = setup_test_state_unprovisioned();
    let app = create_router(state);

    // 1. Missing recovery confirmation -> 400 Bad Request
    let payload = serde_json::json!({
        "recoveryConfirmed": false
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 2. Directory traversal in backupPath -> 400 Bad Request
    let payload = serde_json::json!({
        "recoveryConfirmed": true,
        "backupPath": "../../outside"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 3. Directory traversal in archivePath -> 400 Bad Request
    let payload = serde_json::json!({
        "recoveryConfirmed": true,
        "archivePath": "../archive_traversal"
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 4. Non-directory file passed as backupPath -> 400 Bad Request
    let dummy_file = _temp.path().join("dummy_backup_file.txt");
    std::fs::write(&dummy_file, b"not a directory").unwrap();
    let payload = serde_json::json!({
        "recoveryConfirmed": true,
        "backupPath": dummy_file.to_str().unwrap()
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 5. Non-directory file passed as archivePath -> 400 Bad Request
    let dummy_archive_file = _temp.path().join("dummy_archive_file.txt");
    std::fs::write(&dummy_archive_file, b"not an archive directory").unwrap();
    let payload = serde_json::json!({
        "recoveryConfirmed": true,
        "archivePath": dummy_archive_file.to_str().unwrap()
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 6. An existing but uninitialized directory is not adopted as an archive.
    let empty_archive_dir = _temp.path().join("empty_archive_dir");
    std::fs::create_dir(&empty_archive_dir).unwrap();
    let payload = serde_json::json!({
        "recoveryConfirmed": true,
        "archivePath": empty_archive_dir.to_str().unwrap()
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn system_setup_replay_prevention_persists_across_server_restarts() {
    let temp = tempfile::tempdir().unwrap();
    let archive_path = temp.path().join("archive");
    let archive = Archive::init(&archive_path).unwrap();

    let catalog_path = temp.path().join("catalog.sqlite");
    let catalog = Catalog::open(&catalog_path).unwrap();

    let state = AppState::new(catalog, archive);
    let token = "sess_setup_restart";
    let session = SessionToken {
        token: token.into(),
        device_id: "restart-admin".into(),
        scopes: vec![Scope::ArchiveRead, Scope::ArchiveWrite],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    };
    state.auth_tokens.lock().unwrap().push(session.clone());
    let app = create_router(state);

    // 1. Initial setup succeeds
    let backup_dir = temp.path().join("restart_backups");
    let configured_archive_dir = temp.path().join("restart_configured_archive");
    let setup_payload = serde_json::json!({
        "backupPath": backup_dir.to_str().unwrap(),
        "archivePath": configured_archive_dir.to_str().unwrap(),
        "recoveryConfirmed": true,
        "ownerPassword": "setup-secret-password"
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("x-device-id", "restart-admin")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&setup_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2. Simulate server restart: construct new AppState from persisted catalog & archive on disk
    let restarted_catalog = Catalog::open(&catalog_path).unwrap();
    let restarted_archive = Archive::open(&archive_path).unwrap();
    let restarted_state = AppState::new(restarted_catalog, restarted_archive);
    assert_eq!(
        restarted_state.archive.read().unwrap().root(),
        Archive::open(&configured_archive_dir).unwrap().root()
    );
    restarted_state
        .auth_tokens
        .lock()
        .unwrap()
        .push(session.clone());
    let restarted_app = create_router(restarted_state);

    // 3. Proves status on restarted server reflects completed setup and persisted backup_path
    let resp_status = restarted_app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/system/setup")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "restart-admin")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_status.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp_status.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let status: SystemSetupStatus = serde_json::from_slice(&body).unwrap();
    assert!(status.is_complete);
    assert!(status.recovery_configured);
    assert!(status.backup_path.is_some());

    // 4. Proves replay attempt on restarted server is rejected with 409 Conflict
    let resp_replay = restarted_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "restart-admin")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&setup_payload).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_replay.status(), StatusCode::CONFLICT);
    let body_replay = axum::body::to_bytes(resp_replay.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let err: ErrorResponse = serde_json::from_slice(&body_replay).unwrap();
    assert_eq!(err.code, "setup.already_completed");
}

#[tokio::test]
async fn setup_transaction_failure_rolls_back_and_retry_preserves_data_committed_restart_locks() {
    let temp = tempfile::tempdir().unwrap();
    let archive_path = temp.path().join("archive");
    let archive = Archive::init(&archive_path).unwrap();
    let catalog_path = temp.path().join("catalog.sqlite");
    let catalog = Catalog::open(&catalog_path).unwrap();
    let state = AppState::new(catalog, archive);

    // Inject failure inside transaction before commit
    state.catalog.lock().unwrap().test_fail_tx = true;
    let configured_archive_dir = temp.path().join("prepared_archive");
    let app = create_router(state.clone());

    let payload = serde_json::json!({
        "archivePath": configured_archive_dir,
        "ownerPassword": "secret-passphrase",
        "recoveryConfirmed": true
    });

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

    // Verify transaction rolled back completely: zero markers or auth metadata committed
    {
        let cat = state.catalog.lock().unwrap();
        assert!(cat.get_meta("setup.owner_verifier").unwrap().is_none());
        assert!(cat.get_meta("setup.owner_auth_version").unwrap().is_none());
        assert!(cat.get_meta("setup.completed_unix_ms").unwrap().is_none());
        assert!(cat.get_meta("setup.archive_path").unwrap().is_none());
    }
    assert!(!state.setup_state.lock().unwrap().attempted);

    // Clear injected failure and retry: setup commits successfully
    state.catalog.lock().unwrap().test_fail_tx = false;
    let retry_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retry_response.status(), StatusCode::OK);

    // Rehydrated state on server restart remains locked against replay
    let restarted_catalog = Catalog::open(&catalog_path).unwrap();
    let restarted_archive = Archive::open(&archive_path).unwrap();
    let restarted_state = AppState::new(restarted_catalog, restarted_archive);
    let restarted_app = create_router(restarted_state);

    let token = login_token(&restarted_app, "restart-admin").await;
    let replay = restarted_app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn sec01_recovery_confirmed_false_rejected() {
    let (state, _temp) = setup_test_state_unprovisioned();
    let app = create_router(state.clone());

    // 1. Fresh setup with recoveryConfirmed = false -> 400
    let fresh_req = serde_json::json!({
        "ownerPassword": "my-secret-pass",
        "recoveryConfirmed": false
    });
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(fresh_req.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

    // 2. Legacy claim with recoveryConfirmed = false -> 400
    state
        .catalog
        .lock()
        .unwrap()
        .set_meta("setup.admin_provisioned", "true")
        .unwrap();
    let claim_req = serde_json::json!({
        "ownerPassword": "my-secret-pass",
        "recoveryConfirmed": false
    });
    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup/claim-legacy")
                .header("content-type", "application/json")
                .body(Body::from(claim_req.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn sec01_bootstrap_token_loopback_and_non_loopback_gate() {
    // 1. Loopback bind allows setup without x-bootstrap-token
    {
        let (state, temp) = setup_test_state_unprovisioned();
        let app = create_router(state);
        let payload = serde_json::json!({
            "archivePath": temp.path().join("loopback_arch").to_str().unwrap(),
            "ownerPassword": "loopback-password-123",
            "recoveryConfirmed": true
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/system/setup")
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // 2. Non-loopback bind evaluated via check_bootstrap_token_inner
    let non_loopback_host = "192.168.1.50";
    let secret_token = "valid-bootstrap-secret-tok";

    // 2a. Missing x-bootstrap-token -> 401
    let empty_headers = axum::http::HeaderMap::new();
    let err_missing = check_bootstrap_token_inner(&empty_headers, non_loopback_host, secret_token)
        .expect("should return unauthorized response");
    assert_eq!(err_missing.status(), StatusCode::UNAUTHORIZED);

    // 2b. Wrong x-bootstrap-token -> 401
    let mut wrong_headers = axum::http::HeaderMap::new();
    wrong_headers.insert(
        "x-bootstrap-token",
        "wrong-bootstrap-token".parse().unwrap(),
    );
    let err_wrong = check_bootstrap_token_inner(&wrong_headers, non_loopback_host, secret_token)
        .expect("should return unauthorized response");
    assert_eq!(err_wrong.status(), StatusCode::UNAUTHORIZED);

    // 2c. Valid x-bootstrap-token -> None (no error)
    let mut valid_headers = axum::http::HeaderMap::new();
    valid_headers.insert("x-bootstrap-token", secret_token.parse().unwrap());
    let ok_res = check_bootstrap_token_inner(&valid_headers, non_loopback_host, secret_token);
    assert!(ok_res.is_none());

    // 2d. Missing server configured token on non-loopback -> 401
    let err_unconfigured = check_bootstrap_token_inner(&valid_headers, non_loopback_host, "")
        .expect("should return unauthorized response");
    assert_eq!(err_unconfigured.status(), StatusCode::UNAUTHORIZED);

    // Verify error responses contain zero token leakage
    let body = axum::body::to_bytes(err_missing.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);
    assert!(!body_str.contains(secret_token));
}

#[tokio::test]
async fn sec01_legacy_predicates_admin_only_accepted_fresh_and_inconsistent_denied() {
    // Case 1: Fresh state (no markers) -> claim is denied (409 Conflict)
    {
        let (state, _temp) = setup_test_state_unprovisioned();
        let app = create_router(state);
        let claim_payload = serde_json::json!({
            "ownerPassword": "claim-password",
            "recoveryConfirmed": true
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/system/setup/claim-legacy")
                    .header("content-type", "application/json")
                    .body(Body::from(claim_payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    // Case 2: Inconsistent state (owner_verifier set, but owner_auth_version missing) -> denied (409)
    {
        let (state, _temp) = setup_test_state_unprovisioned();
        state
            .catalog
            .lock()
            .unwrap()
            .set_meta("setup.admin_provisioned", "true")
            .unwrap();
        state
            .catalog
            .lock()
            .unwrap()
            .set_meta("setup.owner_verifier", "{\"dummy\":\"verifier\"}")
            .unwrap();
        let app = create_router(state);
        let claim_payload = serde_json::json!({
            "ownerPassword": "claim-password",
            "recoveryConfirmed": true
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/system/setup/claim-legacy")
                    .header("content-type", "application/json")
                    .body(Body::from(claim_payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    // Case 3: Old admin-only marker (setup.admin_provisioned="true", no verifier/version) -> accepted (200 OK)
    {
        let (state, _temp) = setup_test_state_unprovisioned();
        state
            .catalog
            .lock()
            .unwrap()
            .set_meta("setup.admin_provisioned", "true")
            .unwrap();
        let app = create_router(state.clone());
        let claim_payload = serde_json::json!({
            "ownerPassword": "claim-password",
            "recoveryConfirmed": true
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/system/setup/claim-legacy")
                    .header("content-type", "application/json")
                    .body(Body::from(claim_payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify owner_verifier and owner_auth_version="1" are now durable
        let cat = state.catalog.lock().unwrap();
        assert!(cat.get_meta("setup.owner_verifier").unwrap().is_some());
        assert_eq!(
            cat.get_meta("setup.owner_auth_version").unwrap().as_deref(),
            Some("1")
        );
    }
}

#[tokio::test]
async fn sec01_correct_login_succeeds_after_fresh_setup_and_after_legacy_claim() {
    // Part 1: Fresh setup -> Login succeeds with 32B OsRng token and 24h expiry
    {
        let (state, temp) = setup_test_state_unprovisioned();
        let app = create_router(state.clone());
        let setup_payload = serde_json::json!({
            "archivePath": temp.path().join("fresh_arch").to_str().unwrap(),
            "ownerPassword": "fresh-owner-pass-1",
            "recoveryConfirmed": true
        });
        let setup_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/system/setup")
                    .header("content-type", "application/json")
                    .body(Body::from(setup_payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(setup_resp.status(), StatusCode::OK);

        let login_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/session")
                    .header("content-type", "application/json")
                    .header("x-device-id", "fresh-device")
                    .body(Body::from(r#"{"password":"fresh-owner-pass-1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(login_resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let session: SessionToken = serde_json::from_slice(&body).unwrap();
        assert!(session.token.starts_with("sess_"));
        assert_eq!(session.token.len(), 5 + 64); // sess_ + 64 hex chars (32 bytes)
        assert_eq!(session.device_id, "fresh-device");
    }

    // Part 2: Legacy claim -> Login succeeds with 32B OsRng token
    {
        let (state, _temp) = setup_test_state_unprovisioned();
        state
            .catalog
            .lock()
            .unwrap()
            .set_meta("setup.admin_provisioned", "true")
            .unwrap();
        let app = create_router(state.clone());
        let claim_payload = serde_json::json!({
            "ownerPassword": "legacy-claim-pass-2",
            "recoveryConfirmed": true
        });
        let claim_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/system/setup/claim-legacy")
                    .header("content-type", "application/json")
                    .body(Body::from(claim_payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(claim_resp.status(), StatusCode::OK);

        let login_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/auth/session")
                    .header("content-type", "application/json")
                    .header("x-device-id", "legacy-device")
                    .body(Body::from(r#"{"password":"legacy-claim-pass-2"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(login_resp.into_body(), 1024 * 1024)
            .await
            .unwrap();
        let session: SessionToken = serde_json::from_slice(&body).unwrap();
        assert!(session.token.starts_with("sess_"));
        assert_eq!(session.token.len(), 5 + 64);
        assert_eq!(session.device_id, "legacy-device");
    }
}

#[tokio::test]
async fn sec01_wrong_empty_and_preclaim_passwords_return_401_no_session() {
    // 1. Pre-claim unprovisioned login -> 401 and 0 sessions created
    let (state, _temp) = setup_test_state_unprovisioned();
    let app = create_router(state.clone());
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/session")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"any-passphrase"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(state.auth_tokens.lock().unwrap().len(), 0);

    // 2. Setup owner credentials
    let setup_payload = serde_json::json!({
        "ownerPassword": "correct-owner-password",
        "recoveryConfirmed": true
    });
    let setup_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(setup_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(setup_resp.status(), StatusCode::OK);

    // 3. Empty password -> 401 and 0 sessions created
    let resp_empty = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/session")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":""}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_empty.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(state.auth_tokens.lock().unwrap().len(), 0);

    // 4. Wrong password -> 401 and 0 sessions created
    let resp_wrong = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/session")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"incorrect-password"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_wrong.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(state.auth_tokens.lock().unwrap().len(), 0);

    // 5. Correct password -> 200 OK and exactly 1 session created
    let resp_ok = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/auth/session")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"password":"correct-owner-password"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_ok.status(), StatusCode::OK);
    assert_eq!(state.auth_tokens.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn sec01_setup_and_claim_replay_independently_return_409() {
    let (state, _temp) = setup_test_state_unprovisioned();
    let app = create_router(state);

    let setup_payload = serde_json::json!({
        "ownerPassword": "my-durable-password",
        "recoveryConfirmed": true
    });

    // 1. Initial setup succeeds
    let resp1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(setup_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    // 2. Setup replay -> 409 Conflict
    let resp_setup_replay = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(setup_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_setup_replay.status(), StatusCode::CONFLICT);

    // 3. Claim replay on configured install -> 409 Conflict
    let claim_payload = serde_json::json!({
        "ownerPassword": "my-durable-password",
        "recoveryConfirmed": true
    });
    let resp_claim_replay = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup/claim-legacy")
                .header("content-type", "application/json")
                .body(Body::from(claim_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_claim_replay.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn sec01_legacy_claim_preserves_archive_bytes_config_and_catalog() {
    let temp = tempfile::tempdir().unwrap();
    let archive_path = temp.path().join("preexisting_archive");
    let archive = Archive::init(&archive_path).unwrap();

    let source = oiaf::Source::filesystem("legacy-conn", "evidence.txt", "rev-42");
    let raw_bytes = b"important legacy user evidence payload";
    archive.import_bytes(raw_bytes, source).unwrap();

    let catalog_path = temp.path().join("legacy_catalog.sqlite");
    let mut catalog = Catalog::open(&catalog_path).unwrap();
    catalog.rebuild_from_archive(&archive).unwrap();

    let backup_target = temp.path().join("legacy_backup_target");
    std::fs::create_dir_all(&backup_target).unwrap();

    // Seed legacy markers and paths
    catalog
        .set_meta("setup.archive_path", &archive_path.to_string_lossy())
        .unwrap();
    catalog
        .set_meta("setup.backup_path", &backup_target.to_string_lossy())
        .unwrap();
    catalog.set_meta("setup.admin_provisioned", "true").unwrap();
    catalog
        .set_meta("setup.completed_unix_ms", "500000")
        .unwrap();

    let state = AppState::new(catalog, archive);
    let app = create_router(state.clone());

    // Call legacy claim
    let claim_payload = serde_json::json!({
        "ownerPassword": "legacy-claimed-owner-pass",
        "recoveryConfirmed": true
    });
    let claim_resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup/claim-legacy")
                .header("content-type", "application/json")
                .body(Body::from(claim_payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(claim_resp.status(), StatusCode::OK);

    // Verify archive files and bytes remain completely identical
    let reopened_archive = Archive::open(&archive_path).unwrap();
    let objects = state.catalog.lock().unwrap().list_objects().unwrap();
    assert_eq!(objects.len(), 1);
    let rel_path = oiaf::blob_relative_path(&objects[0].blob_digest).unwrap();
    let blob_bytes = std::fs::read(reopened_archive.root().join(rel_path)).unwrap();
    assert_eq!(blob_bytes, raw_bytes);

    // Verify archive and backup config were preserved
    let cat = state.catalog.lock().unwrap();
    assert_eq!(
        cat.get_meta("setup.archive_path").unwrap().as_deref(),
        Some(archive_path.to_str().unwrap())
    );
    assert_eq!(
        cat.get_meta("setup.backup_path").unwrap().as_deref(),
        Some(backup_target.to_str().unwrap())
    );
    assert_eq!(
        cat.get_meta("setup.completed_unix_ms").unwrap().as_deref(),
        Some("500000")
    );
}

#[tokio::test]
async fn sec01_two_connection_setup_race_winner_loser() {
    let temp = tempfile::tempdir().unwrap();
    let archive_path = temp.path().join("base_archive");
    let _archive = Archive::init(&archive_path).unwrap();
    let catalog_path = temp.path().join("race_catalog.sqlite");

    // Initialize schema first
    {
        let _init = Catalog::open(&catalog_path).unwrap();
    }

    // Two independent catalog connections to the same database file
    let catalog_a = Catalog::open(&catalog_path).unwrap();
    let catalog_b = Catalog::open(&catalog_path).unwrap();

    let state_a = AppState::new(catalog_a, Archive::open(&archive_path).unwrap());
    let state_b = AppState::new(catalog_b, Archive::open(&archive_path).unwrap());

    let app_a = create_router(state_a);
    let app_b = create_router(state_b);

    let dir_a = temp.path().join("archive_a");
    let dir_b = temp.path().join("archive_b");

    let req_a = Request::builder()
        .method("POST")
        .uri("/v1/system/setup")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "archivePath": dir_a.to_str().unwrap(),
                "ownerPassword": "password-candidate-A",
                "recoveryConfirmed": true
            })
            .to_string(),
        ))
        .unwrap();

    let req_b = Request::builder()
        .method("POST")
        .uri("/v1/system/setup")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({
                "archivePath": dir_b.to_str().unwrap(),
                "ownerPassword": "password-candidate-B",
                "recoveryConfirmed": true
            })
            .to_string(),
        ))
        .unwrap();

    // Run both setup requests concurrently across the two independent connections
    let (resp_a, resp_b) = tokio::join!(app_a.oneshot(req_a), app_b.oneshot(req_b));
    let code_a = resp_a.unwrap().status();
    let code_b = resp_b.unwrap().status();

    // Exactly one must succeed with 200, one must fail with 409 Conflict
    let (winner_code, loser_code) = if code_a == StatusCode::OK {
        (code_a, code_b)
    } else {
        (code_b, code_a)
    };
    assert_eq!(winner_code, StatusCode::OK);
    assert_eq!(loser_code, StatusCode::CONFLICT);

    // Loser cannot alter winner's configuration
    let verification_catalog = Catalog::open(&catalog_path).unwrap();
    let committed_path = verification_catalog
        .get_meta("setup.archive_path")
        .unwrap()
        .unwrap();
    let path_committed = std::fs::canonicalize(PathBuf::from(&committed_path))
        .unwrap_or_else(|_| PathBuf::from(&committed_path));
    let can_a = std::fs::canonicalize(&dir_a).unwrap_or_else(|_| dir_a.clone());
    let can_b = std::fs::canonicalize(&dir_b).unwrap_or_else(|_| dir_b.clone());
    assert!(path_committed == can_a || path_committed == can_b);
}

#[tokio::test]
async fn sec01_fresh_setup_without_backup_clears_stale_backup_path_and_rehydrates() {
    let temp = tempfile::tempdir().unwrap();
    let archive_path = temp.path().join("archive");
    let archive = Archive::init(&archive_path).unwrap();
    let catalog_path = temp.path().join("catalog.sqlite");
    let catalog = Catalog::open(&catalog_path).unwrap();

    // Simulate stale backup_path from an earlier incomplete or abandoned state
    catalog
        .set_meta("setup.backup_path", "/stale/candidate/backup")
        .unwrap();

    let state = AppState::new(catalog, archive);
    let app = create_router(state);

    // Fresh setup selecting NO backupPath
    let payload = serde_json::json!({
        "archivePath": temp.path().join("configured_fresh").to_str().unwrap(),
        "ownerPassword": "password-no-backup",
        "recoveryConfirmed": true
    });

    let resp = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(payload.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let setup_resp: SystemSetupResponse = serde_json::from_slice(&body).unwrap();
    assert!(setup_resp.status.backup_path.is_none());

    // Rehydrate server on restart
    let restarted_catalog = Catalog::open(&catalog_path).unwrap();
    assert!(
        restarted_catalog
            .get_meta("setup.backup_path")
            .unwrap()
            .is_none()
    );

    let restarted_state = AppState::new(
        restarted_catalog,
        Archive::open(temp.path().join("configured_fresh")).unwrap(),
    );
    assert!(
        restarted_state
            .setup_state
            .lock()
            .unwrap()
            .backup_path
            .is_none()
    );
}

#[tokio::test]
async fn sec01_status_secrecy_for_legacy_unclaimed_state() {
    let (state, _temp) = setup_test_state_unprovisioned();
    // Seed legacy admin marker without owner verifier or version
    state
        .catalog
        .lock()
        .unwrap()
        .set_meta("setup.admin_provisioned", "true")
        .unwrap();
    state
        .catalog
        .lock()
        .unwrap()
        .set_meta("setup.archive_path", "F:/secret/path/to/archive")
        .unwrap();
    state
        .catalog
        .lock()
        .unwrap()
        .set_meta("setup.backup_path", "F:/secret/path/to/backup")
        .unwrap();

    // Give admin token to query setup status
    let token = "sess_legacy_admin";
    state.auth_tokens.lock().unwrap().push(SessionToken {
        token: token.into(),
        device_id: "status-device".into(),
        scopes: vec![Scope::ArchiveRead],
        expires_at: format_unix_ms(current_time_ms() + 3_600_000),
    });

    let app = create_router(state);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/system/setup")
                .header("authorization", format!("Bearer {token}"))
                .header("x-device-id", "status-device")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let body_str = String::from_utf8_lossy(&body);

    // Status must NOT leak paths or secrets
    assert!(!body_str.contains("secret/path"));
    assert!(!body_str.contains("password"));

    let status: SystemSetupStatus = serde_json::from_slice(&body).unwrap();
    assert_eq!(status.legacy_credential_claim_required, Some(true));
    assert!(!status.admin_provisioned);
    assert!(!status.is_complete);
    assert!(status.archive_path.is_none());
    assert!(status.backup_path.is_none());
}

#[tokio::test]
async fn sec01_token_expiry_and_caller_only_logout() {
    let (state, _temp) = setup_test_state();
    let app = create_router(state.clone());

    // 1. Non-bearer logout is rejected with 401
    let resp_non_bearer = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/auth/session")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_non_bearer.status(), StatusCode::UNAUTHORIZED);

    // 2. Login two concurrent caller sessions
    let login_caller = |dev: &'static str| {
        let app_clone = app.clone();
        async move {
            let resp = app_clone
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/v1/auth/session")
                        .header("content-type", "application/json")
                        .header("x-device-id", dev)
                        .body(Body::from(r#"{"password":"secret-passphrase"}"#))
                        .unwrap(),
                )
                .await
                .unwrap();
            let bytes = axum::body::to_bytes(resp.into_body(), 1024 * 1024)
                .await
                .unwrap();
            serde_json::from_slice::<SessionToken>(&bytes)
                .unwrap()
                .token
        }
    };

    let token_1 = login_caller("device-1").await;
    let token_2 = login_caller("device-2").await;
    assert_eq!(state.auth_tokens.lock().unwrap().len(), 2);

    // 3. Caller 1 logs out: revokes only caller 1's token
    let logout_resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/auth/session")
                .header("authorization", format!("Bearer {token_1}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout_resp.status(), StatusCode::NO_CONTENT);

    // Caller 1 is revoked
    let resp_1 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/archive/objects")
                .header("authorization", format!("Bearer {token_1}"))
                .header("x-device-id", "device-1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_1.status(), StatusCode::UNAUTHORIZED);

    // Caller 2 is preserved and functional
    let resp_2 = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/archive/objects")
                .header("authorization", format!("Bearer {token_2}"))
                .header("x-device-id", "device-2")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_2.status(), StatusCode::OK);

    // 4. Expired token is rejected
    let expired_token = "sess_expired_test";
    state.auth_tokens.lock().unwrap().push(SessionToken {
        token: expired_token.into(),
        device_id: "device-expired".into(),
        scopes: vec![Scope::ArchiveRead],
        expires_at: format_unix_ms(current_time_ms() - 10_000), // in the past
    });
    let resp_expired = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/v1/archive/objects")
                .header("authorization", format!("Bearer {expired_token}"))
                .header("x-device-id", "device-expired")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp_expired.status(), StatusCode::UNAUTHORIZED);
}
