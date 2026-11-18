//! First-run setup, legacy-claim, readiness, and bootstrap handlers.

use crate::*;
fn prepare_setup_archive(
    state: &AppState,
    requested_path: Option<&str>,
) -> Result<(Archive, PathBuf), String> {
    let current = state.archive.read().unwrap().clone();
    let Some(raw) = requested_path else {
        return Ok((current.clone(), current.root().to_path_buf()));
    };
    if raw.is_empty() || raw.len() > 4096 || raw.contains('\0') {
        return Err(
            "archivePath must be nonempty, at most 4096 bytes, and contain no nulls".into(),
        );
    }
    let requested = FsPath::new(raw);
    if requested
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("archivePath must not contain parent directory traversal ('..')".into());
    }

    let archive = if requested.exists() {
        Archive::open(requested)
            .map_err(|error| format!("archivePath is not a valid OIAF archive: {error}"))?
    } else {
        let parent = requested
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| FsPath::new("."));
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("failed to create archivePath parent: {error}"))?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|error| format!("failed to canonicalize archivePath parent: {error}"))?;
        let name = requested
            .file_name()
            .ok_or_else(|| "archivePath must name a directory".to_string())?;
        Archive::init(canonical_parent.join(name))
            .map_err(|error| format!("failed to initialize archivePath: {error}"))?
    };
    let canonical = archive.root().to_path_buf();
    Ok((archive, canonical))
}

fn safe_display_path(p: &FsPath) -> String {
    let s = p.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        stripped.to_string()
    } else {
        s.to_string()
    }
}

fn validate_and_canonicalize_dir(
    raw: &str,
    field_name: &str,
) -> std::result::Result<PathBuf, String> {
    if raw.is_empty() || raw.len() > 4096 {
        return Err(format!(
            "{field_name} must be nonempty and at most 4096 bytes"
        ));
    }
    if raw.contains('\0') {
        return Err(format!("{field_name} must not contain null characters"));
    }
    let p = FsPath::new(raw);
    if p.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(format!(
            "{field_name} must not contain parent directory traversal ('..')"
        ));
    }
    if p.exists() && !p.is_dir() {
        return Err(format!("{field_name} exists but is not a directory"));
    }
    if !p.exists() {
        std::fs::create_dir_all(p)
            .map_err(|e| format!("failed to create directory for {field_name}: {e}"))?;
    }
    let canonical = match p.canonicalize() {
        Ok(c) => c,
        Err(e) => return Err(format!("failed to canonicalize {field_name}: {e}")),
    };
    if !canonical.is_dir() {
        return Err(format!("{field_name} is not a valid directory"));
    }
    let probe_name = format!(".sc_setup_probe_{:012x}", current_time_ms());
    let probe_path = canonical.join(&probe_name);
    match std::fs::write(&probe_path, b"probe") {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe_path);
        }
        Err(e) => return Err(format!("{field_name} directory is not writable: {e}")),
    }

    Ok(canonical)
}

pub(crate) async fn system_readiness(State(state): State<AppState>) -> Response {
    let archive = state.archive.read().unwrap();
    let archive_ready = archive.root().exists();
    let filesystem_ingest_available = state.filesystem_ingest_root.is_some();

    let cat = state.catalog.lock().unwrap();
    let object_count = match cat.list_objects() {
        Ok(objs) => objs.len() as i64,
        Err(e) => return internal_error(&e.to_string()),
    };

    let (pending_jobs, failed_jobs) = match cat.list_jobs(None) {
        Ok(jobs) => {
            let pending = jobs
                .iter()
                .filter(|j| matches!(j.status, JobStatus::Pending))
                .count() as i64;
            let failed = jobs
                .iter()
                .filter(|j| matches!(j.status, JobStatus::Failed))
                .count() as i64;
            (pending, failed)
        }
        Err(e) => return internal_error(&e.to_string()),
    };

    let setup = state.setup_state.lock().unwrap();
    let archive_path = setup
        .archive_path
        .as_ref()
        .map(|p| safe_display_path(p))
        .or_else(|| {
            if archive_ready {
                Some(safe_display_path(archive.root()))
            } else {
                None
            }
        });
    let backup_path = setup.backup_path.as_ref().map(|p| safe_display_path(p));

    (
        StatusCode::OK,
        Json(SystemReadinessResponse {
            archive_ready,
            object_count,
            pending_jobs,
            failed_jobs,
            filesystem_ingest_available,
            archive_path,
            backup_path,
        }),
    )
        .into_response()
}

fn check_bootstrap_token(headers: &axum::http::HeaderMap) -> Option<Response> {
    let host = std::env::var("BIND_ADDR")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "127.0.0.1".into());
    let token = std::env::var("BOOTSTRAP_TOKEN").unwrap_or_default();
    check_bootstrap_token_inner(headers, &host, &token)
}

pub(crate) fn check_bootstrap_token_inner(
    headers: &axum::http::HeaderMap,
    host: &str,
    expected_token: &str,
) -> Option<Response> {
    let is_loopback = host
        .parse::<std::net::IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false);

    if !is_loopback {
        if expected_token.trim().is_empty() {
            return Some(unauthorized("bootstrap token not configured on server"));
        }
        let provided = headers
            .get("x-bootstrap-token")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        if provided != expected_token {
            return Some(unauthorized("invalid or missing bootstrap token"));
        }
    }
    None
}

pub(crate) async fn get_setup_status(State(state): State<AppState>) -> Response {
    let archive = state.archive.read().unwrap();
    let archive_initialized = Archive::open(archive.root()).is_ok();

    let (
        has_owner_verifier,
        has_owner_version,
        catalog_admin_provisioned,
        catalog_completed,
        catalog_prepared,
        catalog_recovery_configured,
    ) = {
        let catalog = state.catalog.lock().unwrap();
        let verifier = catalog
            .get_meta("setup.owner_verifier")
            .ok()
            .flatten()
            .is_some();
        let version = catalog
            .get_meta("setup.owner_auth_version")
            .ok()
            .flatten()
            .is_some();
        let admin = catalog
            .get_meta("setup.admin_provisioned")
            .ok()
            .flatten()
            .is_some_and(|v| v == "true");
        let completed = match catalog.get_meta("setup.completed_unix_ms") {
            Ok(value) => value.is_some(),
            Err(error) => return internal_error(&error.to_string()),
        };
        let prepared = match catalog.get_meta("setup.prepared_unix_ms") {
            Ok(value) => value.is_some(),
            Err(error) => return internal_error(&error.to_string()),
        };
        let configured = match catalog.get_meta("setup.recovery_configured") {
            Ok(value) => value.is_some_and(|value| value == "true"),
            Err(error) => return internal_error(&error.to_string()),
        };
        (verifier, version, admin, completed, prepared, configured)
    };

    let has_any_legacy_marker = catalog_admin_provisioned || catalog_prepared || catalog_completed;
    let is_legacy_unclaimed = has_any_legacy_marker && !has_owner_verifier && !has_owner_version;

    if is_legacy_unclaimed {
        return (
            StatusCode::OK,
            Json(SystemSetupStatus {
                archive_initialized,
                admin_provisioned: false,
                recovery_configured: false,
                is_complete: false,
                legacy_credential_claim_required: Some(true),
                archive_path: None,
                backup_path: None,
            }),
        )
            .into_response();
    }

    let setup = state.setup_state.lock().unwrap();
    let admin_provisioned = setup.admin_provisioned
        || has_real_session(&state)
        || (catalog_completed && has_owner_verifier && has_owner_version);
    let recovery_configured = setup.recovery_configured
        || ((catalog_prepared || catalog_completed) && catalog_recovery_configured);
    let is_complete = (setup.completed_unix_ms.is_some() || catalog_completed || catalog_prepared)
        && has_owner_verifier
        && has_owner_version;

    let archive_path = setup
        .archive_path
        .as_ref()
        .map(|p| safe_display_path(p))
        .or_else(|| {
            if archive_initialized {
                Some(safe_display_path(archive.root()))
            } else {
                None
            }
        });
    let backup_path = setup.backup_path.as_ref().map(|p| safe_display_path(p));

    (
        StatusCode::OK,
        Json(SystemSetupStatus {
            archive_initialized,
            admin_provisioned,
            recovery_configured,
            is_complete,
            legacy_credential_claim_required: None,
            archive_path,
            backup_path,
        }),
    )
        .into_response()
}

pub(crate) async fn execute_setup(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<SystemSetupRequest>,
) -> Response {
    if let Some(resp) = check_bootstrap_token(&headers) {
        return resp;
    }

    let locked_in_catalog = {
        let catalog = state.catalog.lock().unwrap();
        let attempted = match catalog.get_meta("setup.prepared_unix_ms") {
            Ok(value) => value.is_some(),
            Err(error) => return internal_error(&error.to_string()),
        };
        let completed = match catalog.get_meta("setup.completed_unix_ms") {
            Ok(value) => value.is_some(),
            Err(error) => return internal_error(&error.to_string()),
        };
        let verifier = match catalog.get_meta("setup.owner_verifier") {
            Ok(value) => value.is_some(),
            Err(error) => return internal_error(&error.to_string()),
        };
        attempted || completed || verifier
    };
    let setup = state.setup_state.lock().unwrap();
    if setup.attempted || setup.completed_unix_ms.is_some() || locked_in_catalog {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                code: "setup.already_completed".into(),
                message: "first-run setup has already been attempted or completed; replay rejected"
                    .into(),
                request_id: format!("req_{:012x}", current_time_ms()),
            }),
        )
            .into_response();
    }
    drop(setup);

    if bearer_token(&headers).is_some() {
        return unauthorized("first-run setup uses the unauthenticated bootstrap boundary");
    }

    // Require recovery confirmation
    if !body.recovery_confirmed {
        return bad_request("recovery verification confirmation is required to complete setup");
    }

    let Some(ref password) = body.owner_password else {
        return bad_request("owner password is required to complete setup");
    };
    if password.is_empty() {
        return bad_request("owner password cannot be empty");
    }

    // Validate and canonicalize local backup path if provided
    let resolved_backup_path = if let Some(ref bp) = body.backup_path {
        match validate_and_canonicalize_dir(bp, "backupPath") {
            Ok(canonical) => Some(canonical),
            Err(e) => return bad_request(&e),
        }
    } else {
        None
    };

    let (prepared_archive, resolved_archive_path) =
        match prepare_setup_archive(&state, body.archive_path.as_deref()) {
            Ok(prepared) => prepared,
            Err(error) => return bad_request(&error),
        };

    let envelope = match sc_crypto::seal(password.as_bytes(), OWNER_VERIFIER_SENTINEL) {
        Ok(env) => env,
        Err(e) => return internal_error(&format!("crypto seal error: {e}")),
    };
    let verifier_json = match serde_json::to_string(&envelope) {
        Ok(j) => j,
        Err(e) => return internal_error(&format!("json serialization error: {e}")),
    };

    let now = current_time_ms();
    let fresh_config = FreshSetupConfig {
        archive_path: resolved_archive_path.to_string_lossy().into_owned(),
        backup_path: resolved_backup_path
            .as_ref()
            .map(|p| p.to_string_lossy().into_owned()),
    };

    let committed = {
        let mut catalog = state.catalog.lock().unwrap();
        match catalog.provision_owner_credentials(
            OwnerProvisionMode::Fresh,
            &verifier_json,
            Some(&fresh_config),
            now,
        ) {
            Ok(success) => success,
            Err(e) => return internal_error(&e.to_string()),
        }
    };

    if !committed {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                code: "setup.already_completed".into(),
                message:
                    "setup could not be committed due to state conflict or existing credentials"
                        .into(),
                request_id: format!("req_{:012x}", current_time_ms()),
            }),
        )
            .into_response();
    }

    *state.archive.write().unwrap() = prepared_archive;
    let mut setup = state.setup_state.lock().unwrap();
    setup.attempted = true;
    setup.admin_provisioned = true;
    setup.recovery_configured = true;
    setup.archive_path = Some(resolved_archive_path.clone());
    setup.backup_path = resolved_backup_path.clone();
    setup.completed_unix_ms = Some(now);
    drop(setup);

    let status_archive_path = Some(safe_display_path(&resolved_archive_path));
    let status_backup_path = resolved_backup_path.as_ref().map(|p| safe_display_path(p));

    let status = SystemSetupStatus {
        archive_initialized: Archive::open(&resolved_archive_path).is_ok(),
        admin_provisioned: true,
        recovery_configured: true,
        is_complete: true,
        legacy_credential_claim_required: None,
        archive_path: status_archive_path,
        backup_path: status_backup_path,
    };

    // Record audit event in catalog
    let event = AuditEvent {
        id: format!(
            "audit_{now:016x}_{:08x}",
            NEXT_AUDIT_EVENT_ID.fetch_add(1, Ordering::Relaxed)
        ),
        event_type: "system_setup".into(),
        actor: request_device_id(&headers).to_string(),
        object_id: None,
        details_json: Some(r#"{"action":"first_run_setup","recoveryConfirmed":true}"#.to_string()),
        created_unix_ms: now,
    };
    if let Err(e) = state.catalog.lock().unwrap().record_audit_event(&event) {
        return internal_error(&e.to_string());
    }

    (
        StatusCode::OK,
        Json(SystemSetupResponse {
            success: true,
            status,
            message: "first-run core setup successfully completed".into(),
        }),
    )
        .into_response()
}

pub(crate) async fn claim_legacy(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<LegacyClaimRequest>,
) -> Response {
    if let Some(resp) = check_bootstrap_token(&headers) {
        return resp;
    }

    if bearer_token(&headers).is_some() {
        return unauthorized("legacy claim uses the unauthenticated bootstrap boundary");
    }

    if !body.recovery_confirmed {
        return bad_request(
            "recovery verification confirmation is required to complete legacy claim",
        );
    }

    if body.owner_password.is_empty() {
        return bad_request("owner password cannot be empty");
    }

    let envelope = match sc_crypto::seal(body.owner_password.as_bytes(), OWNER_VERIFIER_SENTINEL) {
        Ok(env) => env,
        Err(e) => return internal_error(&format!("crypto seal error: {e}")),
    };
    let verifier_json = match serde_json::to_string(&envelope) {
        Ok(j) => j,
        Err(e) => return internal_error(&format!("json serialization error: {e}")),
    };

    let now = current_time_ms();
    let committed = {
        let mut catalog = state.catalog.lock().unwrap();
        match catalog.provision_owner_credentials(
            OwnerProvisionMode::LegacyClaim,
            &verifier_json,
            None,
            now,
        ) {
            Ok(success) => success,
            Err(e) => return internal_error(&e.to_string()),
        }
    };

    if !committed {
        return (
            StatusCode::CONFLICT,
            Json(ErrorResponse {
                code: "setup.claim_conflict".into(),
                message: "legacy claim rejected: credentials already configured or install is not eligible for legacy claim".into(),
                request_id: format!("req_{:012x}", current_time_ms()),
            }),
        )
            .into_response();
    }

    let mut setup = state.setup_state.lock().unwrap();
    setup.admin_provisioned = true;
    setup.recovery_configured = true;
    drop(setup);

    let event = AuditEvent {
        id: format!(
            "audit_{now:016x}_{:08x}",
            NEXT_AUDIT_EVENT_ID.fetch_add(1, Ordering::Relaxed)
        ),
        event_type: "legacy_claim".into(),
        actor: request_device_id(&headers).to_string(),
        object_id: None,
        details_json: Some(r#"{"action":"claim_legacy","recoveryConfirmed":true}"#.to_string()),
        created_unix_ms: now,
    };
    if let Err(e) = state.catalog.lock().unwrap().record_audit_event(&event) {
        return internal_error(&e.to_string());
    }

    let archive = state.archive.read().unwrap();
    let (saved_archive_path, saved_backup_path) = {
        let catalog = state.catalog.lock().unwrap();
        (
            catalog
                .get_meta("setup.archive_path")
                .ok()
                .flatten()
                .map(PathBuf::from),
            catalog
                .get_meta("setup.backup_path")
                .ok()
                .flatten()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
        )
    };

    let status = SystemSetupStatus {
        archive_initialized: Archive::open(archive.root()).is_ok(),
        admin_provisioned: true,
        recovery_configured: true,
        is_complete: true,
        legacy_credential_claim_required: None,
        archive_path: saved_archive_path.as_ref().map(|p| safe_display_path(p)),
        backup_path: saved_backup_path.as_ref().map(|p| safe_display_path(p)),
    };

    (
        StatusCode::OK,
        Json(SystemSetupResponse {
            success: true,
            status,
            message: "legacy owner credentials successfully claimed".into(),
        }),
    )
        .into_response()
}
