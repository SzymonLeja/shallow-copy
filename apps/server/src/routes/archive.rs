//! Canonical archive read, backup-manifest, and recovery HTTP handlers.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use oiaf::BackupManifest;

use crate::{
    AppState, BackupManifestVerifyResponse, ListAuditQuery, ListObjectsQuery, ObjectListResponse,
    RecoveryDrillResponse, SourceObject, current_time_ms, internal_error, not_found, recovery,
};

pub(crate) async fn list_objects(
    State(state): State<AppState>,
    Query(query): Query<ListObjectsQuery>,
) -> Response {
    let cat = state.catalog.lock().unwrap();
    match cat.list_objects() {
        Ok(objects) => {
            let mut items: Vec<SourceObject> = objects
                .iter()
                .map(SourceObject::from)
                .filter(|object| query.domain.is_none() || Some(object.domain) == query.domain)
                .collect();
            let total = items.len() as i64;
            let limit = query.limit.unwrap_or(50).clamp(1, 100);
            if items.len() > limit {
                items.truncate(limit);
            }
            (
                StatusCode::OK,
                Json(ObjectListResponse {
                    items,
                    next_cursor: None,
                    total: Some(total),
                }),
            )
                .into_response()
        }
        Err(error) => internal_error(&error.to_string()),
    }
}

pub(crate) async fn get_object(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let cat = state.catalog.lock().unwrap();
    match cat.get_object(&id) {
        Ok(Some(ref object)) => (StatusCode::OK, Json(SourceObject::from(object))).into_response(),
        Ok(None) => not_found(&format!("object '{id}' not found")),
        Err(error) => internal_error(&error.to_string()),
    }
}

pub(crate) async fn list_audit_events(
    State(state): State<AppState>,
    Query(query): Query<ListAuditQuery>,
) -> Response {
    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let catalog = state.catalog.lock().unwrap();
    match catalog.list_audit_events(limit) {
        Ok(events) => (StatusCode::OK, Json(events)).into_response(),
        Err(error) => internal_error(&error.to_string()),
    }
}

pub(crate) async fn generate_backup_manifest(State(state): State<AppState>) -> Response {
    match state.archive.read().unwrap().generate_backup_manifest() {
        Ok(manifest) => (StatusCode::OK, Json(manifest)).into_response(),
        Err(error) => internal_error(&error.to_string()),
    }
}

pub(crate) async fn verify_backup_manifest(
    State(state): State<AppState>,
    Json(manifest): Json<BackupManifest>,
) -> Response {
    match state
        .archive
        .read()
        .unwrap()
        .verify_backup_manifest(&manifest)
    {
        Ok(valid) => (StatusCode::OK, Json(BackupManifestVerifyResponse { valid })).into_response(),
        Err(error) => internal_error(&error.to_string()),
    }
}

pub(crate) async fn trigger_recovery_drill(State(state): State<AppState>) -> Response {
    let objects_tested = {
        let catalog = state.catalog.lock().unwrap();
        match catalog.list_objects() {
            Ok(objects) => objects.len() as i32,
            Err(error) => return internal_error(&error.to_string()),
        }
    };
    let recovery_key = recovery::RecoveryKey::generate();
    let now = current_time_ms();
    let fixture = match recovery::RecoveryDrill::create_fixture(
        &recovery_key,
        b"recovery-drill-offline-verification",
        now,
    ) {
        Ok(fixture) => fixture,
        Err(error) => return internal_error(&error.to_string()),
    };
    let outcome = match recovery::RecoveryDrill::execute_drill(&fixture, &recovery_key) {
        Ok(outcome) => outcome,
        Err(error) => return internal_error(&error.to_string()),
    };
    (
        StatusCode::OK,
        Json(RecoveryDrillResponse {
            success: outcome.success,
            objects_tested,
        }),
    )
        .into_response()
}
