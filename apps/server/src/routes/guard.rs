//! Preservation Guard HTTP handlers and request-bound confirmation checks.

use std::hash::{BuildHasher, Hash, Hasher};
use std::sync::atomic::Ordering;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use sc_preservation_guard::{GuardSession, GuardedOperation};
use sc_storage::AuditEvent;

use crate::{
    AppState, GUARD_CONFIRMATION_TTL_MS, GUARD_QUARANTINE_DELAY_MS, GuardActionRequestBody,
    GuardActionResponse, GuardAnalyzeRequestBody, GuardAnalyzeResponse, GuardSessionRecord,
    MAX_GUARDED_OBJECTS, NEXT_AUDIT_EVENT_ID, NEXT_GUARD_SESSION_ID, bad_request, bearer_token,
    current_time_ms, forbidden, format_unix_ms, internal_error, request_device_id,
};

pub(crate) async fn analyze_guarded_delete(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<GuardAnalyzeRequestBody>,
) -> Response {
    if !request_has_destructive_scope(&state, &headers) {
        return forbidden("guarded operations require archive.destructive scope");
    }
    if body.object_ids.is_empty()
        || body.object_ids.len() > MAX_GUARDED_OBJECTS
        || body
            .object_ids
            .iter()
            .any(|object_id| object_id.is_empty() || object_id.len() > 128)
    {
        return bad_request("object_ids must contain between 1 and 100 valid identifiers");
    }

    let mut object_ids = Vec::with_capacity(body.object_ids.len());
    for object_id in body.object_ids {
        if !object_ids.contains(&object_id) {
            object_ids.push(object_id);
        }
    }
    let expected_object_count = object_ids.len();
    let mut session =
        GuardSession::new("pending", GuardedOperation::DeleteCanonical { object_ids });
    let impact = {
        let catalog = state.catalog.lock().unwrap();
        match session.run_impact_analysis(&catalog, false) {
            Ok(report) if report.affected_objects == expected_object_count => report.clone(),
            Ok(_) => return bad_request("all requested objects must exist in the catalog"),
            Err(error) => return internal_error(&error.to_string()),
        }
    };

    let now = current_time_ms();
    let session_id = format!(
        "guard_{now:016x}_{:08x}",
        NEXT_GUARD_SESSION_ID.fetch_add(1, Ordering::Relaxed)
    );
    session.id = session_id.clone();
    let owner_token = bearer_token(&headers).unwrap_or_default().to_owned();
    let owner_device_id = request_device_id(&headers).to_owned();
    let confirmation_token = new_guard_confirmation_token(&session_id, &owner_token, now);
    let expires_at_unix_ms = now.saturating_add(GUARD_CONFIRMATION_TTL_MS);
    let response = GuardAnalyzeResponse {
        session_id: session_id.clone(),
        confirmation_token: confirmation_token.clone(),
        confirmation_expires_at_unix_ms: expires_at_unix_ms,
        impact,
    };

    let mut sessions = state.guard_sessions.lock().unwrap();
    sessions.retain(|_, record| record.expires_at_unix_ms > now);
    sessions.insert(
        session_id,
        GuardSessionRecord {
            session,
            confirmation_token,
            owner_token,
            owner_device_id,
            expires_at_unix_ms,
        },
    );
    (StatusCode::OK, Json(response)).into_response()
}

pub(crate) async fn confirm_guarded_delete(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<GuardActionRequestBody>,
) -> Response {
    if !request_has_destructive_scope(&state, &headers) {
        return forbidden("guarded operations require archive.destructive scope");
    }
    let owner_token = bearer_token(&headers).unwrap_or_default();
    let owner_device_id = request_device_id(&headers);
    let now = current_time_ms();
    let mut sessions = state.guard_sessions.lock().unwrap();
    let Some(record) = sessions.get_mut(&body.session_id) else {
        return forbidden("guard session is invalid or expired");
    };
    if record.expires_at_unix_ms <= now
        || record.owner_token != owner_token
        || record.owner_device_id != owner_device_id
        || record.confirmation_token != body.confirmation_token
        || record.confirmation_token.is_empty()
    {
        return forbidden("guard confirmation token is invalid or expired");
    }
    if let Err(error) = record.session.confirm_step_up(
        &body.typed_confirmation,
        body.allow_unverified_backup_override,
    ) {
        return forbidden(&error.to_string());
    }
    if let Err(error) = record
        .session
        .enter_quarantine(GUARD_QUARANTINE_DELAY_MS, now)
    {
        return internal_error(&error.to_string());
    }
    record.confirmation_token.clear();

    let session_id = record.session.id.clone();
    let session_state = record.session.state;
    let step_up_confirmed = record.session.step_up_confirmed;
    let quarantine_deadline_unix_ms = record.session.quarantine_deadline_unix_ms;
    let (object_id, details_json) = match &record.session.operation {
        GuardedOperation::DeleteCanonical { object_ids }
        | GuardedOperation::LossyTranscodeRemoveSource { object_ids } => (
            object_ids.first().cloned(),
            Some(format!(
                r#"{{"sessionId":"{session_id}","affectedObjects":{}}}"#,
                object_ids.len()
            )),
        ),
        other => (
            None,
            Some(format!(
                r#"{{"sessionId":"{session_id}","operation":"{other:?}"}}"#
            )),
        ),
    };
    drop(sessions);

    let event = AuditEvent {
        id: format!(
            "audit_{now:016x}_{:08x}",
            NEXT_AUDIT_EVENT_ID.fetch_add(1, Ordering::Relaxed)
        ),
        event_type: "guard_action".into(),
        actor: owner_device_id.to_string(),
        object_id,
        details_json,
        created_unix_ms: now,
    };
    if let Err(error) = state.catalog.lock().unwrap().record_audit_event(&event) {
        return internal_error(&error.to_string());
    }
    (
        StatusCode::OK,
        Json(GuardActionResponse {
            session_id,
            state: session_state,
            step_up_confirmed,
            quarantine_deadline_unix_ms,
        }),
    )
        .into_response()
}

fn request_has_destructive_scope(state: &AppState, headers: &axum::http::HeaderMap) -> bool {
    let Some(token) = bearer_token(headers) else {
        return false;
    };
    let device_id = request_device_id(headers);
    state.auth_tokens.lock().unwrap().iter().any(|session| {
        session.token == token
            && session.device_id == device_id
            && session.expires_at > format_unix_ms(current_time_ms())
            && GuardSession::verify_policy_scope(&session.scopes).is_ok()
    })
}

fn new_guard_confirmation_token(session_id: &str, owner_token: &str, now: u64) -> String {
    (0..4)
        .map(|_| {
            let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
            session_id.hash(&mut hasher);
            owner_token.hash(&mut hasher);
            now.hash(&mut hasher);
            format!("{:016x}", hasher.finish())
        })
        .collect()
}
