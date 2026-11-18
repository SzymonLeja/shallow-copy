//! Session authentication and HTTP authorization middleware.

use axum::{
    Json,
    extract::State,
    http::{Request, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use rand::RngCore;
use sc_policy::Scope;

use crate::{
    AppState, LoginRequestBody, OWNER_VERIFIER_SENTINEL, SessionToken, current_time_ms,
    format_unix_ms, hex_digest, unauthorized,
};

pub(crate) async fn authorize_request(
    State(state): State<AppState>,
    request: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let required_scope = if request.method() == axum::http::Method::GET
        || request.uri().path() == "/v1/archive/recovery/drill"
        || request.uri().path() == "/v1/archive/recovery/drill/"
    {
        Scope::ArchiveRead
    } else {
        Scope::ArchiveWrite
    };

    let Some(token) = bearer_token(request.headers()) else {
        return unauthorized("missing bearer token");
    };
    let device_id = request
        .headers()
        .get("x-device-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("local-device");
    let authorized = state.auth_tokens.lock().unwrap().iter().any(|session| {
        session.token == token
            && session.device_id == device_id
            && session.scopes.contains(&required_scope)
            && session.expires_at > format_unix_ms(current_time_ms())
    });

    if !authorized {
        return unauthorized("invalid or expired bearer token");
    }
    if state.archive_config_error.lock().unwrap().is_some() {
        return crate::internal_error("configured archive could not be opened");
    }
    next.run(request).await
}

pub(crate) fn has_real_session(state: &AppState) -> bool {
    let now = format_unix_ms(current_time_ms());
    state
        .auth_tokens
        .lock()
        .unwrap()
        .iter()
        .any(|session| session.expires_at > now)
}

pub(crate) fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

pub(crate) fn request_device_id(headers: &axum::http::HeaderMap) -> &str {
    headers
        .get("x-device-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("local-device")
}

pub(crate) async fn login(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<LoginRequestBody>,
) -> Response {
    if body.password.is_empty() {
        return unauthorized("password cannot be empty");
    }

    let verifier_json = {
        let catalog = state.catalog.lock().unwrap();
        match catalog.get_meta("setup.owner_verifier") {
            Ok(Some(v)) if !v.is_empty() => v,
            _ => return unauthorized("owner credentials have not been provisioned"),
        }
    };
    let envelope: sc_crypto::SealedEnvelope = match serde_json::from_str(&verifier_json) {
        Ok(env) => env,
        Err(_) => return unauthorized("invalid verifier envelope in state"),
    };
    let opened = matches!(
        sc_crypto::open(body.password.as_bytes(), &envelope),
        Ok(plaintext) if plaintext == OWNER_VERIFIER_SENTINEL
    );
    if !opened {
        return unauthorized("invalid credentials");
    }

    let now = current_time_ms();
    let device_id = headers
        .get("x-device-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("local-device")
        .to_owned();
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    let token = format!("sess_{}", hex_digest(&token_bytes));
    let session = SessionToken {
        token,
        device_id,
        scopes: vec![
            Scope::ArchiveRead,
            Scope::ArchiveWrite,
            Scope::ArchiveDestructive,
            Scope::KnowledgeRead,
        ],
        expires_at: format_unix_ms(now + 86400 * 1000),
    };
    state.auth_tokens.lock().unwrap().push(session.clone());
    (axum::http::StatusCode::OK, Json(session)).into_response()
}

pub(crate) async fn logout(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> Response {
    let Some(token) = bearer_token(&headers) else {
        return unauthorized("missing bearer token");
    };
    state
        .auth_tokens
        .lock()
        .unwrap()
        .retain(|session| session.token != token);
    axum::http::StatusCode::NO_CONTENT.into_response()
}
