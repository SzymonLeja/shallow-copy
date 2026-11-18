//! Stable HTTP error responses shared by every server route.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::{ErrorResponse, current_time_ms};

pub(crate) fn unauthorized(message: &str) -> Response {
    response(StatusCode::UNAUTHORIZED, "auth.unauthorized", message)
}

pub(crate) fn bad_request(message: &str) -> Response {
    response(StatusCode::BAD_REQUEST, "request.invalid", message)
}

pub(crate) fn forbidden(message: &str) -> Response {
    response(
        StatusCode::FORBIDDEN,
        "guard.confirmation_required",
        message,
    )
}

pub(crate) fn not_found(message: &str) -> Response {
    response(StatusCode::NOT_FOUND, "resource.not_found", message)
}

pub(crate) fn internal_error(message: &str) -> Response {
    response(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal.server_error",
        message,
    )
}

fn response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(ErrorResponse {
            code: code.into(),
            message: message.to_owned(),
            request_id: format!("req_{:012x}", current_time_ms()),
        }),
    )
        .into_response()
}
