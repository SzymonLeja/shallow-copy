//! Health and static web application delivery handlers.

use std::path::PathBuf;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use tower::ServiceExt;
use tower_http::services::ServeFile;

use crate::{AppState, ErrorResponse, STATIC_DIR_ENV, current_time_ms};

pub(crate) async fn health() -> &'static str {
    "ok"
}

pub(crate) async fn static_or_spa_fallback(
    State(state): State<AppState>,
    request: axum::http::Request<axum::body::Body>,
) -> Response {
    let path = request.uri().path().to_string();
    if path.starts_with("/v1/") || path == "/v1" {
        return api_error(
            StatusCode::NOT_FOUND,
            "not_found",
            format!("route {path} not found"),
        );
    }
    if request.method() != axum::http::Method::GET && request.method() != axum::http::Method::HEAD {
        return api_error(
            StatusCode::METHOD_NOT_ALLOWED,
            "method_not_allowed",
            format!("method {} not allowed on {path}", request.method()),
        );
    }

    let dirs = resolve_static_dirs(&state);
    let clean_path = path.trim_start_matches('/');
    if !clean_path.is_empty() {
        for dir in &dirs {
            let candidate = dir.join(clean_path);
            if candidate.is_file() {
                let Ok(response) = ServeFile::new(candidate).oneshot(request).await;
                return response.into_response();
            }
        }
        for dir in &dirs {
            let candidate = dir.join("dist").join(clean_path);
            if candidate.is_file() {
                let Ok(response) = ServeFile::new(candidate).oneshot(request).await;
                return response.into_response();
            }
        }
    }
    for dir in &dirs {
        for candidate in [dir.join("index.html"), dir.join("dist").join("index.html")] {
            if candidate.is_file() {
                let Ok(response) = ServeFile::new(candidate).oneshot(request).await;
                return response.into_response();
            }
        }
    }
    (StatusCode::NOT_FOUND, "index.html not found").into_response()
}

fn api_error(status: StatusCode, code: &str, message: String) -> Response {
    (
        status,
        Json(ErrorResponse {
            code: code.into(),
            message,
            request_id: format!("req_{:012x}", current_time_ms()),
        }),
    )
        .into_response()
}

fn resolve_static_dirs(state: &AppState) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(dir) = &state.static_dir {
        dirs.push(dir.clone());
    }
    if let Ok(dir) = std::env::var(STATIC_DIR_ENV) {
        let path = PathBuf::from(dir);
        if !dirs.contains(&path) {
            dirs.push(path);
        }
    }
    for default_dir in [
        "apps/web",
        "apps/web/dist",
        "../../apps/web",
        "../../apps/web/dist",
        "/app/apps/web",
        "/app/apps/web/dist",
    ] {
        let path = PathBuf::from(default_dir);
        if !dirs.contains(&path) {
            dirs.push(path);
        }
    }
    dirs
}
