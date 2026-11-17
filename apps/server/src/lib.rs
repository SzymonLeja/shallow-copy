//! Core REST API Server and Orchestration Runtime for shallow-copy.
//!
//! Exposes TypeSpec-aligned REST endpoints for archive operations, verification,
//! export jobs, object provenance, and session authentication.
#![forbid(unsafe_code)]

use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use oiaf::Archive;
pub use sc_ingest as ingest;
use sc_policy::{ArchiveDomain, Scope};
pub use sc_preservation_guard as preservation_guard;
pub use sc_recovery as recovery;
use sc_storage::{Catalog, CatalogJob, CatalogObject, JobStatus};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;

#[derive(Clone)]
pub struct AppState {
    pub catalog: Arc<Mutex<Catalog>>,
    pub archive: Arc<Archive>,
    pub auth_tokens: Arc<Mutex<Vec<SessionToken>>>,
}

impl AppState {
    pub fn new(catalog: Catalog, archive: Archive) -> Self {
        Self {
            catalog: Arc::new(Mutex::new(catalog)),
            archive: Arc::new(archive),
            auth_tokens: Arc::new(Mutex::new(Vec::new())),
        }
    }
}

// ============================================================================
// Data Transfer Objects (matching TypeSpec schemas in specs/typespec/)
// ============================================================================

/// Evidence envelope for one source occurrence (specs/typespec/archive/objects.tsp).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SourceObject {
    pub object_id: String,
    pub domain: ArchiveDomain,
    pub blob_digest: String,
    pub blob_size: i64,
    pub blob_algorithm: String,
    pub connector_id: String,
    pub source_instance: String,
    pub external_id: String,
    pub revision: String,
    pub source_locator: String,
    pub observed_time_unix_ms: i64,
    pub ingested_time_unix_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event_time_unix_ms: Option<i64>,
}

impl From<&CatalogObject> for SourceObject {
    fn from(obj: &CatalogObject) -> Self {
        let domain = match obj.suggested_domain.as_deref() {
            Some("private") => ArchiveDomain::Private,
            Some("restricted") => ArchiveDomain::Restricted,
            Some("legacy") => ArchiveDomain::Legacy,
            Some("secrets") => ArchiveDomain::Secrets,
            _ => ArchiveDomain::Public,
        };

        Self {
            object_id: obj.object_id.clone(),
            domain,
            blob_digest: obj.blob_digest.clone(),
            blob_size: obj.blob_size as i64,
            blob_algorithm: "sha256".into(),
            connector_id: obj.connector.clone(),
            source_instance: obj.source_instance.clone(),
            external_id: obj.external_id.clone(),
            revision: obj.revision.clone(),
            source_locator: obj.external_id.clone(),
            observed_time_unix_ms: obj.observed_time_unix_ms as i64,
            ingested_time_unix_ms: obj.ingested_time_unix_ms as i64,
            event_time_unix_ms: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectListResponse {
    pub items: Vec<SourceObject>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ListObjectsQuery {
    pub cursor: Option<String>,
    pub limit: Option<usize>,
    pub domain: Option<ArchiveDomain>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiJob {
    pub job_id: String,
    pub kind: String,
    pub status: JobStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_pct: Option<u8>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl From<CatalogJob> for ApiJob {
    fn from(job: CatalogJob) -> Self {
        Self {
            job_id: job.job_id,
            kind: job.kind,
            status: job.status,
            progress_pct: job.progress_pct,
            created_at: format_unix_ms(job.created_at_unix_ms),
            updated_at: format_unix_ms(job.updated_at_unix_ms),
            error: job.error,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ListJobsQuery {
    pub status: Option<JobStatus>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequestBody {
    pub full: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct ExportRequestBody {
    pub destination: String,
    #[serde(rename = "objectId")]
    pub object_id: Option<String>,
    pub format: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequestBody {
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionToken {
    pub token: String,
    pub scopes: Vec<Scope>,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
    pub request_id: String,
}

// ============================================================================
// Router & Handlers
// ============================================================================

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/v1/archive/objects", get(list_objects))
        .route("/v1/archive/objects/{id}", get(get_object))
        .route("/v1/archive/verify", post(trigger_verify))
        .route("/v1/archive/export", post(trigger_export))
        .route("/v1/jobs", get(list_jobs))
        .route("/v1/jobs/{id}", get(get_job))
        .route("/v1/auth/session", post(login).delete(logout))
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn list_objects(
    State(state): State<AppState>,
    Query(query): Query<ListObjectsQuery>,
) -> Response {
    let cat = state.catalog.lock().unwrap();
    match cat.list_objects() {
        Ok(objects) => {
            let mut items: Vec<SourceObject> = objects
                .iter()
                .map(SourceObject::from)
                .filter(|o| query.domain.is_none() || Some(o.domain) == query.domain)
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
        Err(e) => internal_error(&e.to_string()),
    }
}

async fn get_object(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let cat = state.catalog.lock().unwrap();
    match cat.get_object(&id) {
        Ok(Some(ref obj)) => (StatusCode::OK, Json(SourceObject::from(obj))).into_response(),
        Ok(None) => not_found(&format!("object '{id}' not found")),
        Err(e) => internal_error(&e.to_string()),
    }
}

async fn trigger_verify(
    State(state): State<AppState>,
    Json(_body): Json<Option<VerifyRequestBody>>,
) -> Response {
    let now = current_time_ms();
    let job_id = format!("01J{:022x}", now);

    let job = CatalogJob {
        job_id: job_id.clone(),
        kind: "verify".into(),
        status: JobStatus::Pending,
        progress_pct: Some(0),
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
        error: None,
    };

    {
        let cat = state.catalog.lock().unwrap();
        if let Err(e) = cat.insert_job(&job) {
            return internal_error(&e.to_string());
        }
    }

    // Execute verification run synchronously/inline or background
    let archive = state.archive.clone();
    let catalog = state.catalog.clone();
    let jid = job_id.clone();
    tokio::spawn(async move {
        let full = true;
        let update_now = current_time_ms();
        match archive.verify(full) {
            Ok(report) => {
                let cat = catalog.lock().unwrap();
                let _ =
                    cat.update_job_status(&jid, JobStatus::Completed, Some(100), None, update_now);
                tracing::info!(
                    "verify job {jid} completed: {} objects verified",
                    report.objects
                );
            }
            Err(e) => {
                let cat = catalog.lock().unwrap();
                let _ = cat.update_job_status(
                    &jid,
                    JobStatus::Failed,
                    Some(0),
                    Some(&e.to_string()),
                    update_now,
                );
            }
        }
    });

    (StatusCode::ACCEPTED, Json(ApiJob::from(job))).into_response()
}

async fn trigger_export(
    State(state): State<AppState>,
    Json(body): Json<ExportRequestBody>,
) -> Response {
    let now = current_time_ms();
    let job_id = format!("01J{:022x}", now);

    let job = CatalogJob {
        job_id: job_id.clone(),
        kind: "export".into(),
        status: JobStatus::Pending,
        progress_pct: Some(0),
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
        error: None,
    };

    {
        let cat = state.catalog.lock().unwrap();
        if let Err(e) = cat.insert_job(&job) {
            return internal_error(&e.to_string());
        }
    }

    let archive = state.archive.clone();
    let catalog = state.catalog.clone();
    let jid = job_id.clone();
    tokio::spawn(async move {
        let dest = std::path::PathBuf::from(&body.destination);
        let update_now = current_time_ms();
        match archive.export(&dest, body.object_id.as_deref()) {
            Ok(res) => {
                let cat = catalog.lock().unwrap();
                let _ =
                    cat.update_job_status(&jid, JobStatus::Completed, Some(100), None, update_now);
                tracing::info!(
                    "export job {jid} completed: {} objects exported",
                    res.objects
                );
            }
            Err(e) => {
                let cat = catalog.lock().unwrap();
                let _ = cat.update_job_status(
                    &jid,
                    JobStatus::Failed,
                    Some(0),
                    Some(&e.to_string()),
                    update_now,
                );
            }
        }
    });

    (StatusCode::ACCEPTED, Json(ApiJob::from(job))).into_response()
}

async fn list_jobs(State(state): State<AppState>, Query(query): Query<ListJobsQuery>) -> Response {
    let cat = state.catalog.lock().unwrap();
    match cat.list_jobs(query.status) {
        Ok(jobs) => {
            let api_jobs: Vec<ApiJob> = jobs.into_iter().map(ApiJob::from).collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({ "items": api_jobs })),
            )
                .into_response()
        }
        Err(e) => internal_error(&e.to_string()),
    }
}

async fn get_job(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let cat = state.catalog.lock().unwrap();
    match cat.list_jobs(None) {
        Ok(jobs) => {
            if let Some(job) = jobs.into_iter().find(|j| j.job_id == id) {
                (StatusCode::OK, Json(ApiJob::from(job))).into_response()
            } else {
                not_found(&format!("job '{id}' not found"))
            }
        }
        Err(e) => internal_error(&e.to_string()),
    }
}

async fn login(State(state): State<AppState>, Json(body): Json<LoginRequestBody>) -> Response {
    if body.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                code: "auth.invalid_credentials".into(),
                message: "password cannot be empty".into(),
                request_id: format!("req_{:012x}", current_time_ms()),
            }),
        )
            .into_response();
    }

    let now = current_time_ms();
    let expires_at = now + 86400 * 1000;
    let token = format!("sess_{:016x}", now);
    let session = SessionToken {
        token: token.clone(),
        scopes: vec![
            Scope::ArchiveRead,
            Scope::ArchiveWrite,
            Scope::ArchiveDestructive,
            Scope::KnowledgeRead,
        ],
        expires_at: format_unix_ms(expires_at),
    };

    state.auth_tokens.lock().unwrap().push(session.clone());

    (StatusCode::OK, Json(session)).into_response()
}

async fn logout(State(state): State<AppState>) -> Response {
    state.auth_tokens.lock().unwrap().clear();
    StatusCode::NO_CONTENT.into_response()
}

fn not_found(message: &str) -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(ErrorResponse {
            code: "resource.not_found".into(),
            message: message.to_owned(),
            request_id: format!("req_{:012x}", current_time_ms()),
        }),
    )
        .into_response()
}

fn internal_error(message: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(ErrorResponse {
            code: "internal.server_error".into(),
            message: message.to_owned(),
            request_id: format!("req_{:012x}", current_time_ms()),
        }),
    )
        .into_response()
}

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn format_unix_ms(ms: u64) -> String {
    let total_secs = ms / 1000;
    let s = total_secs % 60;
    let m = (total_secs / 60) % 60;
    let h = (total_secs / 3600) % 24;
    let days_since_epoch = total_secs / 86400;
    let (year, month, day) = days_to_date(days_since_epoch);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn days_to_date(days: u64) -> (u32, u32, u32) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as u32, m as u32, d as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn setup_test_app() -> (Router, tempfile::TempDir) {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("archive");
        let archive = Archive::init(&archive_path).unwrap();

        let source = oiaf::Source::filesystem("node-test", "note.txt", "rev-1");
        archive.import_bytes(b"hello world", source).unwrap();

        let mut catalog = Catalog::open_in_memory().unwrap();
        catalog.rebuild_from_archive(&archive).unwrap();

        let state = AppState::new(catalog, archive);
        let router = create_router(state);
        (router, temp)
    }

    #[tokio::test]
    async fn object_listing_and_provenance_endpoint() {
        let (app, _temp) = setup_test_app();

        // 1. List objects
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

        // 1. Trigger verification job
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/archive/verify")
                    .header("content-type", "application/json")
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
        assert!(session.scopes.contains(&Scope::ArchiveRead));

        // 2. Logout
        let response = app
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/v1/auth/session")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }
}
