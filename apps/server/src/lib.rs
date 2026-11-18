//! Core REST API Server and Orchestration Runtime for shallow-copy.
//!
//! Exposes TypeSpec-aligned REST endpoints for archive operations, verification,
//! export jobs, object provenance, and session authentication.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::hash::{BuildHasher, Hash, Hasher};
use std::path::{Component, Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{Request, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use oiaf::{Archive, BackupManifest};
pub use sc_connector_browser_chromium as browser_connector;
use sc_connector_browser_chromium::{ChromiumHistoryConfig, ChromiumHistoryConnector};
pub use sc_ingest as ingest;
use sc_ingest::{IngestGateway, IngestItem};
use sc_policy::{ArchiveDomain, Scope};
pub use sc_preservation_guard as preservation_guard;
use sc_preservation_guard::{GuardSession, GuardState, GuardedOperation, ImpactReport};
pub use sc_recovery as recovery;
use sc_storage::{AuditEvent, Catalog, CatalogJob, CatalogObject, JobStatus};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tower::ServiceExt;
use tower_http::cors::CorsLayer;
use tower_http::services::ServeFile;
use tower_http::trace::TraceLayer;

const BROWSER_HISTORY_PATH_ENV: &str = "BROWSER_HISTORY_PATH";
const FILESYSTEM_INGEST_ROOT_ENV: &str = "FILESYSTEM_INGEST_ROOT";
const STATIC_DIR_ENV: &str = "STATIC_DIR";
const MAX_FILESYSTEM_INGEST_PATH_BYTES: usize = 4096;
const MAX_FILESYSTEM_INGEST_FILE_BYTES: u64 = 16 * 1024 * 1024;
const MAX_GUARDED_OBJECTS: usize = 100;
const GUARD_CONFIRMATION_TTL_MS: u64 = 5 * 60 * 1000;
const GUARD_QUARANTINE_DELAY_MS: u64 = 24 * 60 * 60 * 1000;
static NEXT_GUARD_SESSION_ID: AtomicU64 = AtomicU64::new(0);
static NEXT_AUDIT_EVENT_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct AppState {
    pub catalog: Arc<Mutex<Catalog>>,
    pub archive: Arc<RwLock<Archive>>,
    pub auth_tokens: Arc<Mutex<Vec<SessionToken>>>,
    pub filesystem_ingest_root: Option<PathBuf>,
    pub browser_history_path: Option<PathBuf>,
    pub static_dir: Option<PathBuf>,
    guard_sessions: Arc<Mutex<HashMap<String, GuardSessionRecord>>>,
    pub setup_state: Arc<Mutex<SetupStateRecord>>,
    archive_config_error: Arc<Mutex<Option<String>>>,
    #[cfg(test)]
    setup_meta_fail_key: Arc<Mutex<Option<String>>>,
}

impl AppState {
    pub fn new(catalog: Catalog, archive: Archive) -> Self {
        let setup_ready = match catalog.get_meta("setup.prepared_unix_ms") {
            Ok(Some(_)) => true,
            Ok(None) => match catalog.get_meta("setup.completed_unix_ms") {
                Ok(value) => value.is_some(),
                Err(_) => false,
            },
            Err(_) => false,
        };
        let (archive, archive_config_error) = if setup_ready {
            match catalog.get_meta("setup.archive_path") {
                Ok(Some(path)) => match Archive::open(&path) {
                    Ok(configured_archive) => (configured_archive, None),
                    Err(error) => (archive, Some(error.to_string())),
                },
                Ok(None) => (archive, Some("configured archive path is missing".into())),
                Err(error) => (archive, Some(error.to_string())),
            }
        } else {
            (archive, None)
        };
        let setup_state = {
            let mut record = SetupStateRecord::default();
            if let Some(ms) = catalog
                .get_meta("setup.completed_unix_ms")
                .ok()
                .flatten()
                .and_then(|s| s.parse::<u64>().ok())
            {
                record.completed_unix_ms = Some(ms);
            }
            record.attempted = catalog
                .get_meta("setup.prepared_unix_ms")
                .ok()
                .flatten()
                .is_some();
            record.admin_provisioned = catalog
                .get_meta("setup.admin_provisioned")
                .ok()
                .flatten()
                .is_some_and(|value| value == "true");
            record.recovery_configured = catalog
                .get_meta("setup.recovery_configured")
                .ok()
                .flatten()
                .is_some_and(|value| value == "true");
            if setup_ready {
                if let Ok(Some(ap)) = catalog.get_meta("setup.archive_path") {
                    record.archive_path = Some(PathBuf::from(ap));
                }
                if let Ok(Some(bp)) = catalog.get_meta("setup.backup_path")
                    && !bp.is_empty()
                {
                    record.backup_path = Some(PathBuf::from(bp));
                }
            }
            Arc::new(Mutex::new(record))
        };
        Self {
            catalog: Arc::new(Mutex::new(catalog)),
            archive: Arc::new(RwLock::new(archive)),
            auth_tokens: Arc::new(Mutex::new(Vec::new())),
            filesystem_ingest_root: std::env::var_os(FILESYSTEM_INGEST_ROOT_ENV).map(PathBuf::from),
            browser_history_path: std::env::var_os(BROWSER_HISTORY_PATH_ENV).map(PathBuf::from),
            static_dir: std::env::var_os(STATIC_DIR_ENV).map(PathBuf::from),
            guard_sessions: Arc::new(Mutex::new(HashMap::new())),
            setup_state,
            archive_config_error: Arc::new(Mutex::new(archive_config_error)),
            #[cfg(test)]
            setup_meta_fail_key: Arc::new(Mutex::new(None)),
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

#[derive(Debug, Deserialize)]
pub struct ListAuditQuery {
    pub limit: Option<usize>,
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
#[serde(deny_unknown_fields)]
pub struct FilesystemIngestRequestBody {
    pub path: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FilesystemIngestResponse {
    pub object_id: String,
    pub ingest_fingerprint: String,
    pub created: bool,
}

/// Request body for browser history ingestion (specs/typespec/archive/browser.tsp).
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserHistoryIngestRequestBody {
    #[serde(rename = "sourceInstance", default)]
    pub source_instance: Option<String>,
}

/// Response body for browser history ingestion (specs/typespec/archive/browser.tsp).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserHistoryIngestResponse {
    pub source_instance: String,
    pub total_visits: i64,
    pub imported_count: i64,
    pub skipped_count: i64,
    pub object_ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuardAnalyzeRequestBody {
    pub object_ids: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardAnalyzeResponse {
    pub session_id: String,
    pub confirmation_token: String,
    pub confirmation_expires_at_unix_ms: u64,
    pub impact: ImpactReport,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuardActionRequestBody {
    pub session_id: String,
    pub confirmation_token: String,
    pub typed_confirmation: String,
    pub allow_unverified_backup_override: bool,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuardActionResponse {
    pub session_id: String,
    pub state: GuardState,
    pub step_up_confirmed: bool,
    pub quarantine_deadline_unix_ms: Option<u64>,
}

struct GuardSessionRecord {
    session: GuardSession,
    confirmation_token: String,
    owner_token: String,
    owner_device_id: String,
    expires_at_unix_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BackupManifestVerifyResponse {
    pub valid: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryDrillResponse {
    pub success: bool,
    pub objects_tested: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemReadinessResponse {
    pub archive_ready: bool,
    pub object_count: i64,
    pub pending_jobs: i64,
    pub failed_jobs: i64,
    pub filesystem_ingest_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<String>,
}

/// First-run core setup status (specs/typespec/system/setup.tsp).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemSetupStatus {
    pub archive_initialized: bool,
    pub admin_provisioned: bool,
    pub recovery_configured: bool,
    pub is_complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub archive_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<String>,
}

/// Request body for first-run core setup (specs/typespec/system/setup.tsp).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SystemSetupRequest {
    pub archive_path: Option<String>,
    pub backup_path: Option<String>,
    pub recovery_confirmed: bool,
}

/// Response body for first-run core setup (specs/typespec/system/setup.tsp).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemSetupResponse {
    pub success: bool,
    pub status: SystemSetupStatus,
    pub message: String,
}

#[derive(Debug, Clone, Default)]
pub struct SetupStateRecord {
    pub attempted: bool,
    pub admin_provisioned: bool,
    pub recovery_configured: bool,
    pub archive_path: Option<PathBuf>,
    pub backup_path: Option<PathBuf>,
    pub completed_unix_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequestBody {
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionToken {
    pub token: String,
    pub device_id: String,
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
    let protected_routes = Router::new()
        .route("/v1/archive/objects", get(list_objects))
        .route("/v1/archive/objects/{id}", get(get_object))
        .route("/v1/archive/audit", get(list_audit_events))
        .route(
            "/v1/archive/backup-manifest",
            get(generate_backup_manifest).post(generate_backup_manifest),
        )
        .route(
            "/v1/archive/backup-manifest/generate",
            post(generate_backup_manifest),
        )
        .route(
            "/v1/archive/backup-manifest/verify",
            post(verify_backup_manifest),
        )
        .route("/v1/archive/recovery/drill", post(trigger_recovery_drill))
        .route("/v1/archive/verify", post(trigger_verify))
        .route("/v1/archive/export", post(trigger_export))
        .route(
            "/v1/archive/ingest/filesystem",
            post(ingest_filesystem_file),
        )
        .route(
            "/v1/archive/ingest/browser-history",
            post(ingest_browser_history),
        )
        .route(
            "/v1/archive/ingest/browser/chromium",
            post(ingest_browser_history),
        )
        .route("/v1/archive/guard/analyze", post(analyze_guarded_delete))
        .route("/v1/archive/guard/action", post(confirm_guarded_delete))
        .route("/v1/jobs", get(list_jobs))
        .route("/v1/jobs/{id}", get(get_job))
        .route("/v1/system/readiness", get(system_readiness))
        .route("/v1/system/setup", get(get_setup_status))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            authorize_request,
        ));

    // POST /v1/system/setup is intentionally outside protected_routes:
    // the bootstrap window allows unauthenticated POST until setup is complete,
    // then the handler itself returns 409 Conflict for all subsequent attempts.
    Router::new()
        .route("/health", get(health))
        .route("/v1/auth/session", post(login).delete(logout))
        .route("/v1/system/setup", post(execute_setup))
        .merge(protected_routes)
        .fallback(static_or_spa_fallback)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

async fn static_or_spa_fallback(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
) -> Response {
    let path = req.uri().path().to_string();

    // Preserve /v1/* semantics: do not serve index.html on unknown API routes
    if path.starts_with("/v1/") || path == "/v1" {
        return (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                code: "not_found".into(),
                message: format!("route {path} not found"),
                request_id: format!("req_{:012x}", current_time_ms()),
            }),
        )
            .into_response();
    }

    if req.method() != axum::http::Method::GET && req.method() != axum::http::Method::HEAD {
        return (
            StatusCode::METHOD_NOT_ALLOWED,
            Json(ErrorResponse {
                code: "method_not_allowed".into(),
                message: format!("method {} not allowed on {path}", req.method()),
                request_id: format!("req_{:012x}", current_time_ms()),
            }),
        )
            .into_response();
    }

    let dirs = resolve_static_dirs(&state);
    let clean_path = path.trim_start_matches('/');

    // 1. If a specific path was requested, try serving matching file from static directories
    if !clean_path.is_empty() {
        for dir in &dirs {
            let candidate = dir.join(clean_path);
            if candidate.is_file() {
                let Ok(resp) = ServeFile::new(candidate).oneshot(req).await;
                return resp.into_response();
            }
        }
        for dir in &dirs {
            let candidate = dir.join("dist").join(clean_path);
            if candidate.is_file() {
                let Ok(resp) = ServeFile::new(candidate).oneshot(req).await;
                return resp.into_response();
            }
        }
    }

    // 2. Fallback to index.html on root / SPA paths
    for dir in &dirs {
        for candidate in [dir.join("index.html"), dir.join("dist").join("index.html")] {
            if candidate.is_file() {
                let Ok(resp) = ServeFile::new(candidate).oneshot(req).await;
                return resp.into_response();
            }
        }
    }

    (StatusCode::NOT_FOUND, "index.html not found").into_response()
}

fn resolve_static_dirs(state: &AppState) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(ref dir) = state.static_dir {
        dirs.push(dir.clone());
    }
    if let Ok(dir) = std::env::var(STATIC_DIR_ENV) {
        let p = PathBuf::from(dir);
        if !dirs.contains(&p) {
            dirs.push(p);
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
        let p = PathBuf::from(default_dir);
        if !dirs.contains(&p) {
            dirs.push(p);
        }
    }
    dirs
}

async fn authorize_request(
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
        return internal_error("configured archive could not be opened");
    }

    next.run(request).await
}

fn has_real_session(state: &AppState) -> bool {
    let now = format_unix_ms(current_time_ms());
    state
        .auth_tokens
        .lock()
        .unwrap()
        .iter()
        .any(|session| session.expires_at > now)
}

fn set_setup_meta(state: &AppState, key: &str, value: &str) -> Result<(), String> {
    #[cfg(test)]
    if state.setup_meta_fail_key.lock().unwrap().as_deref() == Some(key) {
        return Err(format!("injected catalog metadata failure for {key}"));
    }
    state
        .catalog
        .lock()
        .unwrap()
        .set_meta(key, value)
        .map_err(|error| error.to_string())
}

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

fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
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

async fn list_audit_events(
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

async fn generate_backup_manifest(State(state): State<AppState>) -> Response {
    match state.archive.read().unwrap().generate_backup_manifest() {
        Ok(manifest) => (StatusCode::OK, Json(manifest)).into_response(),
        Err(error) => internal_error(&error.to_string()),
    }
}

async fn verify_backup_manifest(
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

async fn trigger_recovery_drill(State(state): State<AppState>) -> Response {
    let objects_tested = {
        let cat = state.catalog.lock().unwrap();
        match cat.list_objects() {
            Ok(objs) => objs.len() as i32,
            Err(e) => return internal_error(&e.to_string()),
        }
    };

    let recovery_key = recovery::RecoveryKey::generate();
    let control_payload = b"recovery-drill-offline-verification";
    let now = current_time_ms();
    let fixture = match recovery::RecoveryDrill::create_fixture(&recovery_key, control_payload, now)
    {
        Ok(f) => f,
        Err(e) => return internal_error(&e.to_string()),
    };
    let outcome = match recovery::RecoveryDrill::execute_drill(&fixture, &recovery_key) {
        Ok(o) => o,
        Err(e) => return internal_error(&e.to_string()),
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

async fn system_readiness(State(state): State<AppState>) -> Response {
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

async fn get_setup_status(State(state): State<AppState>) -> Response {
    let archive = state.archive.read().unwrap();
    let archive_initialized = Archive::open(archive.root()).is_ok();

    let (catalog_completed, catalog_prepared, catalog_recovery_configured) = {
        let catalog = state.catalog.lock().unwrap();
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
        (completed, prepared, configured)
    };

    let setup = state.setup_state.lock().unwrap();
    let admin_provisioned = setup.admin_provisioned || has_real_session(&state);
    let recovery_configured = setup.recovery_configured
        || ((catalog_prepared || catalog_completed) && catalog_recovery_configured);
    let is_complete = setup.completed_unix_ms.is_some() || catalog_completed || catalog_prepared;

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
            archive_path,
            backup_path,
        }),
    )
        .into_response()
}

async fn execute_setup(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<SystemSetupRequest>,
) -> Response {
    let mut setup = state.setup_state.lock().unwrap();
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
        attempted || completed
    };
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

    if bearer_token(&headers).is_some() {
        return unauthorized("first-run setup uses the unauthenticated bootstrap boundary");
    }

    // Require recovery confirmation
    if !body.recovery_confirmed {
        return bad_request("recovery verification confirmation is required to complete setup");
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

    let now = current_time_ms();
    let admin_provisioned = setup.admin_provisioned || has_real_session(&state);

    // Persist configuration first, then a durable prepared marker, and completion
    // last. A failure before prepared is retry-safe; after prepared, all required
    // configuration is durable and restart rejects replay.
    for (key, value) in [
        ("setup.admin_provisioned", admin_provisioned.to_string()),
        ("setup.recovery_configured", "true".to_string()),
        (
            "setup.archive_path",
            resolved_archive_path.to_string_lossy().into_owned(),
        ),
    ] {
        if let Err(error) = set_setup_meta(&state, key, &value) {
            return internal_error(&error);
        }
    }
    let backup_value = resolved_backup_path
        .as_ref()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_default();
    if let Err(error) = set_setup_meta(&state, "setup.backup_path", &backup_value) {
        return internal_error(&error);
    }
    if let Err(error) = set_setup_meta(&state, "setup.prepared_unix_ms", &now.to_string()) {
        return internal_error(&error);
    }

    // The prepared marker is the commit boundary: all required catalog fields
    // are durable, and the selected archive is active before completion is
    // published. This keeps the service consistent if the final write fails.
    *state.archive.write().unwrap() = prepared_archive;
    setup.attempted = true;
    setup.admin_provisioned = admin_provisioned;
    setup.recovery_configured = true;
    setup.archive_path = Some(resolved_archive_path.clone());
    setup.backup_path = resolved_backup_path.clone();

    if let Err(error) = set_setup_meta(&state, "setup.completed_unix_ms", &now.to_string()) {
        return internal_error(&error);
    }

    setup.completed_unix_ms = Some(now);

    let status_archive_path = Some(safe_display_path(&resolved_archive_path));
    let status_backup_path = resolved_backup_path.as_ref().map(|p| safe_display_path(p));

    let status = SystemSetupStatus {
        archive_initialized: Archive::open(&resolved_archive_path).is_ok(),
        admin_provisioned,
        recovery_configured: true,
        is_complete: true,
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

async fn ingest_filesystem_file(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<FilesystemIngestRequestBody>,
) -> Response {
    let Some(source_root) = state.filesystem_ingest_root.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                code: "ingest.source_unavailable".into(),
                message: "filesystem ingest source is not configured".into(),
                request_id: format!("req_{:012x}", current_time_ms()),
            }),
        )
            .into_response();
    };

    if body.path.is_empty() || body.path.len() > MAX_FILESYSTEM_INGEST_PATH_BYTES {
        return bad_request("path must be nonempty and at most 4096 bytes");
    }
    let relative_path = FsPath::new(&body.path);
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return bad_request("path must stay within the configured source root");
    }

    let canonical_root = match source_root.canonicalize() {
        Ok(root) if root.is_dir() => root,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    code: "ingest.source_unavailable".into(),
                    message: "configured filesystem ingest root is unavailable".into(),
                    request_id: format!("req_{:012x}", current_time_ms()),
                }),
            )
                .into_response();
        }
    };
    let source_path = match canonical_root.join(relative_path).canonicalize() {
        Ok(path) if path.starts_with(&canonical_root) => path,
        _ => return bad_request("path must identify a file under the configured source root"),
    };
    let metadata = match std::fs::metadata(&source_path) {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => {
            return bad_request(
                "path must identify a regular file under the configured source root",
            );
        }
    };
    if metadata.len() > MAX_FILESYSTEM_INGEST_FILE_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                code: "ingest.file_too_large".into(),
                message: "filesystem ingest files are limited to 16 MiB".into(),
                request_id: format!("req_{:012x}", current_time_ms()),
            }),
        )
            .into_response();
    }

    let external_id = relative_path.to_string_lossy().replace('\\', "/");
    let modified_ms = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64);
    let item = IngestItem {
        external_id,
        revision: format!("{}:{}", metadata.len(), modified_ms.unwrap_or(0)),
        media_type: "application/octet-stream".into(),
        event_time_unix_ms: modified_ms,
        content_ref: source_path.to_string_lossy().into_owned(),
        suggested_domain: Some("private".into()),
    };

    let mut catalog = state.catalog.lock().unwrap();
    let archive = state.archive.read().unwrap();
    let mut gateway = IngestGateway::new(&archive, &mut catalog);
    match gateway.ingest_file("local-filesystem", &item, &source_path) {
        Ok(outcome) => {
            let now = current_time_ms();
            let event = AuditEvent {
                id: format!(
                    "audit_{now:016x}_{:08x}",
                    NEXT_AUDIT_EVENT_ID.fetch_add(1, Ordering::Relaxed)
                ),
                event_type: "ingest".into(),
                actor: request_device_id(&headers).to_string(),
                object_id: Some(outcome.object_id.clone()),
                details_json: Some(format!(
                    r#"{{"externalId":"{}","created":{}}}"#,
                    item.external_id, outcome.created
                )),
                created_unix_ms: now,
            };
            if let Err(error) = catalog.record_audit_event(&event) {
                return internal_error(&error.to_string());
            }
            (
                StatusCode::OK,
                Json(FilesystemIngestResponse {
                    object_id: outcome.object_id,
                    ingest_fingerprint: outcome.ingest_fingerprint,
                    created: outcome.created,
                }),
            )
                .into_response()
        }
        Err(error) => internal_error(&error.to_string()),
    }
}

async fn ingest_browser_history(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let Some(configured_path) = state.browser_history_path.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                code: "ingest.source_unavailable".into(),
                message: "browser history source is not configured".into(),
                request_id: format!("req_{:012x}", current_time_ms()),
            }),
        )
            .into_response();
    };

    let _metadata = match std::fs::symlink_metadata(configured_path) {
        Ok(meta) if meta.file_type().is_file() => meta,
        Ok(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    code: "ingest.source_unavailable".into(),
                    message: "configured browser history path is not a regular file".into(),
                    request_id: format!("req_{:012x}", current_time_ms()),
                }),
            )
                .into_response();
        }
        Err(error) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    code: "ingest.source_unavailable".into(),
                    message: format!("configured browser history file is unavailable: {error}"),
                    request_id: format!("req_{:012x}", current_time_ms()),
                }),
            )
                .into_response();
        }
    };

    // Read and hash the source SQLite database before any operation
    let source_bytes_before = match std::fs::read(configured_path) {
        Ok(bytes) => bytes,
        Err(e) => return internal_error(&format!("failed to read source browser history: {e}")),
    };
    let hash_before = hex_digest(&Sha256::digest(&source_bytes_before));

    let body: Option<BrowserHistoryIngestRequestBody> = if bytes.is_empty() {
        None
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(b) => Some(b),
            Err(e) => return bad_request(&format!("invalid request body: {e}")),
        }
    };

    let source_instance = body
        .and_then(|b| b.source_instance)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "browser-history.chromium".to_string());

    let staging_temp = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            return internal_error(&format!(
                "failed to create temporary staging directory: {e}"
            ));
        }
    };

    let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
        source_instance: source_instance.clone(),
        history_db_path: configured_path.clone(),
        staging_dir: Some(staging_temp.path().to_path_buf()),
    });

    let envelope = match connector.scan() {
        Ok(env) => env,
        Err(e) => return internal_error(&format!("browser history scan failed: {e}")),
    };

    // Prove source database was unmodified by the scan
    let source_bytes_after = match std::fs::read(configured_path) {
        Ok(bytes) => bytes,
        Err(e) => return internal_error(&format!("failed to re-read source browser history: {e}")),
    };
    let hash_after = hex_digest(&Sha256::digest(&source_bytes_after));
    if hash_before != hash_after {
        return internal_error("source browser history database was modified during scan");
    }

    let total_visits = envelope.items.len() as i64;
    let mut imported_count = 0i64;
    let mut skipped_count = 0i64;
    let mut object_ids = Vec::with_capacity(envelope.items.len());

    let now = current_time_ms();
    {
        let mut catalog = state.catalog.lock().unwrap();
        let archive = state.archive.read().unwrap();
        let mut gateway = IngestGateway::new(&archive, &mut catalog);

        for item in &envelope.items {
            match gateway.ingest_file(&source_instance, item, &item.content_ref) {
                Ok(outcome) => {
                    if outcome.created {
                        imported_count += 1;
                    } else {
                        skipped_count += 1;
                    }
                    object_ids.push(outcome.object_id);
                }
                Err(e) => {
                    return internal_error(&format!(
                        "failed to ingest visit {}: {e}",
                        item.external_id
                    ));
                }
            }
        }

        let event = AuditEvent {
            id: format!(
                "audit_{now:016x}_{:08x}",
                NEXT_AUDIT_EVENT_ID.fetch_add(1, Ordering::Relaxed)
            ),
            event_type: "ingest_browser_history".into(),
            actor: request_device_id(&headers).to_string(),
            object_id: object_ids.first().cloned(),
            details_json: Some(format!(
                r#"{{"sourceInstance":"{}","totalVisits":{},"imported":{},"skipped":{}}}"#,
                source_instance, total_visits, imported_count, skipped_count
            )),
            created_unix_ms: now,
        };
        if let Err(error) = catalog.record_audit_event(&event) {
            return internal_error(&error.to_string());
        }
    }

    (
        StatusCode::OK,
        Json(BrowserHistoryIngestResponse {
            source_instance,
            total_visits,
            imported_count,
            skipped_count,
            object_ids,
        }),
    )
        .into_response()
}

async fn analyze_guarded_delete(
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
    let operation = GuardedOperation::DeleteCanonical { object_ids };
    let mut session = GuardSession::new("pending", operation);
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

async fn confirm_guarded_delete(
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

fn request_device_id(headers: &axum::http::HeaderMap) -> &str {
    headers
        .get("x-device-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("local-device")
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
        match archive.read().unwrap().verify(full) {
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
        match archive
            .read()
            .unwrap()
            .export(&dest, body.object_id.as_deref())
        {
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

async fn login(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<LoginRequestBody>,
) -> Response {
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
    let device_id = headers
        .get("x-device-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("local-device")
        .to_owned();
    if let Err(error) = set_setup_meta(&state, "setup.admin_provisioned", "true") {
        return internal_error(&format!("failed to persist admin session state: {error}"));
    }
    let mut auth_tokens = state.auth_tokens.lock().unwrap();
    let token = format!("sess_{:016x}{:04x}", now, auth_tokens.len());
    let session = SessionToken {
        token: token.clone(),
        device_id: device_id.clone(),
        scopes: vec![
            Scope::ArchiveRead,
            Scope::ArchiveWrite,
            Scope::ArchiveDestructive,
            Scope::KnowledgeRead,
        ],
        expires_at: format_unix_ms(expires_at),
    };

    auth_tokens.push(session.clone());

    (StatusCode::OK, Json(session)).into_response()
}

async fn logout(State(state): State<AppState>, headers: axum::http::HeaderMap) -> Response {
    if let Some(token) = bearer_token(&headers) {
        state
            .auth_tokens
            .lock()
            .unwrap()
            .retain(|session| session.token != token);
    } else {
        state.auth_tokens.lock().unwrap().clear();
    }
    StatusCode::NO_CONTENT.into_response()
}

fn unauthorized(message: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(ErrorResponse {
            code: "auth.unauthorized".into(),
            message: message.to_owned(),
            request_id: format!("req_{:012x}", current_time_ms()),
        }),
    )
        .into_response()
}

fn bad_request(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ErrorResponse {
            code: "request.invalid".into(),
            message: message.to_owned(),
            request_id: format!("req_{:012x}", current_time_ms()),
        }),
    )
        .into_response()
}

fn forbidden(message: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(ErrorResponse {
            code: "guard.confirmation_required".into(),
            message: message.to_owned(),
            request_id: format!("req_{:012x}", current_time_ms()),
        }),
    )
        .into_response()
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

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn setup_test_state() -> (AppState, tempfile::TempDir) {
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
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

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
        test_state_missing.browser_history_path =
            Some(PathBuf::from("nonexistent_history_file.db"));
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
        let (state, _temp) = setup_test_state();
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

        let token = login_token(&app, "local-device").await;
        let ordinary_session_attempt = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/system/setup")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"recoveryConfirmed": true}"#))
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
                    .body(Body::from(r#"{"recoveryConfirmed": true}"#))
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
                    .body(Body::from(r#"{"recoveryConfirmed": true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);

        // A normal session can inspect state, but cannot replay setup.
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/system/setup")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"recoveryConfirmed": true}"#))
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
        let (state, temp) = setup_test_state();
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
            "recoveryConfirmed": true
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
        let (state, _temp) = setup_test_state();
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
            "recoveryConfirmed": true
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
    async fn setup_metadata_failure_returns_500_and_restart_remains_locked() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("archive");
        let archive = Archive::init(&archive_path).unwrap();
        let catalog_path = temp.path().join("catalog.sqlite");
        let catalog = Catalog::open(&catalog_path).unwrap();
        let state = AppState::new(catalog, archive);
        *state.setup_meta_fail_key.lock().unwrap() = Some("setup.completed_unix_ms".into());
        let configured_archive_dir = temp.path().join("prepared_archive");
        let app = create_router(state.clone());

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/system/setup")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "archivePath": configured_archive_dir,
                            "recoveryConfirmed": true
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            state
                .setup_state
                .lock()
                .unwrap()
                .completed_unix_ms
                .is_none()
        );
        assert!(state.setup_state.lock().unwrap().attempted);
        assert_eq!(
            state.archive.read().unwrap().root(),
            Archive::open(&configured_archive_dir).unwrap().root()
        );

        let restarted_state = AppState::new(
            Catalog::open(&catalog_path).unwrap(),
            Archive::open(&archive_path).unwrap(),
        );
        assert_eq!(
            restarted_state.archive.read().unwrap().root(),
            Archive::open(&configured_archive_dir).unwrap().root()
        );
        let restarted_app = create_router(restarted_state);
        let token = login_token(&restarted_app, "restart-admin").await;
        let replay = restarted_app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/system/setup")
                    .header("authorization", format!("Bearer {token}"))
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"recoveryConfirmed":true}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(replay.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn setup_failure_before_prepared_marker_is_retryable_after_restart() {
        let temp = tempfile::tempdir().unwrap();
        let archive_path = temp.path().join("archive");
        let archive = Archive::init(&archive_path).unwrap();
        let catalog_path = temp.path().join("catalog.sqlite");
        let catalog = Catalog::open(&catalog_path).unwrap();
        let state = AppState::new(catalog, archive);
        *state.setup_meta_fail_key.lock().unwrap() = Some("setup.archive_path".into());
        let app = create_router(state.clone());
        let request = || {
            Request::builder()
                .method("POST")
                .uri("/v1/system/setup")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"recoveryConfirmed":true}"#))
                .unwrap()
        };

        let response = app.oneshot(request()).await.unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            state
                .setup_state
                .lock()
                .unwrap()
                .completed_unix_ms
                .is_none()
        );
        assert!(!state.setup_state.lock().unwrap().attempted);

        let restarted_app = create_router(AppState::new(
            Catalog::open(&catalog_path).unwrap(),
            Archive::open(&archive_path).unwrap(),
        ));
        let retry = restarted_app.oneshot(request()).await.unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
    }
}
