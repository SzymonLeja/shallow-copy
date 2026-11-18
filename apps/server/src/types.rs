//! TypeSpec-aligned HTTP request and response models.
//!
//! These types are intentionally separate from route orchestration so the API
//! contract can evolve and be verified independently of HTTP handlers.

use std::path::PathBuf;

use sc_policy::{ArchiveDomain, Scope};
use sc_preservation_guard::{GuardSession, GuardState, ImpactReport};
use sc_storage::{CatalogJob, CatalogObject, JobStatus};
use serde::{Deserialize, Serialize};

use crate::format_unix_ms;

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

pub(crate) struct GuardSessionRecord {
    pub(crate) session: GuardSession,
    pub(crate) confirmation_token: String,
    pub(crate) owner_token: String,
    pub(crate) owner_device_id: String,
    pub(crate) expires_at_unix_ms: u64,
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
    pub legacy_credential_claim_required: Option<bool>,
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
    pub owner_password: Option<String>,
}

/// Request body for claiming unmigrated legacy credentials (specs/typespec/system/setup.tsp).
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LegacyClaimRequest {
    pub owner_password: String,
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
