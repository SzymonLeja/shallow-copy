//! Core REST API Server and Orchestration Runtime for shallow-copy.
//!
//! Exposes TypeSpec-aligned REST endpoints for archive operations, verification,
//! export jobs, object provenance, and session authentication.
#![forbid(unsafe_code)]

use std::path::{Component, Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use oiaf::Archive;
pub use sc_connector_browser_chromium as browser_connector;
use sc_connector_browser_chromium::{ChromiumHistoryConfig, ChromiumHistoryConnector};
pub use sc_ingest as ingest;
use sc_ingest::{IngestGateway, IngestItem};
pub use sc_preservation_guard as preservation_guard;
pub use sc_recovery as recovery;
use sc_storage::{AuditEvent, CatalogJob, FreshSetupConfig, JobStatus, OwnerProvisionMode};
use sha2::{Digest, Sha256};

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
const OWNER_VERIFIER_SENTINEL: &[u8] = b"shallow-copy:owner-verifier:v1";

mod auth;
mod error;
mod router;
mod routes;
mod state;
mod types;
mod util;
use auth::{bearer_token, has_real_session, request_device_id};
pub(crate) use error::{bad_request, forbidden, internal_error, not_found, unauthorized};
pub use router::create_router;
pub use state::AppState;
pub use types::*;
pub(crate) use util::{current_time_ms, format_unix_ms, hex_digest};

#[cfg(test)]
pub(crate) use routes::setup::check_bootstrap_token_inner;

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
