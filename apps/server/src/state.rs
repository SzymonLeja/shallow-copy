//! Process-local server runtime state.
//!
//! This module owns construction and rehydration of state shared by HTTP routes.

use crate::{
    BROWSER_HISTORY_PATH_ENV, FILESYSTEM_INGEST_ROOT_ENV, GuardSessionRecord, STATIC_DIR_ENV,
    SessionToken, SetupStateRecord,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};

use oiaf::Archive;
use sc_storage::Catalog;
#[derive(Clone)]
pub struct AppState {
    pub catalog: Arc<Mutex<Catalog>>,
    pub archive: Arc<RwLock<Archive>>,
    pub auth_tokens: Arc<Mutex<Vec<SessionToken>>>,
    pub filesystem_ingest_root: Option<PathBuf>,
    pub browser_history_path: Option<PathBuf>,
    pub static_dir: Option<PathBuf>,
    pub(crate) guard_sessions: Arc<Mutex<HashMap<String, GuardSessionRecord>>>,
    pub setup_state: Arc<Mutex<SetupStateRecord>>,
    pub(crate) archive_config_error: Arc<Mutex<Option<String>>>,
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
            let has_owner_auth = catalog
                .get_meta("setup.owner_verifier")
                .ok()
                .flatten()
                .is_some()
                && catalog
                    .get_meta("setup.owner_auth_version")
                    .ok()
                    .flatten()
                    .is_some();
            record.admin_provisioned = has_owner_auth;
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
        }
    }
}
