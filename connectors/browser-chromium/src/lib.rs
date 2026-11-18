//! Chromium browser history and bookmarks ingestion connector for shallow-copy.
//!
//! # Guarantees
//! - Copies a snapshot of the source SQLite database and Bookmarks JSON before opening,
//!   preventing locks against active browsers (per `project.md` line 358).
//! - Operates strictly read-only on copied snapshots.
//! - Enforces cryptographic pre/post SHA-256 fixity checks on source files.
//! - Transforms Chromium visit records (with page titles and transition types)
//!   and bookmark records (with folder hierarchy) into standard `IngestItem` records.
#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, OpenFlags, Result as SqlResult};
use sc_ingest::{IngestEnvelope, IngestItem};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const CHROMIUM_EPOCH_DELTA_US: i64 = 11_644_473_600_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChromiumHistoryConfig {
    pub source_instance: String,
    pub history_db_path: PathBuf,
    pub staging_dir: Option<PathBuf>,
}

/// Chromium PageTransition core types (low 8 bits of transition integer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PageTransitionType {
    Link,
    Typed,
    AutoBookmark,
    AutoSubframe,
    ManualSubframe,
    Generated,
    AutoToplevel,
    FormSubmit,
    Reload,
    Keyword,
    KeywordGenerated,
    Other(u32),
}

impl PageTransitionType {
    pub fn from_raw(raw: i64) -> Self {
        let core = (raw as u32) & 0xFF;
        match core {
            0 => Self::Link,
            1 => Self::Typed,
            2 => Self::AutoBookmark,
            3 => Self::AutoSubframe,
            4 => Self::ManualSubframe,
            5 => Self::Generated,
            6 => Self::AutoToplevel,
            7 => Self::FormSubmit,
            8 => Self::Reload,
            9 => Self::Keyword,
            10 => Self::KeywordGenerated,
            other => Self::Other(other),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Link => "link",
            Self::Typed => "typed",
            Self::AutoBookmark => "auto_bookmark",
            Self::AutoSubframe => "auto_subframe",
            Self::ManualSubframe => "manual_subframe",
            Self::Generated => "generated",
            Self::AutoToplevel => "auto_toplevel",
            Self::FormSubmit => "form_submit",
            Self::Reload => "reload",
            Self::Keyword => "keyword",
            Self::KeywordGenerated => "keyword_generated",
            Self::Other(_) => "other",
        }
    }
}

/// Enriched browser visit record stored in OIAF source metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserVisitRecord {
    pub visit_id: i64,
    pub url: String,
    pub title: Option<String>,
    pub visit_count: Option<i64>,
    pub visit_time_raw: i64,
    pub event_time_unix_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_raw: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition_type: Option<String>,
}

/// Chromium bookmark record with titles, URLs, and folder hierarchy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserBookmarkRecord {
    pub bookmark_id: String,
    pub title: String,
    pub url: String,
    pub folder_path: Vec<String>,
    pub folder: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_added_raw: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date_added_unix_ms: Option<u64>,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Sql(rusqlite::Error),
    Json(serde_json::Error),
    Invalid(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Sql(e) => write!(f, "SQLite error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::Invalid(e) => write!(f, "invalid browser data: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Sql(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::Invalid(_) => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct ChromiumHistoryConnector {
    config: ChromiumHistoryConfig,
    bookmarks_path: Option<PathBuf>,
}

impl ChromiumHistoryConnector {
    pub fn new(config: ChromiumHistoryConfig) -> Self {
        let default_bookmarks = config.history_db_path.with_file_name("Bookmarks");
        let bookmarks_path = if default_bookmarks.is_file() {
            Some(default_bookmarks)
        } else {
            None
        };
        Self {
            config,
            bookmarks_path,
        }
    }

    pub fn with_bookmarks_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.bookmarks_path = Some(path.into());
        self
    }

    pub fn bookmarks_path(&self) -> Option<&Path> {
        self.bookmarks_path.as_deref()
    }

    /// Read browser history and bookmarks from configured locations and produce an `IngestEnvelope`.
    ///
    /// Copies a snapshot of the database file and bookmarks before querying to avoid
    /// lock contention with running Chromium instances. Performs strict pre/post SHA-256
    /// fixity checks on source files.
    pub fn scan(&self) -> Result<IngestEnvelope> {
        let src = &self.config.history_db_path;
        validate_regular_file(src, "history database")?;

        // 1. Strict SHA-256 pre-scan fixity check on History DB and SQLite sidecars (WAL/SHM)
        let history_hash_before = file_sha256(src)?;
        let wal_path = sidecar_path(src, "-wal");
        let shm_path = sidecar_path(src, "-shm");
        let wal_hash_before = check_sidecar_pre_fixity(&wal_path, "WAL")?;
        let shm_hash_before = check_sidecar_pre_fixity(&shm_path, "SHM")?;

        // Validate and check pre-scan fixity on Bookmarks if configured/present
        let bookmarks_hash_before = if let Some(ref bpath) = self.bookmarks_path {
            validate_regular_file(bpath, "bookmarks")?;
            Some(file_sha256(bpath)?)
        } else {
            None
        };

        // 2. Create temporary snapshot directory for sidecar staging
        let snapshot_dir = tempfile::tempdir()?;
        let snapshot_path = snapshot_dir.path().join("History.snapshot");
        fs::copy(src, &snapshot_path)?;

        // Copy WAL and SHM files if present for consistent point-in-time snapshot
        if wal_hash_before.is_some() {
            copy_sidecar(&wal_path, &snapshot_dir.path().join("History.snapshot-wal"))?;
        }
        if shm_hash_before.is_some() {
            copy_sidecar(&shm_path, &snapshot_dir.path().join("History.snapshot-shm"))?;
        }

        // Snapshot Bookmarks if present
        let bookmarks_snapshot = if let Some(ref bpath) = self.bookmarks_path {
            let dest = snapshot_dir.path().join("Bookmarks.snapshot");
            fs::copy(bpath, &dest)?;
            Some(dest)
        } else {
            None
        };

        // Open snapshot read-only
        let conn = Connection::open_with_flags(&snapshot_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let raw_visits = read_visits(&conn)?;
        drop(conn);

        // 3. Strict SHA-256 post-scan fixity verification on History DB and SQLite sidecars
        let history_hash_after = file_sha256(src)?;
        if history_hash_before != history_hash_after {
            return Err(Error::Invalid(
                "history database was modified during scan (fixity violation)".into(),
            ));
        }
        verify_sidecar_post_fixity(&wal_path, wal_hash_before.as_deref(), "WAL")?;
        verify_sidecar_post_fixity(&shm_path, shm_hash_before.as_deref(), "SHM")?;

        // Parse bookmarks from snapshot if present
        let raw_bookmarks = if let Some(ref bsnap) = bookmarks_snapshot {
            read_bookmarks(bsnap)?
        } else {
            Vec::new()
        };

        // 4. Strict SHA-256 post-scan fixity verification on Bookmarks
        if let (Some(bpath), Some(b_before)) = (&self.bookmarks_path, &bookmarks_hash_before) {
            let bookmarks_hash_after = file_sha256(bpath)?;
            if b_before != &bookmarks_hash_after {
                return Err(Error::Invalid(
                    "bookmarks file was modified during scan (fixity violation)".into(),
                ));
            }
        }

        // 5. Staging items into standard IngestEnvelope
        let staging_dir = match &self.config.staging_dir {
            Some(dir) => {
                fs::create_dir_all(dir)?;
                dir.clone()
            }
            None => tempfile::Builder::new()
                .prefix("sc-browser-chromium-stage-")
                .tempdir()?
                .keep(),
        };

        let mut items = Vec::with_capacity(raw_visits.len() + raw_bookmarks.len());

        for visit in raw_visits {
            let content_path = staging_dir.join(format!("visit_{}.json", visit.visit_id));
            let json_bytes = serde_json::to_vec_pretty(&visit)?;
            let mut file = File::create(&content_path)?;
            file.write_all(&json_bytes)?;

            let rev = format!(
                "{}:{}",
                visit.visit_time_raw,
                hex_digest(visit.url.as_bytes())
            );

            items.push(IngestItem {
                external_id: format!("history:{}", visit.visit_id),
                revision: rev,
                media_type: "application/vnd.shallowcopy.browser-visit+json".into(),
                event_time_unix_ms: visit.event_time_unix_ms,
                content_ref: content_path.to_string_lossy().to_string(),
                suggested_domain: Some("private".into()),
            });
        }

        for bookmark in raw_bookmarks {
            let content_path = staging_dir.join(format!("bookmark_{}.json", bookmark.bookmark_id));
            let json_bytes = serde_json::to_vec_pretty(&bookmark)?;
            let mut file = File::create(&content_path)?;
            file.write_all(&json_bytes)?;

            let rev = format!(
                "{}:{}",
                bookmark.date_added_unix_ms.unwrap_or(0),
                hex_digest(bookmark.url.as_bytes())
            );

            items.push(IngestItem {
                external_id: format!("bookmark:{}", bookmark.bookmark_id),
                revision: rev,
                media_type: "application/vnd.shallowcopy.browser-bookmark+json".into(),
                event_time_unix_ms: bookmark.date_added_unix_ms,
                content_ref: content_path.to_string_lossy().to_string(),
                suggested_domain: Some("private".into()),
            });
        }

        Ok(IngestEnvelope {
            source_instance: self.config.source_instance.clone(),
            cursor: None,
            items,
        })
    }

    /// Extract visit records directly without staging
    pub fn scan_visits(&self) -> Result<Vec<BrowserVisitRecord>> {
        let src = &self.config.history_db_path;
        validate_regular_file(src, "history database")?;
        let hash_before = file_sha256(src)?;
        let wal_path = sidecar_path(src, "-wal");
        let shm_path = sidecar_path(src, "-shm");
        let wal_hash_before = check_sidecar_pre_fixity(&wal_path, "WAL")?;
        let shm_hash_before = check_sidecar_pre_fixity(&shm_path, "SHM")?;

        let snapshot_dir = tempfile::tempdir()?;
        let snapshot_path = snapshot_dir.path().join("History.snapshot");
        fs::copy(src, &snapshot_path)?;

        if wal_hash_before.is_some() {
            copy_sidecar(&wal_path, &snapshot_dir.path().join("History.snapshot-wal"))?;
        }
        if shm_hash_before.is_some() {
            copy_sidecar(&shm_path, &snapshot_dir.path().join("History.snapshot-shm"))?;
        }

        let conn = Connection::open_with_flags(&snapshot_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let records = read_visits(&conn)?;
        drop(conn);

        let hash_after = file_sha256(src)?;
        if hash_before != hash_after {
            return Err(Error::Invalid(
                "history database was modified during scan (fixity violation)".into(),
            ));
        }
        verify_sidecar_post_fixity(&wal_path, wal_hash_before.as_deref(), "WAL")?;
        verify_sidecar_post_fixity(&shm_path, shm_hash_before.as_deref(), "SHM")?;

        Ok(records)
    }

    /// Extract bookmark records directly without staging
    pub fn scan_bookmarks(&self) -> Result<Vec<BrowserBookmarkRecord>> {
        let Some(ref bpath) = self.bookmarks_path else {
            return Ok(Vec::new());
        };
        validate_regular_file(bpath, "bookmarks")?;
        let hash_before = file_sha256(bpath)?;

        let snapshot_dir = tempfile::tempdir()?;
        let snapshot_path = snapshot_dir.path().join("Bookmarks.snapshot");
        fs::copy(bpath, &snapshot_path)?;

        let records = read_bookmarks(&snapshot_path)?;

        let hash_after = file_sha256(bpath)?;
        if hash_before != hash_after {
            return Err(Error::Invalid(
                "bookmarks file was modified during scan (fixity violation)".into(),
            ));
        }

        Ok(records)
    }
}

fn file_sha256(path: &Path) -> Result<String> {
    let bytes = fs::read(path)?;
    Ok(hex_digest(&Sha256::digest(&bytes)))
}

fn validate_regular_file(path: &Path, file_label: &str) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(Error::Invalid(format!(
                "{file_label} file not found: {}",
                path.display()
            )));
        }
        Err(error) => return Err(Error::Io(error)),
    };
    if !metadata.file_type().is_file() {
        return Err(Error::Invalid(format!(
            "{file_label} is not a regular file: {}",
            path.display()
        )));
    }
    Ok(())
}

fn copy_sidecar(src: &Path, dest: &Path) -> Result<()> {
    match fs::symlink_metadata(src) {
        Ok(metadata) if metadata.file_type().is_file() => {
            fs::copy(src, dest)?;
            Ok(())
        }
        Ok(_) => Err(Error::Invalid(format!(
            "history sidecar is not a regular file: {}",
            src.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Error::Io(error)),
    }
}

fn sidecar_path(db_path: &Path, suffix: &str) -> PathBuf {
    let file_name = db_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("History");
    let candidate = db_path.with_file_name(format!("{file_name}{suffix}"));
    if candidate.exists() || fs::symlink_metadata(&candidate).is_ok() {
        candidate
    } else {
        let fallback = db_path.with_file_name(format!("History{suffix}"));
        if fallback.exists() || fs::symlink_metadata(&fallback).is_ok() {
            fallback
        } else {
            candidate
        }
    }
}

fn check_sidecar_pre_fixity(path: &Path, label: &str) -> Result<Option<String>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => {
            let hash = file_sha256(path)?;
            Ok(Some(hash))
        }
        Ok(_) => Err(Error::Invalid(format!(
            "{label} sidecar is not a regular file: {}",
            path.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Io(error)),
    }
}

fn verify_sidecar_post_fixity(path: &Path, pre_hash: Option<&str>, label: &str) -> Result<()> {
    match (pre_hash, fs::symlink_metadata(path)) {
        (Some(before), Ok(metadata)) if metadata.file_type().is_file() => {
            let after = file_sha256(path)?;
            if before != after {
                return Err(Error::Invalid(format!(
                    "{label} sidecar was modified during scan (fixity violation)"
                )));
            }
            Ok(())
        }
        (Some(_), Ok(_)) => Err(Error::Invalid(format!(
            "{label} sidecar is no longer a regular file (fixity violation)"
        ))),
        (Some(_), Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Err(Error::Invalid(
            format!("{label} sidecar disappeared during scan (fixity violation)"),
        )),
        (None, Ok(_)) => Err(Error::Invalid(format!(
            "{label} sidecar was created during scan (fixity violation)"
        ))),
        (None, Err(e)) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        (_, Err(e)) => Err(Error::Io(e)),
    }
}

/// Read bookmarks from a Chromium Bookmarks JSON file and extract flat records with folder hierarchy.
pub fn read_bookmarks(path: &Path) -> Result<Vec<BrowserBookmarkRecord>> {
    let content = fs::read_to_string(path)?;
    parse_bookmarks_str(&content)
}

/// Parse bookmarks from a JSON string.
pub fn parse_bookmarks_str(json_str: &str) -> Result<Vec<BrowserBookmarkRecord>> {
    let value: serde_json::Value = serde_json::from_str(json_str)?;
    parse_bookmarks_json(&value)
}

/// Parse bookmarks from a serde_json Value.
pub fn parse_bookmarks_json(value: &serde_json::Value) -> Result<Vec<BrowserBookmarkRecord>> {
    let mut results = Vec::new();
    if let Some(roots) = value.get("roots").and_then(|v| v.as_object()) {
        let mut root_keys: Vec<_> = roots.keys().collect();
        root_keys.sort();
        for root_key in root_keys {
            if let Some(root_node) = roots.get(root_key) {
                let mut current_path = Vec::new();
                traverse_bookmark_node(root_node, &mut current_path, &mut results);
            }
        }
    } else {
        let mut current_path = Vec::new();
        traverse_bookmark_node(value, &mut current_path, &mut results);
    }
    Ok(results)
}

fn traverse_bookmark_node(
    node: &serde_json::Value,
    current_path: &mut Vec<String>,
    results: &mut Vec<BrowserBookmarkRecord>,
) {
    let node_type = node.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let name = node.get("name").and_then(|v| v.as_str()).unwrap_or("");

    match node_type {
        "folder" => {
            let is_named = !name.is_empty();
            if is_named {
                current_path.push(name.to_string());
            }
            if let Some(children) = node.get("children").and_then(|v| v.as_array()) {
                for child in children {
                    traverse_bookmark_node(child, current_path, results);
                }
            }
            if is_named {
                current_path.pop();
            }
        }
        "url" => {
            if let Some(url) = node.get("url").and_then(|v| v.as_str()) {
                let id = node
                    .get("id")
                    .and_then(|v| {
                        if let Some(s) = v.as_str() {
                            Some(s.to_string())
                        } else {
                            v.as_i64().map(|n| n.to_string())
                        }
                    })
                    .unwrap_or_else(|| format!("bkmk_{}", results.len() + 1));

                let date_added_raw = node.get("date_added").and_then(|v| {
                    if let Some(s) = v.as_str() {
                        Some(s.to_string())
                    } else {
                        v.as_i64().map(|n| n.to_string())
                    }
                });

                let date_added_unix_ms = date_added_raw
                    .as_deref()
                    .and_then(|s| s.parse::<i64>().ok())
                    .and_then(convert_chromium_timestamp);

                let folder_path = current_path.clone();
                let folder = folder_path.join("/");

                results.push(BrowserBookmarkRecord {
                    bookmark_id: id,
                    title: name.to_string(),
                    url: url.to_string(),
                    folder_path,
                    folder,
                    date_added_raw,
                    date_added_unix_ms,
                });
            }
        }
        _ => {}
    }
}

struct RawVisit {
    id: i64,
    url: String,
    title: Option<String>,
    visit_count: Option<i64>,
    visit_time: i64,
    transition: Option<i64>,
}

fn read_visits(conn: &Connection) -> Result<Vec<BrowserVisitRecord>> {
    let has_visits_table: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='visits'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);

    let has_transition_col: bool = if has_visits_table {
        conn.query_row(
            "SELECT COUNT(*) > 0 FROM pragma_table_info('visits') WHERE name='transition'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false)
    } else {
        false
    };

    let raw_list: Vec<RawVisit> = if has_visits_table && has_transition_col {
        let mut stmt = conn.prepare(
            "SELECT v.id, u.url, u.title, u.visit_count, v.visit_time, v.transition
             FROM visits v
             JOIN urls u ON v.url = u.id
             ORDER BY v.id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RawVisit {
                id: row.get(0)?,
                url: row.get(1)?,
                title: row.get(2)?,
                visit_count: row.get(3)?,
                visit_time: row.get(4)?,
                transition: row.get(5)?,
            })
        })?;
        rows.collect::<SqlResult<Vec<_>>>()?
    } else if has_visits_table {
        let mut stmt = conn.prepare(
            "SELECT v.id, u.url, u.title, u.visit_count, v.visit_time
             FROM visits v
             JOIN urls u ON v.url = u.id
             ORDER BY v.id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RawVisit {
                id: row.get(0)?,
                url: row.get(1)?,
                title: row.get(2)?,
                visit_count: row.get(3)?,
                visit_time: row.get(4)?,
                transition: None,
            })
        })?;
        rows.collect::<SqlResult<Vec<_>>>()?
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, url, title, visit_count, last_visit_time
             FROM urls
             ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(RawVisit {
                id: row.get(0)?,
                url: row.get(1)?,
                title: row.get(2)?,
                visit_count: row.get(3)?,
                visit_time: row.get(4)?,
                transition: None,
            })
        })?;
        rows.collect::<SqlResult<Vec<_>>>()?
    };

    let mut records = Vec::with_capacity(raw_list.len());
    for raw in raw_list {
        let event_time = convert_chromium_timestamp(raw.visit_time);
        let (transition_raw, transition_type) = match raw.transition {
            Some(t) => (
                Some(t),
                Some(PageTransitionType::from_raw(t).as_str().to_string()),
            ),
            None => (None, None),
        };
        records.push(BrowserVisitRecord {
            visit_id: raw.id,
            url: raw.url,
            title: raw.title,
            visit_count: raw.visit_count,
            visit_time_raw: raw.visit_time,
            event_time_unix_ms: event_time,
            transition_raw,
            transition_type,
        });
    }

    Ok(records)
}

fn convert_chromium_timestamp(raw: i64) -> Option<u64> {
    if raw <= 0 {
        return None;
    }
    if raw > CHROMIUM_EPOCH_DELTA_US {
        let us_since_unix = raw - CHROMIUM_EPOCH_DELTA_US;
        Some((us_since_unix / 1000) as u64)
    } else if raw > 1_000_000_000_000 {
        Some(raw as u64)
    } else if raw > 1_000_000_000 {
        Some(raw as u64 * 1000)
    } else {
        None
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Helper to create a mock Chromium History SQLite database with visits and urls tables.
pub fn create_mock_history_db(path: &Path) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0 NOT NULL,
            last_visit_time INTEGER NOT NULL
        );
        CREATE TABLE visits (
            id INTEGER PRIMARY KEY,
            url INTEGER NOT NULL,
            visit_time INTEGER NOT NULL,
            transition INTEGER DEFAULT 0 NOT NULL
        );
        INSERT INTO urls (id, url, title, visit_count, last_visit_time)
        VALUES (10, 'https://shallow-copy.org', 'Shallow Copy Project', 3, 13350000000000000);
        INSERT INTO visits (id, url, visit_time, transition)
        VALUES (100, 10, 13350000000000000, 1);
        INSERT INTO visits (id, url, visit_time, transition)
        VALUES (101, 10, 13350000050000000, 0);
        ",
    )?;
    Ok(())
}

/// Helper to create a mock Chromium History SQLite database with only a urls table.
pub fn create_mock_urls_db(path: &Path) -> Result<()> {
    let conn = Connection::open(path)?;
    conn.execute_batch(
        "
        CREATE TABLE urls (
            id INTEGER PRIMARY KEY,
            url TEXT NOT NULL,
            title TEXT,
            visit_count INTEGER DEFAULT 0 NOT NULL,
            last_visit_time INTEGER NOT NULL
        );
        INSERT INTO urls (id, url, title, visit_count, last_visit_time)
        VALUES (1, 'https://example.com', 'Example Domain', 5, 13350000000000000);
        INSERT INTO urls (id, url, title, visit_count, last_visit_time)
        VALUES (2, 'https://rust-lang.org', 'Rust Programming Language', 12, 13350000010000000);
        ",
    )?;
    Ok(())
}

/// Helper to create a mock Chromium Bookmarks JSON file with nested folder hierarchy.
pub fn create_mock_bookmarks_file(path: &Path) -> Result<()> {
    let mock_json = r#"{
        "checksum": "mock_checksum",
        "roots": {
            "bookmark_bar": {
                "children": [
                    {
                        "date_added": "13350000000000000",
                        "id": "1",
                        "name": "Rust Language",
                        "type": "url",
                        "url": "https://www.rust-lang.org/"
                    },
                    {
                        "date_added": "13350000010000000",
                        "date_modified": "13350000020000000",
                        "id": "2",
                        "name": "Engineering",
                        "type": "folder",
                        "children": [
                            {
                                "date_added": "13350000030000000",
                                "id": "3",
                                "name": "DeepMind",
                                "type": "url",
                                "url": "https://deepmind.google/"
                            },
                            {
                                "date_added": "13350000040000000",
                                "date_modified": "13350000050000000",
                                "id": "4",
                                "name": "Projects",
                                "type": "folder",
                                "children": [
                                    {
                                        "date_added": "13350000060000000",
                                        "id": "5",
                                        "name": "Shallow Copy",
                                        "type": "url",
                                        "url": "https://github.com/shallow-copy"
                                    }
                                ]
                            }
                        ]
                    }
                ],
                "date_added": "13350000000000000",
                "date_modified": "13350000000000000",
                "id": "0",
                "name": "Bookmarks bar",
                "type": "folder"
            },
            "other": {
                "children": [
                    {
                        "date_added": "13350000070000000",
                        "id": "6",
                        "name": "Documentation",
                        "type": "url",
                        "url": "https://docs.rs/"
                    }
                ],
                "date_added": "13350000000000000",
                "date_modified": "13350000000000000",
                "id": "99",
                "name": "Other bookmarks",
                "type": "folder"
            }
        },
        "version": 1
    }"#;
    fs::write(path, mock_json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_mock_db_with_urls_table() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("History");
        let stage_dir = temp.path().join("stage");
        create_mock_urls_db(&db_path).unwrap();

        let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
            source_instance: "chrome-laptop".into(),
            history_db_path: db_path,
            staging_dir: Some(stage_dir),
        });

        let envelope = connector.scan().unwrap();
        assert_eq!(envelope.source_instance, "chrome-laptop");
        assert_eq!(envelope.items.len(), 2);

        let first = &envelope.items[0];
        assert_eq!(first.external_id, "history:1");
        assert_eq!(
            first.media_type,
            "application/vnd.shallowcopy.browser-visit+json"
        );
        assert_eq!(first.suggested_domain.as_deref(), Some("private"));
        assert!(first.event_time_unix_ms.is_some());
        assert!(Path::new(&first.content_ref).is_file());

        let content_str = fs::read_to_string(&first.content_ref).unwrap();
        let record: BrowserVisitRecord = serde_json::from_str(&content_str).unwrap();
        assert_eq!(record.visit_id, 1);
        assert_eq!(record.url, "https://example.com");
        assert_eq!(record.title.as_deref(), Some("Example Domain"));
        assert!(record.transition_type.is_none());
    }

    #[test]
    fn scans_mock_db_with_visits_and_urls_table_with_transitions() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("History");
        create_mock_history_db(&db_path).unwrap();

        let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
            source_instance: "chrome-desktop".into(),
            history_db_path: db_path,
            staging_dir: None,
        });

        let envelope = connector.scan().unwrap();
        assert_eq!(envelope.items.len(), 2);
        assert_eq!(envelope.items[0].external_id, "history:100");
        assert_eq!(envelope.items[1].external_id, "history:101");

        let content_0 = fs::read_to_string(&envelope.items[0].content_ref).unwrap();
        let record_0: BrowserVisitRecord = serde_json::from_str(&content_0).unwrap();
        assert_eq!(record_0.visit_id, 100);
        assert_eq!(record_0.url, "https://shallow-copy.org");
        assert_eq!(record_0.title.as_deref(), Some("Shallow Copy Project"));
        assert_eq!(record_0.transition_raw, Some(1));
        assert_eq!(record_0.transition_type.as_deref(), Some("typed"));

        let content_1 = fs::read_to_string(&envelope.items[1].content_ref).unwrap();
        let record_1: BrowserVisitRecord = serde_json::from_str(&content_1).unwrap();
        assert_eq!(record_1.visit_id, 101);
        assert_eq!(record_1.transition_raw, Some(0));
        assert_eq!(record_1.transition_type.as_deref(), Some("link"));
    }

    #[test]
    fn extracts_bookmarks_with_nested_folder_hierarchy() {
        let temp = tempfile::tempdir().unwrap();
        let bpath = temp.path().join("Bookmarks");
        create_mock_bookmarks_file(&bpath).unwrap();

        let db_path = temp.path().join("History");
        create_mock_urls_db(&db_path).unwrap();

        let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
            source_instance: "chrome-test".into(),
            history_db_path: db_path,
            staging_dir: None,
        })
        .with_bookmarks_path(bpath);

        let bookmarks = connector.scan_bookmarks().unwrap();
        assert_eq!(bookmarks.len(), 4);

        // Bookmark 1: in "Bookmarks bar"
        let b1 = bookmarks.iter().find(|b| b.bookmark_id == "1").unwrap();
        assert_eq!(b1.title, "Rust Language");
        assert_eq!(b1.url, "https://www.rust-lang.org/");
        assert_eq!(b1.folder_path, vec!["Bookmarks bar"]);
        assert_eq!(b1.folder, "Bookmarks bar");
        assert!(b1.date_added_unix_ms.is_some());

        // Bookmark 3: in "Bookmarks bar/Engineering"
        let b3 = bookmarks.iter().find(|b| b.bookmark_id == "3").unwrap();
        assert_eq!(b3.title, "DeepMind");
        assert_eq!(b3.url, "https://deepmind.google/");
        assert_eq!(b3.folder_path, vec!["Bookmarks bar", "Engineering"]);
        assert_eq!(b3.folder, "Bookmarks bar/Engineering");

        // Bookmark 5: in "Bookmarks bar/Engineering/Projects"
        let b5 = bookmarks.iter().find(|b| b.bookmark_id == "5").unwrap();
        assert_eq!(b5.title, "Shallow Copy");
        assert_eq!(b5.url, "https://github.com/shallow-copy");
        assert_eq!(
            b5.folder_path,
            vec!["Bookmarks bar", "Engineering", "Projects"]
        );
        assert_eq!(b5.folder, "Bookmarks bar/Engineering/Projects");

        // Bookmark 6: in "Other bookmarks"
        let b6 = bookmarks.iter().find(|b| b.bookmark_id == "6").unwrap();
        assert_eq!(b6.title, "Documentation");
        assert_eq!(b6.url, "https://docs.rs/");
        assert_eq!(b6.folder_path, vec!["Other bookmarks"]);
        assert_eq!(b6.folder, "Other bookmarks");
    }

    #[test]
    fn scan_combines_visits_and_bookmarks_into_single_envelope() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("History");
        let bpath = temp.path().join("Bookmarks");
        create_mock_history_db(&db_path).unwrap();
        create_mock_bookmarks_file(&bpath).unwrap();

        let stage_dir = temp.path().join("stage");

        let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
            source_instance: "chrome-full".into(),
            history_db_path: db_path,
            staging_dir: Some(stage_dir),
        })
        .with_bookmarks_path(bpath);

        let envelope = connector.scan().unwrap();
        // 2 visits + 4 bookmarks = 6 items
        assert_eq!(envelope.items.len(), 6);

        let visit_items: Vec<_> = envelope
            .items
            .iter()
            .filter(|i| i.media_type == "application/vnd.shallowcopy.browser-visit+json")
            .collect();
        assert_eq!(visit_items.len(), 2);

        let bookmark_items: Vec<_> = envelope
            .items
            .iter()
            .filter(|i| i.media_type == "application/vnd.shallowcopy.browser-bookmark+json")
            .collect();
        assert_eq!(bookmark_items.len(), 4);

        // Verify bookmark item content
        let b_item = bookmark_items
            .iter()
            .find(|i| i.external_id == "bookmark:1")
            .unwrap();
        let b_content = fs::read_to_string(&b_item.content_ref).unwrap();
        let b_record: BrowserBookmarkRecord = serde_json::from_str(&b_content).unwrap();
        assert_eq!(b_record.title, "Rust Language");
        assert_eq!(b_record.folder, "Bookmarks bar");
    }

    #[test]
    fn snapshot_scan_is_deterministic_and_does_not_mutate_source() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("History");
        let bpath = temp.path().join("Bookmarks");
        let stage_dir = temp.path().join("stage");
        create_mock_history_db(&db_path).unwrap();
        create_mock_bookmarks_file(&bpath).unwrap();

        let history_before = fs::read(&db_path).unwrap();
        let bookmarks_before = fs::read(&bpath).unwrap();

        let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
            source_instance: "chrome-laptop".into(),
            history_db_path: db_path.clone(),
            staging_dir: Some(stage_dir),
        })
        .with_bookmarks_path(bpath.clone());

        let first = connector.scan().unwrap();
        let second = connector.scan().unwrap();

        assert_eq!(first.items, second.items);
        assert_eq!(fs::read(&db_path).unwrap(), history_before);
        assert_eq!(fs::read(&bpath).unwrap(), bookmarks_before);
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_history_database_and_sidecar() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let real_db = temp.path().join("real-History");
        let db_path = temp.path().join("History");
        create_mock_urls_db(&real_db).unwrap();
        symlink(&real_db, &db_path).unwrap();

        let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
            source_instance: "chrome-laptop".into(),
            history_db_path: db_path,
            staging_dir: None,
        });
        assert!(connector.scan().is_err());

        let regular_db = temp.path().join("regular-History");
        create_mock_urls_db(&regular_db).unwrap();
        let sidecar = temp.path().join("History-wal");
        symlink(&real_db, &sidecar).unwrap();
        let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
            source_instance: "chrome-laptop".into(),
            history_db_path: regular_db,
            staging_dir: None,
        });
        assert!(connector.scan().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_bookmarks_file() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("History");
        create_mock_urls_db(&db_path).unwrap();

        let real_b = temp.path().join("real-Bookmarks");
        create_mock_bookmarks_file(&real_b).unwrap();
        let sym_b = temp.path().join("Bookmarks");
        symlink(&real_b, &sym_b).unwrap();

        let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
            source_instance: "chrome-laptop".into(),
            history_db_path: db_path,
            staging_dir: None,
        })
        .with_bookmarks_path(sym_b);

        assert!(connector.scan().is_err());
    }

    #[test]
    fn propagates_sidecar_copy_failure() {
        let temp = tempfile::tempdir().unwrap();
        let sidecar = temp.path().join("History-wal");
        fs::write(&sidecar, b"wal").unwrap();

        assert!(copy_sidecar(&sidecar, temp.path()).is_err());
    }

    #[test]
    fn fails_on_nonexistent_history_db() {
        let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
            source_instance: "chrome-desktop".into(),
            history_db_path: PathBuf::from("nonexistent_path_history.db"),
            staging_dir: None,
        });
        assert!(connector.scan().is_err());
    }

    #[test]
    fn fails_on_nonexistent_bookmarks_file() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("History");
        create_mock_urls_db(&db_path).unwrap();

        let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
            source_instance: "chrome-desktop".into(),
            history_db_path: db_path,
            staging_dir: None,
        })
        .with_bookmarks_path(PathBuf::from("nonexistent_bookmarks.json"));

        assert!(connector.scan().is_err());
    }

    #[test]
    fn scans_history_with_wal_and_shm_sidecars_and_verifies_fixity() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("History");
        create_mock_history_db(&db_path).unwrap();

        let wal_path = temp.path().join("History-wal");
        let shm_path = temp.path().join("History-shm");
        fs::write(&wal_path, b"initial wal state content").unwrap();
        fs::write(&shm_path, b"initial shm state content").unwrap();

        let wal_before = fs::read(&wal_path).unwrap();
        let shm_before = fs::read(&shm_path).unwrap();

        let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
            source_instance: "chrome-wal-test".into(),
            history_db_path: db_path,
            staging_dir: None,
        });

        let envelope = connector.scan().unwrap();
        assert_eq!(envelope.items.len(), 2);

        let visits = connector.scan_visits().unwrap();
        assert_eq!(visits.len(), 2);

        assert_eq!(fs::read(&wal_path).unwrap(), wal_before);
        assert_eq!(fs::read(&shm_path).unwrap(), shm_before);
    }

    #[test]
    fn sidecar_post_fixity_detects_mutation_removal_and_creation() {
        let temp = tempfile::tempdir().unwrap();
        let sidecar = temp.path().join("History-wal");

        // 1. Initial matching hash passes
        fs::write(&sidecar, b"original sidecar bytes").unwrap();
        let hash = file_sha256(&sidecar).unwrap();
        assert!(verify_sidecar_post_fixity(&sidecar, Some(&hash), "WAL").is_ok());

        // 2. Tampered content fails
        fs::write(&sidecar, b"tampered sidecar bytes").unwrap();
        let err = verify_sidecar_post_fixity(&sidecar, Some(&hash), "WAL").unwrap_err();
        assert!(err.to_string().contains("fixity violation"));

        // 3. Disappearing sidecar fails
        fs::remove_file(&sidecar).unwrap();
        let err = verify_sidecar_post_fixity(&sidecar, Some(&hash), "WAL").unwrap_err();
        assert!(err.to_string().contains("fixity violation"));

        // 4. Unexpected sidecar creation when none existed before fails
        fs::write(&sidecar, b"newly created sidecar").unwrap();
        let err = verify_sidecar_post_fixity(&sidecar, None, "WAL").unwrap_err();
        assert!(err.to_string().contains("fixity violation"));
    }
}
