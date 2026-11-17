//! Chromium browser history ingestion connector for shallow-copy.
//!
//! # Guarantees
//! - Copies a snapshot of the source SQLite database before opening, preventing
//!   locks against active browsers (per `project.md` line 358).
//! - Operates strictly read-only on the copied snapshot.
//! - Transforms Chromium visit records into standard `IngestItem` records.
#![forbid(unsafe_code)]

use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserVisitRecord {
    pub visit_id: i64,
    pub url: String,
    pub title: Option<String>,
    pub visit_count: Option<i64>,
    pub visit_time_raw: i64,
    pub event_time_unix_ms: Option<u64>,
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
            Self::Invalid(e) => write!(f, "invalid browser history: {e}"),
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
}

impl ChromiumHistoryConnector {
    pub fn new(config: ChromiumHistoryConfig) -> Self {
        Self { config }
    }

    /// Read browser history from configured SQLite database and produce an `IngestEnvelope`.
    ///
    /// Copies a snapshot of the database file before querying to avoid lock contention
    /// with running Chromium instances.
    pub fn scan(&self) -> Result<IngestEnvelope> {
        let src = &self.config.history_db_path;
        if !src.is_file() {
            return Err(Error::Invalid(format!(
                "history database file not found: {}",
                src.display()
            )));
        }

        // Create temporary snapshot directory
        let snapshot_dir = tempfile::tempdir()?;
        let snapshot_path = snapshot_dir.path().join("History.snapshot");
        fs::copy(src, &snapshot_path)?;

        // Copy WAL and SHM files if present for consistent point-in-time snapshot
        let wal = src.with_file_name("History-wal");
        if wal.exists() {
            let _ = fs::copy(&wal, snapshot_dir.path().join("History.snapshot-wal"));
        }
        let shm = src.with_file_name("History-shm");
        if shm.exists() {
            let _ = fs::copy(&shm, snapshot_dir.path().join("History.snapshot-shm"));
        }

        // Open snapshot read-only
        let conn = Connection::open_with_flags(&snapshot_path, OpenFlags::SQLITE_OPEN_READ_ONLY)?;

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

        let raw_visits = read_visits(&conn)?;
        let mut items = Vec::with_capacity(raw_visits.len());

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

        Ok(IngestEnvelope {
            source_instance: self.config.source_instance.clone(),
            cursor: None,
            items,
        })
    }
}

struct RawVisit {
    id: i64,
    url: String,
    title: Option<String>,
    visit_count: Option<i64>,
    visit_time: i64,
}

fn read_visits(conn: &Connection) -> Result<Vec<BrowserVisitRecord>> {
    let has_visits_table: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name='visits'",
            [],
            |row| row.get(0),
        )
        .unwrap_or(false);

    let raw_list: Vec<RawVisit> = if has_visits_table {
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
            })
        })?;
        rows.collect::<SqlResult<Vec<_>>>()?
    };

    let mut records = Vec::with_capacity(raw_list.len());
    for raw in raw_list {
        let event_time = convert_chromium_timestamp(raw.visit_time);
        records.push(BrowserVisitRecord {
            visit_id: raw.id,
            url: raw.url,
            title: raw.title,
            visit_count: raw.visit_count,
            visit_time_raw: raw.visit_time,
            event_time_unix_ms: event_time,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn create_mock_urls_db(path: &Path) {
        let conn = Connection::open(path).unwrap();
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
        )
        .unwrap();
    }

    fn create_mock_history_db(path: &Path) {
        let conn = Connection::open(path).unwrap();
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
                visit_time INTEGER NOT NULL
            );
            INSERT INTO urls (id, url, title, visit_count, last_visit_time)
            VALUES (10, 'https://shallow-copy.org', 'Shallow Copy Project', 3, 13350000000000000);
            INSERT INTO visits (id, url, visit_time)
            VALUES (100, 10, 13350000000000000);
            INSERT INTO visits (id, url, visit_time)
            VALUES (101, 10, 13350000050000000);
            ",
        )
        .unwrap();
    }

    #[test]
    fn scans_mock_db_with_urls_table() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("History");
        let stage_dir = temp.path().join("stage");
        create_mock_urls_db(&db_path);

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
    }

    #[test]
    fn scans_mock_db_with_visits_and_urls_table() {
        let temp = tempfile::tempdir().unwrap();
        let db_path = temp.path().join("History");
        create_mock_history_db(&db_path);

        let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
            source_instance: "chrome-desktop".into(),
            history_db_path: db_path,
            staging_dir: None,
        });

        let envelope = connector.scan().unwrap();
        assert_eq!(envelope.items.len(), 2);
        assert_eq!(envelope.items[0].external_id, "history:100");
        assert_eq!(envelope.items[1].external_id, "history:101");
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
}
