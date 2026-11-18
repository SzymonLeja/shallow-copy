//! Operational SQLite catalog for shallow-copy.
//!
//! # Guarantees
//! - The catalog is a derived, queryable index over the OIAF canonical archive.
//! - It MUST be fully rebuildable from OIAF manifests; nothing canonical lives
//!   exclusively here.
//! - Blobs and envelope bytes stay in the OIAF CAS; the catalog stores metadata.
//! - All writes use transactions; the DB file must be on a local filesystem.
#![forbid(unsafe_code)]

use oiaf::{Archive, Envelope};
use rusqlite::{Connection, Result as SqlResult, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Target schema version enforced via `PRAGMA user_version` (ADR-003).
pub const SCHEMA_VERSION: u32 = 1;

/// A single row in the objects catalog table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogObject {
    pub object_id: String,
    pub blob_digest: String,
    pub blob_size: u64,
    pub connector: String,
    pub source_instance: String,
    pub external_id: String,
    pub revision: String,
    pub observed_time_unix_ms: u64,
    pub ingested_time_unix_ms: u64,
    pub ingest_fingerprint: Option<String>,
    pub media_type: Option<String>,
    pub suggested_domain: Option<String>,
}

impl From<&Envelope> for CatalogObject {
    fn from(e: &Envelope) -> Self {
        Self {
            object_id: e.object_id.clone(),
            blob_digest: e.blob.digest.clone(),
            blob_size: e.blob.size,
            connector: e.source.connector.clone(),
            source_instance: e.source.source_instance.clone(),
            external_id: e.source.external_id.clone(),
            revision: e.source.revision.clone(),
            observed_time_unix_ms: e.time.observed_time_unix_ms,
            ingested_time_unix_ms: e.time.ingested_time_unix_ms,
            ingest_fingerprint: None,
            media_type: None,
            suggested_domain: None,
        }
    }
}

/// Job status as stored in the catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl JobStatus {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "pending" => Some(Self::Pending),
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "cancelled" => Some(Self::Cancelled),
            _ => None,
        }
    }
}

/// A job row in the catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogJob {
    pub job_id: String,
    pub kind: String,
    pub status: JobStatus,
    pub progress_pct: Option<u8>,
    pub created_at_unix_ms: u64,
    pub updated_at_unix_ms: u64,
    pub error: Option<String>,
}

/// An append-only audit event stored in the catalog (ADR-009, project.md:33).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: String,
    pub event_type: String,
    pub actor: String,
    pub object_id: Option<String>,
    pub details_json: Option<String>,
    pub created_unix_ms: u64,
}

#[derive(Debug)]
pub enum Error {
    Sql(rusqlite::Error),
    Archive(oiaf::Error),
    Invalid(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sql(e) => write!(f, "SQL: {e}"),
            Self::Archive(e) => write!(f, "archive: {e}"),
            Self::Invalid(e) => write!(f, "invalid: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Sql(e) => Some(e),
            Self::Archive(e) => Some(e),
            Self::Invalid(_) => None,
        }
    }
}

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}

impl From<oiaf::Error> for Error {
    fn from(e: oiaf::Error) -> Self {
        Self::Archive(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Operational catalog backed by a local SQLite database.
pub struct Catalog {
    conn: Connection,
}

impl Catalog {
    /// Open or create the catalog at the given path.
    /// The path must be on a local filesystem (not NFS/SMB).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let cat = Self { conn };
        cat.init_schema()?;
        Ok(cat)
    }

    /// Open an in-memory catalog (useful for tests and rebuilds).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let cat = Self { conn };
        cat.init_schema()?;
        Ok(cat)
    }

    fn init_schema(&self) -> Result<()> {
        let user_version: u32 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        if user_version != 0 && user_version != SCHEMA_VERSION {
            return Err(Error::Invalid(format!(
                "unsupported catalog schema version: {user_version} (expected {SCHEMA_VERSION})"
            )));
        }

        self.conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS catalog_meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS objects (
                object_id              TEXT PRIMARY KEY,
                blob_digest            TEXT NOT NULL,
                blob_size              INTEGER NOT NULL,
                connector              TEXT NOT NULL,
                source_instance        TEXT NOT NULL,
                external_id            TEXT NOT NULL,
                revision               TEXT NOT NULL,
                observed_time_unix_ms  INTEGER NOT NULL,
                ingested_time_unix_ms  INTEGER NOT NULL,
                ingest_fingerprint     TEXT,
                media_type             TEXT,
                suggested_domain       TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_objects_blob_digest
                ON objects (blob_digest);

            CREATE INDEX IF NOT EXISTS idx_objects_connector
                ON objects (connector, source_instance);

            CREATE INDEX IF NOT EXISTS idx_objects_suggested_domain
            ON objects (suggested_domain);

            CREATE TABLE IF NOT EXISTS jobs (
                job_id              TEXT PRIMARY KEY,
                kind                TEXT NOT NULL,
                status              TEXT NOT NULL,
                progress_pct        INTEGER,
                created_at_unix_ms  INTEGER NOT NULL,
                updated_at_unix_ms  INTEGER NOT NULL,
                error               TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs (status);

            CREATE TABLE IF NOT EXISTS audit_events (
                id               TEXT PRIMARY KEY,
                event_type       TEXT NOT NULL,
                actor            TEXT NOT NULL,
                object_id        TEXT,
                details_json     TEXT,
                created_unix_ms  INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_events_created
                ON audit_events (created_unix_ms DESC);
            ",
        )?;
        for (name, definition) in [
            ("ingest_fingerprint", "TEXT"),
            ("media_type", "TEXT"),
            ("suggested_domain", "TEXT"),
        ] {
            let exists: i64 = self.conn.query_row(
                "SELECT COUNT(*) FROM pragma_table_info('objects') WHERE name = ?1",
                params![name],
                |row| row.get(0),
            )?;
            if exists == 0 {
                self.conn.execute(
                    &format!("ALTER TABLE objects ADD COLUMN {name} {definition}"),
                    [],
                )?;
            }
        }
        self.conn.execute_batch(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_objects_ingest_fingerprint
             ON objects (ingest_fingerprint);",
        )?;

        if user_version == 0 {
            self.conn
                .execute(&format!("PRAGMA user_version = {SCHEMA_VERSION}"), [])?;
        }

        Ok(())
    }

    /// Return the PRAGMA user_version of the catalog SQLite database.
    pub fn schema_version(&self) -> Result<u32> {
        let version: u32 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))?;
        Ok(version)
    }

    /// Retrieve a metadata value by key from the catalog_meta table.
    pub fn get_meta(&self, key: &str) -> Result<Option<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT value FROM catalog_meta WHERE key = ?1")?;
        let mut rows = stmt.query_map(params![key], |row| row.get(0))?;
        rows.next().transpose().map_err(Into::into)
    }

    /// Set or update a metadata value for the given key in the catalog_meta table.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        self.conn.execute(
            "INSERT INTO catalog_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        )?;
        Ok(())
    }

    /// Insert or update a single object from a CatalogObject without changing
    /// the metadata of an existing idempotent occurrence.
    pub fn upsert_catalog_object(&self, obj: &CatalogObject) -> Result<()> {
        let changed = self.conn.execute(
            "INSERT INTO objects
             (object_id, blob_digest, blob_size, connector, source_instance,
              external_id, revision, observed_time_unix_ms, ingested_time_unix_ms,
              ingest_fingerprint, media_type, suggested_domain)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
             ON CONFLICT(object_id) DO UPDATE SET
               blob_digest = excluded.blob_digest,
               blob_size = excluded.blob_size,
               connector = excluded.connector,
               source_instance = excluded.source_instance,
               external_id = excluded.external_id,
               revision = excluded.revision,
               observed_time_unix_ms = excluded.observed_time_unix_ms,
               ingested_time_unix_ms = excluded.ingested_time_unix_ms,
               ingest_fingerprint = excluded.ingest_fingerprint,
               media_type = excluded.media_type,
               suggested_domain = excluded.suggested_domain
             WHERE objects.ingest_fingerprint IS excluded.ingest_fingerprint
               AND objects.media_type IS excluded.media_type
               AND objects.suggested_domain IS excluded.suggested_domain",
            params![
                obj.object_id,
                obj.blob_digest,
                obj.blob_size as i64,
                obj.connector,
                obj.source_instance,
                obj.external_id,
                obj.revision,
                obj.observed_time_unix_ms as i64,
                obj.ingested_time_unix_ms as i64,
                obj.ingest_fingerprint,
                obj.media_type,
                obj.suggested_domain,
            ],
        )?;
        if changed == 0 {
            return Err(Error::Invalid(
                "existing object metadata conflicts with idempotent upsert".into(),
            ));
        }
        Ok(())
    }

    /// Set or clear the suggested domain for a given object ID.
    pub fn set_suggested_domain(&self, object_id: &str, domain: Option<&str>) -> Result<()> {
        self.conn.execute(
            "UPDATE objects SET suggested_domain = ?1 WHERE object_id = ?2",
            params![domain, object_id],
        )?;
        Ok(())
    }

    /// Insert or update a single object from an OIAF envelope with optional ingest metadata.
    ///
    /// Preserves existing object occurrences and rejects conflicting metadata or
    /// duplicate fingerprints across different objects.
    pub fn upsert_object(
        &self,
        envelope: &Envelope,
        ingest_fingerprint: Option<&str>,
        media_type: Option<&str>,
        suggested_domain: Option<&str>,
    ) -> Result<()> {
        let mut obj = CatalogObject::from(envelope);
        obj.ingest_fingerprint = ingest_fingerprint.map(ToOwned::to_owned);
        obj.media_type = media_type.map(ToOwned::to_owned);
        obj.suggested_domain = suggested_domain.map(ToOwned::to_owned);
        self.upsert_catalog_object(&obj)
    }

    /// Rebuild the entire catalog from an OIAF archive.
    ///
    /// Executes within a single SQLite transaction:
    /// - Purges stale or orphan object records no longer present in the canonical manifest.
    /// - Indexes all valid envelopes from the manifest.
    /// - Records rebuild metadata in `catalog_meta` (`last_rebuild_unix_ms`, `rebuilt_count`, `oiaf_version`).
    /// - Aborts and rolls back on any error, preventing partial or corrupted catalog state.
    pub fn rebuild_from_archive(&mut self, archive: &Archive) -> Result<usize> {
        let envelopes = archive.list_objects()?;
        let active_ids: std::collections::HashSet<String> =
            envelopes.iter().map(|e| e.object_id.clone()).collect();

        let tx = self.conn.transaction()?;

        // 1. Purge stale/orphan object records not present in the canonical manifest
        let existing_ids: Vec<String> = {
            let mut select_stmt = tx.prepare("SELECT object_id FROM objects")?;
            select_stmt
                .query_map([], |row| row.get(0))?
                .collect::<SqlResult<Vec<_>>>()?
        };
        for id in existing_ids {
            if !active_ids.contains(&id) {
                tx.execute("DELETE FROM objects WHERE object_id = ?1", params![id])?;
            }
        }

        // 2. Index all valid envelopes from the manifest
        for envelope in &envelopes {
            let obj = CatalogObject::from(envelope);
            tx.execute(
                "INSERT INTO objects
                 (object_id, blob_digest, blob_size, connector, source_instance,
                  external_id, revision, observed_time_unix_ms, ingested_time_unix_ms,
                  ingest_fingerprint, media_type, suggested_domain)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)
                 ON CONFLICT(object_id) DO UPDATE SET
                   blob_digest = excluded.blob_digest,
                   blob_size = excluded.blob_size,
                   connector = excluded.connector,
                   source_instance = excluded.source_instance,
                   external_id = excluded.external_id,
                   revision = excluded.revision,
                   observed_time_unix_ms = excluded.observed_time_unix_ms,
                   ingested_time_unix_ms = excluded.ingested_time_unix_ms",
                params![
                    obj.object_id,
                    obj.blob_digest,
                    obj.blob_size as i64,
                    obj.connector,
                    obj.source_instance,
                    obj.external_id,
                    obj.revision,
                    obj.observed_time_unix_ms as i64,
                    obj.ingested_time_unix_ms as i64,
                    obj.ingest_fingerprint,
                    obj.media_type,
                    obj.suggested_domain,
                ],
            )?;
        }

        // 3. Record rebuild metadata in catalog_meta
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let rebuilt_count = envelopes.len();
        let oiaf_version = archive.summary().oiaf_version;

        tx.execute(
            "INSERT INTO catalog_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params!["last_rebuild_unix_ms", now_ms.to_string()],
        )?;
        tx.execute(
            "INSERT INTO catalog_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params!["rebuilt_count", rebuilt_count.to_string()],
        )?;
        tx.execute(
            "INSERT INTO catalog_meta (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params!["oiaf_version", oiaf_version],
        )?;

        tx.commit()?;
        Ok(rebuilt_count)
    }

    /// List all objects, ordered by ingestion time.
    pub fn list_objects(&self) -> Result<Vec<CatalogObject>> {
        let mut stmt = self.conn.prepare(
            "SELECT object_id, blob_digest, blob_size, connector, source_instance,
                    external_id, revision, observed_time_unix_ms, ingested_time_unix_ms,
                    ingest_fingerprint, media_type, suggested_domain
             FROM objects ORDER BY ingested_time_unix_ms ASC",
        )?;
        let rows = stmt.query_map([], map_object_row)?;
        rows.collect::<SqlResult<Vec<_>>>().map_err(Into::into)
    }

    /// List objects filtered by suggested domain, ordered by ingestion time.
    pub fn list_objects_by_domain(&self, domain: &str) -> Result<Vec<CatalogObject>> {
        let mut stmt = self.conn.prepare(
            "SELECT object_id, blob_digest, blob_size, connector, source_instance,
                    external_id, revision, observed_time_unix_ms, ingested_time_unix_ms,
                    ingest_fingerprint, media_type, suggested_domain
             FROM objects WHERE suggested_domain = ?1 ORDER BY ingested_time_unix_ms ASC",
        )?;
        let rows = stmt.query_map(params![domain], map_object_row)?;
        rows.collect::<SqlResult<Vec<_>>>().map_err(Into::into)
    }

    /// Return count of objects in a given suggested domain.
    pub fn domain_object_count(&self, domain: &str) -> Result<u64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM objects WHERE suggested_domain = ?1",
            params![domain],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Get a single object by ID.
    pub fn get_object(&self, object_id: &str) -> Result<Option<CatalogObject>> {
        let mut stmt = self.conn.prepare(
            "SELECT object_id, blob_digest, blob_size, connector, source_instance,
                    external_id, revision, observed_time_unix_ms, ingested_time_unix_ms,
                    ingest_fingerprint, media_type, suggested_domain
             FROM objects WHERE object_id = ?1",
        )?;
        let mut rows = stmt.query_map(params![object_id], map_object_row)?;
        rows.next().transpose().map_err(Into::into)
    }

    /// Get a single object by ingest fingerprint.
    pub fn get_object_by_fingerprint(&self, fingerprint: &str) -> Result<Option<CatalogObject>> {
        let mut stmt = self.conn.prepare(
            "SELECT object_id, blob_digest, blob_size, connector, source_instance,
                    external_id, revision, observed_time_unix_ms, ingested_time_unix_ms,
                    ingest_fingerprint, media_type, suggested_domain
             FROM objects WHERE ingest_fingerprint = ?1",
        )?;
        let mut rows = stmt.query_map(params![fingerprint], map_object_row)?;
        rows.next().transpose().map_err(Into::into)
    }

    /// Total number of objects in the catalog.
    pub fn object_count(&self) -> Result<u64> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM objects", [], |row| row.get(0))?;
        Ok(count as u64)
    }

    /// Insert a new job record.
    pub fn insert_job(&self, job: &CatalogJob) -> Result<()> {
        self.conn.execute(
            "INSERT INTO jobs
             (job_id, kind, status, progress_pct, created_at_unix_ms, updated_at_unix_ms, error)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![
                job.job_id,
                job.kind,
                job.status.as_str(),
                job.progress_pct.map(|p| p as i64),
                job.created_at_unix_ms as i64,
                job.updated_at_unix_ms as i64,
                job.error,
            ],
        )?;
        Ok(())
    }

    /// Update job status and optional progress/error.
    pub fn update_job_status(
        &self,
        job_id: &str,
        status: JobStatus,
        progress_pct: Option<u8>,
        error: Option<&str>,
        updated_at_unix_ms: u64,
    ) -> Result<bool> {
        let changed = self.conn.execute(
            "UPDATE jobs SET status=?1, progress_pct=?2, error=?3, updated_at_unix_ms=?4
             WHERE job_id=?5",
            params![
                status.as_str(),
                progress_pct.map(|p| p as i64),
                error,
                updated_at_unix_ms as i64,
                job_id,
            ],
        )?;
        Ok(changed > 0)
    }

    /// List jobs filtered by status (None = all).
    pub fn list_jobs(&self, status: Option<JobStatus>) -> Result<Vec<CatalogJob>> {
        let sql = if status.is_some() {
            "SELECT job_id, kind, status, progress_pct, created_at_unix_ms, updated_at_unix_ms, error
             FROM jobs WHERE status=?1 ORDER BY created_at_unix_ms DESC"
        } else {
            "SELECT job_id, kind, status, progress_pct, created_at_unix_ms, updated_at_unix_ms, error
             FROM jobs WHERE 1=1 ORDER BY created_at_unix_ms DESC"
        };
        let rows: Vec<CatalogJob> = if let Some(ref s) = status {
            let mut stmt = self.conn.prepare(sql)?;
            stmt.query_map(params![s.as_str()], map_job_row)?
                .collect::<SqlResult<_>>()?
        } else {
            let sql_all =
                "SELECT job_id, kind, status, progress_pct, created_at_unix_ms, updated_at_unix_ms, error
                 FROM jobs ORDER BY created_at_unix_ms DESC";
            let mut stmt = self.conn.prepare(sql_all)?;
            stmt.query_map([], map_job_row)?.collect::<SqlResult<_>>()?
        };
        Ok(rows)
    }

    /// Record an audit event into the append-only audit log.
    pub fn record_audit_event(&self, event: &AuditEvent) -> SqlResult<()> {
        self.conn.execute(
            "INSERT INTO audit_events (id, event_type, actor, object_id, details_json, created_unix_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                event.id,
                event.event_type,
                event.actor,
                event.object_id,
                event.details_json,
                event.created_unix_ms as i64,
            ],
        )?;
        Ok(())
    }

    /// List audit events ordered by `created_unix_ms DESC`, bounded by `limit`.
    pub fn list_audit_events(&self, limit: usize) -> SqlResult<Vec<AuditEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, event_type, actor, object_id, details_json, created_unix_ms
             FROM audit_events
             ORDER BY created_unix_ms DESC
             LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], map_audit_event_row)?;
        rows.collect()
    }
}

fn map_audit_event_row(row: &rusqlite::Row<'_>) -> SqlResult<AuditEvent> {
    Ok(AuditEvent {
        id: row.get(0)?,
        event_type: row.get(1)?,
        actor: row.get(2)?,
        object_id: row.get(3)?,
        details_json: row.get(4)?,
        created_unix_ms: row.get::<_, i64>(5)? as u64,
    })
}

fn map_object_row(row: &rusqlite::Row<'_>) -> SqlResult<CatalogObject> {
    Ok(CatalogObject {
        object_id: row.get(0)?,
        blob_digest: row.get(1)?,
        blob_size: row.get::<_, i64>(2)? as u64,
        connector: row.get(3)?,
        source_instance: row.get(4)?,
        external_id: row.get(5)?,
        revision: row.get(6)?,
        observed_time_unix_ms: row.get::<_, i64>(7)? as u64,
        ingested_time_unix_ms: row.get::<_, i64>(8)? as u64,
        ingest_fingerprint: row.get(9)?,
        media_type: row.get(10)?,
        suggested_domain: row.get(11)?,
    })
}

fn map_job_row(row: &rusqlite::Row<'_>) -> SqlResult<CatalogJob> {
    let status_str: String = row.get(2)?;
    Ok(CatalogJob {
        job_id: row.get(0)?,
        kind: row.get(1)?,
        status: JobStatus::from_str(&status_str).unwrap_or(JobStatus::Pending),
        progress_pct: row.get::<_, Option<i64>>(3)?.map(|v| v as u8),
        created_at_unix_ms: row.get::<_, i64>(4)? as u64,
        updated_at_unix_ms: row.get::<_, i64>(5)? as u64,
        error: row.get(6)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use oiaf::{Archive, Source};

    fn test_archive(dir: &tempfile::TempDir) -> Archive {
        Archive::init(dir.path().join("archive")).unwrap()
    }

    fn test_source(name: &str, rev: &str) -> Source {
        Source::filesystem("test", name, rev)
    }

    #[test]
    fn empty_catalog_has_zero_objects() {
        let cat = Catalog::open_in_memory().unwrap();
        assert_eq!(cat.object_count().unwrap(), 0);
        assert!(cat.list_objects().unwrap().is_empty());
    }

    #[test]
    fn rebuild_from_archive_imports_all_objects() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = test_archive(&tmp);
        archive
            .import_bytes(b"alpha", test_source("alpha", "1"))
            .unwrap();
        archive
            .import_bytes(b"beta", test_source("beta", "1"))
            .unwrap();
        let mut cat = Catalog::open_in_memory().unwrap();
        let count = cat.rebuild_from_archive(&archive).unwrap();
        assert_eq!(count, 2);
        assert_eq!(cat.object_count().unwrap(), 2);
    }

    #[test]
    fn rebuild_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = test_archive(&tmp);
        archive.import_bytes(b"x", test_source("x", "1")).unwrap();
        let mut cat = Catalog::open_in_memory().unwrap();
        cat.rebuild_from_archive(&archive).unwrap();
        cat.rebuild_from_archive(&archive).unwrap();
        assert_eq!(cat.object_count().unwrap(), 1);
    }

    #[test]
    fn get_object_returns_correct_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = test_archive(&tmp);
        let result = archive
            .import_bytes(b"payload", test_source("doc", "v1"))
            .unwrap();
        let mut cat = Catalog::open_in_memory().unwrap();
        cat.rebuild_from_archive(&archive).unwrap();
        let obj = cat.get_object(&result.envelope.object_id).unwrap().unwrap();
        assert_eq!(obj.object_id, result.envelope.object_id);
        assert_eq!(obj.blob_digest, result.envelope.blob.digest);
        assert_eq!(obj.blob_size, result.envelope.blob.size);
        assert_eq!(obj.connector, "filesystem");
        assert_eq!(obj.source_instance, "test");
        assert_eq!(obj.external_id, "doc");
        assert_eq!(obj.revision, "v1");
    }

    #[test]
    fn get_object_returns_none_for_unknown_id() {
        let cat = Catalog::open_in_memory().unwrap();
        let missing = cat.get_object(&"a".repeat(64)).unwrap();
        assert!(missing.is_none());
    }

    #[test]
    fn job_lifecycle_pending_to_completed() {
        let cat = Catalog::open_in_memory().unwrap();
        let job = CatalogJob {
            job_id: "01JFAKE000000000000000000A".into(),
            kind: "verify".into(),
            status: JobStatus::Pending,
            progress_pct: None,
            created_at_unix_ms: 1_000_000,
            updated_at_unix_ms: 1_000_000,
            error: None,
        };
        cat.insert_job(&job).unwrap();
        let pending = cat.list_jobs(Some(JobStatus::Pending)).unwrap();
        assert_eq!(pending.len(), 1);
        let changed = cat
            .update_job_status(
                &job.job_id,
                JobStatus::Completed,
                Some(100),
                None,
                2_000_000,
            )
            .unwrap();
        assert!(changed);
        assert!(cat.list_jobs(Some(JobStatus::Pending)).unwrap().is_empty());
        let done = cat.list_jobs(Some(JobStatus::Completed)).unwrap();
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].progress_pct, Some(100));
    }

    #[test]
    fn list_all_jobs_returns_all_statuses() {
        let cat = Catalog::open_in_memory().unwrap();
        for (id, status) in [
            ("A", JobStatus::Pending),
            ("B", JobStatus::Running),
            ("C", JobStatus::Completed),
        ] {
            cat.insert_job(&CatalogJob {
                job_id: id.into(),
                kind: "test".into(),
                status,
                progress_pct: None,
                created_at_unix_ms: 1000,
                updated_at_unix_ms: 1000,
                error: None,
            })
            .unwrap();
        }
        assert_eq!(cat.list_jobs(None).unwrap().len(), 3);
    }

    #[test]
    fn upsert_object_with_metadata_stores_and_retrieves_fields() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = test_archive(&tmp);
        let result = archive
            .import_bytes(b"metadata-test", test_source("meta-doc", "v1"))
            .unwrap();
        let cat = Catalog::open_in_memory().unwrap();

        cat.upsert_object(
            &result.envelope,
            Some("fingerprint-123"),
            Some("text/markdown"),
            Some("private"),
        )
        .unwrap();

        let obj = cat.get_object(&result.envelope.object_id).unwrap().unwrap();
        assert_eq!(obj.ingest_fingerprint.as_deref(), Some("fingerprint-123"));
        assert_eq!(obj.media_type.as_deref(), Some("text/markdown"));
        assert_eq!(obj.suggested_domain.as_deref(), Some("private"));

        let by_fp = cat
            .get_object_by_fingerprint("fingerprint-123")
            .unwrap()
            .unwrap();
        assert_eq!(by_fp.object_id, result.envelope.object_id);
    }

    #[test]
    fn unique_index_prevents_duplicate_fingerprint_for_different_object() {
        let cat = Catalog::open_in_memory().unwrap();

        let obj1 = CatalogObject {
            object_id: "obj-1".into(),
            blob_digest: "digest-1".into(),
            blob_size: 10,
            connector: "filesystem".into(),
            source_instance: "node1".into(),
            external_id: "file1".into(),
            revision: "r1".into(),
            observed_time_unix_ms: 100,
            ingested_time_unix_ms: 100,
            ingest_fingerprint: Some("unique-fp".into()),
            media_type: None,
            suggested_domain: None,
        };

        let obj2 = CatalogObject {
            object_id: "obj-2".into(),
            blob_digest: "digest-2".into(),
            blob_size: 20,
            connector: "filesystem".into(),
            source_instance: "node1".into(),
            external_id: "file2".into(),
            revision: "r1".into(),
            observed_time_unix_ms: 200,
            ingested_time_unix_ms: 200,
            ingest_fingerprint: Some("unique-fp".into()),
            media_type: None,
            suggested_domain: None,
        };

        cat.upsert_catalog_object(&obj1).unwrap();
        assert!(cat.upsert_catalog_object(&obj2).is_err());

        assert_eq!(cat.object_count().unwrap(), 1);
        let by_fp = cat.get_object_by_fingerprint("unique-fp").unwrap().unwrap();
        assert_eq!(by_fp.object_id, "obj-1");
    }

    #[test]
    fn idempotent_upsert_rejects_metadata_drift() {
        let cat = Catalog::open_in_memory().unwrap();
        let base = CatalogObject {
            object_id: "obj-1".into(),
            blob_digest: "digest-1".into(),
            blob_size: 10,
            connector: "filesystem".into(),
            source_instance: "node1".into(),
            external_id: "file1".into(),
            revision: "r1".into(),
            observed_time_unix_ms: 100,
            ingested_time_unix_ms: 100,
            ingest_fingerprint: Some("stable-fp".into()),
            media_type: Some("text/plain".into()),
            suggested_domain: Some("private".into()),
        };
        cat.upsert_catalog_object(&base).unwrap();

        let mut changed = base.clone();
        changed.media_type = Some("application/pdf".into());
        assert!(cat.upsert_catalog_object(&changed).is_err());
        assert_eq!(
            cat.get_object("obj-1")
                .unwrap()
                .unwrap()
                .media_type
                .as_deref(),
            Some("text/plain")
        );
    }

    #[test]
    fn schema_version_enforced_and_rejects_unsupported() {
        let cat = Catalog::open_in_memory().unwrap();
        assert_eq!(cat.schema_version().unwrap(), SCHEMA_VERSION);
        assert_eq!(cat.schema_version().unwrap(), 1);

        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("catalog.db");
        {
            let disk_cat = Catalog::open(&db_path).unwrap();
            assert_eq!(disk_cat.schema_version().unwrap(), 1);
        }
        {
            let disk_cat = Catalog::open(&db_path).unwrap();
            assert_eq!(disk_cat.schema_version().unwrap(), 1);
        }
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute("PRAGMA user_version = 99", []).unwrap();
        }
        let err = match Catalog::open(&db_path) {
            Ok(_) => panic!("expected error opening database with unsupported user_version"),
            Err(e) => e,
        };
        assert!(matches!(err, Error::Invalid(_)));
    }

    #[test]
    fn catalog_meta_get_and_set() {
        let cat = Catalog::open_in_memory().unwrap();
        assert_eq!(cat.get_meta("nonexistent").unwrap(), None);

        cat.set_meta("custom_key", "custom_val").unwrap();
        assert_eq!(
            cat.get_meta("custom_key").unwrap().as_deref(),
            Some("custom_val")
        );

        cat.set_meta("custom_key", "updated_val").unwrap();
        assert_eq!(
            cat.get_meta("custom_key").unwrap().as_deref(),
            Some("updated_val")
        );
    }

    #[test]
    fn rebuild_from_archive_records_metadata() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = test_archive(&tmp);
        archive
            .import_bytes(b"test1", test_source("f1", "1"))
            .unwrap();
        archive
            .import_bytes(b"test2", test_source("f2", "1"))
            .unwrap();

        let mut cat = Catalog::open_in_memory().unwrap();
        let count = cat.rebuild_from_archive(&archive).unwrap();
        assert_eq!(count, 2);

        let last_rebuild = cat.get_meta("last_rebuild_unix_ms").unwrap();
        assert!(last_rebuild.is_some());
        let ts: u64 = last_rebuild.unwrap().parse().unwrap();
        assert!(ts > 0);

        assert_eq!(cat.get_meta("rebuilt_count").unwrap().as_deref(), Some("2"));
        assert_eq!(
            cat.get_meta("oiaf_version").unwrap().as_deref(),
            Some(oiaf::FORMAT_VERSION)
        );
    }

    #[test]
    fn rebuild_purges_stale_orphan_objects() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = test_archive(&tmp);
        let res = archive
            .import_bytes(b"valid", test_source("valid_file", "1"))
            .unwrap();

        let mut cat = Catalog::open_in_memory().unwrap();

        let orphan = CatalogObject {
            object_id: "orphan-id-12345".into(),
            blob_digest: "stale-blob-digest".into(),
            blob_size: 999,
            connector: "filesystem".into(),
            source_instance: "old".into(),
            external_id: "old_external".into(),
            revision: "1".into(),
            observed_time_unix_ms: 100,
            ingested_time_unix_ms: 100,
            ingest_fingerprint: None,
            media_type: None,
            suggested_domain: None,
        };
        cat.upsert_catalog_object(&orphan).unwrap();
        assert_eq!(cat.object_count().unwrap(), 1);
        assert!(cat.get_object("orphan-id-12345").unwrap().is_some());

        let count = cat.rebuild_from_archive(&archive).unwrap();
        assert_eq!(count, 1);
        assert_eq!(cat.object_count().unwrap(), 1);

        assert!(cat.get_object("orphan-id-12345").unwrap().is_none());
        assert!(cat.get_object(&res.envelope.object_id).unwrap().is_some());
    }

    #[test]
    fn rebuild_transaction_rollback_preserves_prior_state_on_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = test_archive(&tmp);
        let res = archive
            .import_bytes(b"valid-init", test_source("init_file", "1"))
            .unwrap();

        let mut cat = Catalog::open_in_memory().unwrap();
        cat.rebuild_from_archive(&archive).unwrap();
        assert_eq!(cat.object_count().unwrap(), 1);

        let manifest_path = tmp.path().join("archive/manifest.json");
        std::fs::write(&manifest_path, b"corrupted non-json manifest").unwrap();

        let err = cat.rebuild_from_archive(&archive).unwrap_err();
        assert!(matches!(err, Error::Archive(_)));

        assert_eq!(cat.object_count().unwrap(), 1);
        assert!(cat.get_object(&res.envelope.object_id).unwrap().is_some());
    }

    #[test]
    fn record_and_list_audit_events() {
        let cat = Catalog::open_in_memory().unwrap();
        assert!(cat.list_audit_events(10).unwrap().is_empty());

        let evt1 = AuditEvent {
            id: "evt-001".into(),
            event_type: "auth.login".into(),
            actor: "user-alice".into(),
            object_id: None,
            details_json: Some(r#"{"ip":"127.0.0.1"}"#.into()),
            created_unix_ms: 1000,
        };
        let evt2 = AuditEvent {
            id: "evt-002".into(),
            event_type: "archive.delete".into(),
            actor: "guard-session".into(),
            object_id: Some("obj-999".into()),
            details_json: None,
            created_unix_ms: 2000,
        };

        cat.record_audit_event(&evt1).unwrap();
        cat.record_audit_event(&evt2).unwrap();

        let events = cat.list_audit_events(10).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0], evt2);
        assert_eq!(events[1], evt1);
    }

    #[test]
    fn audit_events_ordered_by_created_desc_and_bounded_by_limit() {
        let cat = Catalog::open_in_memory().unwrap();
        for (id, ts) in [("e1", 1000), ("e3", 3000), ("e2", 2000), ("e4", 4000)] {
            cat.record_audit_event(&AuditEvent {
                id: id.into(),
                event_type: "test".into(),
                actor: "actor".into(),
                object_id: None,
                details_json: None,
                created_unix_ms: ts,
            })
            .unwrap();
        }

        let all = cat.list_audit_events(10).unwrap();
        assert_eq!(all.len(), 4);
        assert_eq!(all[0].id, "e4");
        assert_eq!(all[1].id, "e3");
        assert_eq!(all[2].id, "e2");
        assert_eq!(all[3].id, "e1");

        let top2 = cat.list_audit_events(2).unwrap();
        assert_eq!(top2.len(), 2);
        assert_eq!(top2[0].id, "e4");
        assert_eq!(top2[1].id, "e3");
    }

    #[test]
    fn audit_events_rejects_duplicate_id() {
        let cat = Catalog::open_in_memory().unwrap();
        let evt = AuditEvent {
            id: "duplicate-id".into(),
            event_type: "test".into(),
            actor: "actor".into(),
            object_id: None,
            details_json: None,
            created_unix_ms: 1000,
        };
        cat.record_audit_event(&evt).unwrap();
        assert!(cat.record_audit_event(&evt).is_err());
    }

    #[test]
    fn audit_events_transaction_rollback_safety() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let evt = AuditEvent {
            id: "tx-evt".into(),
            event_type: "test".into(),
            actor: "actor".into(),
            object_id: None,
            details_json: None,
            created_unix_ms: 1000,
        };

        {
            let tx = cat.conn.transaction().unwrap();
            tx.execute(
                "INSERT INTO audit_events (id, event_type, actor, object_id, details_json, created_unix_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    evt.id,
                    evt.event_type,
                    evt.actor,
                    evt.object_id,
                    evt.details_json,
                    evt.created_unix_ms as i64,
                ],
            )
            .unwrap();
        }
        assert!(cat.list_audit_events(10).unwrap().is_empty());

        cat.record_audit_event(&evt).unwrap();
        assert_eq!(cat.list_audit_events(10).unwrap().len(), 1);
    }

    #[test]
    fn rebuild_from_archive_preserves_audit_events() {
        let tmp = tempfile::tempdir().unwrap();
        let archive = test_archive(&tmp);
        archive
            .import_bytes(b"data", test_source("f", "1"))
            .unwrap();

        let mut cat = Catalog::open_in_memory().unwrap();
        cat.record_audit_event(&AuditEvent {
            id: "preserve-evt".into(),
            event_type: "audit.test".into(),
            actor: "admin".into(),
            object_id: None,
            details_json: None,
            created_unix_ms: 5000,
        })
        .unwrap();

        cat.rebuild_from_archive(&archive).unwrap();
        let events = cat.list_audit_events(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "preserve-evt");
    }

    // new tests
    #[test]
    fn list_objects_by_domain_and_count() {
        let cat = Catalog::open_in_memory().unwrap();
        let obj1 = CatalogObject {
            object_id: "obj-1".into(),
            blob_digest: "d1".into(),
            blob_size: 10,
            connector: "c1".into(),
            source_instance: "s1".into(),
            external_id: "e1".into(),
            revision: "r1".into(),
            observed_time_unix_ms: 100,
            ingested_time_unix_ms: 100,
            ingest_fingerprint: None,
            media_type: None,
            suggested_domain: Some("alpha".into()),
        };
        let obj2 = CatalogObject {
            object_id: "obj-2".into(),
            blob_digest: "d2".into(),
            blob_size: 20,
            connector: "c2".into(),
            source_instance: "s2".into(),
            external_id: "e2".into(),
            revision: "r2".into(),
            observed_time_unix_ms: 200,
            ingested_time_unix_ms: 200,
            ingest_fingerprint: None,
            media_type: None,
            suggested_domain: Some("beta".into()),
        };
        let obj3 = CatalogObject {
            object_id: "obj-3".into(),
            blob_digest: "d3".into(),
            blob_size: 30,
            connector: "c3".into(),
            source_instance: "s3".into(),
            external_id: "e3".into(),
            revision: "r3".into(),
            observed_time_unix_ms: 300,
            ingested_time_unix_ms: 300,
            ingest_fingerprint: None,
            media_type: None,
            suggested_domain: Some("alpha".into()),
        };
        cat.upsert_catalog_object(&obj1).unwrap();
        cat.upsert_catalog_object(&obj2).unwrap();
        cat.upsert_catalog_object(&obj3).unwrap();

        let alpha_objs = cat.list_objects_by_domain("alpha").unwrap();
        assert_eq!(alpha_objs.len(), 2);
        assert_eq!(alpha_objs[0].object_id, "obj-1");
        assert_eq!(alpha_objs[1].object_id, "obj-3");

        let beta_objs = cat.list_objects_by_domain("beta").unwrap();
        assert_eq!(beta_objs.len(), 1);
        assert_eq!(beta_objs[0].object_id, "obj-2");

        assert_eq!(cat.domain_object_count("alpha").unwrap(), 2);
        assert_eq!(cat.domain_object_count("beta").unwrap(), 1);
        assert_eq!(cat.domain_object_count("gamma").unwrap(), 0);
    }

    #[test]
    fn rebuild_preserves_domain_indexing() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let foo = "foo";
        let obj = CatalogObject {
            object_id: "obj-1".into(),
            blob_digest: "d1".into(),
            blob_size: 10,
            connector: "c1".into(),
            source_instance: "s1".into(),
            external_id: "e1".into(),
            revision: "r1".into(),
            observed_time_unix_ms: 100,
            ingested_time_unix_ms: 100,
            ingest_fingerprint: None,
            media_type: None,
            suggested_domain: Some(foo.into()),
        };
        cat.upsert_catalog_object(&obj).unwrap();

        let tmp = tempfile::tempdir().unwrap();
        let archive = test_archive(&tmp);
        let env = archive
            .import_bytes(b"obj-1", test_source("file", "1"))
            .unwrap();
        cat.rebuild_from_archive(&archive).unwrap();
        cat.set_suggested_domain(&env.envelope.object_id, Some(foo))
            .unwrap();
        cat.rebuild_from_archive(&archive).unwrap();
        let domain_objs = cat.list_objects_by_domain(foo).unwrap();
        assert_eq!(domain_objs.len(), 1);
        assert_eq!(cat.domain_object_count(foo).unwrap(), 1);
        assert_eq!(cat.object_count().unwrap(), 1);
    }
}
