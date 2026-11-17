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

    /// Rebuild the entire catalog from an OIAF archive. Existing object rows
    /// are replaced; job rows are left untouched.
    pub fn rebuild_from_archive(&mut self, archive: &Archive) -> Result<usize> {
        let envelopes = archive.list_objects()?;
        let tx = self.conn.transaction()?;
        for envelope in &envelopes {
            let obj = CatalogObject::from(envelope);
            tx.execute(
                "INSERT OR REPLACE INTO objects
                 (object_id, blob_digest, blob_size, connector, source_instance,
                  external_id, revision, observed_time_unix_ms, ingested_time_unix_ms,
                  ingest_fingerprint, media_type, suggested_domain)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
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
        tx.commit()?;
        Ok(envelopes.len())
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
}
