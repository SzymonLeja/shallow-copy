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

/// Mode for provisioning owner credentials in the catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerProvisionMode {
    Fresh,
    LegacyClaim,
}

/// Candidate archive and backup paths staged in memory for fresh setup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FreshSetupConfig {
    pub archive_path: String,
    pub backup_path: Option<String>,
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
    pub test_fail_tx: bool,
}

impl Catalog {
    /// Open or create the catalog at the given path.
    /// The path must be on a local filesystem (not NFS/SMB).
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let cat = Self {
            conn,
            test_fail_tx: false,
        };
        cat.init_schema()?;
        Ok(cat)
    }

    /// Open an in-memory catalog (useful for tests and rebuilds).
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let cat = Self {
            conn,
            test_fail_tx: false,
        };
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

    /// Atomically provision owner credentials under strict transactional predicates.
    ///
    /// - Fresh mode: requires that ALL legacy markers (`setup.admin_provisioned`,
    ///   `setup.prepared_unix_ms`, `setup.completed_unix_ms`) AND `setup.owner_verifier`
    ///   AND `setup.owner_auth_version` are ABSENT.
    ///   Atomically commits `setup.archive_path`, `setup.backup_path` (if provided),
    ///   `setup.owner_verifier`, `setup.owner_auth_version = "1"`,
    ///   `setup.admin_provisioned = "true"`, `setup.prepared_unix_ms = "<now_ms>"`,
    ///   and `setup.completed_unix_ms = "<now_ms>"`.
    ///
    /// - LegacyClaim mode: requires that ANY legacy marker (`setup.admin_provisioned == "true"`,
    ///   `setup.prepared_unix_ms`, OR `setup.completed_unix_ms`) is PRESENT, AND
    ///   BOTH `setup.owner_verifier` and `setup.owner_auth_version` are ABSENT.
    ///   Atomically commits `setup.owner_verifier`, `setup.owner_auth_version = "1"`,
    ///   and `setup.admin_provisioned = "true"`, preserving existing `setup.archive_path`,
    ///   `setup.backup_path`, and all objects and audit events.
    ///
    /// Executes within a single SQLite IMMEDIATE transaction. First claimant wins
    /// across connections; losing concurrent attempts or inconsistent states return
    /// `Ok(false)` without mutating data.
    pub fn provision_owner_credentials(
        &mut self,
        mode: OwnerProvisionMode,
        verifier: &str,
        fresh_config: Option<&FreshSetupConfig>,
        now_ms: u64,
    ) -> Result<bool> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        let get_tx_meta = |key: &str| -> rusqlite::Result<Option<String>> {
            let mut stmt = tx.prepare_cached("SELECT value FROM catalog_meta WHERE key = ?1")?;
            let mut rows = stmt.query(params![key])?;
            if let Some(row) = rows.next()? {
                Ok(Some(row.get(0)?))
            } else {
                Ok(None)
            }
        };

        let has_owner_verifier = get_tx_meta("setup.owner_verifier")?.is_some();
        let has_owner_auth_version = get_tx_meta("setup.owner_auth_version")?.is_some();
        let has_admin_provisioned =
            get_tx_meta("setup.admin_provisioned")?.is_some_and(|v| v == "true");
        let has_prepared = get_tx_meta("setup.prepared_unix_ms")?.is_some();
        let has_completed = get_tx_meta("setup.completed_unix_ms")?.is_some();
        let has_any_legacy_marker = has_admin_provisioned || has_prepared || has_completed;

        // If verifier or auth_version is already durable, credentials are fully configured.
        if has_owner_verifier || has_owner_auth_version {
            return Ok(false);
        }

        match mode {
            OwnerProvisionMode::Fresh => {
                // Fresh mode requires ALL legacy markers to be strictly absent.
                if has_any_legacy_marker {
                    return Ok(false);
                }
                let config = match fresh_config {
                    Some(c) => c,
                    None => return Ok(false),
                };

                tx.execute(
                    "INSERT INTO catalog_meta (key, value) VALUES ('setup.archive_path', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![config.archive_path],
                )?;

                if let Some(ref bp) = config.backup_path {
                    tx.execute(
                        "INSERT INTO catalog_meta (key, value) VALUES ('setup.backup_path', ?1)
                         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                        params![bp],
                    )?;
                } else {
                    tx.execute(
                        "DELETE FROM catalog_meta WHERE key = 'setup.backup_path'",
                        [],
                    )?;
                }

                tx.execute(
                    "INSERT INTO catalog_meta (key, value) VALUES ('setup.owner_verifier', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![verifier],
                )?;

                tx.execute(
                    "INSERT INTO catalog_meta (key, value) VALUES ('setup.owner_auth_version', '1')
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [],
                )?;

                tx.execute(
                    "INSERT INTO catalog_meta (key, value) VALUES ('setup.admin_provisioned', 'true')
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [],
                )?;

                tx.execute(
                    "INSERT INTO catalog_meta (key, value) VALUES ('setup.recovery_configured', 'true')
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [],
                )?;

                tx.execute(
                    "INSERT INTO catalog_meta (key, value) VALUES ('setup.recovery_configured', 'true')
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [],
                )?;

                let now_str = now_ms.to_string();
                tx.execute(
                    "INSERT INTO catalog_meta (key, value) VALUES ('setup.prepared_unix_ms', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![now_str],
                )?;

                tx.execute(
                    "INSERT INTO catalog_meta (key, value) VALUES ('setup.completed_unix_ms', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![now_str],
                )?;
            }
            OwnerProvisionMode::LegacyClaim => {
                // Legacy claim requires AT LEAST ONE legacy marker present, and verifier/version absent.
                if !has_any_legacy_marker {
                    return Ok(false);
                }

                tx.execute(
                    "INSERT INTO catalog_meta (key, value) VALUES ('setup.owner_verifier', ?1)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    params![verifier],
                )?;

                tx.execute(
                    "INSERT INTO catalog_meta (key, value) VALUES ('setup.owner_auth_version', '1')
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [],
                )?;

                tx.execute(
                    "INSERT INTO catalog_meta (key, value) VALUES ('setup.admin_provisioned', 'true')
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [],
                )?;

                tx.execute(
                    "INSERT INTO catalog_meta (key, value) VALUES ('setup.recovery_configured', 'true')
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    [],
                )?;
            }
        }

        if self.test_fail_tx {
            return Err(Error::Invalid(
                "injected transaction failure before commit".into(),
            ));
        }

        tx.commit()?;
        Ok(true)
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
#[path = "tests/mod.rs"]
mod tests;
