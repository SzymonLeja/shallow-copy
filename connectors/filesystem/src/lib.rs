//! Filesystem ingestion connector for shallow-copy.
//!
//! # Guarantees
//! - Reads files read-only without mutating source filesystems.
//! - Normalizes paths into portable relative external IDs.
//! - Generates standard IngestEnvelope packages.
#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::time::UNIX_EPOCH;

use sc_ingest::{IngestEnvelope, IngestItem};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilesystemConnectorConfig {
    pub source_instance: String,
    pub root_dir: PathBuf,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Json(serde_json::Error),
    Invalid(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::Invalid(e) => write!(f, "invalid filesystem scan: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct FilesystemConnector {
    config: FilesystemConnectorConfig,
}

impl FilesystemConnector {
    pub fn new(config: FilesystemConnectorConfig) -> Self {
        Self { config }
    }

    /// Scan configured root directory and produce an IngestEnvelope containing
    /// discovered regular files.
    pub fn scan(&self) -> Result<IngestEnvelope> {
        let root = &self.config.root_dir;
        if !root.is_dir() {
            return Err(Error::Invalid(format!(
                "root path is not a directory: {}",
                root.display()
            )));
        }

        let entries = walkdir::WalkDir::new(root).follow_links(false).into_iter();
        self.scan_entries(entries)
    }

    fn scan_entries<I>(&self, entries: I) -> Result<IngestEnvelope>
    where
        I: IntoIterator<Item = std::result::Result<walkdir::DirEntry, walkdir::Error>>,
    {
        let root = &self.config.root_dir;
        let mut items = Vec::new();

        for entry in entries {
            let entry =
                entry.map_err(|e| Error::Invalid(format!("walkdir traversal failed: {e}")))?;
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(|e| Error::Invalid(e.to_string()))?;
            let external_id = relative.to_string_lossy().replace('\\', "/");

            let metadata = fs::metadata(path)?;
            let mtime_ms = metadata
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_millis() as u64);

            let revision = format!("{}:{}", metadata.len(), mtime_ms.unwrap_or(0));

            items.push(IngestItem {
                external_id,
                revision,
                media_type: "application/octet-stream".into(),
                event_time_unix_ms: mtime_ms,
                content_ref: path.to_string_lossy().to_string(),
                suggested_domain: Some("private".into()),
            });
        }

        items.sort_by(|a, b| a.external_id.cmp(&b.external_id));

        Ok(IngestEnvelope {
            source_instance: self.config.source_instance.clone(),
            cursor: None,
            items,
        })
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
