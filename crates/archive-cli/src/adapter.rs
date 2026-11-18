use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::json;
use std::fs::File;
use std::io::Write;

pub trait ArchiveAdapter {
    type Output: Serialize;

    fn init(path: &Path) -> Result<Self::Output, AdapterError>
    where
        Self: Sized;
    fn open(path: &Path) -> Result<Self, AdapterError>
    where
        Self: Sized;
    fn import(&self, source: &Path) -> Result<Self::Output, AdapterError>;
    fn list(&self) -> Result<Self::Output, AdapterError>;
    fn verify(&self, full: bool) -> Result<Self::Output, AdapterError>;
    fn export(
        &self,
        destination: &Path,
        object_id: Option<&str>,
    ) -> Result<Self::Output, AdapterError>;
    fn generate_backup_manifest(&self) -> Result<Self::Output, AdapterError>;
    fn verify_backup_manifest(&self, manifest_path: &Path) -> Result<Self::Output, AdapterError>;
    fn provenance(&self, object_id: &str) -> Result<Self::Output, AdapterError>;
    fn export_jsonl(&self, destination: Option<&Path>) -> Result<Self::Output, AdapterError>;
}

struct CountingWriter<W: Write> {
    inner: W,
    count: usize,
}

impl<W: Write> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, count: 0 }
    }
    fn count(&self) -> usize {
        self.count
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.count += buf.iter().filter(|&&b| b == b'\n').count();
        self.inner.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub struct OiafAdapter {
    archive: oiaf::Archive,
}

impl OiafAdapter {
    fn new(archive: oiaf::Archive) -> Self {
        Self { archive }
    }
}

impl ArchiveAdapter for OiafAdapter {
    type Output = serde_json::Value;

    fn init(path: &Path) -> Result<Self::Output, AdapterError> {
        let archive = oiaf::Archive::init(path).map_err(AdapterError::from)?;
        serde_json::to_value(archive.summary()).map_err(AdapterError::output)
    }

    fn open(path: &Path) -> Result<Self, AdapterError> {
        let archive = oiaf::Archive::open(path).map_err(AdapterError::from)?;
        Ok(Self::new(archive))
    }

    fn import(&self, source: &Path) -> Result<Self::Output, AdapterError> {
        let result = self
            .archive
            .import_file(source)
            .map_err(AdapterError::from)?;
        serde_json::to_value(result).map_err(AdapterError::output)
    }

    fn list(&self) -> Result<Self::Output, AdapterError> {
        let result = self.archive.list_objects().map_err(AdapterError::from)?;
        serde_json::to_value(result).map_err(AdapterError::output)
    }

    fn verify(&self, full: bool) -> Result<Self::Output, AdapterError> {
        let result = self.archive.verify(full).map_err(AdapterError::from)?;
        serde_json::to_value(result).map_err(AdapterError::output)
    }

    fn export(
        &self,
        destination: &Path,
        object_id: Option<&str>,
    ) -> Result<Self::Output, AdapterError> {
        let result = self
            .archive
            .export(destination, object_id)
            .map_err(AdapterError::from)?;
        serde_json::to_value(result).map_err(AdapterError::output)
    }

    fn provenance(&self, object_id: &str) -> Result<Self::Output, AdapterError> {
        let result = self
            .archive
            .provenance(object_id)
            .map_err(AdapterError::from)?;
        serde_json::to_value(result).map_err(AdapterError::output)
    }

    fn export_jsonl(&self, destination: Option<&Path>) -> Result<Self::Output, AdapterError> {
        match destination {
            Some(path) => {
                let file = File::create(path)
                    .map_err(oiaf::Error::from)
                    .map_err(AdapterError::from)?;
                let mut writer = CountingWriter::new(file);
                self.archive
                    .export_jsonl(&mut writer)
                    .map_err(AdapterError::from)?;
                let count = writer.count();
                serde_json::to_value(json!({"status":"ok","count":count}))
                    .map_err(AdapterError::output)
            }
            None => {
                let mut buffer = Vec::new();
                self.archive
                    .export_jsonl(&mut buffer)
                    .map_err(AdapterError::from)?;
                let count = buffer.iter().filter(|&&b| b == b'\n').count();
                serde_json::to_value(json!({"status":"ok","count":count}))
                    .map_err(AdapterError::output)
            }
        }
    }

    fn generate_backup_manifest(&self) -> Result<Self::Output, AdapterError> {
        let result = self
            .archive
            .generate_backup_manifest()
            .map_err(AdapterError::from)?;
        serde_json::to_value(result).map_err(AdapterError::output)
    }
    fn verify_backup_manifest(&self, manifest_path: &Path) -> Result<Self::Output, AdapterError> {
        let bytes = std::fs::read(manifest_path)
            .map_err(oiaf::Error::from)
            .map_err(AdapterError::from)?;
        let manifest: oiaf::BackupManifest = serde_json::from_slice(&bytes)
            .map_err(oiaf::Error::from)
            .map_err(AdapterError::from)?;
        let valid = self
            .archive
            .verify_backup_manifest(&manifest)
            .map_err(AdapterError::from)?;
        serde_json::to_value(serde_json::json!({ "valid": valid })).map_err(AdapterError::output)
    }
}

#[derive(Debug)]
pub enum AdapterError {
    Oiaf(String),
    Output(serde_json::Error),
    UnknownObjectId(String),
    MissingData(PathBuf),
    CorruptData(String),
    MalformedMetadata(String),
}

impl AdapterError {
    fn output(error: serde_json::Error) -> Self {
        Self::Output(error)
    }
}

impl std::fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Oiaf(error) => write!(formatter, "{}", sanitize(error)),
            Self::Output(error) => write!(
                formatter,
                "could not encode archive result: {}",
                sanitize(&error.to_string())
            ),
            Self::UnknownObjectId(id) => write!(formatter, "unknown object ID: {}", sanitize(id)),
            Self::MissingData(path) => {
                write!(
                    formatter,
                    "missing archive data: {}",
                    sanitize(&path.display().to_string())
                )
            }
            Self::CorruptData(message) => {
                write!(formatter, "corrupt archive data: {}", sanitize(message))
            }
            Self::MalformedMetadata(message) => {
                write!(
                    formatter,
                    "malformed archive metadata: {}",
                    sanitize(message)
                )
            }
        }
    }
}

impl std::error::Error for AdapterError {}

impl From<oiaf::Error> for AdapterError {
    fn from(error: oiaf::Error) -> Self {
        match error {
            oiaf::Error::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Self::MissingData(PathBuf::from(error.to_string()))
            }
            oiaf::Error::Json(error) => Self::MalformedMetadata(error.to_string()),
            oiaf::Error::Invalid(message) if message == "unknown object ID" => {
                Self::UnknownObjectId(message)
            }
            oiaf::Error::Invalid(message) => Self::MalformedMetadata(message),
            oiaf::Error::Integrity(message) => Self::CorruptData(message),
            other => Self::Oiaf(other.to_string()),
        }
    }
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '\n' => "\\n".to_owned(),
            '\r' => "\\r".to_owned(),
            '\t' => "\\t".to_owned(),
            character if character.is_control() => format!("\\u{{{:04x}}}", character as u32),
            character => character.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    // use std::fs::read_to_string;
    // use std::env::temp_dir for test temp directories

    #[test]
    fn maps_public_error_variants_to_stable_cli_categories() {
        assert!(matches!(
            AdapterError::from(oiaf::Error::Invalid("unknown object ID".into())),
            AdapterError::UnknownObjectId(_)
        ));
        assert!(matches!(
            AdapterError::from(oiaf::Error::Integrity("blob hash".into())),
            AdapterError::CorruptData(_)
        ));
        assert!(matches!(
            AdapterError::from(oiaf::Error::Json(
                serde_json::from_str::<serde_json::Value>("{").expect_err("invalid JSON")
            )),
            AdapterError::MalformedMetadata(_)
        ));
        assert!(matches!(
            AdapterError::from(oiaf::Error::Io(io::Error::new(
                io::ErrorKind::NotFound,
                "missing"
            ))),
            AdapterError::MissingData(_)
        ));
    }

    #[test]
    fn sanitizes_terminal_control_characters() {
        let error = AdapterError::CorruptData("bad\n\u{1b}[31mdata".into());

        assert_eq!(
            error.to_string(),
            r"corrupt archive data: bad\n\u{001b}[31mdata"
        );
    }

    #[test]
    fn test_generate_and_verify_backup_manifest_tamper() {
        let temp_dir = std::env::temp_dir().join(format!(
            "cli-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let archive_path = temp_dir.join("archive");
        let _init = OiafAdapter::init(&archive_path).unwrap();
        let adapter = OiafAdapter::open(&archive_path).unwrap();
        let manifest_json = adapter.generate_backup_manifest().unwrap();
        let manifest_path = temp_dir.join("manifest.json");
        std::fs::write(
            &manifest_path,
            serde_json::to_string(&manifest_json).unwrap(),
        )
        .unwrap();
        std::fs::write(&manifest_path, b"tampered").unwrap();
        let verify_err = adapter.verify_backup_manifest(&manifest_path);
        assert!(verify_err.is_err());
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_export_jsonl_none() {
        let temp_dir = std::env::temp_dir().join(format!(
            "cli-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let archive_path = temp_dir.join("archive");
        let _init = OiafAdapter::init(&archive_path).unwrap();
        let adapter = OiafAdapter::open(&archive_path).unwrap();
        // Import a sample file to ensure the archive has at least one object
        let sample_file = temp_dir.join("sample.txt");
        std::fs::write(&sample_file, b"sample payload").unwrap();
        adapter.import(&sample_file).unwrap();
        let result = adapter.export_jsonl(None).unwrap();
        let count = result.get("count").and_then(|v| v.as_u64()).unwrap();
        assert!(count > 0);
        std::fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_export_jsonl_some() {
        let temp_dir = std::env::temp_dir().join(format!(
            "cli-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&temp_dir).unwrap();
        let archive_path = temp_dir.join("archive");
        let _init = OiafAdapter::init(&archive_path).unwrap();
        let adapter = OiafAdapter::open(&archive_path).unwrap();
        // Import a sample file to ensure the archive has at least one object
        let sample_file = temp_dir.join("sample.txt");
        std::fs::write(&sample_file, b"sample payload").unwrap();
        adapter.import(&sample_file).unwrap();
        let output_path = temp_dir.join("output.jsonl");
        let result = adapter.export_jsonl(Some(&output_path)).unwrap();
        let count = result.get("count").and_then(|v| v.as_u64()).unwrap();
        assert!(count > 0);
        let data = std::fs::read_to_string(&output_path).unwrap();
        assert!(data.lines().count() == count as usize);
        std::fs::remove_dir_all(&temp_dir).ok();
    }
}
