use oiaf::{Archive, Error, Source, blob_relative_path, json_bytes};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);
impl TestDir {
    fn new() -> Self {
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-data");
        fs::create_dir_all(&parent).unwrap();
        loop {
            let path = parent.join(format!(
                "{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(fs::canonicalize(path).unwrap()),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                Err(e) => panic!("test directory: {e}"),
            }
        }
    }

    fn archive(&self) -> Archive {
        Archive::init(self.0.join("archive")).unwrap()
    }
}
impl Drop for TestDir {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn source(name: &str, revision: &str) -> Source {
    Source::filesystem("test-source", name, revision)
}

#[test]
fn duplicate_retry_returns_original_ack_and_does_not_republish() {
    let dir = TestDir::new();
    let archive = dir.archive();
    let first = archive
        .import_bytes(b"original\r\n", source("note", "v1"))
        .unwrap();
    let before = snapshot(archive.root());
    let retry = Archive::open(archive.root())
        .unwrap()
        .import_bytes(b"original\r\n", source("note", "v1"))
        .unwrap();
    assert!(first.created);
    assert!(!retry.created);
    assert_eq!(first.envelope, retry.envelope);
    assert_eq!(snapshot(archive.root()), before);
    assert_eq!(archive.list_objects().unwrap().len(), 1);
    assert!(matches!(
        archive.import_bytes(b"different", source("note", "v1")),
        Err(Error::SourceConflict)
    ));
    assert_eq!(snapshot(archive.root()), before);
}

#[test]
fn same_bytes_different_sources_and_revisions_keep_distinct_evidence() {
    let dir = TestDir::new();
    let archive = dir.archive();
    let a = archive
        .import_bytes(b"same", source("one", "v1"))
        .unwrap()
        .envelope;
    let b = archive
        .import_bytes(b"same", source("two", "v1"))
        .unwrap()
        .envelope;
    let c = archive
        .import_bytes(b"same", source("one", "v2"))
        .unwrap()
        .envelope;
    let mut remote = source("one", "v1");
    remote.source_instance = "other-machine".into();
    let d = archive.import_bytes(b"same", remote).unwrap().envelope;
    let ids: std::collections::BTreeSet<_> =
        [&a, &b, &c, &d].iter().map(|e| &e.object_id).collect();
    assert_eq!(ids.len(), 4);
    assert_eq!(a.blob, b.blob);
    let report = archive.verify(true).unwrap();
    assert_eq!((report.objects, report.blobs, report.bytes), (4, 1, 4));
    assert!(report.fixity_only);
    assert_eq!(
        archive
            .provenance(&b.object_id)
            .unwrap()
            .source
            .source_locator,
        "two"
    );
}

#[test]
fn binary_and_empty_bytes_survive_file_import_and_export_exactly() {
    let dir = TestDir::new();
    let archive = dir.archive();
    let fixtures: [&[u8]; 3] = [b"", b"\0\xff\xfe\x80\r\n\0", "Zażółć\r\n".as_bytes()];
    let mut expected = BTreeMap::new();
    for (index, bytes) in fixtures.iter().enumerate() {
        let input = dir.0.join(format!("source-{index}"));
        fs::write(&input, bytes).unwrap();
        let result = archive.import_file(&input).unwrap();
        assert_eq!(fs::read(&input).unwrap(), *bytes);
        assert!(!archive.import_file(&input).unwrap().created);
        let relative = blob_relative_path(&result.envelope.blob.digest).unwrap();
        assert_eq!(fs::read(archive.root().join(&relative)).unwrap(), *bytes);
        expected.insert(relative, bytes.to_vec());
    }
    let before = snapshot(archive.root());
    let destination = dir.0.join("export");
    let report = archive.export(&destination, None).unwrap();
    assert_eq!(report.objects, 3);
    let exported = Archive::open(&destination).unwrap();
    assert_eq!(
        exported.list_objects().unwrap(),
        archive.list_objects().unwrap()
    );
    assert_eq!(exported.verify(true).unwrap(), report);
    for (relative, bytes) in expected {
        assert_eq!(fs::read(destination.join(relative)).unwrap(), bytes);
    }
    assert_eq!(snapshot(archive.root()), before);
    assert!(archive.export(&destination, None).is_err());
    assert!(archive.export(archive.root().join("nested"), None).is_err());
}

#[test]
fn export_can_select_one_occurrence_and_retains_its_provenance() {
    let dir = TestDir::new();
    let archive = dir.archive();
    let selected = archive
        .import_bytes(b"yes", source("selected", "1"))
        .unwrap()
        .envelope;
    archive
        .import_bytes(b"no", source("excluded", "1"))
        .unwrap();
    let destination = dir.0.join("selected");
    let report = archive
        .export(&destination, Some(&selected.object_id))
        .unwrap();
    assert_eq!(report.objects, 1);
    assert_eq!(
        Archive::open(destination).unwrap().list_objects().unwrap(),
        vec![selected]
    );
    let destination = dir.0.join("unknown");
    assert!(archive.export(&destination, Some(&"a".repeat(64))).is_err());
    assert!(!destination.exists());
}

#[test]
fn jsonl_is_deterministic_utf8_and_sorted_by_object_id() {
    let dir = TestDir::new();
    let archive = dir.archive();
    for locator in ["żółw", "alpha", "文"] {
        archive.import_bytes(b"x", source(locator, "1")).unwrap();
    }
    let mut first = Vec::new();
    let mut second = Vec::new();
    archive.export_jsonl(&mut first).unwrap();
    archive.export_jsonl(&mut second).unwrap();
    assert_eq!(first, second);
    assert!(std::str::from_utf8(&first).unwrap().contains("żółw"));
    let expected: Vec<_> = archive
        .list_objects()
        .unwrap()
        .iter()
        .flat_map(|e| json_bytes(e).unwrap())
        .collect();
    assert_eq!(first, expected);
    assert_eq!(first.iter().filter(|b| **b == b'\n').count(), 3);
}

#[test]
fn tamper_missing_blobs_and_changed_envelopes_are_detected_without_writes() {
    for damage in ["tamper", "missing", "envelope"] {
        let dir = TestDir::new();
        let archive = dir.archive();
        let envelope = archive
            .import_bytes(b"original", source("note", "1"))
            .unwrap()
            .envelope;
        let blob = archive
            .root()
            .join(blob_relative_path(&envelope.blob.digest).unwrap());
        match damage {
            "tamper" => fs::write(&blob, b"modified").unwrap(),
            "missing" => fs::remove_file(&blob).unwrap(),
            _ => fs::write(
                archive
                    .root()
                    .join(format!("objects/envelopes/{}.json", envelope.object_id)),
                b"{}\n",
            )
            .unwrap(),
        }
        let before = snapshot(archive.root());
        assert!(archive.verify(true).is_err(), "{damage}");
        assert!(archive.verify(false).is_err(), "{damage}");
        assert_eq!(snapshot(archive.root()), before);
        let destination = dir.0.join("failed-export");
        assert!(archive.export(&destination, None).is_err());
        assert!(!destination.exists());
        assert_eq!(snapshot(archive.root()), before);
    }
}

#[test]
fn verify_works_without_writer_lock_file_and_does_not_recreate_it() {
    let dir = TestDir::new();
    let archive = dir.archive();
    archive.import_bytes(b"x", source("x", "1")).unwrap();
    fs::remove_file(archive.root().join(".writer.lock")).unwrap();
    let before = snapshot(archive.root());
    Archive::open(archive.root()).unwrap().verify(true).unwrap();
    assert_eq!(snapshot(archive.root()), before);
    assert!(!archive.root().join(".writer.lock").exists());
}

#[test]
fn init_refuses_existing_directories_and_unsupported_versions() {
    let dir = TestDir::new();
    let existing = dir.0.join("existing");
    fs::create_dir(&existing).unwrap();
    fs::write(existing.join("important"), b"preserve").unwrap();
    assert!(Archive::init(&existing).is_err());
    assert_eq!(fs::read(existing.join("important")).unwrap(), b"preserve");
    let archive = dir.archive();
    fs::write(archive.root().join("OIAF-VERSION"), "future\n").unwrap();
    assert!(Archive::open(archive.root()).is_err());
}

#[test]
fn dedup_import_detects_corrupt_blob_and_does_not_republish() {
    // Covers the verify_blob call on the commit() dedup path:
    // when an object is already in the manifest but its blob is corrupt,
    // import_bytes must return an Integrity error rather than silently
    // acknowledging the import with the stale (bad) bytes.
    let dir = TestDir::new();
    let archive = dir.archive();
    let result = archive
        .import_bytes(b"original", source("dup", "v1"))
        .unwrap();
    assert!(result.created);
    // Corrupt the blob in-place.
    let blob_path = archive
        .root()
        .join(blob_relative_path(&result.envelope.blob.digest).unwrap());
    fs::write(&blob_path, b"corrupted").unwrap();
    // A retry of the same import must detect the corruption and return an
    // error rather than successfully acknowledging the import.
    assert!(matches!(
        archive.import_bytes(b"original", source("dup", "v1")),
        Err(oiaf::Error::Integrity(_))
    ));
    // The archive manifest must be unchanged.
    assert_eq!(archive.list_objects().unwrap().len(), 1);
}

#[test]
fn export_to_existing_destination_leaves_no_stage_artefact() {
    // Covers the guarantee that a failed export (destination already exists)
    // leaves no staging directory behind in the destination parent.
    let dir = TestDir::new();
    let archive = dir.archive();
    archive.import_bytes(b"data", source("src", "1")).unwrap();
    let destination = dir.0.join("out");
    // First export succeeds.
    archive.export(&destination, None).unwrap();
    let parent_before: std::collections::BTreeSet<_> = fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    // Second export to the same path must fail.
    assert!(archive.export(&destination, None).is_err());
    // The parent directory must look exactly as it did before the second
    // attempt — no staging directory left behind.
    let parent_after: std::collections::BTreeSet<_> = fs::read_dir(&dir.0)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(
        parent_before, parent_after,
        "staging artefact left after failed export"
    );
}

fn snapshot(root: &Path) -> BTreeMap<PathBuf, (Vec<u8>, std::time::SystemTime)> {
    fn visit(
        path: &Path,
        root: &Path,
        output: &mut BTreeMap<PathBuf, (Vec<u8>, std::time::SystemTime)>,
    ) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                visit(&entry.path(), root, output);
            } else {
                output.insert(
                    entry.path().strip_prefix(root).unwrap().to_path_buf(),
                    (
                        fs::read(entry.path()).unwrap(),
                        entry.metadata().unwrap().modified().unwrap(),
                    ),
                );
            }
        }
    }
    let mut output = BTreeMap::new();
    visit(root, root, &mut output);
    output
}
