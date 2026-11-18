use super::*;

fn test_dir() -> Stage {
    let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/unit-data");
    fs::create_dir_all(&parent).unwrap();
    Stage::new(&fs::canonicalize(parent).unwrap()).unwrap()
}

#[test]
fn sha256_vectors_and_digest_validation() {
    assert_eq!(
        digest(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    let abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    assert_eq!(digest(b"abc"), abc);
    assert_eq!(
        blob_relative_path(abc).unwrap(),
        format!("objects/sha256/ba/78/{abc}.blob")
    );
    for invalid in [
        "",
        "../escape",
        &"a".repeat(63),
        &"A".repeat(64),
        &"g".repeat(64),
        &"é".repeat(32),
    ] {
        assert!(blob_relative_path(invalid).is_err(), "{invalid}");
    }
}

#[test]
fn strict_portable_relative_paths() {
    for path in [
        "",
        "/root",
        "//server/share",
        "a//b",
        "a/",
        ".",
        "..",
        "a/../b",
        "a/./b",
        "C:/x",
        "C:x",
        "a\\b",
        "a\0b",
        "a\nb",
        "a:b",
        "a?b",
        "a*b",
        "a|b",
        "a<",
        "a>",
        "a\"",
        "a.",
        "a ",
        "a/NUL.txt",
        "con",
        "COM1",
        "lpt9.txt",
        "COM¹.txt",
    ] {
        assert!(validate_relative_path(path).is_err(), "accepted {path:?}");
    }
    for path in [
        "objects/sha256/ab/cd/file.blob",
        "żółw/文.json",
        "normal-file.txt",
    ] {
        validate_relative_path(path).unwrap();
    }
}

#[test]
fn deterministic_json_has_utf8_and_one_lf() {
    let values = BTreeMap::from([("z", "文"), ("a", "ż")]);
    assert_eq!(
        json_bytes(&values).unwrap(),
        "{\"a\":\"ż\",\"z\":\"文\"}\n".as_bytes()
    );
}

#[test]
fn writer_lock_excludes_other_writers_but_allows_readers() {
    let dir = test_dir();
    let archive = Archive::init(dir.0.join("archive")).unwrap();
    let lock = archive.writer_lock().unwrap();
    let second = Archive::open(archive.root()).unwrap();
    assert!(matches!(
        second.import_bytes(b"x", Source::filesystem("test", "x", "1")),
        Err(Error::Locked)
    ));
    assert_eq!(second.verify(true).unwrap().objects, 0);
    drop(lock);
    second
        .import_bytes(b"x", Source::filesystem("test", "x", "1"))
        .unwrap();
}

#[test]
fn source_mutation_is_rejected_before_canonical_publication() {
    let dir = test_dir();
    let archive = Archive::init(dir.0.join("archive")).unwrap();
    let input = dir.0.join("input");
    fs::write(&input, b"before").unwrap();
    let old_modified = fs::metadata(&input).unwrap().modified().unwrap();
    let result = archive.import_file_inner(
        &input,
        Some(Source::filesystem("test", "input", "1")),
        || {
            fs::write(&input, b"after!").unwrap();
            // Equal length and restored mtime still fail the second content pass.
            File::options()
                .write(true)
                .open(&input)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(old_modified))
                .unwrap();
        },
    );
    assert!(matches!(result, Err(Error::SourceChanged)));
    assert!(archive.list_objects().unwrap().is_empty());
    assert_eq!(
        fs::read_dir(archive.root().join("objects/sha256"))
            .unwrap()
            .count(),
        0
    );
    assert_eq!(fs::read_dir(archive.root()).unwrap().count(), 4);
}

#[test]
fn interrupted_publication_is_invisible_and_retry_recovers_orphans() {
    let dir = test_dir();
    let archive = Archive::init(dir.0.join("archive")).unwrap();
    let initial_manifest = fs::read(archive.root().join("manifest.json")).unwrap();
    let source = Source::filesystem("test", "x", "1");
    let committed = archive.import_bytes(b"x", source.clone()).unwrap();
    // Simulate crash after blob/envelope publication but before manifest rename.
    fs::write(archive.root().join("manifest.json"), initial_manifest).unwrap();
    assert_eq!(archive.verify(true).unwrap().objects, 0);
    assert!(archive.import_bytes(b"x", source.clone()).unwrap().created);
    let retry = archive.import_bytes(b"x", source).unwrap();
    assert!(!retry.created);
    assert_eq!(retry.envelope.object_id, committed.envelope.object_id);
    assert_eq!(archive.verify(true).unwrap().objects, 1);
}

#[test]
fn untrusted_manifest_keys_and_inconsistent_envelopes_are_rejected() {
    let dir = test_dir();
    let archive = Archive::init(dir.0.join("archive")).unwrap();
    let imported = archive
        .import_bytes(b"x", Source::filesystem("test", "x", "1"))
        .unwrap();
    let mut manifest = archive.manifest().unwrap();
    manifest
        .envelopes
        .insert("../outside".into(), "a".repeat(64));
    fs::write(
        archive.root().join("manifest.json"),
        json_bytes(&manifest).unwrap(),
    )
    .unwrap();
    assert!(archive.verify(true).is_err());
    manifest.envelopes.remove("../outside");
    let mut envelope = imported.envelope;
    envelope.blob.digest = "A".repeat(64);
    let bytes = json_bytes(&envelope).unwrap();
    manifest
        .envelopes
        .insert(envelope.object_id.clone(), digest(&bytes));
    fs::write(
        archive
            .root()
            .join(envelope_relative_path(&envelope.object_id).unwrap()),
        bytes,
    )
    .unwrap();
    fs::write(
        archive.root().join("manifest.json"),
        json_bytes(&manifest).unwrap(),
    )
    .unwrap();
    assert!(archive.verify(true).is_err());
}

#[test]
fn manifest_parser_rejects_noncanonical_duplicate_keys_and_oversized_json() {
    let dir = test_dir();
    let path = dir.0.join("manifest.json");
    fs::write(
        &path,
        format!(
            "{{\"oiaf_version\":\"{FORMAT_VERSION}\",\"envelopes\":{{}},\"envelopes\":{{}}}}\n"
        ),
    )
    .unwrap();
    assert!(read_json_snapshot::<Manifest>(&path, MANIFEST_LIMIT).is_err());
    fs::write(&path, vec![b' '; 129]).unwrap();
    assert!(read_json_snapshot::<Manifest>(&path, 128).is_err());
}

#[test]
fn domain_encrypted_import_export_readback_and_retry() {
    let dir = test_dir();
    let archive = Archive::init(dir.0.join("archive")).unwrap();
    let destination = dir.0.join("encrypted-export");
    let source = Source::filesystem("test", "private-note", "1");
    let plaintext = b"domain encrypted archival payload";
    let key = [0x42; 32];

    let imported = archive
        .import_bytes_in_domain(plaintext, source.clone(), ArchiveDomain::Private, &key)
        .unwrap();
    assert!(imported.created);
    assert_eq!(imported.envelope.blob.domain, Some(ArchiveDomain::Private));
    let stored = fs::read(
        archive
            .root()
            .join(blob_relative_path(&imported.envelope.blob.digest).unwrap()),
    )
    .unwrap();
    assert!(
        !stored
            .windows(plaintext.len())
            .any(|window| window == plaintext)
    );

    let retry = archive
        .import_bytes_in_domain(plaintext, source, ArchiveDomain::Private, &key)
        .unwrap();
    assert!(!retry.created);
    assert_eq!(retry.envelope, imported.envelope);
    assert_eq!(
        archive
            .read_domain_bytes(&imported.envelope.object_id, ArchiveDomain::Private, &key)
            .unwrap(),
        plaintext
    );
    assert!(
        archive
            .read_domain_bytes(
                &imported.envelope.object_id,
                ArchiveDomain::Restricted,
                &key
            )
            .is_err()
    );
    assert!(
        archive
            .read_domain_bytes(
                &imported.envelope.object_id,
                ArchiveDomain::Private,
                &[0x24; 32]
            )
            .is_err()
    );

    let report = archive.export(&destination, None).unwrap();
    let exported = Archive::open(&destination).unwrap();
    assert_eq!(exported.verify(true).unwrap(), report);
    assert_eq!(
        exported
            .read_domain_bytes(&imported.envelope.object_id, ArchiveDomain::Private, &key)
            .unwrap(),
        plaintext
    );
}

fn replace_encrypted_payload(
    archive: &Archive,
    object_id: &str,
    payload: &[u8],
    domain: ArchiveDomain,
) {
    let mut envelope = archive.provenance(object_id).unwrap();
    let blob_path = archive
        .root()
        .join(blob_relative_path(&envelope.blob.digest).unwrap());
    fs::write(blob_path, payload).unwrap();
    envelope.blob.digest = digest(payload);
    envelope.blob.size = payload.len() as u64;
    envelope.blob.domain = Some(domain);
    let envelope_bytes = json_bytes(&envelope).unwrap();
    fs::write(
        archive
            .root()
            .join(envelope_relative_path(object_id).unwrap()),
        &envelope_bytes,
    )
    .unwrap();
    let mut manifest = archive.manifest().unwrap();
    manifest
        .envelopes
        .insert(object_id.to_string(), digest(&envelope_bytes));
    fs::write(
        archive.root().join("manifest.json"),
        json_bytes(&manifest).unwrap(),
    )
    .unwrap();
}

#[test]
fn domain_binding_and_ciphertext_tampering_are_rejected() {
    let key = [0x51; 32];
    for tamper_domain in [false, true] {
        let dir = test_dir();
        let archive = Archive::init(dir.0.join("archive")).unwrap();
        let imported = archive
            .import_bytes_in_domain(
                b"authenticated payload",
                Source::filesystem("test", "secret", "1"),
                ArchiveDomain::Private,
                &key,
            )
            .unwrap();
        let blob_path = archive
            .root()
            .join(blob_relative_path(&imported.envelope.blob.digest).unwrap());
        let mut sealed: sc_crypto::DomainSealedEnvelope =
            serde_json::from_slice(&fs::read(&blob_path).unwrap()).unwrap();
        if tamper_domain {
            sealed.domain = "restricted".into();
        } else {
            let mut ciphertext = sealed.ciphertext_b64.into_bytes();
            ciphertext[0] = if ciphertext[0] == b'A' { b'B' } else { b'A' };
            sealed.ciphertext_b64 = String::from_utf8(ciphertext).unwrap();
        }
        let payload = serde_json::to_vec(&sealed).unwrap();
        replace_encrypted_payload(
            &archive,
            &imported.envelope.object_id,
            &payload,
            if tamper_domain {
                ArchiveDomain::Restricted
            } else {
                ArchiveDomain::Private
            },
        );
        let reopened = Archive::open(archive.root()).unwrap();
        let expected_domain = if tamper_domain {
            ArchiveDomain::Restricted
        } else {
            ArchiveDomain::Private
        };
        assert!(
            reopened
                .read_domain_bytes(&imported.envelope.object_id, expected_domain, &key)
                .is_err()
        );
    }

    let dir = test_dir();
    let archive = Archive::init(dir.0.join("archive")).unwrap();
    let imported = archive
        .import_bytes_in_domain(
            b"plain visible only after decryption",
            Source::filesystem("test", "tampered", "1"),
            ArchiveDomain::Private,
            &key,
        )
        .unwrap();
    let blob_path = archive
        .root()
        .join(blob_relative_path(&imported.envelope.blob.digest).unwrap());
    fs::write(blob_path, b"altered physical payload").unwrap();
    assert!(
        archive
            .read_domain_bytes(&imported.envelope.object_id, ArchiveDomain::Private, &key)
            .is_err()
    );
    assert!(archive.verify(true).is_err());
}

#[test]
fn backup_manifest_creation_verification_and_tamper_detection() {
    let dir = test_dir();
    let archive = Archive::init(dir.0.join("archive")).unwrap();
    let s1 = Source::filesystem("test", "doc1", "1");
    let s2 = Source::filesystem("test", "doc2", "1");
    let e1 = archive.import_bytes(b"hello world", s1).unwrap().envelope;
    let e2 = archive
        .import_bytes(b"second blob data", s2)
        .unwrap()
        .envelope;
    let s3 = Source::filesystem("test", "doc3", "1");
    let e3 = archive.import_bytes(b"hello world", s3).unwrap().envelope;

    // Creation check
    let root_manifest_path = archive.root().join("manifest.json");
    let root_manifest_before = fs::read(&root_manifest_path).unwrap();
    let backup = archive.generate_backup_manifest().unwrap();
    assert_eq!(backup.oiaf_version, FORMAT_VERSION);
    assert_eq!(backup.total_objects, 3);
    assert_eq!(backup.total_blob_bytes, e1.blob.size + e2.blob.size);
    assert_eq!(backup.envelopes.len(), 3);
    assert_eq!(fs::read(&root_manifest_path).unwrap(), root_manifest_before);
    assert_eq!(
        backup.envelopes.get(&e1.object_id).unwrap(),
        &digest(&json_bytes(&e1).unwrap())
    );
    assert_eq!(
        backup.envelopes.get(&e2.object_id).unwrap(),
        &digest(&json_bytes(&e2).unwrap())
    );
    assert_eq!(
        backup.envelopes.get(&e3.object_id).unwrap(),
        &digest(&json_bytes(&e3).unwrap())
    );

    let manifest_bytes = fs::read(&root_manifest_path).unwrap();
    assert_eq!(backup.root_manifest_hash, digest(&manifest_bytes));

    // Verification check
    assert!(archive.verify_backup_manifest(&backup).unwrap());

    // Tamper detection: root_manifest_hash modified
    let mut tampered = backup.clone();
    tampered.root_manifest_hash = "0".repeat(64);
    assert!(!archive.verify_backup_manifest(&tampered).unwrap());

    // Tamper detection: total_blob_bytes modified
    let mut tampered = backup.clone();
    tampered.total_blob_bytes += 1;
    assert!(!archive.verify_backup_manifest(&tampered).unwrap());

    // Tamper detection: total_objects modified
    let mut tampered = backup.clone();
    tampered.total_objects += 1;
    assert!(!archive.verify_backup_manifest(&tampered).unwrap());

    // Tamper detection: oiaf_version modified
    let mut tampered = backup.clone();
    tampered.oiaf_version = "invalid-version".into();
    assert!(!archive.verify_backup_manifest(&tampered).unwrap());

    // Tamper detection: envelopes map modified with unknown entry
    let mut tampered = backup.clone();
    tampered.envelopes.insert("0".repeat(64), "1".repeat(64));
    tampered.total_objects = tampered.envelopes.len();
    assert!(!archive.verify_backup_manifest(&tampered).unwrap());

    // Tamper detection: a self-consistent subset still omits live objects.
    let mut tampered = backup.clone();
    tampered.envelopes.remove(&e1.object_id);
    tampered.total_objects = tampered.envelopes.len();
    assert!(!archive.verify_backup_manifest(&tampered).unwrap());

    // Tamper detection: physical blob modified on disk
    let blob_path = archive
        .root()
        .join(blob_relative_path(&e1.blob.digest).unwrap());
    fs::write(&blob_path, b"corrupted payload").unwrap();
    assert!(!archive.verify_backup_manifest(&backup).unwrap());
}

#[cfg(unix)]
#[test]
fn archive_symlinks_cannot_escape_root() {
    let dir = test_dir();
    let archive = Archive::init(dir.0.join("archive")).unwrap();
    fs::remove_dir(archive.root().join("objects/sha256")).unwrap();
    let outside = dir.0.join("outside");
    fs::create_dir(&outside).unwrap();
    std::os::unix::fs::symlink(&outside, archive.root().join("objects/sha256")).unwrap();
    assert!(
        archive
            .import_bytes(b"x", Source::filesystem("test", "x", "1"))
            .is_err()
    );
    assert_eq!(fs::read_dir(outside).unwrap().count(), 0);
}
