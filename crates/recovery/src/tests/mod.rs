use super::*;

#[test]
fn directory_backup_drill_reopens_and_rejects_tampering() {
    let root = std::env::temp_dir().join(format!("sc-recovery-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir(&root).unwrap();
    let source = oiaf::Archive::init(root.join("source")).unwrap();
    source
        .import_bytes(
            b"backup payload",
            oiaf::Source::filesystem("test", "item", "1"),
        )
        .unwrap();
    let destination = root.join("backup");
    let sidecar = DirectoryBackup::create(&source, &destination).unwrap();
    assert_eq!(DirectoryBackup::drill(&destination).unwrap().objects, 1);
    let manifest = std::fs::read(&sidecar).unwrap();
    std::fs::write(&sidecar, b"{}").unwrap();
    assert!(DirectoryBackup::drill(&destination).is_err());
    std::fs::write(&sidecar, manifest).unwrap();
    let object = oiaf::Archive::open(&destination)
        .unwrap()
        .list_objects()
        .unwrap()
        .remove(0);
    let blob = destination.join(oiaf::blob_relative_path(&object.blob.digest).unwrap());
    std::fs::write(blob, b"tampered").unwrap();
    assert!(DirectoryBackup::drill(&destination).is_err());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn recovery_kit_roundtrips_and_authenticates_its_root_key() {
    let root_key = [0x5a; 32];
    let kit = RecoveryKit::generate(&root_key, 1_800_000_000_000).unwrap();
    assert_eq!(kit.recovery_key.len(), 52);
    assert!(kit.fingerprint.starts_with("recov-"));
    assert_eq!(
        kit.envelope
            .unseal(&kit.recovery_key_value().unwrap())
            .unwrap(),
        root_key
    );
    let json = kit.to_json().unwrap();
    RecoveryKit::from_json(&json).unwrap();
    RecoveryKit::from_text(&kit.to_text().unwrap()).unwrap();
    assert!(RecoveryKit::from_json("{}").is_err());

    let mut tampered = kit;
    let ciphertext = &mut tampered.envelope.sealed_archive_root_key.ciphertext_b64;
    let first = ciphertext.remove(0);
    ciphertext.insert(0, if first == 'A' { 'B' } else { 'A' });
    assert!(tampered.validate().is_err());
}

#[test]
fn domain_keys_unlock_after_recovery_and_remain_isolated() {
    let root_key = [0x27; 32];
    let kit = RecoveryKit::generate(&root_key, 1_800_000_000_001).unwrap();
    let ring = DomainKeyRing::generate(&root_key).unwrap();
    let serialized = serde_json::to_vec(&ring).unwrap();
    let ring: DomainKeyRing = serde_json::from_slice(&serialized).unwrap();
    let recovered_root = kit
        .envelope
        .unseal(&kit.recovery_key_value().unwrap())
        .unwrap();
    let unlocked = ring.unlock(&recovered_root).unwrap();
    let payload = unlocked
        .seal(KeyDomain::Secrets, b"private payload")
        .unwrap();
    assert_eq!(
        unlocked.open(KeyDomain::Secrets, &payload).unwrap(),
        b"private payload"
    );
    assert!(unlocked.open(KeyDomain::Public, &payload).is_err());

    let mut tampered = ring;
    tampered.records[0].envelope.domain = "secrets".into();
    assert!(tampered.unlock(&recovered_root).is_err());
}

#[test]
fn key_formatting_and_roundtrip_parsing() {
    let key = RecoveryKey::generate();
    let formatted = key.to_formatted_string();

    assert_eq!(formatted.len(), 52 + 12); // 52 chars + 12 hyphens
    assert_eq!(formatted.matches('-').count(), 12);

    // Standard parsing
    let parsed = RecoveryKey::from_formatted_string(&formatted).unwrap();
    assert_eq!(key, parsed);

    // Lowercase and whitespace tolerance
    let lowercase_messy = format!(" {} \n", formatted.to_lowercase());
    let parsed_messy = RecoveryKey::from_formatted_string(&lowercase_messy).unwrap();
    assert_eq!(key, parsed_messy);

    // Reject invalid length or character
    assert!(RecoveryKey::from_formatted_string("TOO-SHORT").is_err());
    let invalid_char = format!("${}", &formatted[1..]);
    assert!(RecoveryKey::from_formatted_string(&invalid_char).is_err());
}

#[test]
fn deterministic_sealing_and_unsealing_of_root_keys() {
    let recovery_key = RecoveryKey::generate();
    let root_key = b"master-archive-root-key-32-byte";

    let envelope = RecoveryKeyEnvelope::seal(&recovery_key, root_key, 1_700_000_000_000).unwrap();
    assert!(envelope.key_id.starts_with("recov-"));

    let unsealed = envelope.unseal(&recovery_key).unwrap();
    assert_eq!(unsealed, root_key);

    // Wrong recovery key fails decryption
    let wrong_key = RecoveryKey::generate();
    assert!(envelope.unseal(&wrong_key).is_err());
}

#[test]
fn tampered_recovery_envelope_detection() {
    let recovery_key = RecoveryKey::generate();
    let root_key = b"top-secret-vault-master-kek-byte";

    let mut envelope =
        RecoveryKeyEnvelope::seal(&recovery_key, root_key, 1_700_000_000_000).unwrap();

    // Tamper with ciphertext by corrupting characters
    let mut b64 = envelope.sealed_archive_root_key.ciphertext_b64.into_bytes();
    if let Some(first) = b64.first_mut() {
        *first = if *first == b'A' { b'B' } else { b'A' };
    }
    envelope.sealed_archive_root_key.ciphertext_b64 = String::from_utf8(b64).unwrap();

    assert!(envelope.unseal(&recovery_key).is_err());
}

#[test]
fn standalone_drill_execution_without_database_dependencies() {
    let recovery_key = RecoveryKey::generate();
    let control_payload = b"offline-drill-control-payload-verification-2026";

    let fixture =
        RecoveryDrill::create_fixture(&recovery_key, control_payload, 1_700_000_000_000).unwrap();

    // Serialize and deserialize to ensure full portability
    let json_fixture = serde_json::to_string(&fixture).unwrap();
    let loaded_fixture: RecoveryFixture = serde_json::from_str(&json_fixture).unwrap();

    let outcome = RecoveryDrill::execute_drill(&loaded_fixture, &recovery_key).unwrap();
    assert!(outcome.success);
    assert!(outcome.matches_control);
    assert_eq!(outcome.recovered_bytes_len, control_payload.len());
}

#[test]
fn rejects_nonzero_padding_bits_in_final_character() {
    let recovery_key = RecoveryKey::generate();
    let formatted = recovery_key.to_formatted_string();
    // The last character in canonical encoding must have bits 3..0 as zero (i.e. '0' (0) or 'G' (16)).
    // Replacing the last character with '1' (val 1) has nonzero lower bits (0b00001).
    let mut corrupted = formatted;
    corrupted.pop();
    corrupted.push('1');
    let err = RecoveryKey::from_formatted_string(&corrupted).unwrap_err();
    assert!(matches!(err, Error::InvalidKeyFormat(_)));
}

#[test]
fn crockford_alias_substitution_preserves_key() {
    let key = RecoveryKey::generate();
    let formatted = key.to_formatted_string();

    let aliased = formatted
        .chars()
        .map(|c| match c {
            '0' => 'O',
            '1' => 'I',
            other => other,
        })
        .collect::<String>();

    let parsed = RecoveryKey::from_formatted_string(&aliased).unwrap();
    assert_eq!(key, parsed);

    let aliased_l = formatted
        .chars()
        .map(|c| match c {
            '1' => 'L',
            other => other,
        })
        .collect::<String>();
    let parsed_l = RecoveryKey::from_formatted_string(&aliased_l).unwrap();
    assert_eq!(key, parsed_l);
}

#[test]
fn tampered_envelope_nonce_or_salt_rejected() {
    let recovery_key = RecoveryKey::generate();
    let root_key = b"root-key-data-sample-32-bytes!!";

    let mut envelope_nonce =
        RecoveryKeyEnvelope::seal(&recovery_key, root_key, 1_700_000_000_000).unwrap();
    let mut nonce_bytes = envelope_nonce
        .sealed_archive_root_key
        .nonce_b64
        .into_bytes();
    if let Some(first) = nonce_bytes.first_mut() {
        *first = if *first == b'A' { b'B' } else { b'A' };
    }
    envelope_nonce.sealed_archive_root_key.nonce_b64 = String::from_utf8(nonce_bytes).unwrap();
    assert!(envelope_nonce.unseal(&recovery_key).is_err());

    let mut envelope_salt =
        RecoveryKeyEnvelope::seal(&recovery_key, root_key, 1_700_000_000_000).unwrap();
    let mut salt_bytes = envelope_salt
        .sealed_archive_root_key
        .kdf
        .salt_b64
        .into_bytes();
    if let Some(first) = salt_bytes.first_mut() {
        *first = if *first == b'A' { b'B' } else { b'A' };
    }
    envelope_salt.sealed_archive_root_key.kdf.salt_b64 = String::from_utf8(salt_bytes).unwrap();
    assert!(envelope_salt.unseal(&recovery_key).is_err());
}

#[test]
fn drill_detects_wrong_key_and_tampered_fixture() {
    let recovery_key = RecoveryKey::generate();
    let wrong_key = RecoveryKey::generate();
    let control_payload = b"offline-drill-tamper-check-payload";

    let fixture =
        RecoveryDrill::create_fixture(&recovery_key, control_payload, 1_700_000_000_000).unwrap();

    // 1. Drill with wrong recovery key fails unsealing
    let err = RecoveryDrill::execute_drill(&fixture, &wrong_key);
    assert!(err.is_err());

    // 2. Drill with tampered control payload reports failure
    let mut tampered_fixture = fixture.clone();
    tampered_fixture.control_payload = b"modified-control-bytes-detected".to_vec();
    let outcome = RecoveryDrill::execute_drill(&tampered_fixture, &recovery_key).unwrap();
    assert!(!outcome.success);
    assert!(!outcome.matches_control);
}
