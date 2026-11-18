use super::*;

#[test]
fn seal_and_open_roundtrip() {
    let plaintext = b"shallow-copy secret payload";
    let passphrase = b"correct horse battery staple";
    let envelope = seal(passphrase, plaintext).unwrap();
    let recovered = open(passphrase, &envelope).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn wrong_passphrase_fails_authentication() {
    let envelope = seal(b"right", b"payload").unwrap();
    assert!(open(b"wrong", &envelope).is_err());
}

#[test]
fn tampered_ciphertext_fails_authentication() {
    let mut envelope = seal(b"pass", b"data").unwrap();
    // Flip a byte in the ciphertext.
    let mut ct = base64_std_decode(&envelope.ciphertext_b64).unwrap();
    ct[0] ^= 0xff;
    envelope.ciphertext_b64 = base64_std(&ct);
    assert!(open(b"pass", &envelope).is_err());
}

#[test]
fn envelope_is_json_serializable_and_self_describing() {
    let envelope = seal(b"pass", b"hello").unwrap();
    let json = serde_json::to_string_pretty(&envelope).unwrap();
    let restored: SealedEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(open(b"pass", &restored).unwrap(), b"hello");
}

#[test]
fn unsupported_format_version_is_rejected() {
    let mut envelope = seal(b"pass", b"data").unwrap();
    envelope.format_version = "99.0-future".into();
    assert!(matches!(open(b"pass", &envelope), Err(Error::Decode(_))));
}

#[test]
fn derive_key_is_deterministic_for_same_params() {
    let mut kdf = Kdf::recommended();
    kdf.salt_b64 = base64_std(&[0xab; 16]);
    let k1 = derive_key(b"pass", &kdf).unwrap();
    let k2 = derive_key(b"pass", &kdf).unwrap();
    assert_eq!(k1.0, k2.0);
}

#[test]
fn base64_roundtrip_all_byte_values() {
    let all_bytes: Vec<u8> = (0u8..=255).collect();
    let encoded = base64_std(&all_bytes);
    let decoded = base64_std_decode(&encoded).unwrap();
    assert_eq!(decoded, all_bytes);
}

#[test]
fn seal_domain_and_open_domain_roundtrip() {
    let plaintext = b"domain secret";
    let passphrase = b"passphrase";
    let domain = "app";
    let envelope = seal_domain(passphrase, plaintext, domain).unwrap();
    let recovered = open_domain(passphrase, &envelope, domain).unwrap();
    assert_eq!(recovered, plaintext);
}

#[test]
fn seal_domain_wrong_domain_fails() {
    let envelope = seal_domain(b"pass", b"data", "app").unwrap();
    assert!(open_domain(b"pass", &envelope, "other").is_err());
}

#[test]
fn seal_domain_tampered_ciphertext_fails() {
    let mut envelope = seal_domain(b"pass", b"data", "app").unwrap();
    let mut ct = base64_std_decode(&envelope.ciphertext_b64).unwrap();
    ct[0] ^= 0xff;
    envelope.ciphertext_b64 = base64_std(&ct);
    assert!(open_domain(b"pass", &envelope, "app").is_err());
}

#[test]
fn domain_envelope_is_json_serializable_and_self_describing() {
    let envelope = seal_domain(b"pass", b"hello", "app").unwrap();
    let json = serde_json::to_string_pretty(&envelope).unwrap();
    let restored: DomainSealedEnvelope = serde_json::from_str(&json).unwrap();
    assert_eq!(open_domain(b"pass", &restored, "app").unwrap(), b"hello");
}

#[test]
fn seal_domain_wrong_passphrase_fails() {
    let envelope = seal_domain(b"right", b"payload", "app").unwrap();
    assert!(open_domain(b"wrong", &envelope, "app").is_err());
}
