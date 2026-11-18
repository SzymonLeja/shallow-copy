//! Crypto primitives for shallow-copy.
//!
//! # Design
//! - Argon2id for passphrase-based key derivation (RFC 9106).
//! - XChaCha20-Poly1305 for AEAD encryption (192-bit nonce, safe for random).
//! - `CipherSuite` and `format_version` fields ensure crypto-agility.
//! - Key material is zeroized on drop.
//! - No unsafe code.
#![forbid(unsafe_code)]

use argon2::{Argon2, Params, Version};
use chacha20poly1305::{
    AeadCore, KeyInit, XChaCha20Poly1305,
    aead::{Aead, AeadInPlace, OsRng, Tag},
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const FORMAT_VERSION: &str = "0.1-crypto";

/// Identifies the cipher suite used for a sealed envelope.
/// New variants may be added; readers must reject unknown suites.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CipherSuite {
    /// XChaCha20-Poly1305 with Argon2id key derivation.
    XChacha20Poly1305Argon2id,
}

/// Argon2id parameters stored alongside every sealed envelope so they
/// can be raised at next unlock without re-encrypting ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Kdf {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    /// Base64-standard-encoded 16-byte random salt.
    pub salt_b64: String,
}

impl Kdf {
    /// Recommended interactive parameters (calibrate higher in production).
    pub fn recommended() -> Self {
        Self {
            algorithm: "argon2id".into(),
            memory_kib: 65536, // 64 MiB — RFC 9106 constrained profile
            iterations: 3,
            parallelism: 1,
            salt_b64: String::new(), // filled by derive_key
        }
    }
}

/// 32-byte derived key, zeroed on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DerivedKey(pub [u8; 32]);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Kdf(String),
    Aead(String),
    Decode(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Kdf(e) => write!(f, "KDF error: {e}"),
            Self::Aead(e) => write!(f, "AEAD error: {e}"),
            Self::Decode(e) => write!(f, "decode error: {e}"),
        }
    }
}
impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

/// Derive a 32-byte key from a passphrase using Argon2id.
/// `kdf.salt_b64` must be populated before calling (use `generate_salt`).
pub fn derive_key(passphrase: &[u8], kdf: &Kdf) -> Result<DerivedKey> {
    let salt = base64_decode(&kdf.salt_b64)?;
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase, &salt, &mut key)
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(DerivedKey(key))
}

/// Generate a random 16-byte salt encoded as base64.
pub fn generate_salt() -> String {
    use rand::RngCore;
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    base64_encode(&salt)
}

/// Sealed envelope: ciphertext + authentication tag + all params needed to decrypt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedEnvelope {
    pub format_version: String,
    pub cipher_suite: CipherSuite,
    pub kdf: Kdf,
    /// Base64-encoded 24-byte XChaCha20 nonce.
    pub nonce_b64: String,
    /// Base64-encoded ciphertext (includes 16-byte Poly1305 tag appended).
    pub ciphertext_b64: String,
}

/// Encrypt plaintext with a passphrase. Returns a self-describing envelope.
pub fn seal(passphrase: &[u8], plaintext: &[u8]) -> Result<SealedEnvelope> {
    let mut kdf = Kdf::recommended();
    kdf.salt_b64 = generate_salt();
    let key = derive_key(passphrase, &kdf)?;
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| Error::Aead(e.to_string()))?;
    Ok(SealedEnvelope {
        format_version: FORMAT_VERSION.into(),
        cipher_suite: CipherSuite::XChacha20Poly1305Argon2id,
        kdf,
        nonce_b64: base64_encode(&nonce),
        ciphertext_b64: base64_encode(&ciphertext),
    })
}

/// Decrypt a sealed envelope with the original passphrase.
pub fn open(passphrase: &[u8], envelope: &SealedEnvelope) -> Result<Vec<u8>> {
    if envelope.format_version != FORMAT_VERSION {
        return Err(Error::Decode(format!(
            "unsupported format version: {}",
            envelope.format_version
        )));
    }
    if envelope.cipher_suite != CipherSuite::XChacha20Poly1305Argon2id {
        return Err(Error::Decode("unsupported cipher suite".into()));
    }
    let key = derive_key(passphrase, &envelope.kdf)?;
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let nonce_bytes = base64_decode(&envelope.nonce_b64)?;
    if nonce_bytes.len() != 24 {
        return Err(Error::Decode("invalid nonce length".into()));
    }
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    let ciphertext = base64_decode(&envelope.ciphertext_b64)?;
    cipher
        .decrypt(nonce, ciphertext.as_slice())
        .map_err(|e| Error::Aead(e.to_string()))
}

// Domain‑separated encryption primitives
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainSealedEnvelope {
    pub format_version: String,
    pub cipher_suite: CipherSuite,
    pub kdf: Kdf,
    pub domain: String,
    /// Base64-encoded 24-byte XChaCha20 nonce.
    pub nonce_b64: String,
    /// Base64-encoded ciphertext (includes 16-byte Poly1305 tag appended).
    pub ciphertext_b64: String,
}

pub fn seal_domain(
    passphrase: &[u8],
    plaintext: &[u8],
    domain: &str,
) -> Result<DomainSealedEnvelope> {
    let mut kdf = Kdf::recommended();
    kdf.salt_b64 = generate_salt();
    let key = derive_key(passphrase, &kdf)?;
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
    // Use domain as AAD.
    let mut ciphertext = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(&nonce, domain.as_bytes(), &mut ciphertext)
        .map_err(|e| Error::Aead(e.to_string()))?;
    let mut final_ct = ciphertext;
    final_ct.extend_from_slice(tag.as_slice());
    let ciphertext = final_ct;
    Ok(DomainSealedEnvelope {
        format_version: FORMAT_VERSION.into(),
        cipher_suite: CipherSuite::XChacha20Poly1305Argon2id,
        kdf,
        domain: domain.into(),
        nonce_b64: base64_encode(&nonce),
        ciphertext_b64: base64_encode(&ciphertext),
    })
}

pub fn open_domain(
    passphrase: &[u8],
    envelope: &DomainSealedEnvelope,
    domain: &str,
) -> Result<Vec<u8>> {
    if envelope.format_version != FORMAT_VERSION {
        return Err(Error::Decode(format!(
            "unsupported format version: {}",
            envelope.format_version
        )));
    }
    if envelope.cipher_suite != CipherSuite::XChacha20Poly1305Argon2id {
        return Err(Error::Decode("unsupported cipher suite".into()));
    }
    if envelope.domain != domain {
        return Err(Error::Decode("domain mismatch".into()));
    }
    let key = derive_key(passphrase, &envelope.kdf)?;
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let nonce_bytes = base64_decode(&envelope.nonce_b64)?;
    if nonce_bytes.len() != 24 {
        return Err(Error::Decode("invalid nonce length".into()));
    }
    let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
    let ciphertext = base64_decode(&envelope.ciphertext_b64)?;
    if ciphertext.len() < 16 {
        return Err(Error::Decode("ciphertext too short".into()));
    }
    let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
    let mut buffer = ct.to_vec();
    cipher
        .decrypt_in_place_detached(
            nonce,
            domain.as_bytes(),
            &mut buffer,
            Tag::<XChaCha20Poly1305>::from_slice(tag),
        )
        .map_err(|e| Error::Aead(e.to_string()))?;
    Ok(buffer)
}

fn base64_encode(bytes: &[u8]) -> String {
    base64_std(bytes)
}

fn base64_decode(s: &str) -> Result<Vec<u8>> {
    base64_std_decode(s).map_err(Error::Decode)
}

// --- minimal base64 (standard alphabet, no padding variant needed) ---

const B64_CHARS: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_std(input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as usize;
        let b1 = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        let b2 = if chunk.len() > 2 {
            chunk[2] as usize
        } else {
            0
        };
        out.push(B64_CHARS[b0 >> 2] as char);
        out.push(B64_CHARS[((b0 & 3) << 4) | (b1 >> 4)] as char);
        out.push(if chunk.len() > 1 {
            B64_CHARS[((b1 & 0xf) << 2) | (b2 >> 6)] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64_CHARS[b2 & 0x3f] as char
        } else {
            '='
        });
    }
    out
}

fn base64_std_decode(input: &str) -> std::result::Result<Vec<u8>, String> {
    let input = input.trim_end_matches('=');
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut buf = 0u32;
    let mut bits = 0u8;
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err(format!("invalid base64 char: {c}")),
        } as u32;
        buf = (buf << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
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
}
