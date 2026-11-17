//! Standalone recovery key mechanics and offline verification drill core.
//!
//! # Guarantees
//! - Zero external database or secret dependencies: operates standalone per `project.md` line 215-238 and ADR-011.
//! - High-entropy 256-bit keys formatted with Crockford Base32 in hyphenated chunks for paper printability.
//! - Self-contained `RecoveryKeyEnvelope` sealed with `sc-crypto` (XChaCha20-Poly1305 + Argon2id).
//! - Standalone drill execution to verify recoverability without runtime infrastructure.
#![forbid(unsafe_code)]

use std::fmt;

use rand::RngCore;
use serde::{Deserialize, Serialize};

const CROCKFORD_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// 256-bit high-entropy recovery key suitable for offline paper backup.
#[derive(Clone, PartialEq, Eq)]
pub struct RecoveryKey(pub [u8; 32]);

impl RecoveryKey {
    /// Generate a fresh 256-bit recovery key from cryptographically secure random bytes.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Format the 256-bit key as 13 hyphenated groups of 4 Crockford Base32 characters
    /// (e.g. `XXXX-XXXX-XXXX-...`).
    pub fn to_formatted_string(&self) -> String {
        let mut raw_chars = Vec::with_capacity(52);
        for i in 0..52 {
            let bit_offset = i * 5;
            let byte_idx = bit_offset / 8;
            let bit_idx = bit_offset % 8;
            let byte_0 = self.0[byte_idx];
            let byte_1 = if byte_idx + 1 < 32 {
                self.0[byte_idx + 1]
            } else {
                0
            };
            let combined = ((byte_0 as u16) << 8) | (byte_1 as u16);
            let val = ((combined >> (11 - bit_idx)) & 0x1F) as usize;
            raw_chars.push(CROCKFORD_ALPHABET[val] as char);
        }

        let mut formatted = String::with_capacity(52 + 12);
        for (idx, ch) in raw_chars.into_iter().enumerate() {
            if idx > 0 && idx % 4 == 0 {
                formatted.push('-');
            }
            formatted.push(ch);
        }
        formatted
    }

    /// Parse and validate a formatted recovery key string (case-insensitive, ignoring hyphens/whitespace,
    /// with Crockford character alias substitution for I/L -> 1, O -> 0).
    pub fn from_formatted_string(input: &str) -> Result<Self, Error> {
        let mut clean_chars = Vec::with_capacity(52);
        for ch in input.chars() {
            if ch == '-' || ch.is_whitespace() {
                continue;
            }
            let normalized = match ch.to_ascii_uppercase() {
                'O' => '0',
                'I' | 'L' => '1',
                c => c,
            };
            clean_chars.push(normalized);
        }

        if clean_chars.len() != 52 {
            return Err(Error::InvalidKeyFormat(format!(
                "expected exactly 52 base32 characters, got {}",
                clean_chars.len()
            )));
        }

        let mut bytes = [0u8; 32];
        for (i, &ch) in clean_chars.iter().enumerate() {
            let val = decode_crockford_char(ch)?;
            let bit_offset = i * 5;
            let byte_idx = bit_offset / 8;
            let bit_idx = bit_offset % 8;

            if i == 51 {
                if (val & 0x0F) != 0 {
                    return Err(Error::InvalidKeyFormat(
                        "invalid padding bits in recovery key: last character must have zero padding"
                            .into(),
                    ));
                }
                bytes[31] |= (val >> 4) & 1;
            } else {
                let bits_in_0 = std::cmp::min(5, 8 - bit_idx);
                let leftover = 5 - bits_in_0;
                bytes[byte_idx] |= (val >> leftover) << (8 - bit_idx - bits_in_0);
                if leftover > 0 {
                    bytes[byte_idx + 1] |= (val & ((1 << leftover) - 1)) << (8 - leftover);
                }
            }
        }

        Ok(Self(bytes))
    }
}

fn decode_crockford_char(ch: char) -> Result<u8, Error> {
    for (idx, &c) in CROCKFORD_ALPHABET.iter().enumerate() {
        if (c as char) == ch {
            return Ok(idx as u8);
        }
    }
    Err(Error::InvalidKeyFormat(format!(
        "invalid character '{ch}' in recovery key"
    )))
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RecoveryKey([REDACTED])")
    }
}

impl fmt::Display for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_formatted_string())
    }
}

/// Self-contained wrapper sealing archive root key material with a recovery key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryKeyEnvelope {
    pub key_id: String,
    pub created_at_unix_ms: u64,
    pub sealed_archive_root_key: sc_crypto::SealedEnvelope,
}

impl RecoveryKeyEnvelope {
    /// Seal root key material using the specified recovery key.
    pub fn seal(
        recovery_key: &RecoveryKey,
        archive_root_key: &[u8],
        created_at_unix_ms: u64,
    ) -> Result<Self, Error> {
        let key_str = recovery_key.to_formatted_string();
        let sealed = sc_crypto::seal(key_str.as_bytes(), archive_root_key)?;
        let key_id = format!("recov-{:016x}", crc64_iso(&recovery_key.0));
        Ok(Self {
            key_id,
            created_at_unix_ms,
            sealed_archive_root_key: sealed,
        })
    }

    /// Decrypt and unseal the archive root key using the recovery key.
    pub fn unseal(&self, recovery_key: &RecoveryKey) -> Result<Vec<u8>, Error> {
        let key_str = recovery_key.to_formatted_string();
        sc_crypto::open(key_str.as_bytes(), &self.sealed_archive_root_key).map_err(Into::into)
    }
}

fn crc64_iso(data: &[u8]) -> u64 {
    let mut crc = 0u64;
    for &byte in data {
        crc ^= (byte as u64) << 56;
        for _ in 0..8 {
            if crc & 0x8000_0000_0000_0000 != 0 {
                crc = (crc << 1) ^ 0x0000_0000_0000_001B;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

/// Self-contained control fixture used to test recovery drills.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryFixture {
    pub fixture_id: String,
    pub envelope: RecoveryKeyEnvelope,
    pub control_payload: Vec<u8>,
}

/// Result of executing an offline recovery drill against a control fixture.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DrillOutcome {
    pub success: bool,
    pub recovered_bytes_len: usize,
    pub matches_control: bool,
}

/// Offline recovery drill validator executing standalone verification.
pub struct RecoveryDrill;

impl RecoveryDrill {
    /// Create a test recovery fixture containing sealed control bytes.
    pub fn create_fixture(
        recovery_key: &RecoveryKey,
        control_payload: &[u8],
        now_ms: u64,
    ) -> Result<RecoveryFixture, Error> {
        let envelope = RecoveryKeyEnvelope::seal(recovery_key, control_payload, now_ms)?;
        Ok(RecoveryFixture {
            fixture_id: "drill-fixture-control".into(),
            envelope,
            control_payload: control_payload.to_vec(),
        })
    }

    /// Execute a recovery drill using only the recovery key and fixture,
    /// without requiring an active database or network connection.
    pub fn execute_drill(
        fixture: &RecoveryFixture,
        recovery_key: &RecoveryKey,
    ) -> Result<DrillOutcome, Error> {
        let unsealed = fixture.envelope.unseal(recovery_key)?;
        let matches = unsealed == fixture.control_payload;
        Ok(DrillOutcome {
            success: matches,
            recovered_bytes_len: unsealed.len(),
            matches_control: matches,
        })
    }
}

#[derive(Debug)]
pub enum Error {
    Crypto(sc_crypto::Error),
    InvalidKeyFormat(String),
    Json(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Crypto(e) => write!(f, "cryptographic error: {e}"),
            Self::InvalidKeyFormat(msg) => write!(f, "invalid recovery key format: {msg}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Crypto(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::InvalidKeyFormat(_) => None,
        }
    }
}

impl From<sc_crypto::Error> for Error {
    fn from(e: sc_crypto::Error) -> Self {
        Self::Crypto(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let envelope =
            RecoveryKeyEnvelope::seal(&recovery_key, root_key, 1_700_000_000_000).unwrap();
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
            RecoveryDrill::create_fixture(&recovery_key, control_payload, 1_700_000_000_000)
                .unwrap();

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
}
