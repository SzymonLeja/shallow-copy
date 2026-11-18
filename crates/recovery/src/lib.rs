//! Standalone recovery key mechanics and offline verification drill core.
//!
//! # Guarantees
//! - Zero external database or secret dependencies: operates standalone per `project.md` line 215-238 and ADR-011.
//! - High-entropy 256-bit keys formatted with Crockford Base32 in hyphenated chunks for paper printability.
//! - Self-contained `RecoveryKeyEnvelope` sealed with `sc-crypto` (XChaCha20-Poly1305 + Argon2id).
//! - Standalone drill execution to verify recoverability without runtime infrastructure.
#![forbid(unsafe_code)]

use std::fmt;
use std::{
    fs,
    path::{Path, PathBuf},
};

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

    /// Canonical Crockford encoding without display separators (52 characters).
    pub fn to_compact_string(&self) -> String {
        self.to_formatted_string().replace('-', "")
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

const RECOVERY_KIT_VERSION: &str = "1";
const RECOVERY_INSTRUCTIONS: &str = "Keep this recovery kit offline and separate from the archive. To restore, install a compatible archive reader, open this kit, enter the printed recovery key, then run a full archive verification before using recovered data. Anyone holding the key and kit can unlock the archive root key.";

/// Printable, self-describing offline recovery package.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryKit {
    pub format_version: String,
    /// Exactly 52 Crockford Base32 characters, without separators.
    pub recovery_key: String,
    /// CRC64/ISO fingerprint, in `recov-` plus 16 lowercase hex digits form.
    pub fingerprint: String,
    pub created_at_unix_ms: u64,
    pub instructions: String,
    pub envelope: RecoveryKeyEnvelope,
}

impl RecoveryKit {
    pub fn generate(archive_root_key: &[u8], created_at_unix_ms: u64) -> Result<Self, Error> {
        let recovery_key = RecoveryKey::generate();
        let envelope =
            RecoveryKeyEnvelope::seal(&recovery_key, archive_root_key, created_at_unix_ms)?;
        let kit = Self {
            format_version: RECOVERY_KIT_VERSION.into(),
            recovery_key: recovery_key.to_compact_string(),
            fingerprint: envelope.key_id.clone(),
            created_at_unix_ms,
            instructions: RECOVERY_INSTRUCTIONS.into(),
            envelope,
        };
        kit.validate()?;
        Ok(kit)
    }

    pub fn to_json(&self) -> Result<String, Error> {
        self.validate()?;
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Printable text wrapper with instructions followed by the complete JSON package.
    pub fn to_text(&self) -> Result<String, Error> {
        let json = self.to_json()?;
        Ok(format!(
            "OFFLINE ARCHIVE RECOVERY KIT\n{}\n\n--- RECOVERY PACKAGE JSON ---\n{}\n",
            self.instructions, json
        ))
    }

    pub fn from_json(input: &str) -> Result<Self, Error> {
        let kit: Self = serde_json::from_str(input)?;
        kit.validate()?;
        Ok(kit)
    }

    pub fn from_text(input: &str) -> Result<Self, Error> {
        let marker = "--- RECOVERY PACKAGE JSON ---\n";
        let json = input
            .split_once(marker)
            .ok_or_else(|| Error::InvalidKit("missing JSON package marker".into()))?
            .1;
        Self::from_json(json)
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.format_version != RECOVERY_KIT_VERSION
            || self.created_at_unix_ms != self.envelope.created_at_unix_ms
        {
            return Err(Error::InvalidKit(
                "unsupported version or inconsistent timestamp".into(),
            ));
        }
        if self.instructions.trim().is_empty() {
            return Err(Error::InvalidKit("missing recovery instructions".into()));
        }
        let key = RecoveryKey::from_formatted_string(&self.recovery_key)?;
        let fingerprint = format!("recov-{:016x}", crc64_iso(&key.0));
        if self.recovery_key.len() != 52
            || self.fingerprint != fingerprint
            || self.envelope.key_id != fingerprint
        {
            return Err(Error::InvalidKit(
                "recovery key fingerprint mismatch".into(),
            ));
        }
        let mut root_key = self
            .envelope
            .unseal(&key)
            .map_err(|_| Error::InvalidKit("recovery envelope authentication failed".into()))?;
        root_key.fill(0);
        Ok(())
    }

    pub fn recovery_key_value(&self) -> Result<RecoveryKey, Error> {
        RecoveryKey::from_formatted_string(&self.recovery_key)
    }
}

/// Canonical, independently keyed archive domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyDomain {
    Public,
    Private,
    Restricted,
    Legacy,
    Secrets,
}

impl KeyDomain {
    pub const ALL: [Self; 5] = [
        Self::Public,
        Self::Private,
        Self::Restricted,
        Self::Legacy,
        Self::Secrets,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Restricted => "restricted",
            Self::Legacy => "legacy",
            Self::Secrets => "secrets",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedDomainKey {
    pub domain: KeyDomain,
    pub envelope: sc_crypto::DomainSealedEnvelope,
}

/// Portable key inventory; each random domain key is independently sealed under the root key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DomainKeyRing {
    pub records: Vec<SealedDomainKey>,
}

impl DomainKeyRing {
    pub fn generate(archive_root_key: &[u8]) -> Result<Self, Error> {
        let mut records = Vec::with_capacity(KeyDomain::ALL.len());
        for domain in KeyDomain::ALL {
            let mut key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut key);
            let envelope = sc_crypto::seal_domain(archive_root_key, &key, domain.as_str())?;
            key.fill(0);
            records.push(SealedDomainKey { domain, envelope });
        }
        Ok(Self { records })
    }

    pub fn unlock(&self, archive_root_key: &[u8]) -> Result<UnlockedDomainKeyRing, Error> {
        if self.records.len() != KeyDomain::ALL.len() {
            return Err(Error::InvalidKit(
                "domain key ring must contain each canonical domain exactly once".into(),
            ));
        }
        let mut keys = std::collections::BTreeMap::new();
        for record in &self.records {
            if keys.contains_key(&record.domain) {
                return Err(Error::InvalidKit("duplicate domain key record".into()));
            }
            let key =
                sc_crypto::open_domain(archive_root_key, &record.envelope, record.domain.as_str())?;
            if key.len() != 32 {
                return Err(Error::InvalidKit("domain key has invalid length".into()));
            }
            let key: [u8; 32] = key
                .try_into()
                .map_err(|_| Error::InvalidKit("domain key has invalid length".into()))?;
            keys.insert(record.domain, sc_crypto::DerivedKey(key));
        }
        Ok(UnlockedDomainKeyRing { keys })
    }
}

/// In-memory domain keys unlocked from a validated sealed key ring.
pub struct UnlockedDomainKeyRing {
    keys: std::collections::BTreeMap<KeyDomain, sc_crypto::DerivedKey>,
}

impl UnlockedDomainKeyRing {
    pub fn seal(
        &self,
        domain: KeyDomain,
        plaintext: &[u8],
    ) -> Result<sc_crypto::DomainSealedEnvelope, Error> {
        Ok(sc_crypto::seal_domain(
            self.key(domain)?,
            plaintext,
            domain.as_str(),
        )?)
    }
    pub fn open(
        &self,
        domain: KeyDomain,
        envelope: &sc_crypto::DomainSealedEnvelope,
    ) -> Result<Vec<u8>, Error> {
        Ok(sc_crypto::open_domain(
            self.key(domain)?,
            envelope,
            domain.as_str(),
        )?)
    }
    fn key(&self, domain: KeyDomain) -> Result<&[u8], Error> {
        self.keys
            .get(&domain)
            .map(|key| key.0.as_slice())
            .ok_or_else(|| Error::InvalidKit("domain key is unavailable".into()))
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

/// Local directory backup and restore drill, backed by OIAF's verified export.
pub struct DirectoryBackup;

impl DirectoryBackup {
    /// Export a complete archive, verify the fresh copy, then publish its sidecar manifest.
    pub fn create(source: &oiaf::Archive, destination: impl AsRef<Path>) -> Result<PathBuf, Error> {
        let destination = destination.as_ref();
        source.verify(true)?;
        source.export(destination, None)?;
        let copy = oiaf::Archive::open(destination)?;
        copy.verify(true)?;
        let manifest = copy.generate_backup_manifest()?;
        if !copy.verify_backup_manifest(&manifest)? {
            return Err(Error::Backup("export manifest verification failed".into()));
        }
        let sidecar = sidecar_path(destination);
        let bytes = serde_json::to_vec_pretty(&manifest)?;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&sidecar)?;
        use std::io::Write;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(sidecar)
    }

    /// Reopen backup as a fresh archive and verify both archive fixity and its sidecar.
    pub fn drill(destination: impl AsRef<Path>) -> Result<oiaf::VerificationReport, Error> {
        let destination = destination.as_ref();
        let archive = oiaf::Archive::open(destination)?;
        let report = archive.verify(true)?;
        let manifest: oiaf::BackupManifest =
            serde_json::from_slice(&fs::read(sidecar_path(destination))?)?;
        if !archive.verify_backup_manifest(&manifest)? {
            return Err(Error::Backup("backup manifest mismatch".into()));
        }
        Ok(report)
    }
}

fn sidecar_path(archive: &Path) -> PathBuf {
    let mut name = archive.as_os_str().to_os_string();
    name.push(".backup-manifest.json");
    PathBuf::from(name)
}

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
    Io(std::io::Error),
    Crypto(sc_crypto::Error),
    InvalidKeyFormat(String),
    Json(serde_json::Error),
    Oiaf(oiaf::Error),
    Backup(String),
    InvalidKit(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Crypto(e) => write!(f, "cryptographic error: {e}"),
            Self::InvalidKeyFormat(msg) => write!(f, "invalid recovery key format: {msg}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
            Self::Oiaf(e) => write!(f, "archive error: {e}"),
            Self::Backup(e) => write!(f, "backup error: {e}"),
            Self::InvalidKit(e) => write!(f, "invalid recovery kit: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Crypto(e) => Some(e),
            Self::Json(e) => Some(e),
            Self::Oiaf(e) => Some(e),
            Self::InvalidKeyFormat(_) => None,
            Self::Backup(_) => None,
            Self::InvalidKit(_) => None,
        }
    }
}

impl From<sc_crypto::Error> for Error {
    fn from(e: sc_crypto::Error) -> Self {
        Self::Crypto(e)
    }
}

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

impl From<oiaf::Error> for Error {
    fn from(e: oiaf::Error) -> Self {
        Self::Oiaf(e)
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
