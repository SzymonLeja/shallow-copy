//! Preservation Guard core for destructive operation interception and impact analysis.
//!
//! # Guarantees
//! - Operates strictly as trusted core without AI dependencies (per `project.md` line 270).
//! - Intercepts destructive archive actions and enforces explicit step-up confirmation.
//! - Verifies backup availability before permitting destructive commits.
//! - Provides quarantine delay windows with undo/restore capability.
#![forbid(unsafe_code)]

use std::fmt;

use sc_storage::Catalog;
use serde::{Deserialize, Serialize};

/// High-impact operations intercepted by the Preservation Guard.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardedOperation {
    DeleteCanonical { object_ids: Vec<String> },
    LossyTranscodeRemoveSource { object_ids: Vec<String> },
    ChangeRecoveryKey,
    DestroyKey,
    PurgeSnapshots,
    DowngradeEncryption,
    DisableLastBackup,
}

impl fmt::Display for GuardedOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeleteCanonical { object_ids } => {
                write!(f, "delete canonical ({} objects)", object_ids.len())
            }
            Self::LossyTranscodeRemoveSource { object_ids } => write!(
                f,
                "lossy transcode and remove source ({} objects)",
                object_ids.len()
            ),
            Self::ChangeRecoveryKey => f.write_str("change recovery key"),
            Self::DestroyKey => f.write_str("destroy master encryption key"),
            Self::PurgeSnapshots => f.write_str("purge snapshots"),
            Self::DowngradeEncryption => f.write_str("downgrade encryption suite"),
            Self::DisableLastBackup => f.write_str("disable last backup"),
        }
    }
}

/// Preservation Guard lifecycle state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardState {
    Requested,
    ImpactAnalysis,
    DryRunReady,
    ExplicitConfirmation,
    QuarantineDelay,
    Committed,
    Cancelled,
    Restored,
}

impl fmt::Display for GuardState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested => f.write_str("requested"),
            Self::ImpactAnalysis => f.write_str("impact_analysis"),
            Self::DryRunReady => f.write_str("dry_run_ready"),
            Self::ExplicitConfirmation => f.write_str("explicit_confirmation"),
            Self::QuarantineDelay => f.write_str("quarantine_delay"),
            Self::Committed => f.write_str("committed"),
            Self::Cancelled => f.write_str("cancelled"),
            Self::Restored => f.write_str("restored"),
        }
    }
}

/// Evaluated impact report for a requested guarded operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactReport {
    pub affected_objects: usize,
    pub affected_bytes: u64,
    pub is_reversible: bool,
    pub has_verified_backup: bool,
    pub backup_checkpoint_timestamp: Option<u64>,
    pub warnings: Vec<String>,
}

#[derive(Debug)]
pub enum Error {
    Storage(sc_storage::Error),
    PolicyScopeDenied(String),
    InvalidTransition(String),
    ConfirmationMismatch(String),
    BackupRequirementUnmet(String),
    QuarantineActive(String),
    Json(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Storage(e) => write!(f, "storage: {e}"),
            Self::PolicyScopeDenied(e) => write!(f, "policy scope denied: {e}"),
            Self::InvalidTransition(e) => write!(f, "invalid state transition: {e}"),
            Self::ConfirmationMismatch(e) => write!(f, "confirmation mismatch: {e}"),
            Self::BackupRequirementUnmet(e) => write!(f, "backup requirement unmet: {e}"),
            Self::QuarantineActive(e) => write!(f, "quarantine delay active: {e}"),
            Self::Json(e) => write!(f, "JSON error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Storage(e) => Some(e),
            Self::Json(e) => Some(e),
            _ => None,
        }
    }
}

impl From<sc_storage::Error> for Error {
    fn from(e: sc_storage::Error) -> Self {
        Self::Storage(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Non-AI impact analyzer inspecting catalog impact and backup dependencies.
pub struct ImpactAnalyzer;

impl ImpactAnalyzer {
    pub fn analyze(
        catalog: &Catalog,
        operation: &GuardedOperation,
        has_verified_backup: bool,
    ) -> Result<ImpactReport> {
        Self::analyze_with_backup(catalog, operation, has_verified_backup, None)
    }

    pub fn analyze_with_backup(
        catalog: &Catalog,
        operation: &GuardedOperation,
        has_verified_backup: bool,
        backup_checkpoint_timestamp: Option<u64>,
    ) -> Result<ImpactReport> {
        let mut affected_objects = 0;
        let mut affected_bytes = 0;
        let mut warnings = Vec::new();

        let is_reversible = match operation {
            GuardedOperation::DeleteCanonical { object_ids } => {
                let mut unknown_ids = Vec::new();
                for id in object_ids {
                    if let Some(obj) = catalog.get_object(id)? {
                        affected_objects += 1;
                        affected_bytes += obj.blob_size;
                    } else {
                        unknown_ids.push(id.as_str());
                    }
                }
                if !unknown_ids.is_empty() {
                    warnings.push(format!(
                        "Warning: {} requested object(s) not found in catalog ({}); impact may be undercounted",
                        unknown_ids.len(),
                        unknown_ids.join(", ")
                    ));
                }
                warnings.push(format!(
                    "Permanent removal of {affected_objects} canonical objects ({affected_bytes} bytes)"
                ));
                false
            }
            GuardedOperation::LossyTranscodeRemoveSource { object_ids } => {
                let mut unknown_ids = Vec::new();
                for id in object_ids {
                    if let Some(obj) = catalog.get_object(id)? {
                        affected_objects += 1;
                        affected_bytes += obj.blob_size;
                    } else {
                        unknown_ids.push(id.as_str());
                    }
                }
                if !unknown_ids.is_empty() {
                    warnings.push(format!(
                        "Warning: {} requested object(s) not found in catalog ({}); impact may be undercounted",
                        unknown_ids.len(),
                        unknown_ids.join(", ")
                    ));
                }
                warnings.push(format!(
                    "Raw original bytes for {affected_objects} objects will be discarded"
                ));
                false
            }
            GuardedOperation::ChangeRecoveryKey => {
                warnings.push(
                    "Prior recovery key shares and emergency contacts will be invalidated".into(),
                );
                true
            }
            GuardedOperation::DestroyKey => {
                warnings.push(
                    "Destroying master vault keys renders all encrypted data permanently unrecoverable"
                        .into(),
                );
                false
            }
            GuardedOperation::PurgeSnapshots => {
                warnings.push("All point-in-time snapshot history will be erased".into());
                false
            }
            GuardedOperation::DowngradeEncryption => {
                warnings.push("Cryptographic downgrade reduces security margins".into());
                false
            }
            GuardedOperation::DisableLastBackup => {
                warnings.push(
                    "Disabling the last verified backup copy leaves vault with single point of failure"
                        .into(),
                );
                false
            }
        };

        let has_backup = has_verified_backup || backup_checkpoint_timestamp.is_some();
        if !has_backup {
            warnings.push("CRITICAL: No verified external backup detected!".into());
        }

        Ok(ImpactReport {
            affected_objects,
            affected_bytes,
            is_reversible,
            has_verified_backup: has_backup,
            backup_checkpoint_timestamp,
            warnings,
        })
    }
}

/// Active Preservation Guard session tracking approval lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardSession {
    pub id: String,
    pub operation: GuardedOperation,
    pub state: GuardState,
    pub impact: Option<ImpactReport>,
    pub step_up_confirmed: bool,
    pub backup_override: bool,
    pub quarantine_deadline_unix_ms: Option<u64>,
}

impl GuardSession {
    pub fn new(id: impl Into<String>, operation: GuardedOperation) -> Self {
        Self {
            id: id.into(),
            operation,
            state: GuardState::Requested,
            impact: None,
            step_up_confirmed: false,
            backup_override: false,
            quarantine_deadline_unix_ms: None,
        }
    }

    /// Run impact analysis without AI and advance state to `DryRunReady`.
    pub fn run_impact_analysis(
        &mut self,
        catalog: &Catalog,
        has_verified_backup: bool,
    ) -> Result<&ImpactReport> {
        self.run_impact_analysis_with_backup(catalog, has_verified_backup, None)
    }

    /// Run impact analysis with optional real backup checkpoint timestamp.
    pub fn run_impact_analysis_with_backup(
        &mut self,
        catalog: &Catalog,
        has_verified_backup: bool,
        backup_checkpoint_timestamp: Option<u64>,
    ) -> Result<&ImpactReport> {
        if self.state != GuardState::Requested {
            return Err(Error::InvalidTransition(format!(
                "cannot run impact analysis from state {:?}",
                self.state
            )));
        }
        self.state = GuardState::ImpactAnalysis;
        let report = ImpactAnalyzer::analyze_with_backup(
            catalog,
            &self.operation,
            has_verified_backup,
            backup_checkpoint_timestamp,
        )?;
        self.impact = Some(report);
        self.state = GuardState::DryRunReady;
        Ok(self.impact.as_ref().expect("impact report initialized"))
    }

    /// Cancel the requested operation at any pre-commit stage.
    pub fn cancel(&mut self) -> Result<()> {
        match self.state {
            GuardState::DryRunReady
            | GuardState::ExplicitConfirmation
            | GuardState::QuarantineDelay => {
                self.state = GuardState::Cancelled;
                Ok(())
            }
            _ => Err(Error::InvalidTransition(format!(
                "cannot cancel from state {:?}",
                self.state
            ))),
        }
    }

    /// Verify that the caller holds the required destructive policy scope.
    pub fn verify_policy_scope(scopes: &[sc_policy::Scope]) -> Result<()> {
        if !scopes.contains(&sc_policy::Scope::ArchiveDestructive) {
            return Err(Error::PolicyScopeDenied(
                "destructive operation requires archive.destructive scope".into(),
            ));
        }
        Ok(())
    }

    /// Submit explicit step-up confirmation and verify backup requirement.
    pub fn confirm_step_up(
        &mut self,
        typed_confirmation: &str,
        allow_unverified_backup_override: bool,
    ) -> Result<()> {
        if self.state != GuardState::DryRunReady {
            return Err(Error::InvalidTransition(format!(
                "cannot confirm step-up from state {:?}",
                self.state
            )));
        }

        if typed_confirmation != "CONFIRM DESTRUCTIVE OPERATION" {
            return Err(Error::ConfirmationMismatch(
                "typed confirmation text does not match required phrase".into(),
            ));
        }

        let impact = self.impact.as_ref().ok_or_else(|| {
            Error::InvalidTransition("impact report missing before confirmation".into())
        })?;

        if !impact.has_verified_backup && !allow_unverified_backup_override {
            return Err(Error::BackupRequirementUnmet(
                "destructive operation blocked: no verified backup exists and override was not granted"
                    .into(),
            ));
        }

        self.step_up_confirmed = true;
        self.backup_override = allow_unverified_backup_override;
        self.state = GuardState::ExplicitConfirmation;
        Ok(())
    }

    /// Move to quarantine delay window before physical commit.
    pub fn enter_quarantine(&mut self, delay_ms: u64, now_ms: u64) -> Result<()> {
        if self.state != GuardState::ExplicitConfirmation {
            return Err(Error::InvalidTransition(format!(
                "cannot enter quarantine from state {:?}",
                self.state
            )));
        }
        if delay_ms > 0 {
            self.quarantine_deadline_unix_ms = Some(now_ms + delay_ms);
            self.state = GuardState::QuarantineDelay;
        } else {
            self.state = GuardState::Committed;
        }
        Ok(())
    }

    /// Undo operation while inside quarantine window, transitioning to `Restored`.
    pub fn restore_from_quarantine(&mut self) -> Result<()> {
        if self.state != GuardState::QuarantineDelay {
            return Err(Error::InvalidTransition(format!(
                "cannot restore from quarantine in state {:?}",
                self.state
            )));
        }
        self.state = GuardState::Restored;
        Ok(())
    }

    /// Execute final commit once confirmation and quarantine delay elapse.
    pub fn commit(&mut self, now_ms: u64) -> Result<()> {
        match self.state {
            GuardState::ExplicitConfirmation => {
                self.state = GuardState::Committed;
                Ok(())
            }
            GuardState::QuarantineDelay => {
                if let Some(deadline) = self.quarantine_deadline_unix_ms
                    && now_ms < deadline
                {
                    return Err(Error::QuarantineActive(format!(
                        "quarantine delay active until {deadline}; current time {now_ms}"
                    )));
                }
                self.state = GuardState::Committed;
                Ok(())
            }
            _ => Err(Error::InvalidTransition(format!(
                "cannot commit destructive operation from state {:?}",
                self.state
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sc_storage::CatalogObject;

    fn setup_mock_catalog() -> Catalog {
        let cat = Catalog::open_in_memory().unwrap();
        cat.upsert_catalog_object(&CatalogObject {
            object_id: "obj-100".into(),
            blob_digest: "digest-100".into(),
            blob_size: 4096,
            connector: "filesystem".into(),
            source_instance: "node1".into(),
            external_id: "doc1.pdf".into(),
            revision: "rev1".into(),
            observed_time_unix_ms: 1000,
            ingested_time_unix_ms: 1000,
            ingest_fingerprint: Some("fp-100".into()),
            media_type: Some("application/pdf".into()),
            suggested_domain: Some("private".into()),
        })
        .unwrap();
        cat
    }

    #[test]
    fn state_transition_validation_dry_run_to_cancelled_vs_confirmed() {
        let cat = setup_mock_catalog();
        let op = GuardedOperation::DeleteCanonical {
            object_ids: vec!["obj-100".into()],
        };

        // Path A: Requested -> DryRunReady -> Cancelled
        let mut session_cancel = GuardSession::new("sess-1", op.clone());
        assert_eq!(session_cancel.state, GuardState::Requested);
        let report = session_cancel.run_impact_analysis(&cat, true).unwrap();
        assert_eq!(report.affected_objects, 1);
        assert_eq!(report.affected_bytes, 4096);
        assert_eq!(session_cancel.state, GuardState::DryRunReady);

        session_cancel.cancel().unwrap();
        assert_eq!(session_cancel.state, GuardState::Cancelled);

        // Path B: Requested -> DryRunReady -> Confirmed -> Quarantine -> Committed
        let mut session_confirm = GuardSession::new("sess-2", op);
        session_confirm.run_impact_analysis(&cat, true).unwrap();
        session_confirm
            .confirm_step_up("CONFIRM DESTRUCTIVE OPERATION", false)
            .unwrap();
        assert_eq!(session_confirm.state, GuardState::ExplicitConfirmation);

        session_confirm.enter_quarantine(60_000, 1_000_000).unwrap();
        assert_eq!(session_confirm.state, GuardState::QuarantineDelay);

        // Commit fails while quarantine is active
        assert!(session_confirm.commit(1_030_000).is_err());

        // Commit succeeds after quarantine window elapses
        session_confirm.commit(1_070_000).unwrap();
        assert_eq!(session_confirm.state, GuardState::Committed);
    }

    #[test]
    fn unverified_backup_blocks_destructive_commit_without_override() {
        let cat = setup_mock_catalog();
        let op = GuardedOperation::DeleteCanonical {
            object_ids: vec!["obj-100".into()],
        };

        let mut session = GuardSession::new("sess-nobackup", op);
        let report = session.run_impact_analysis(&cat, false).unwrap();
        assert!(!report.has_verified_backup);

        // Confirm fails without override
        let err = session
            .confirm_step_up("CONFIRM DESTRUCTIVE OPERATION", false)
            .unwrap_err();
        assert!(matches!(err, Error::BackupRequirementUnmet(_)));

        // Confirm succeeds with explicit override
        session
            .confirm_step_up("CONFIRM DESTRUCTIVE OPERATION", true)
            .unwrap();
        assert_eq!(session.state, GuardState::ExplicitConfirmation);
    }

    #[test]
    fn guard_execution_without_ai_dependencies() {
        let cat = setup_mock_catalog();
        let op = GuardedOperation::DestroyKey;

        let mut session = GuardSession::new("sess-no-ai", op);
        let impact = session.run_impact_analysis(&cat, true).unwrap();

        assert!(!impact.is_reversible);
        assert!(
            impact
                .warnings
                .iter()
                .any(|w| w.contains("Destroying master vault keys"))
        );
    }

    #[test]
    fn quarantine_undo_transitions_to_restored() {
        let cat = setup_mock_catalog();
        let mut session = GuardSession::new("sess-undo", GuardedOperation::PurgeSnapshots);
        session.run_impact_analysis(&cat, true).unwrap();
        session
            .confirm_step_up("CONFIRM DESTRUCTIVE OPERATION", false)
            .unwrap();
        session.enter_quarantine(100_000, 1_000).unwrap();

        session.restore_from_quarantine().unwrap();
        assert_eq!(session.state, GuardState::Restored);
    }

    #[test]
    fn policy_scope_verification_enforces_destructive_scope() {
        assert!(GuardSession::verify_policy_scope(&[]).is_err());
        assert!(GuardSession::verify_policy_scope(&[sc_policy::Scope::ArchiveRead]).is_err());
        assert!(GuardSession::verify_policy_scope(&[sc_policy::Scope::ArchiveDestructive]).is_ok());
    }

    #[test]
    fn unknown_object_id_records_warning_and_real_checkpoint_preserved() {
        let cat = setup_mock_catalog();
        let op = GuardedOperation::DeleteCanonical {
            object_ids: vec!["obj-100".into(), "obj-unknown-999".into()],
        };

        let mut session = GuardSession::new("sess-unknown-check", op);
        let impact = session
            .run_impact_analysis_with_backup(&cat, true, Some(1_700_555_000_000))
            .unwrap();

        assert_eq!(impact.affected_objects, 1);
        assert_eq!(impact.affected_bytes, 4096);
        assert_eq!(impact.backup_checkpoint_timestamp, Some(1_700_555_000_000));
        assert!(
            impact
                .warnings
                .iter()
                .any(|w| w.contains("obj-unknown-999") && w.contains("undercounted"))
        );
    }
}
