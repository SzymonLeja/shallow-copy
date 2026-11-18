//! Domain boundary and scope isolation policy core.
//!
//! Enforces access decisions, role authority, domain boundaries, and ADR-010 invariants
//! for Persona Runtime secrets isolation.
#![forbid(unsafe_code)]

use std::fmt;

use serde::{Deserialize, Serialize};

/// Canonical archive storage domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveDomain {
    Public,
    Private,
    Restricted,
    Legacy,
    Secrets,
}

impl ArchiveDomain {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Private => "private",
            Self::Restricted => "restricted",
            Self::Legacy => "legacy",
            Self::Secrets => "secrets",
        }
    }
}

impl fmt::Display for ArchiveDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Granular permission scopes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Scope {
    #[serde(rename = "archive.read")]
    ArchiveRead,
    #[serde(rename = "archive.write")]
    ArchiveWrite,
    #[serde(rename = "archive.destructive")]
    ArchiveDestructive,
    #[serde(rename = "recovery.manage")]
    RecoveryManage,
    #[serde(rename = "connector.manage")]
    ConnectorManage,
    #[serde(rename = "knowledge.read")]
    KnowledgeRead,
    #[serde(rename = "persona.use")]
    PersonaUse,
    #[serde(rename = "secrets.read")]
    SecretsRead,
}

impl Scope {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::ArchiveRead => "archive.read",
            Self::ArchiveWrite => "archive.write",
            Self::ArchiveDestructive => "archive.destructive",
            Self::RecoveryManage => "recovery.manage",
            Self::ConnectorManage => "connector.manage",
            Self::KnowledgeRead => "knowledge.read",
            Self::PersonaUse => "persona.use",
            Self::SecretsRead => "secrets.read",
        }
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Subject role attempting an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectRole {
    Owner,
    Admin,
    Reader,
    Writer,
    Connector,
    PersonaRuntime,
    RecoveryAgent,
}

impl fmt::Display for SubjectRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Owner => f.write_str("owner"),
            Self::Admin => f.write_str("admin"),
            Self::Reader => f.write_str("reader"),
            Self::Writer => f.write_str("writer"),
            Self::Connector => f.write_str("connector"),
            Self::PersonaRuntime => f.write_str("persona_runtime"),
            Self::RecoveryAgent => f.write_str("recovery_agent"),
        }
    }
}

/// Requested action on the target domain/resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Read,
    Write,
    Delete,
    Purge,
    Export,
    ManageRecovery,
    ManageConnector,
}

impl Action {
    pub const fn is_destructive(&self) -> bool {
        matches!(self, Self::Delete | Self::Purge)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read => f.write_str("read"),
            Self::Write => f.write_str("write"),
            Self::Delete => f.write_str("delete"),
            Self::Purge => f.write_str("purge"),
            Self::Export => f.write_str("export"),
            Self::ManageRecovery => f.write_str("manage_recovery"),
            Self::ManageConnector => f.write_str("manage_connector"),
        }
    }
}

/// Specific reason why access was denied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DenyReason {
    MissingRequiredScope(Scope),
    PersonaSecretsAccessBlocked,
    SecretsScopeForbiddenForPersona,
    DestructiveScopeRequired,
    RoleNotAuthorized(String),
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingRequiredScope(scope) => {
                write!(f, "missing required permission scope: {scope}")
            }
            Self::PersonaSecretsAccessBlocked => {
                f.write_str("PersonaRuntime is prohibited from accessing the Secrets domain")
            }
            Self::SecretsScopeForbiddenForPersona => f.write_str(
                "PersonaRuntime subjects or persona.use scopes cannot hold secrets.read",
            ),
            Self::DestructiveScopeRequired => {
                f.write_str("destructive operations require archive.destructive scope")
            }
            Self::RoleNotAuthorized(msg) => {
                write!(f, "subject role not authorized: {msg}")
            }
        }
    }
}

/// Policy evaluation outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Decision {
    Allow,
    Deny(DenyReason),
}

impl Decision {
    pub const fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    pub const fn is_denied(&self) -> bool {
        matches!(self, Self::Deny(_))
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Core policy evaluation engine.
pub struct PolicyEngine;

impl PolicyEngine {
    /// Evaluates whether a subject role with given scopes can perform `action` on `domain`.
    pub fn evaluate(
        role: SubjectRole,
        action: Action,
        domain: ArchiveDomain,
        scopes: &[Scope],
    ) -> Decision {
        let is_persona = role == SubjectRole::PersonaRuntime || scopes.contains(&Scope::PersonaUse);

        // ADR-010: PersonaRuntime or persona.use scope MUST NEVER receive secrets.read or access Secrets domain.
        if is_persona {
            if scopes.contains(&Scope::SecretsRead) {
                return Decision::Deny(DenyReason::SecretsScopeForbiddenForPersona);
            }
            if domain == ArchiveDomain::Secrets {
                return Decision::Deny(DenyReason::PersonaSecretsAccessBlocked);
            }
        }

        // Invariant: Destructive operations require archive.destructive scope.
        if action.is_destructive() && !scopes.contains(&Scope::ArchiveDestructive) {
            return Decision::Deny(DenyReason::DestructiveScopeRequired);
        }

        // Role-based authorization checks
        match role {
            SubjectRole::Reader => {
                if matches!(
                    action,
                    Action::Write
                        | Action::Delete
                        | Action::Purge
                        | Action::ManageRecovery
                        | Action::ManageConnector
                ) {
                    return Decision::Deny(DenyReason::RoleNotAuthorized(
                        "Reader role cannot perform write or administrative actions".to_owned(),
                    ));
                }
            }
            SubjectRole::Connector => {
                if matches!(
                    action,
                    Action::Delete | Action::Purge | Action::ManageRecovery
                ) {
                    return Decision::Deny(DenyReason::RoleNotAuthorized(
                        "Connector role cannot perform destructive or recovery operations"
                            .to_owned(),
                    ));
                }
            }
            SubjectRole::PersonaRuntime if action.is_destructive() => {
                return Decision::Deny(DenyReason::RoleNotAuthorized(
                    "PersonaRuntime cannot perform destructive actions".to_owned(),
                ));
            }
            _ => {}
        }

        // Scope validation per action and domain
        match action {
            Action::Read | Action::Export => {
                if domain == ArchiveDomain::Secrets {
                    if !scopes.contains(&Scope::SecretsRead) {
                        return Decision::Deny(DenyReason::MissingRequiredScope(
                            Scope::SecretsRead,
                        ));
                    }
                } else if !scopes.contains(&Scope::ArchiveRead)
                    && !scopes.contains(&Scope::KnowledgeRead)
                {
                    return Decision::Deny(DenyReason::MissingRequiredScope(Scope::ArchiveRead));
                }
            }
            Action::Write => {
                if domain == ArchiveDomain::Secrets && !scopes.contains(&Scope::SecretsRead) {
                    return Decision::Deny(DenyReason::MissingRequiredScope(Scope::SecretsRead));
                }
                if !scopes.contains(&Scope::ArchiveWrite) {
                    return Decision::Deny(DenyReason::MissingRequiredScope(Scope::ArchiveWrite));
                }
            }
            Action::Delete | Action::Purge => {
                if domain == ArchiveDomain::Secrets && !scopes.contains(&Scope::SecretsRead) {
                    return Decision::Deny(DenyReason::MissingRequiredScope(Scope::SecretsRead));
                }
                if !scopes.contains(&Scope::ArchiveDestructive) {
                    return Decision::Deny(DenyReason::DestructiveScopeRequired);
                }
            }
            Action::ManageRecovery => {
                if !scopes.contains(&Scope::RecoveryManage) {
                    return Decision::Deny(DenyReason::MissingRequiredScope(Scope::RecoveryManage));
                }
            }
            Action::ManageConnector => {
                if !scopes.contains(&Scope::ConnectorManage) {
                    return Decision::Deny(DenyReason::MissingRequiredScope(
                        Scope::ConnectorManage,
                    ));
                }
            }
        }

        Decision::Allow
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
