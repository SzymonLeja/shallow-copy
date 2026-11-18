use super::*;

#[test]
fn persona_denial_on_secrets_domain() {
    let scopes = [Scope::ArchiveRead, Scope::PersonaUse];
    let decision = PolicyEngine::evaluate(
        SubjectRole::PersonaRuntime,
        Action::Read,
        ArchiveDomain::Secrets,
        &scopes,
    );
    assert_eq!(
        decision,
        Decision::Deny(DenyReason::PersonaSecretsAccessBlocked)
    );

    // Also when role is not PersonaRuntime but scope has PersonaUse
    let decision = PolicyEngine::evaluate(
        SubjectRole::Reader,
        Action::Read,
        ArchiveDomain::Secrets,
        &[Scope::PersonaUse, Scope::ArchiveRead],
    );
    assert_eq!(
        decision,
        Decision::Deny(DenyReason::PersonaSecretsAccessBlocked)
    );
}

#[test]
fn persona_with_secrets_read_scope_is_rejected() {
    let scopes = [Scope::PersonaUse, Scope::SecretsRead];
    let decision = PolicyEngine::evaluate(
        SubjectRole::PersonaRuntime,
        Action::Read,
        ArchiveDomain::Public,
        &scopes,
    );
    assert_eq!(
        decision,
        Decision::Deny(DenyReason::SecretsScopeForbiddenForPersona)
    );
}

#[test]
fn reader_allowed_on_public_and_private_with_appropriate_scopes() {
    let scopes = [Scope::ArchiveRead];

    let public_decision = PolicyEngine::evaluate(
        SubjectRole::Reader,
        Action::Read,
        ArchiveDomain::Public,
        &scopes,
    );
    assert_eq!(public_decision, Decision::Allow);

    let private_decision = PolicyEngine::evaluate(
        SubjectRole::Reader,
        Action::Read,
        ArchiveDomain::Private,
        &scopes,
    );
    assert_eq!(private_decision, Decision::Allow);
}

#[test]
fn destructive_action_denied_without_archive_destructive() {
    let scopes = [Scope::ArchiveWrite, Scope::ArchiveRead];
    let decision = PolicyEngine::evaluate(
        SubjectRole::Admin,
        Action::Delete,
        ArchiveDomain::Public,
        &scopes,
    );
    assert_eq!(
        decision,
        Decision::Deny(DenyReason::DestructiveScopeRequired)
    );

    let purge_decision = PolicyEngine::evaluate(
        SubjectRole::Owner,
        Action::Purge,
        ArchiveDomain::Private,
        &scopes,
    );
    assert_eq!(
        purge_decision,
        Decision::Deny(DenyReason::DestructiveScopeRequired)
    );
}

#[test]
fn destructive_action_allowed_with_archive_destructive() {
    let scopes = [Scope::ArchiveDestructive, Scope::ArchiveWrite];
    let decision = PolicyEngine::evaluate(
        SubjectRole::Admin,
        Action::Delete,
        ArchiveDomain::Public,
        &scopes,
    );
    assert_eq!(decision, Decision::Allow);
}

#[test]
fn reader_denied_without_read_scope() {
    let scopes = [];
    let decision = PolicyEngine::evaluate(
        SubjectRole::Reader,
        Action::Read,
        ArchiveDomain::Public,
        &scopes,
    );
    assert_eq!(
        decision,
        Decision::Deny(DenyReason::MissingRequiredScope(Scope::ArchiveRead))
    );
}

#[test]
fn reader_denied_write_action() {
    let scopes = [Scope::ArchiveWrite, Scope::ArchiveRead];
    let decision = PolicyEngine::evaluate(
        SubjectRole::Reader,
        Action::Write,
        ArchiveDomain::Public,
        &scopes,
    );
    assert!(matches!(
        decision,
        Decision::Deny(DenyReason::RoleNotAuthorized(_))
    ));
}

#[test]
fn secrets_domain_allowed_for_authorized_owner_with_secrets_read() {
    let scopes = [Scope::SecretsRead, Scope::ArchiveRead];
    let decision = PolicyEngine::evaluate(
        SubjectRole::Owner,
        Action::Read,
        ArchiveDomain::Secrets,
        &scopes,
    );
    assert_eq!(decision, Decision::Allow);
}

#[test]
fn serialization_roundtrip() {
    let domain = ArchiveDomain::Secrets;
    let serialized = serde_json::to_string(&domain).unwrap();
    assert_eq!(serialized, "\"secrets\"");
    let deserialized: ArchiveDomain = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, domain);

    let scope = Scope::ArchiveDestructive;
    let serialized = serde_json::to_string(&scope).unwrap();
    assert_eq!(serialized, "\"archive.destructive\"");
    let deserialized: Scope = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, scope);

    let decision = Decision::Allow;
    let json = decision.to_json().unwrap();
    assert_eq!(Decision::from_json(&json).unwrap(), decision);
}
