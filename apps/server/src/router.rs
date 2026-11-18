//! HTTP router composition and middleware placement.

use axum::{
    Router, middleware,
    routing::{get, post},
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};

use crate::{AppState, auth, routes};

pub fn create_router(state: AppState) -> Router {
    let protected_routes = Router::new()
        .route("/v1/archive/objects", get(routes::archive::list_objects))
        .route("/v1/archive/objects/{id}", get(routes::archive::get_object))
        .route("/v1/archive/audit", get(routes::archive::list_audit_events))
        .route(
            "/v1/archive/backup-manifest",
            get(routes::archive::generate_backup_manifest)
                .post(routes::archive::generate_backup_manifest),
        )
        .route(
            "/v1/archive/backup-manifest/generate",
            post(routes::archive::generate_backup_manifest),
        )
        .route(
            "/v1/archive/backup-manifest/verify",
            post(routes::archive::verify_backup_manifest),
        )
        .route(
            "/v1/archive/recovery/drill",
            post(routes::archive::trigger_recovery_drill),
        )
        .route("/v1/archive/verify", post(routes::jobs::trigger_verify))
        .route("/v1/archive/export", post(routes::jobs::trigger_export))
        .route(
            "/v1/archive/ingest/filesystem",
            post(routes::ingest::ingest_filesystem_file),
        )
        .route(
            "/v1/archive/ingest/browser-history",
            post(routes::ingest::ingest_browser_history),
        )
        .route(
            "/v1/archive/ingest/browser/chromium",
            post(routes::ingest::ingest_browser_history),
        )
        .route(
            "/v1/archive/guard/analyze",
            post(routes::guard::analyze_guarded_delete),
        )
        .route(
            "/v1/archive/guard/action",
            post(routes::guard::confirm_guarded_delete),
        )
        .route("/v1/jobs", get(routes::jobs::list_jobs))
        .route("/v1/jobs/{id}", get(routes::jobs::get_job))
        .route("/v1/system/readiness", get(routes::setup::system_readiness))
        .route("/v1/system/setup", get(routes::setup::get_setup_status))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::authorize_request,
        ));

    // Setup is outside the protected router only during the guarded bootstrap window.
    Router::new()
        .route("/health", get(routes::web::health))
        .route("/v1/auth/session", post(auth::login).delete(auth::logout))
        .route("/v1/system/setup", post(routes::setup::execute_setup))
        .route(
            "/v1/system/setup/claim-legacy",
            post(routes::setup::claim_legacy),
        )
        .merge(protected_routes)
        .fallback(routes::web::static_or_spa_fallback)
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive())
        .with_state(state)
}
