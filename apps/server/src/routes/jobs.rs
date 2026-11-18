//! Job status HTTP handlers; execution stays in the job coordinator.

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};

use crate::{
    ApiJob, AppState, CatalogJob, ExportRequestBody, JobStatus, ListJobsQuery, VerifyRequestBody,
    current_time_ms, internal_error, not_found,
};

pub(crate) async fn trigger_verify(
    State(state): State<AppState>,
    Json(_body): Json<Option<VerifyRequestBody>>,
) -> Response {
    let now = current_time_ms();
    let job_id = format!("01J{now:022x}");
    let job = CatalogJob {
        job_id: job_id.clone(),
        kind: "verify".into(),
        status: JobStatus::Pending,
        progress_pct: Some(0),
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
        error: None,
    };
    if let Err(error) = state.catalog.lock().unwrap().insert_job(&job) {
        return internal_error(&error.to_string());
    }
    let archive = state.archive.clone();
    let catalog = state.catalog.clone();
    tokio::spawn(async move {
        let update_now = current_time_ms();
        match archive.read().unwrap().verify(true) {
            Ok(report) => {
                let catalog = catalog.lock().unwrap();
                let _ = catalog.update_job_status(
                    &job_id,
                    JobStatus::Completed,
                    Some(100),
                    None,
                    update_now,
                );
                tracing::info!(
                    "verify job {job_id} completed: {} objects verified",
                    report.objects
                );
            }
            Err(error) => {
                let catalog = catalog.lock().unwrap();
                let _ = catalog.update_job_status(
                    &job_id,
                    JobStatus::Failed,
                    Some(0),
                    Some(&error.to_string()),
                    update_now,
                );
            }
        }
    });
    (StatusCode::ACCEPTED, Json(ApiJob::from(job))).into_response()
}

pub(crate) async fn trigger_export(
    State(state): State<AppState>,
    Json(body): Json<ExportRequestBody>,
) -> Response {
    let now = current_time_ms();
    let job_id = format!("01J{now:022x}");
    let job = CatalogJob {
        job_id: job_id.clone(),
        kind: "export".into(),
        status: JobStatus::Pending,
        progress_pct: Some(0),
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
        error: None,
    };
    if let Err(error) = state.catalog.lock().unwrap().insert_job(&job) {
        return internal_error(&error.to_string());
    }
    let archive = state.archive.clone();
    let catalog = state.catalog.clone();
    tokio::spawn(async move {
        let destination = std::path::PathBuf::from(&body.destination);
        let update_now = current_time_ms();
        match archive
            .read()
            .unwrap()
            .export(&destination, body.object_id.as_deref())
        {
            Ok(result) => {
                let catalog = catalog.lock().unwrap();
                let _ = catalog.update_job_status(
                    &job_id,
                    JobStatus::Completed,
                    Some(100),
                    None,
                    update_now,
                );
                tracing::info!(
                    "export job {job_id} completed: {} objects exported",
                    result.objects
                );
            }
            Err(error) => {
                let catalog = catalog.lock().unwrap();
                let _ = catalog.update_job_status(
                    &job_id,
                    JobStatus::Failed,
                    Some(0),
                    Some(&error.to_string()),
                    update_now,
                );
            }
        }
    });
    (StatusCode::ACCEPTED, Json(ApiJob::from(job))).into_response()
}

pub(crate) async fn list_jobs(
    State(state): State<AppState>,
    Query(query): Query<ListJobsQuery>,
) -> Response {
    let catalog = state.catalog.lock().unwrap();
    match catalog.list_jobs(query.status) {
        Ok(jobs) => {
            let items: Vec<ApiJob> = jobs.into_iter().map(ApiJob::from).collect();
            (StatusCode::OK, Json(serde_json::json!({ "items": items }))).into_response()
        }
        Err(error) => internal_error(&error.to_string()),
    }
}

pub(crate) async fn get_job(State(state): State<AppState>, Path(id): Path<String>) -> Response {
    let catalog = state.catalog.lock().unwrap();
    match catalog.list_jobs(None) {
        Ok(jobs) => match jobs.into_iter().find(|job| job.job_id == id) {
            Some(job) => (StatusCode::OK, Json(ApiJob::from(job))).into_response(),
            None => not_found(&format!("job '{id}' not found")),
        },
        Err(error) => internal_error(&error.to_string()),
    }
}
