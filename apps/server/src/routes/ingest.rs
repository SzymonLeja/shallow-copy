//! Filesystem and browser ingestion HTTP handlers.

use crate::*;
pub(crate) async fn ingest_filesystem_file(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Json(body): Json<FilesystemIngestRequestBody>,
) -> Response {
    let Some(source_root) = state.filesystem_ingest_root.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                code: "ingest.source_unavailable".into(),
                message: "filesystem ingest source is not configured".into(),
                request_id: format!("req_{:012x}", current_time_ms()),
            }),
        )
            .into_response();
    };

    if body.path.is_empty() || body.path.len() > MAX_FILESYSTEM_INGEST_PATH_BYTES {
        return bad_request("path must be nonempty and at most 4096 bytes");
    }
    let relative_path = FsPath::new(&body.path);
    if relative_path.is_absolute()
        || relative_path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return bad_request("path must stay within the configured source root");
    }

    let canonical_root = match source_root.canonicalize() {
        Ok(root) if root.is_dir() => root,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    code: "ingest.source_unavailable".into(),
                    message: "configured filesystem ingest root is unavailable".into(),
                    request_id: format!("req_{:012x}", current_time_ms()),
                }),
            )
                .into_response();
        }
    };
    let source_path = match canonical_root.join(relative_path).canonicalize() {
        Ok(path) if path.starts_with(&canonical_root) => path,
        _ => return bad_request("path must identify a file under the configured source root"),
    };
    let metadata = match std::fs::metadata(&source_path) {
        Ok(metadata) if metadata.is_file() => metadata,
        _ => {
            return bad_request(
                "path must identify a regular file under the configured source root",
            );
        }
    };
    if metadata.len() > MAX_FILESYSTEM_INGEST_FILE_BYTES {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(ErrorResponse {
                code: "ingest.file_too_large".into(),
                message: "filesystem ingest files are limited to 16 MiB".into(),
                request_id: format!("req_{:012x}", current_time_ms()),
            }),
        )
            .into_response();
    }

    let external_id = relative_path.to_string_lossy().replace('\\', "/");
    let modified_ms = metadata
        .modified()
        .ok()
        .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64);
    let item = IngestItem {
        external_id,
        revision: format!("{}:{}", metadata.len(), modified_ms.unwrap_or(0)),
        media_type: "application/octet-stream".into(),
        event_time_unix_ms: modified_ms,
        content_ref: source_path.to_string_lossy().into_owned(),
        suggested_domain: Some("private".into()),
    };

    let mut catalog = state.catalog.lock().unwrap();
    let archive = state.archive.read().unwrap();
    let mut gateway = IngestGateway::new(&archive, &mut catalog);
    match gateway.ingest_file("local-filesystem", &item, &source_path) {
        Ok(outcome) => {
            let now = current_time_ms();
            let event = AuditEvent {
                id: format!(
                    "audit_{now:016x}_{:08x}",
                    NEXT_AUDIT_EVENT_ID.fetch_add(1, Ordering::Relaxed)
                ),
                event_type: "ingest".into(),
                actor: request_device_id(&headers).to_string(),
                object_id: Some(outcome.object_id.clone()),
                details_json: Some(format!(
                    r#"{{"externalId":"{}","created":{}}}"#,
                    item.external_id, outcome.created
                )),
                created_unix_ms: now,
            };
            if let Err(error) = catalog.record_audit_event(&event) {
                return internal_error(&error.to_string());
            }
            (
                StatusCode::OK,
                Json(FilesystemIngestResponse {
                    object_id: outcome.object_id,
                    ingest_fingerprint: outcome.ingest_fingerprint,
                    created: outcome.created,
                }),
            )
                .into_response()
        }
        Err(error) => internal_error(&error.to_string()),
    }
}

pub(crate) async fn ingest_browser_history(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    bytes: axum::body::Bytes,
) -> Response {
    let Some(configured_path) = state.browser_history_path.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ErrorResponse {
                code: "ingest.source_unavailable".into(),
                message: "browser history source is not configured".into(),
                request_id: format!("req_{:012x}", current_time_ms()),
            }),
        )
            .into_response();
    };

    let _metadata = match std::fs::symlink_metadata(configured_path) {
        Ok(meta) if meta.file_type().is_file() => meta,
        Ok(_) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    code: "ingest.source_unavailable".into(),
                    message: "configured browser history path is not a regular file".into(),
                    request_id: format!("req_{:012x}", current_time_ms()),
                }),
            )
                .into_response();
        }
        Err(error) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(ErrorResponse {
                    code: "ingest.source_unavailable".into(),
                    message: format!("configured browser history file is unavailable: {error}"),
                    request_id: format!("req_{:012x}", current_time_ms()),
                }),
            )
                .into_response();
        }
    };

    // Read and hash the source SQLite database before any operation
    let source_bytes_before = match std::fs::read(configured_path) {
        Ok(bytes) => bytes,
        Err(e) => return internal_error(&format!("failed to read source browser history: {e}")),
    };
    let hash_before = hex_digest(&Sha256::digest(&source_bytes_before));

    let body: Option<BrowserHistoryIngestRequestBody> = if bytes.is_empty() {
        None
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(b) => Some(b),
            Err(e) => return bad_request(&format!("invalid request body: {e}")),
        }
    };

    let source_instance = body
        .and_then(|b| b.source_instance)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "browser-history.chromium".to_string());

    let staging_temp = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            return internal_error(&format!(
                "failed to create temporary staging directory: {e}"
            ));
        }
    };

    let connector = ChromiumHistoryConnector::new(ChromiumHistoryConfig {
        source_instance: source_instance.clone(),
        history_db_path: configured_path.clone(),
        staging_dir: Some(staging_temp.path().to_path_buf()),
    });

    let envelope = match connector.scan() {
        Ok(env) => env,
        Err(e) => return internal_error(&format!("browser history scan failed: {e}")),
    };

    // Prove source database was unmodified by the scan
    let source_bytes_after = match std::fs::read(configured_path) {
        Ok(bytes) => bytes,
        Err(e) => return internal_error(&format!("failed to re-read source browser history: {e}")),
    };
    let hash_after = hex_digest(&Sha256::digest(&source_bytes_after));
    if hash_before != hash_after {
        return internal_error("source browser history database was modified during scan");
    }

    let total_visits = envelope.items.len() as i64;
    let mut imported_count = 0i64;
    let mut skipped_count = 0i64;
    let mut object_ids = Vec::with_capacity(envelope.items.len());

    let now = current_time_ms();
    {
        let mut catalog = state.catalog.lock().unwrap();
        let archive = state.archive.read().unwrap();
        let mut gateway = IngestGateway::new(&archive, &mut catalog);

        for item in &envelope.items {
            match gateway.ingest_file(&source_instance, item, &item.content_ref) {
                Ok(outcome) => {
                    if outcome.created {
                        imported_count += 1;
                    } else {
                        skipped_count += 1;
                    }
                    object_ids.push(outcome.object_id);
                }
                Err(e) => {
                    return internal_error(&format!(
                        "failed to ingest visit {}: {e}",
                        item.external_id
                    ));
                }
            }
        }

        let event = AuditEvent {
            id: format!(
                "audit_{now:016x}_{:08x}",
                NEXT_AUDIT_EVENT_ID.fetch_add(1, Ordering::Relaxed)
            ),
            event_type: "ingest_browser_history".into(),
            actor: request_device_id(&headers).to_string(),
            object_id: object_ids.first().cloned(),
            details_json: Some(format!(
                r#"{{"sourceInstance":"{}","totalVisits":{},"imported":{},"skipped":{}}}"#,
                source_instance, total_visits, imported_count, skipped_count
            )),
            created_unix_ms: now,
        };
        if let Err(error) = catalog.record_audit_event(&event) {
            return internal_error(&error.to_string());
        }
    }

    (
        StatusCode::OK,
        Json(BrowserHistoryIngestResponse {
            source_instance,
            total_visits,
            imported_count,
            skipped_count,
            object_ids,
        }),
    )
        .into_response()
}
