use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use devdrop_core::SLICE_LABEL;
use serde::{Deserialize, Serialize};

use crate::{
    config::DEFAULT_SAFETY_HEADER,
    error::{DaemonError, DaemonResult},
    queue::ScanReason,
    scanner::ScanReport,
    state::{DaemonState, MachineSummary, RegisteredProject},
};

/// Redaction notice used across daemon API responses.
pub const REDACTION_NOTICE: &str =
    "Daemon API responses are metadata-only; secret values and file contents are absent.";

/// Stable safety envelope included in every daemon API response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SafetyEnvelope {
    /// Whether files were mutated by this response/action.
    pub mutated_files: bool,
    /// Whether this action is a dry-run/scheduling-only action.
    pub dry_run: bool,
    /// Whether this route is read-only.
    pub read_only: bool,
    /// Redaction notice for API consumers.
    pub redaction_notice: String,
}

impl SafetyEnvelope {
    /// Read-only envelope.
    pub fn read_only() -> Self {
        Self {
            mutated_files: false,
            dry_run: false,
            read_only: true,
            redaction_notice: REDACTION_NOTICE.to_string(),
        }
    }

    /// Dry-run/scheduling-only envelope.
    pub fn dry_run() -> Self {
        Self {
            mutated_files: false,
            dry_run: true,
            read_only: false,
            redaction_notice: REDACTION_NOTICE.to_string(),
        }
    }
}

/// API response wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    /// Safety envelope.
    pub safety: SafetyEnvelope,
    /// Response payload.
    pub data: T,
}

impl<T> ApiResponse<T> {
    fn read_only(data: T) -> Self {
        Self {
            safety: SafetyEnvelope::read_only(),
            data,
        }
    }

    fn dry_run(data: T) -> Self {
        Self {
            safety: SafetyEnvelope::dry_run(),
            data,
        }
    }
}

/// Safe API error response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiErrorResponse {
    /// Safety envelope.
    pub safety: SafetyEnvelope,
    /// Error payload.
    pub error: ApiError,
}

/// Safe API error payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    /// Stable error code.
    pub code: String,
    /// Redacted message.
    pub message: String,
}

/// Health payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    /// Slice label.
    pub slice: String,
    /// Whether watcher events are treated as truth.
    pub watcher_events_are_truth: bool,
    /// Whether reconciliation scans are the source of truth.
    pub reconciliation_scan_is_truth: bool,
    /// Local API bind posture.
    pub bind_policy: String,
    /// Placeholder safety header name.
    pub safety_header: String,
}

/// Project list payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectsResponse {
    /// Registered projects.
    pub projects: Vec<ProjectSummary>,
}

/// Project summary without raw file contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSummary {
    /// Project ID.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Number of latest scan errors.
    pub latest_scan_errors: usize,
    /// Whether a metadata scan has run.
    pub metadata_scan_observed: bool,
}

impl From<RegisteredProject> for ProjectSummary {
    fn from(project: RegisteredProject) -> Self {
        let latest_scan_errors = project
            .latest_scan
            .as_ref()
            .map(|scan| scan.errors.len())
            .unwrap_or_default();
        Self {
            id: project.id,
            name: project.name,
            latest_scan_errors,
            metadata_scan_observed: project.latest_scan.is_some(),
        }
    }
}

/// Project status payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectStatusResponse {
    /// Project summary.
    pub project: ProjectSummary,
    /// Foundation readiness report.
    pub readiness: devdrop_core::ReadinessReport,
    /// Latest metadata-only scan report.
    pub latest_scan: Option<ScanReport>,
}

/// Scan enqueue payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanEnqueueResponse {
    /// Project ID.
    pub project_id: String,
    /// Whether a scan request was queued.
    pub queued: bool,
    /// Whether the request was de-duplicated.
    pub deduped: bool,
    /// Current queue length.
    pub queue_len: usize,
    /// Non-mutating summary.
    pub summary: String,
}

/// Sync plan payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPlanResponse {
    /// Dry-run sync preview.
    pub preview: devdrop_core::SyncPreview,
}

/// Conflict list payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictsResponse {
    /// Conflicts are empty in this daemon slice unless future in-memory state adds them.
    pub conflicts: Vec<devdrop_core::Conflict>,
    /// Reminder that conflicts must never be hidden.
    pub conflict_visibility: String,
}

/// Hydration payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HydrationResponse {
    /// Hydration operations are read-only summaries in this daemon slice.
    pub hydration_ops: Vec<devdrop_core::HydrationOperation>,
    /// Hydration counts exposed as read-only metadata.
    pub counts: devdrop_core::HydrationCounts,
    /// Hydration safety posture.
    pub summary: String,
}

/// Machine list payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachinesResponse {
    /// Known machines.
    pub machines: Vec<MachineSummary>,
}

/// Builds the local API router.
pub fn build_router(state: DaemonState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/projects", get(projects))
        .route("/projects/:id/status", get(project_status))
        .route("/projects/:id/scan", post(enqueue_scan))
        .route("/projects/:id/sync-plan", get(sync_plan))
        .route("/projects/:id/conflicts", get(conflicts))
        .route("/projects/:id/hydration", get(hydration))
        .route("/machines", get(machines))
        .with_state(state)
}

async fn health(State(state): State<DaemonState>) -> Response {
    Json(ApiResponse::read_only(HealthResponse {
        slice: SLICE_LABEL.to_string(),
        watcher_events_are_truth: false,
        reconciliation_scan_is_truth: true,
        bind_policy: "loopback-only; localhost is not the long-term security boundary".to_string(),
        safety_header: state.config().safety_header_name.clone(),
    }))
    .into_response()
}

async fn projects(State(state): State<DaemonState>) -> Response {
    let projects = state
        .projects()
        .into_iter()
        .map(ProjectSummary::from)
        .collect();
    Json(ApiResponse::read_only(ProjectsResponse { projects })).into_response()
}

async fn project_status(State(state): State<DaemonState>, Path(id): Path<String>) -> Response {
    match project_status_payload(&state, &id) {
        Ok(payload) => Json(ApiResponse::read_only(payload)).into_response(),
        Err(error) => api_error(error, SafetyEnvelope::read_only()).into_response(),
    }
}

async fn enqueue_scan(
    State(state): State<DaemonState>,
    Path(id): Path<String>,
    headers: HeaderMap,
    _body: Bytes,
) -> Response {
    if let Err(error) = require_json_content_type(&headers) {
        return api_error(error, SafetyEnvelope::dry_run()).into_response();
    }

    match state.enqueue_scan(&id, ScanReason::Manual) {
        Ok(decision) => Json(ApiResponse::dry_run(ScanEnqueueResponse {
            project_id: id,
            queued: decision.queued,
            deduped: decision.deduped,
            queue_len: decision.queue_len,
            summary: decision.summary,
        }))
        .into_response(),
        Err(error) => api_error(error, SafetyEnvelope::dry_run()).into_response(),
    }
}

async fn sync_plan(State(state): State<DaemonState>, Path(id): Path<String>) -> Response {
    match state.sync_preview(&id) {
        Ok(preview) => Json(ApiResponse::read_only(SyncPlanResponse { preview })).into_response(),
        Err(error) => api_error(error, SafetyEnvelope::read_only()).into_response(),
    }
}

async fn conflicts(State(state): State<DaemonState>, Path(id): Path<String>) -> Response {
    match state.project(&id) {
        Ok(_) => Json(ApiResponse::read_only(ConflictsResponse {
            conflicts: Vec::new(),
            conflict_visibility:
                "No conflicts are hidden; this daemon slice exposes read-only summaries."
                    .to_string(),
        }))
        .into_response(),
        Err(error) => api_error(error, SafetyEnvelope::read_only()).into_response(),
    }
}

async fn hydration(State(state): State<DaemonState>, Path(id): Path<String>) -> Response {
    match state.project(&id) {
        Ok(_) => Json(ApiResponse::read_only(HydrationResponse {
            hydration_ops: Vec::new(),
            counts: devdrop_core::HydrationCounts::default(),
            summary:
                "Hydration is read-only in the daemon MVP; no daemon route can apply hydration."
                    .to_string(),
        }))
        .into_response(),
        Err(error) => api_error(error, SafetyEnvelope::read_only()).into_response(),
    }
}

async fn machines(State(state): State<DaemonState>) -> Response {
    Json(ApiResponse::read_only(MachinesResponse {
        machines: state.machines(),
    }))
    .into_response()
}

fn project_status_payload(state: &DaemonState, id: &str) -> DaemonResult<ProjectStatusResponse> {
    let project = state.project(id)?;
    let readiness = state.readiness_status(id)?;
    let latest_scan = project.latest_scan.clone();
    Ok(ProjectStatusResponse {
        project: ProjectSummary::from(project),
        readiness,
        latest_scan,
    })
}

fn require_json_content_type(headers: &HeaderMap) -> Result<(), DaemonError> {
    let Some(value) = headers.get(CONTENT_TYPE) else {
        return Err(DaemonError::UnsupportedContentType);
    };
    let Ok(value) = value.to_str() else {
        return Err(DaemonError::UnsupportedContentType);
    };
    if value
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|mime| mime.eq_ignore_ascii_case("application/json"))
    {
        Ok(())
    } else {
        Err(DaemonError::UnsupportedContentType)
    }
}

fn api_error(error: DaemonError, safety: SafetyEnvelope) -> (StatusCode, Json<ApiErrorResponse>) {
    let (status, code, message) = match error {
        DaemonError::UnknownProject { .. } => (
            StatusCode::NOT_FOUND,
            "unknown_project",
            "Project ID is not registered with this daemon.",
        ),
        DaemonError::UnsupportedContentType => (
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported_content_type",
            "POST endpoints require Content-Type: application/json.",
        ),
        DaemonError::PathOutsideRegisteredRoot => (
            StatusCode::BAD_REQUEST,
            "outside_registered_root",
            "Path is outside the registered project root.",
        ),
        DaemonError::NonLoopbackBind { .. } => (
            StatusCode::BAD_REQUEST,
            "non_loopback_bind",
            "Daemon API is loopback-only in this slice.",
        ),
        DaemonError::Io(_) | DaemonError::Hyper(_) | DaemonError::InvalidConfig(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "daemon_error",
            "Daemon failed while producing a redacted response.",
        ),
    };

    (
        status,
        Json(ApiErrorResponse {
            safety,
            error: ApiError {
                code: code.to_string(),
                message: message.to_string(),
            },
        }),
    )
}

/// Header documented as future auth placeholder.
pub fn safety_header_name() -> &'static str {
    DEFAULT_SAFETY_HEADER
}

#[cfg(test)]
mod tests {
    use axum::{
        body::{to_bytes, Body},
        http::{header::CONTENT_TYPE, Method, Request},
    };
    use serde_json::Value;
    use tempfile::tempdir;
    use tower::ServiceExt;

    use super::*;
    use crate::{config::DaemonConfig, state::RegisteredProject};

    fn test_state() -> DaemonState {
        let dir = tempdir().expect("tempdir");
        let root = dir.keep();
        std::fs::write(root.join("README.md"), "fixture").expect("write fixture");
        let state = DaemonState::new(DaemonConfig::default());
        state.register_project(RegisteredProject::new("project:ready", "ready", root));
        state
    }

    async fn request_json(router: Router, request: Request<Body>) -> (StatusCode, Value) {
        let response = router.oneshot(request).await.expect("response");
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        let value = serde_json::from_slice(&bytes).expect("json response");
        (status, value)
    }

    fn assert_safety(value: &Value) {
        let safety = value.get("safety").expect("safety envelope");
        assert_eq!(safety.get("mutated_files"), Some(&Value::Bool(false)));
        assert!(
            safety.get("dry_run") == Some(&Value::Bool(true))
                || safety.get("read_only") == Some(&Value::Bool(true))
        );
        assert!(safety
            .get("redaction_notice")
            .and_then(Value::as_str)
            .expect("redaction notice")
            .contains("secret values"));
    }

    #[tokio::test]
    async fn api_responses_include_safety_envelopes() {
        let state = test_state();
        let router = build_router(state.clone());

        for uri in [
            "/projects",
            "/projects/project:ready/status",
            "/projects/project:ready/sync-plan",
            "/projects/project:ready/conflicts",
            "/projects/project:ready/hydration",
            "/machines",
        ] {
            let (status, value) = request_json(
                router.clone(),
                Request::builder()
                    .method(Method::GET)
                    .uri(uri)
                    .body(Body::empty())
                    .expect("request"),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{uri}");
            assert_safety(&value);
        }

        let (status, value) = request_json(
            router,
            Request::builder()
                .method(Method::POST)
                .uri("/projects/project:ready/scan")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::empty())
                .expect("request"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_safety(&value);
        assert_eq!(value["safety"]["dry_run"], Value::Bool(true));
    }

    #[tokio::test]
    async fn post_scan_rejects_missing_or_wrong_content_type() {
        let router = build_router(test_state());
        for request in [
            Request::builder()
                .method(Method::POST)
                .uri("/projects/project:ready/scan")
                .body(Body::empty())
                .expect("request"),
            Request::builder()
                .method(Method::POST)
                .uri("/projects/project:ready/scan")
                .header(CONTENT_TYPE, "text/plain")
                .body(Body::empty())
                .expect("request"),
        ] {
            let (status, value) = request_json(router.clone(), request).await;
            assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
            assert_safety(&value);
            assert_eq!(
                value["error"]["code"],
                Value::String("unsupported_content_type".to_string())
            );
        }
    }

    #[tokio::test]
    async fn unknown_project_returns_safe_error_and_does_not_enqueue() {
        let state = test_state();
        let before = state.queue().len();
        let router = build_router(state.clone());

        let (status, value) = request_json(
            router,
            Request::builder()
                .method(Method::POST)
                .uri("/projects/project:missing/scan")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_safety(&value);
        assert_eq!(state.queue().len(), before);
    }

    #[tokio::test]
    async fn traversal_like_project_id_is_not_a_path() {
        let state = test_state();
        let before = state.queue().len();
        let router = build_router(state.clone());
        let (status, value) = request_json(
            router,
            Request::builder()
                .method(Method::POST)
                .uri("/projects/..%2Foutside/scan")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_safety(&value);
        assert_eq!(state.queue().len(), before);
    }

    #[tokio::test]
    async fn api_responses_do_not_use_forbidden_keys_or_secret_values() {
        let router = build_router(test_state());
        let (_status, value) = request_json(
            router,
            Request::builder()
                .method(Method::GET)
                .uri("/projects")
                .body(Body::empty())
                .expect("request"),
        )
        .await;

        fn walk(value: &Value) {
            match value {
                Value::Object(map) => {
                    for (key, value) in map {
                        assert!(
                            !matches!(
                                key.as_str(),
                                "secret" | "env_value" | "raw_value" | "contents" | "file_contents"
                            ),
                            "forbidden key {key}"
                        );
                        walk(value);
                    }
                }
                Value::Array(values) => values.iter().for_each(walk),
                Value::String(value) => assert!(!value.contains("DD_DO_NOT_LEAK_VALUE")),
                _ => {}
            }
        }

        walk(&value);
    }

    #[tokio::test]
    async fn daemon_exposes_no_hydration_apply_route() {
        let router = build_router(test_state());
        let response = router
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/projects/project:ready/hydration/apply")
                    .header(CONTENT_TYPE, "application/json")
                    .body(Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
