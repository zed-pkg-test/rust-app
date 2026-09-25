//! Private read-only API for BeamScale durable security-block state.

#[path = "../security_state.rs"]
mod security_state;

use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::{env, path::PathBuf};
use tokio::net::TcpListener;

const MAX_REQUEST_BYTES: usize = 16 * 1024;

#[derive(Clone)]
struct AppState {
    artifact_root: PathBuf,
    service_token_sha256: [u8; 32],
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({"error": self.message}))).into_response()
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let state = match state_from_env() {
        Ok(state) => state,
        Err(error) => {
            eprintln!("invalid security-state configuration: {error}");
            std::process::exit(2);
        }
    };

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/admin/security/state", post(lookup))
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state);

    let bind = env::var("BMSCL_SECURITY_STATE_BIND").unwrap_or_else(|_| "127.0.0.1:8383".into());
    let listener = TcpListener::bind(&bind)
        .await
        .expect("bind security state API");
    tracing::info!(%bind, "bmscl security state API listening");
    axum::serve(listener, app)
        .await
        .expect("serve security state API");
}

async fn lookup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<security_state::SecurityStateRequest>,
) -> Result<Json<security_state::SecurityStateResponse>, ApiError> {
    security_state::authenticate_service(&headers, &state.service_token_sha256)
        .map_err(|_| ApiError::new(StatusCode::UNAUTHORIZED, "service authorization rejected"))?;
    let root = state.artifact_root.clone();
    tokio::task::spawn_blocking(move || security_state::lookup(&root, &request))
        .await
        .map_err(|error| {
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("security-state task failed: {error}"),
            )
        })?
        .map(Json)
        .map_err(|error| {
            tracing::error!(error = %error, "security block ledger lookup failed closed");
            ApiError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "security block ledger is unavailable or invalid",
            )
        })
}

fn state_from_env() -> Result<AppState, String> {
    let artifact_root = env::var_os("BMSCL_ARTIFACT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./var/deployments"));
    let digest_hex = env::var("BMSCL_SECURITY_STATE_SERVICE_TOKEN_SHA256")
        .map_err(|_| "BMSCL_SECURITY_STATE_SERVICE_TOKEN_SHA256 is required".to_owned())?;
    let digest = hex::decode(&digest_hex)
        .map_err(|_| "BMSCL_SECURITY_STATE_SERVICE_TOKEN_SHA256 must be hex".to_owned())?;
    let service_token_sha256: [u8; 32] = digest.try_into().map_err(|_| {
        "BMSCL_SECURITY_STATE_SERVICE_TOKEN_SHA256 must encode exactly 32 bytes".to_owned()
    })?;
    Ok(AppState {
        artifact_root,
        service_token_sha256,
    })
}
