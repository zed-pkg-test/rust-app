//! Narrow internal receiver for signed BeamScale host-containment incidents.

#[path = "../host_incident_replay.rs"]
mod host_incident_replay;
#[path = "../incident.rs"]
mod incident;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    env,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::Mutex};

const DEFAULT_MAX_SKEW_SECONDS: u64 = 300;
const MAX_INCIDENT_BYTES: usize = 64 * 1024;

#[derive(Clone)]
struct AppState {
    artifact_root: PathBuf,
    host_keys: Arc<BTreeMap<String, Vec<u8>>>,
    max_skew_seconds: u64,
    ledger_lock: Arc<Mutex<()>>,
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
            eprintln!("invalid host incident ingest configuration: {error}");
            std::process::exit(2);
        }
    };
    if let Err(error) = tokio::fs::create_dir_all(&state.artifact_root).await {
        eprintln!("create artifact root failed: {error}");
        std::process::exit(2);
    }

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/admin/security/host-incidents", post(ingest))
        .layer(DefaultBodyLimit::max(MAX_INCIDENT_BYTES))
        .with_state(state);

    let bind = env::var("BMSCL_HOST_INCIDENT_BIND").unwrap_or_else(|_| "127.0.0.1:8282".into());
    let listener = TcpListener::bind(&bind)
        .await
        .expect("bind host incident ingest");
    tracing::info!(%bind, "bmscl host incident ingest listening");
    axum::serve(listener, app)
        .await
        .expect("serve host incident ingest");
}

async fn ingest(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<(StatusCode, Json<incident::IncidentReceipt>), ApiError> {
    let now =
        unix_seconds().map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error))?;
    let auth = incident::authenticate(
        &headers,
        &body,
        &state.host_keys,
        now,
        state.max_skew_seconds,
    )
    .map_err(|error| ApiError::new(StatusCode::UNAUTHORIZED, error.to_string()))?;
    let parsed = incident::parse_contained(&body)
        .map_err(|error| ApiError::new(StatusCode::UNPROCESSABLE_ENTITY, error.to_string()))?;

    // Serialize replay reservation + ledger commit inside this receiver process.
    // O_EXCL remains authoritative across processes/restarts, while this lock
    // prevents same-process quota/prune races between concurrent HTTP requests.
    let _ledger_guard = state.ledger_lock.lock().await;
    let root = state.artifact_root.clone();
    let body = body.to_vec();
    let max_skew_seconds = state.max_skew_seconds;
    let receipt = tokio::task::spawn_blocking(move || {
        // Reserve the authenticated host nonce before committing incident effects.
        // An exact retry is idempotent; conflicting reuse fails closed. If commit
        // fails after reservation, the exact request can retry and resume safely.
        host_incident_replay::reserve(&root, &auth, &parsed, now, max_skew_seconds)?;
        incident::commit(&root, &parsed, &auth, &body, now)
    })
    .await
    .map_err(|error| {
        ApiError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("incident ledger task failed: {error}"),
        )
    })?
    .map_err(|error| {
        let message = error.to_string();
        let status = if message.contains("already exists with a different")
            || message.contains("nonce already exists with a conflicting")
        {
            StatusCode::CONFLICT
        } else if message.contains("replay index is at capacity") {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        ApiError::new(status, message)
    })?;

    let status = if receipt.duplicate {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((status, Json(receipt)))
}

fn state_from_env() -> Result<AppState, String> {
    let artifact_root = env::var_os("BMSCL_ARTIFACT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./var/deployments"));
    let raw = env::var("BMSCL_HOST_INCIDENT_HMAC_KEYS_JSON")
        .map_err(|_| "BMSCL_HOST_INCIDENT_HMAC_KEYS_JSON is required".to_owned())?;
    let encoded: BTreeMap<String, String> = serde_json::from_str(&raw).map_err(|error| {
        format!("BMSCL_HOST_INCIDENT_HMAC_KEYS_JSON must be host-id -> hex key: {error}")
    })?;
    if encoded.is_empty() {
        return Err("at least one host incident key is required".to_owned());
    }
    let mut host_keys = BTreeMap::new();
    for (host_id, key_hex) in encoded {
        if host_id.is_empty()
            || host_id.len() > 256
            || !host_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
            })
        {
            return Err(format!("invalid host id {host_id:?}"));
        }
        let key = hex::decode(&key_hex)
            .map_err(|_| format!("host incident key for {host_id:?} must be hexadecimal"))?;
        if key.len() != 32 {
            return Err(format!(
                "host incident key for {host_id:?} must decode to exactly 32 bytes"
            ));
        }
        host_keys.insert(host_id, key);
    }
    let max_skew_seconds = env::var("BMSCL_HOST_INCIDENT_MAX_SKEW_SECONDS")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|_| "BMSCL_HOST_INCIDENT_MAX_SKEW_SECONDS must be an integer".to_owned())?
        .unwrap_or(DEFAULT_MAX_SKEW_SECONDS);
    if max_skew_seconds == 0 || max_skew_seconds > 3600 {
        return Err("BMSCL_HOST_INCIDENT_MAX_SKEW_SECONDS must be 1..=3600".to_owned());
    }
    Ok(AppState {
        artifact_root,
        host_keys: Arc::new(host_keys),
        max_skew_seconds,
        ledger_lock: Arc::new(Mutex::new(())),
    })
}

fn unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock before Unix epoch: {error}"))
}
