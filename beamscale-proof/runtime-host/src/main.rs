mod artifact_store;
mod runtime_auth;

use artifact_store::{AdmittedArtifact, ArtifactStore};
use runtime_auth::{ExpectedRuntimeRequest, RuntimeContract, SignedRequest};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use bmscl_runtime_host::{
    EnsureShardRequest, EpochRequest, ExecutionBackend, ExecutionClass, HostConfig, HostError,
    LifecycleState, RuntimeHost, ShardStatus, TouchRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::hash_map::DefaultHasher,
    collections::{BTreeSet, HashMap, HashSet},
    env,
    hash::{Hash, Hasher},
    io,
    path::Path as FsPath,
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
    sync::{Mutex, RwLock},
    time::{sleep, timeout, Duration},
};

const MAX_CAPABILITY_REFS: usize = 64;
const MAX_CAPABILITY_NAME_BYTES: usize = 128;
const MAX_CAPABILITY_TOKEN_REF_BYTES: usize = 256;
const MAX_ACTIVATION_TIMEOUT_MS: u64 = 60_000;
const SHARD_GATE_STRIPES: usize = 256;

#[derive(Clone)]
struct AppState {
    host: Arc<RuntimeHost>,
    artifact_store: Arc<ArtifactStore>,
    guest_vsock_port: u32,
    guest_max_frame_bytes: usize,
    guest_max_artifact_chunk_bytes: usize,
    lifecycle_barrier: Arc<RwLock<()>>,
    shard_gates: Arc<Vec<Mutex<()>>>,
    observed_activation: Arc<RwLock<HashMap<ShardEpochKey, ObservedActivation>>>,
    runtime_control_secret: Arc<Vec<u8>>,
    consumed_nonces: Arc<Mutex<HashMap<String, u64>>>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ShardEpochKey {
    execution_class: ExecutionClass,
    tenant_id: String,
    shard_id: String,
    runtime_epoch: u64,
}

#[derive(Debug, Clone, Default)]
struct ObservedActivation {
    root_active_deployment_id: Option<String>,
    loaded_deployment_ids: BTreeSet<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
struct CapabilityRef {
    name: String,
    token_ref: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct InvokeRequest {
    tenant_id: String,
    shard_id: String,
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
    runtime_epoch: u64,
    invocation_id: String,
    deployment_id: String,
    request: Value,
    context: Value,
    #[serde(default)]
    capability_refs: Vec<CapabilityRef>,
    timeout_ms: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct ActivateRequest {
    tenant_id: String,
    shard_id: String,
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
    runtime_epoch: u64,
    deployment_id: String,
    #[serde(default = "default_activation_timeout_ms")]
    timeout_ms: u64,
}

trait RuntimeRequestIdentity {
    fn tenant_id(&self) -> &str;
    fn shard_id(&self) -> &str;
    fn execution_class(&self) -> ExecutionClass;
    fn execution_backend(&self) -> ExecutionBackend;
    fn runtime_epoch(&self) -> u64;
}

macro_rules! impl_runtime_request_identity {
    ($type:ty) => {
        impl RuntimeRequestIdentity for $type {
            fn tenant_id(&self) -> &str {
                &self.tenant_id
            }

            fn shard_id(&self) -> &str {
                &self.shard_id
            }

            fn execution_class(&self) -> ExecutionClass {
                self.execution_class
            }

            fn execution_backend(&self) -> ExecutionBackend {
                self.execution_backend
            }

            fn runtime_epoch(&self) -> u64 {
                self.runtime_epoch
            }
        }
    };
}

impl_runtime_request_identity!(EnsureShardRequest);
impl_runtime_request_identity!(EpochRequest);
impl_runtime_request_identity!(TouchRequest);
impl_runtime_request_identity!(ActivateRequest);
impl_runtime_request_identity!(InvokeRequest);

#[derive(Debug, Serialize)]
struct ActivationStatus {
    tenant_id: String,
    shard_id: String,
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
    runtime_epoch: u64,
    placement_deployment_id: String,
    observed: bool,
    root_active_deployment_id: Option<String>,
    loaded_deployment_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

type ApiError = (StatusCode, Json<ErrorBody>);

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let host = Arc::new(RuntimeHost::new(HostConfig::from_env()));
    let runtime_control_secret = Arc::new(
        runtime_auth::load_secret().expect("load BMSCL_RUNTIME_CONTROL_SECRET"),
    );
    let guest_vsock_port = env::var("BMSCL_GUEST_VSOCK_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000);
    let guest_max_frame_bytes = env::var("BMSCL_GUEST_MAX_FRAME_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(16 * 1024 * 1024);
    let guest_max_artifact_chunk_bytes = env::var("BMSCL_GUEST_MAX_ARTIFACT_CHUNK_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(1024 * 1024)
        .min(guest_max_frame_bytes);
    let artifact_root = env::var("BMSCL_RUNTIME_ARTIFACT_ROOT")
        .unwrap_or_else(|_| "/var/lib/beamscale/artifacts".into());
    let max_artifact_bytes = env::var("BMSCL_MAX_ARTIFACT_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(64 * 1024 * 1024);
    let state = AppState {
        host,
        artifact_store: Arc::new(ArtifactStore::new(artifact_root, max_artifact_bytes)),
        guest_vsock_port,
        guest_max_frame_bytes,
        guest_max_artifact_chunk_bytes,
        lifecycle_barrier: Arc::new(RwLock::new(())),
        shard_gates: Arc::new((0..SHARD_GATE_STRIPES).map(|_| Mutex::new(())).collect()),
        observed_activation: Arc::new(RwLock::new(HashMap::new())),
        runtime_control_secret,
        consumed_nonces: Arc::new(Mutex::new(HashMap::new())),
    };

    let sweeper_state = state.clone();
    tokio::spawn(async move {
        loop {
            sleep(Duration::from_secs(5)).await;
            let _barrier = sweeper_state.lifecycle_barrier.write().await;
            sweeper_state.host.sweep_once().await;
        }
    });

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/shards/ensure", post(ensure))
        .route("/v1/shards/start", post(start))
        .route("/v1/shards/activate", post(activate))
        .route("/v1/shards/touch", post(touch))
        .route("/v1/shards/invoke", post(invoke))
        .route("/v1/shards/warm-idle", post(warm_idle))
        .route("/v1/shards/hibernate", post(hibernate))
        .route("/v1/shards/terminate", post(terminate))
        .route(
            "/v1/shards/{execution_class}/{tenant_id}/{shard_id}/activation",
            get(get_activation),
        )
        .route(
            "/v1/shards/{execution_class}/{tenant_id}/{shard_id}/metering",
            get(get_metering),
        )
        .route(
            "/v1/shards/{execution_class}/{tenant_id}/{shard_id}",
            get(get_shard),
        )
        .with_state(state);

    let bind = env::var("BMSCL_RUNTIME_HOST_BIND").unwrap_or_else(|_| "127.0.0.1:9090".into());
    let listener = TcpListener::bind(&bind).await.expect("bind runtime host");
    tracing::info!(%bind, "BeamScale runtime host listening");
    axum::serve(listener, app)
        .await
        .expect("serve runtime host");
}

async fn ensure(
    State(state): State<AppState>,
    Json(signed): Json<SignedRequest<EnsureShardRequest>>,
) -> Result<impl IntoResponse, ApiError> {
    let SignedRequest { contract, request: req } = signed;
    authorize_runtime_request(&state, "ensure", &req, &contract).await?;
    validate_shard_identity(&req.tenant_id, &req.shard_id)?;
    let requested_digest = normalize_build_digest(&req.deployment_digest)
        .map_err(|message| api_error(StatusCode::BAD_REQUEST, message))?;
    let execution_class = req.execution_class;
    let tenant_id = req.tenant_id.clone();
    let shard_id = req.shard_id.clone();
    let runtime_epoch = req.runtime_epoch;

    let _barrier = state.lifecycle_barrier.read().await;
    let gate_index = shard_gate_index(execution_class, &tenant_id, &shard_id);
    let _gate = state.shard_gates[gate_index].lock().await;

    let existing = match state.host.get(execution_class, &tenant_id, &shard_id).await {
        Ok(status) => Some(status),
        Err(HostError::UnknownShard) => None,
        Err(err) => return Err(map_err(err)),
    };
    let mut clear_observed = existing.is_none();
    if let Some(current) = existing.as_ref() {
        let current_digest = normalize_build_digest(&current.deployment_digest).map_err(|_| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "runtime host contains a non-canonical deployment digest",
            )
        })?;
        let digest_changed = requested_digest != current_digest;
        if current.runtime_epoch == runtime_epoch
            && digest_changed
            && !matches!(
                current.state,
                LifecycleState::Cold | LifecycleState::Terminated
            )
        {
            return Err(api_error(
                StatusCode::CONFLICT,
                "live same-epoch deployment changes require /v1/shards/activate",
            ));
        }
        clear_observed = current.runtime_epoch != runtime_epoch || digest_changed;
    }

    let status = state.host.ensure(req).await.map_err(map_err)?;
    if clear_observed {
        clear_observed_for_shard(&state, execution_class, &tenant_id, &shard_id).await;
    }
    Ok(Json(status))
}

async fn start(
    State(state): State<AppState>,
    Json(signed): Json<SignedRequest<EpochRequest>>,
) -> Result<impl IntoResponse, ApiError> {
    let SignedRequest { contract, request: req } = signed;
    authorize_runtime_request(&state, "start", &req, &contract).await?;
    validate_shard_identity(&req.tenant_id, &req.shard_id)?;
    let _barrier = state.lifecycle_barrier.read().await;
    let gate_index = shard_gate_index(req.execution_class, &req.tenant_id, &req.shard_id);
    let _gate = state.shard_gates[gate_index].lock().await;
    state.host.start(req).await.map(Json).map_err(map_err)
}

async fn activate(
    State(state): State<AppState>,
    Json(signed): Json<SignedRequest<ActivateRequest>>,
) -> Result<impl IntoResponse, ApiError> {
    let SignedRequest { contract, request: req } = signed;
    authorize_runtime_request(&state, "activate", &req, &contract).await?;
    validate_shard_identity(&req.tenant_id, &req.shard_id)?;
    validate_firecracker_target(req.execution_class, req.execution_backend)?;
    if req.timeout_ms == 0 || req.timeout_ms > MAX_ACTIVATION_TIMEOUT_MS {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            format!("timeout_ms must be 1..={MAX_ACTIVATION_TIMEOUT_MS}"),
        ));
    }
    let deployment_id = normalize_build_digest(&req.deployment_id)
        .map_err(|message| api_error(StatusCode::BAD_REQUEST, message))?;

    let preliminary = state
        .host
        .get(req.execution_class, &req.tenant_id, &req.shard_id)
        .await
        .map_err(map_err)?;
    check_runtime_epoch(&preliminary, req.runtime_epoch)?;
    let admitted_artifact = if preliminary.backend != "mock" {
        Some(
            state
                .artifact_store
                .resolve_admitted_bundle(&deployment_id)
                .await
                .map_err(|err| {
                    api_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("admitted artifact preflight failed for {deployment_id}: {err}"),
                    )
                })?,
        )
    } else {
        None
    };

    let envelope = json!({
        "op": "activate_artifact",
        "deployment_id": &deployment_id,
        "execution_class": req.execution_class,
        "execution_backend": req.execution_backend,
        "tenant_id": &req.tenant_id,
        "runtime_epoch": req.runtime_epoch
    });
    let request_bytes = serde_json::to_vec(&envelope)
        .map_err(|err| api_error(StatusCode::BAD_REQUEST, err.to_string()))?;
    if request_bytes.len() > state.guest_max_frame_bytes {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "activation frame too large",
        ));
    }

    let _barrier = state.lifecycle_barrier.read().await;
    let gate_index = shard_gate_index(req.execution_class, &req.tenant_id, &req.shard_id);
    let _gate = state.shard_gates[gate_index].lock().await;
    let shard = state
        .host
        .get(req.execution_class, &req.tenant_id, &req.shard_id)
        .await
        .map_err(map_err)?;
    check_runtime_epoch(&shard, req.runtime_epoch)?;
    check_execution_target(&shard, req.execution_class, req.execution_backend)?;
    if !matches!(shard.state, LifecycleState::Hot | LifecycleState::WarmIdle) {
        return Err(api_error(
            StatusCode::CONFLICT,
            format!("shard is not activatable: {:?}", shard.state),
        ));
    }

    let response_bytes = if shard.backend == "mock" {
        serde_json::to_vec(&json!({
            "op": "activate_artifact_result",
            "ok": true,
            "deployment_id": &deployment_id,
            "active_deployment_id": &deployment_id
        }))
        .map_err(|err| api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    } else {
        let vsock_path = shard.vsock_path.as_deref().ok_or_else(|| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "runnable shard is missing vsock path",
            )
        })?;
        let artifact = admitted_artifact.as_ref().ok_or_else(|| {
            api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "non-mock activation is missing admitted artifact bytes",
            )
        })?;
        put_artifact_over_vsock(
            FsPath::new(vsock_path),
            state.guest_vsock_port,
            &shard,
            artifact,
            req.timeout_ms,
            state.guest_max_frame_bytes,
            state.guest_max_artifact_chunk_bytes,
        )
        .await
        .map_err(|message| api_error(StatusCode::SERVICE_UNAVAILABLE, message))?;
        invoke_over_vsock(
            FsPath::new(vsock_path),
            state.guest_vsock_port,
            &request_bytes,
            req.timeout_ms,
            state.guest_max_frame_bytes,
        )
        .await
        .map_err(|message| api_error(StatusCode::SERVICE_UNAVAILABLE, message))?
    };
    validate_activation_response(&response_bytes, &deployment_id)
        .map_err(|message| api_error(StatusCode::BAD_GATEWAY, message))?;

    let key = shard_epoch_key(
        req.execution_class,
        &req.tenant_id,
        &req.shard_id,
        req.runtime_epoch,
    );
    let mut observed = state.observed_activation.write().await;
    let activation = observed.entry(key).or_default();
    if let Ok(bootstrap) = normalize_build_digest(&shard.deployment_digest) {
        activation.loaded_deployment_ids.insert(bootstrap);
    }
    activation
        .loaded_deployment_ids
        .insert(deployment_id.clone());
    activation.root_active_deployment_id = Some(deployment_id);
    Ok(Json(activation_status(&shard, Some(activation))))
}

async fn touch(
    State(state): State<AppState>,
    Json(signed): Json<SignedRequest<TouchRequest>>,
) -> Result<impl IntoResponse, ApiError> {
    let SignedRequest { contract, request: req } = signed;
    authorize_runtime_request(&state, "touch", &req, &contract).await?;
    validate_shard_identity(&req.tenant_id, &req.shard_id)?;
    if !(-1..=1).contains(&req.active_delta) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "active_delta must be -1, 0, or 1",
        ));
    }
    let _barrier = state.lifecycle_barrier.read().await;
    let gate_index = shard_gate_index(req.execution_class, &req.tenant_id, &req.shard_id);
    let _gate = state.shard_gates[gate_index].lock().await;
    state.host.touch(req).await.map(Json).map_err(map_err)
}

async fn invoke(
    State(state): State<AppState>,
    Json(signed): Json<SignedRequest<InvokeRequest>>,
) -> Result<impl IntoResponse, ApiError> {
    let SignedRequest { contract, request: req } = signed;
    authorize_runtime_request(&state, "invoke", &req, &contract).await?;
    validate_shard_identity(&req.tenant_id, &req.shard_id)?;
    validate_firecracker_target(req.execution_class, req.execution_backend)?;
    if req.invocation_id.is_empty() || req.invocation_id.len() > 128 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invocation_id must be 1..=128 bytes",
        ));
    }
    if req.timeout_ms == 0 || req.timeout_ms > 300_000 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "timeout_ms must be 1..=300000",
        ));
    }
    if !req.request.is_object() || !req.context.is_object() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "request and context must be JSON objects",
        ));
    }
    validate_capability_refs(&req.capability_refs)
        .map_err(|message| api_error(StatusCode::BAD_REQUEST, message))?;
    let deployment_id = normalize_build_digest(&req.deployment_id)
        .map_err(|message| api_error(StatusCode::BAD_REQUEST, message))?;
    let envelope = guest_invocation_envelope(&req, &deployment_id);
    let request_bytes = serde_json::to_vec(&envelope)
        .map_err(|err| api_error(StatusCode::BAD_REQUEST, err.to_string()))?;
    if request_bytes.len() > state.guest_max_frame_bytes {
        return Err(api_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "invocation frame too large",
        ));
    }

    let (backend, vsock_path) = {
        let _barrier = state.lifecycle_barrier.read().await;
        let gate_index = shard_gate_index(req.execution_class, &req.tenant_id, &req.shard_id);
        let _gate = state.shard_gates[gate_index].lock().await;
        let shard = state
            .host
            .get(req.execution_class, &req.tenant_id, &req.shard_id)
            .await
            .map_err(map_err)?;
        check_runtime_epoch(&shard, req.runtime_epoch)?;
        check_execution_target(&shard, req.execution_class, req.execution_backend)?;
        if !matches!(shard.state, LifecycleState::Hot | LifecycleState::WarmIdle) {
            return Err(api_error(
                StatusCode::CONFLICT,
                format!("shard is not runnable: {:?}", shard.state),
            ));
        }
        if !deployment_allowed(&state, &shard, &deployment_id).await? {
            return Err(api_error(
                StatusCode::CONFLICT,
                "deployment digest is not observed as loaded for this shard epoch",
            ));
        }
        state
            .host
            .touch(TouchRequest {
                tenant_id: req.tenant_id.clone(),
                shard_id: req.shard_id.clone(),
                execution_class: req.execution_class,
                execution_backend: req.execution_backend,
                runtime_epoch: req.runtime_epoch,
                active_delta: 1,
                ingress_bytes: request_bytes.len() as u64,
                egress_bytes: 0,
            })
            .await
            .map_err(map_err)?;
        (shard.backend, shard.vsock_path)
    };

    let transport_result: Result<Vec<u8>, ApiError> = async {
        if backend != "mock" {
            state
                .artifact_store
                .resolve(&deployment_id)
                .await
                .map_err(|err| {
                    api_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("artifact preflight failed for {deployment_id}: {err}"),
                    )
                })?;
        }
        if backend == "mock" {
            serde_json::to_vec(&json!({
                "invocation_id": envelope["invocation_id"],
                "ok": true,
                "payload_encoding": "mock",
                "payload_etf_base64": null
            }))
            .map_err(|err| api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))
        } else {
            let path = vsock_path.as_deref().ok_or_else(|| {
                api_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "runnable shard is missing vsock path",
                )
            })?;
            invoke_over_vsock(
                FsPath::new(path),
                state.guest_vsock_port,
                &request_bytes,
                req.timeout_ms,
                state.guest_max_frame_bytes,
            )
            .await
            .map_err(|message| api_error(StatusCode::SERVICE_UNAVAILABLE, message))
        }
    }
    .await;

    let response_len = transport_result
        .as_ref()
        .map(|bytes| bytes.len())
        .unwrap_or(0);
    let cleanup = state
        .host
        .touch(TouchRequest {
            tenant_id: req.tenant_id,
            shard_id: req.shard_id,
            execution_class: req.execution_class,
            execution_backend: req.execution_backend,
            runtime_epoch: req.runtime_epoch,
            active_delta: -1,
            ingress_bytes: 0,
            egress_bytes: response_len as u64,
        })
        .await;
    if let Err(err) = cleanup {
        return Err(map_err(err));
    }

    let response_bytes = transport_result?;
    let response: Value = serde_json::from_slice(&response_bytes).map_err(|err| {
        api_error(
            StatusCode::BAD_GATEWAY,
            format!("invalid guest response: {err}"),
        )
    })?;
    Ok(Json(response))
}

fn validate_capability_refs(refs: &[CapabilityRef]) -> Result<(), &'static str> {
    if refs.len() > MAX_CAPABILITY_REFS {
        return Err("capability_refs may contain at most 64 entries");
    }

    let mut names = HashSet::with_capacity(refs.len());
    for capability in refs {
        if !valid_capability_name(&capability.name) {
            return Err(
                "capability_refs names must match ctx.[a-zA-Z0-9._-]+ and be at most 128 bytes",
            );
        }
        let token_ref_len = capability.token_ref.len();
        if token_ref_len == 0 || token_ref_len > MAX_CAPABILITY_TOKEN_REF_BYTES {
            return Err("capability_refs token_ref must be 1..=256 bytes");
        }
        if !names.insert(capability.name.as_str()) {
            return Err("capability_refs names must be unique");
        }
    }
    Ok(())
}

fn valid_capability_name(name: &str) -> bool {
    if name.len() <= 4 || name.len() > MAX_CAPABILITY_NAME_BYTES || !name.starts_with("ctx.") {
        return false;
    }
    name.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn guest_invocation_envelope(req: &InvokeRequest, deployment_id: &str) -> Value {
    json!({
        "op": "invoke",
        "invocation_id": &req.invocation_id,
        "deployment_id": deployment_id,
        "execution_class": req.execution_class,
        "execution_backend": req.execution_backend,
        "tenant_id": &req.tenant_id,
        "runtime_epoch": req.runtime_epoch,
        "request": &req.request,
        "context": &req.context,
        "capability_refs": &req.capability_refs,
        "timeout_ms": req.timeout_ms
    })
}

fn validate_activation_response(bytes: &[u8], expected_deployment_id: &str) -> Result<(), String> {
    let response: Value = serde_json::from_slice(bytes)
        .map_err(|err| format!("invalid guest activation response: {err}"))?;
    if response.get("op").and_then(Value::as_str) != Some("activate_artifact_result") {
        return Err("guest activation response has wrong operation".into());
    }
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err("guest rejected artifact activation".into());
    }
    for field in ["deployment_id", "active_deployment_id"] {
        let value = response
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(|| format!("guest activation response is missing {field}"))?;
        let normalized = normalize_build_digest(value)
            .map_err(|_| format!("guest activation response has invalid {field}"))?;
        if normalized != expected_deployment_id {
            return Err(format!(
                "guest activation response {field} does not match request"
            ));
        }
    }
    Ok(())
}

fn validate_put_artifact_response(bytes: &[u8], artifact: &AdmittedArtifact) -> Result<(), String> {
    let response: Value = serde_json::from_slice(bytes)
        .map_err(|err| format!("invalid guest artifact response: {err}"))?;
    if response.get("op").and_then(Value::as_str) != Some("put_artifact_result") {
        return Err("guest artifact response has wrong operation".into());
    }
    if response.get("ok").and_then(Value::as_bool) != Some(true) {
        return Err("guest rejected admitted artifact".into());
    }
    if response.get("build_sha256").and_then(Value::as_str) != Some(&artifact.build_sha256) {
        return Err("guest artifact response build_sha256 does not match request".into());
    }
    if response.get("archive_sha256").and_then(Value::as_str) != Some(&artifact.archive_sha256) {
        return Err("guest artifact response archive_sha256 does not match request".into());
    }
    if response.get("archive_bytes").and_then(Value::as_u64) != Some(artifact.archive_bytes) {
        return Err("guest artifact response archive_bytes does not match request".into());
    }
    let state = response
        .get("state")
        .and_then(Value::as_str)
        .ok_or_else(|| "guest artifact response is missing state".to_string())?;
    if !matches!(state, "stored" | "already_present") {
        return Err("guest artifact response has invalid state".into());
    }
    Ok(())
}

async fn put_artifact_over_vsock(
    vsock_path: &FsPath,
    guest_port: u32,
    shard: &ShardStatus,
    artifact: &AdmittedArtifact,
    timeout_ms: u64,
    max_frame_bytes: usize,
    chunk_bytes: usize,
) -> Result<(), String> {
    if chunk_bytes == 0 || chunk_bytes > max_frame_bytes {
        return Err("invalid host artifact chunk size".into());
    }
    if artifact.archive_bytes != artifact.bytes.len() as u64 {
        return Err("admitted artifact byte count changed before transport".into());
    }
    let header = serde_json::to_vec(&json!({
        "op": "put_artifact",
        "execution_class": shard.execution_class,
        "execution_backend": shard.execution_backend,
        "tenant_id": &shard.tenant_id,
        "runtime_epoch": shard.runtime_epoch,
        "build_sha256": artifact.build_sha256,
        "archive_sha256": artifact.archive_sha256,
        "archive_name": artifact.archive_name,
        "archive_bytes": artifact.archive_bytes,
        "chunk_bytes": chunk_bytes
    }))
    .map_err(|err| format!("serialize guest artifact header: {err}"))?;

    let operation = async {
        let mut stream = connect_vsock_proxy(vsock_path, guest_port).await?;
        write_frame(&mut stream, &header, max_frame_bytes).await?;
        for chunk in artifact.bytes.chunks(chunk_bytes) {
            write_frame(&mut stream, chunk, chunk_bytes).await?;
        }
        let response = read_frame(&mut stream, max_frame_bytes).await?;
        Ok::<Vec<u8>, io::Error>(response)
    };

    let response = timeout(Duration::from_millis(timeout_ms), operation)
        .await
        .map_err(|_| "guest artifact transfer timed out".to_string())?
        .map_err(|err| format!("guest artifact transfer failed: {err}"))?;
    validate_put_artifact_response(&response, artifact)
}

async fn connect_vsock_proxy(vsock_path: &FsPath, guest_port: u32) -> io::Result<UnixStream> {
    let mut stream = UnixStream::connect(vsock_path).await?;
    stream
        .write_all(format!("CONNECT {guest_port}\n").as_bytes())
        .await?;

    let mut ack = Vec::with_capacity(32);
    while ack.len() < 128 {
        let byte = stream.read_u8().await?;
        ack.push(byte);
        if byte == b'\n' {
            break;
        }
    }
    let ack_text = std::str::from_utf8(&ack)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "non-utf8 vsock ack"))?;
    if !ack_text.starts_with("OK ") || !ack_text.ends_with('\n') {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("Firecracker vsock handshake failed: {ack_text:?}"),
        ));
    }
    Ok(stream)
}

async fn invoke_over_vsock(
    vsock_path: &FsPath,
    guest_port: u32,
    request: &[u8],
    timeout_ms: u64,
    max_frame_bytes: usize,
) -> Result<Vec<u8>, String> {
    let operation = async {
        let mut stream = connect_vsock_proxy(vsock_path, guest_port).await?;
        write_frame(&mut stream, request, max_frame_bytes).await?;
        read_frame(&mut stream, max_frame_bytes).await
    };

    timeout(Duration::from_millis(timeout_ms), operation)
        .await
        .map_err(|_| "guest transport timed out".to_string())?
        .map_err(|err| format!("guest vsock transport failed: {err}"))
}

async fn read_frame(stream: &mut UnixStream, max_frame_bytes: usize) -> io::Result<Vec<u8>> {
    let len = stream.read_u32().await? as usize;
    if len == 0 || len > max_frame_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid guest frame length {len}"),
        ));
    }
    let mut bytes = vec![0u8; len];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn write_frame(
    stream: &mut UnixStream,
    bytes: &[u8],
    max_frame_bytes: usize,
) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() > max_frame_bytes || bytes.len() > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid host frame length {}", bytes.len()),
        ));
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(bytes).await?;
    stream.flush().await
}

async fn warm_idle(
    State(state): State<AppState>,
    Json(signed): Json<SignedRequest<EpochRequest>>,
) -> Result<impl IntoResponse, ApiError> {
    let SignedRequest { contract, request: req } = signed;
    authorize_runtime_request(&state, "warm_idle", &req, &contract).await?;
    validate_shard_identity(&req.tenant_id, &req.shard_id)?;
    let _barrier = state.lifecycle_barrier.read().await;
    let gate_index = shard_gate_index(req.execution_class, &req.tenant_id, &req.shard_id);
    let _gate = state.shard_gates[gate_index].lock().await;
    state
        .host
        .mark_warm_idle(req)
        .await
        .map(Json)
        .map_err(map_err)
}

async fn hibernate(
    State(state): State<AppState>,
    Json(signed): Json<SignedRequest<EpochRequest>>,
) -> Result<impl IntoResponse, ApiError> {
    let SignedRequest { contract, request: req } = signed;
    authorize_runtime_request(&state, "hibernate", &req, &contract).await?;
    validate_shard_identity(&req.tenant_id, &req.shard_id)?;
    let _barrier = state.lifecycle_barrier.read().await;
    let gate_index = shard_gate_index(req.execution_class, &req.tenant_id, &req.shard_id);
    let _gate = state.shard_gates[gate_index].lock().await;
    state.host.hibernate(req).await.map(Json).map_err(map_err)
}

async fn terminate(
    State(state): State<AppState>,
    Json(signed): Json<SignedRequest<EpochRequest>>,
) -> Result<impl IntoResponse, ApiError> {
    let SignedRequest { contract, request: req } = signed;
    authorize_runtime_request(&state, "terminate", &req, &contract).await?;
    validate_shard_identity(&req.tenant_id, &req.shard_id)?;
    let execution_class = req.execution_class;
    let tenant_id = req.tenant_id.clone();
    let shard_id = req.shard_id.clone();
    let _barrier = state.lifecycle_barrier.read().await;
    let gate_index = shard_gate_index(execution_class, &tenant_id, &shard_id);
    let _gate = state.shard_gates[gate_index].lock().await;
    let current = state
        .host
        .get(execution_class, &tenant_id, &shard_id)
        .await
        .map_err(map_err)?;
    check_runtime_epoch(&current, req.runtime_epoch)?;
    if current.active_invocations != 0 {
        return Err(api_error(
            StatusCode::CONFLICT,
            "cannot terminate shard while invocations are active",
        ));
    }
    let status = state.host.terminate(req).await.map_err(map_err)?;
    clear_observed_for_shard(&state, execution_class, &tenant_id, &shard_id).await;
    Ok(Json(status))
}

async fn get_activation(
    Path((execution_class, tenant_id, shard_id)): Path<(ExecutionClass, String, String)>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    validate_shard_identity(&tenant_id, &shard_id)?;
    let _barrier = state.lifecycle_barrier.read().await;
    let gate_index = shard_gate_index(execution_class, &tenant_id, &shard_id);
    let _gate = state.shard_gates[gate_index].lock().await;
    let shard = state
        .host
        .get(execution_class, &tenant_id, &shard_id)
        .await
        .map_err(map_err)?;
    let key = shard_epoch_key(execution_class, &tenant_id, &shard_id, shard.runtime_epoch);
    let observed = state.observed_activation.read().await.get(&key).cloned();
    Ok(Json(activation_status(&shard, observed.as_ref())))
}

async fn get_metering(
    Path((execution_class, tenant_id, shard_id)): Path<(ExecutionClass, String, String)>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    validate_shard_identity(&tenant_id, &shard_id)?;
    state
        .host
        .metering(execution_class, &tenant_id, &shard_id)
        .await
        .map(Json)
        .map_err(map_err)
}

async fn get_shard(
    Path((execution_class, tenant_id, shard_id)): Path<(ExecutionClass, String, String)>,
    State(state): State<AppState>,
) -> Result<impl IntoResponse, ApiError> {
    validate_shard_identity(&tenant_id, &shard_id)?;
    state
        .host
        .get(execution_class, &tenant_id, &shard_id)
        .await
        .map(Json)
        .map_err(map_err)
}

fn default_activation_timeout_ms() -> u64 {
    30_000
}

fn shard_epoch_key(
    execution_class: ExecutionClass,
    tenant_id: &str,
    shard_id: &str,
    runtime_epoch: u64,
) -> ShardEpochKey {
    ShardEpochKey {
        execution_class,
        tenant_id: tenant_id.to_owned(),
        shard_id: shard_id.to_owned(),
        runtime_epoch,
    }
}

fn shard_gate_index(execution_class: ExecutionClass, tenant_id: &str, shard_id: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    execution_class.hash(&mut hasher);
    tenant_id.hash(&mut hasher);
    shard_id.hash(&mut hasher);
    (hasher.finish() as usize) % SHARD_GATE_STRIPES
}

async fn clear_observed_for_shard(
    state: &AppState,
    execution_class: ExecutionClass,
    tenant_id: &str,
    shard_id: &str,
) {
    state.observed_activation.write().await.retain(|key, _| {
        key.execution_class != execution_class
            || key.tenant_id != tenant_id
            || key.shard_id != shard_id
    });
}

async fn deployment_allowed(
    state: &AppState,
    shard: &ShardStatus,
    requested_deployment_id: &str,
) -> Result<bool, ApiError> {
    let key = shard_epoch_key(
        shard.execution_class,
        &shard.tenant_id,
        &shard.shard_id,
        shard.runtime_epoch,
    );
    if let Some(observed) = state.observed_activation.read().await.get(&key) {
        return Ok(observed
            .loaded_deployment_ids
            .contains(requested_deployment_id));
    }
    let placement = normalize_build_digest(&shard.deployment_digest).map_err(|_| {
        api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "runtime host contains a non-canonical deployment digest",
        )
    })?;
    Ok(placement == requested_deployment_id)
}

fn activation_status(
    shard: &ShardStatus,
    observed: Option<&ObservedActivation>,
) -> ActivationStatus {
    ActivationStatus {
        tenant_id: shard.tenant_id.clone(),
        shard_id: shard.shard_id.clone(),
        execution_class: shard.execution_class,
        execution_backend: shard.execution_backend,
        runtime_epoch: shard.runtime_epoch,
        placement_deployment_id: shard.deployment_digest.clone(),
        observed: observed.is_some(),
        root_active_deployment_id: observed
            .and_then(|activation| activation.root_active_deployment_id.clone()),
        loaded_deployment_ids: observed
            .map(|activation| activation.loaded_deployment_ids.iter().cloned().collect())
            .unwrap_or_default(),
    }
}

fn normalize_build_digest(value: &str) -> Result<String, &'static str> {
    let raw = value.strip_prefix("sha256:").unwrap_or(value);
    if raw.len() == 64
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(raw.to_owned())
    } else {
        Err("deployment_id must be a lowercase 64-character SHA-256 digest")
    }
}

fn validate_shard_identity(tenant_id: &str, shard_id: &str) -> Result<(), ApiError> {
    if !valid_runtime_identifier(tenant_id) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "tenant_id must use 1..=128 ASCII letters, digits, '.', '_' or '-'",
        ));
    }
    if !valid_runtime_identifier(shard_id) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "shard_id must use 1..=128 ASCII letters, digits, '.', '_' or '-'",
        ));
    }
    Ok(())
}

fn valid_runtime_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn execution_class_name(class: ExecutionClass) -> &'static str {
    match class {
        ExecutionClass::Faas => "faas",
        ExecutionClass::Phoenix => "phoenix",
        ExecutionClass::DurableActor => "durable_actor",
    }
}

fn execution_backend_name(backend: ExecutionBackend) -> &'static str {
    match backend {
        ExecutionBackend::BareProcess => "bare_process",
        ExecutionBackend::Firecracker => "firecracker",
    }
}

async fn authorize_runtime_request<T>(
    state: &AppState,
    operation: &str,
    request: &T,
    contract: &RuntimeContract,
) -> Result<(), ApiError>
where
    T: Serialize + RuntimeRequestIdentity,
{
    let expected = ExpectedRuntimeRequest {
        operation,
        tenant_id: request.tenant_id(),
        shard_id: request.shard_id(),
        execution_class: execution_class_name(request.execution_class()),
        execution_backend: execution_backend_name(request.execution_backend()),
        runtime_epoch: request.runtime_epoch(),
    };
    let expires_at = runtime_auth::verify(
        state.runtime_control_secret.as_slice(),
        &expected,
        request,
        contract,
    )
    .map_err(|message| api_error(StatusCode::UNAUTHORIZED, message))?;

    let now = runtime_auth::now_unix()
        .map_err(|message| api_error(StatusCode::INTERNAL_SERVER_ERROR, message))?;
    let mut consumed = state.consumed_nonces.lock().await;
    consumed.retain(|_, expiry| *expiry >= now);
    if consumed.insert(contract.nonce.clone(), expires_at).is_some() {
        return Err(api_error(
            StatusCode::UNAUTHORIZED,
            "runtime control contract replay detected",
        ));
    }
    Ok(())
}


fn validate_firecracker_target(
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
) -> Result<(), ApiError> {
    if execution_backend != ExecutionBackend::Firecracker {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "this runtime host accepts execution_backend=firecracker only",
        ));
    }
    if !matches!(
        execution_class,
        ExecutionClass::Phoenix | ExecutionClass::DurableActor
    ) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Firecracker runtime host accepts only phoenix or durable_actor",
        ));
    }
    Ok(())
}

fn check_execution_target(
    shard: &ShardStatus,
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
) -> Result<(), ApiError> {
    validate_firecracker_target(execution_class, execution_backend)?;
    if shard.execution_class != execution_class || shard.execution_backend != execution_backend {
        return Err(api_error(
            StatusCode::CONFLICT,
            "runtime shard execution class/backend does not match request",
        ));
    }
    Ok(())
}

fn check_runtime_epoch(shard: &ShardStatus, requested: u64) -> Result<(), ApiError> {
    if shard.runtime_epoch == requested {
        Ok(())
    } else {
        Err(api_error(
            StatusCode::CONFLICT,
            format!(
                "stale runtime epoch: requested {}, current {}",
                requested, shard.runtime_epoch
            ),
        ))
    }
}

fn map_err(err: HostError) -> ApiError {
    let status = match &err {
        HostError::UnknownShard => StatusCode::NOT_FOUND,
        HostError::StaleEpoch { .. }
        | HostError::EpochReplacementConflict
        | HostError::InvalidState(_)
        | HostError::IdentityConflict(_) => StatusCode::CONFLICT,
        HostError::InvalidPolicy(_)
        | HostError::InvalidIdentity(_)
        | HostError::InvalidExecutionTarget(_) => StatusCode::BAD_REQUEST,
        HostError::Firecracker(_)
        | HostError::Cgroup(_)
        | HostError::Identity(_)
        | HostError::Io(_) => StatusCode::SERVICE_UNAVAILABLE,
    };
    api_error(status, err.to_string())
}

fn api_error(status: StatusCode, message: impl Into<String>) -> ApiError {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request_with_capabilities(capability_refs: Vec<CapabilityRef>) -> InvokeRequest {
        InvokeRequest {
            tenant_id: "tenant-1".into(),
            shard_id: "shard-1".into(),
            execution_class: ExecutionClass::Phoenix,
            execution_backend: ExecutionBackend::Firecracker,
            runtime_epoch: 7,
            invocation_id: "invocation-1".into(),
            deployment_id: "a".repeat(64),
            request: json!({"method": "GET", "path": "/"}),
            context: json!({"trace_id": "trace-1"}),
            capability_refs,
            timeout_ms: 5_000,
        }
    }

    #[test]
    fn firecracker_target_validation_rejects_faas_and_bare_process() {
        assert!(validate_firecracker_target(
            ExecutionClass::Phoenix,
            ExecutionBackend::Firecracker
        )
        .is_ok());
        assert!(validate_firecracker_target(
            ExecutionClass::DurableActor,
            ExecutionBackend::Firecracker
        )
        .is_ok());
        assert!(
            validate_firecracker_target(ExecutionClass::Faas, ExecutionBackend::Firecracker)
                .is_err()
        );
        assert!(validate_firecracker_target(
            ExecutionClass::Phoenix,
            ExecutionBackend::BareProcess
        )
        .is_err());
    }

    #[test]
    fn accepts_and_forwards_bounded_capability_refs() {
        let refs = vec![CapabilityRef {
            name: "ctx.fetch".into(),
            token_ref: "opaque-token-ref-1".into(),
        }];
        assert_eq!(validate_capability_refs(&refs), Ok(()));

        let request = request_with_capabilities(refs);
        let envelope = guest_invocation_envelope(&request, &"a".repeat(64));
        assert_eq!(envelope["capability_refs"][0]["name"], json!("ctx.fetch"));
        assert_eq!(
            envelope["capability_refs"][0]["token_ref"],
            json!("opaque-token-ref-1")
        );
    }

    #[test]
    fn rejects_duplicate_capability_names() {
        let capability = CapabilityRef {
            name: "ctx.kv".into(),
            token_ref: "one".into(),
        };
        let refs = vec![capability.clone(), capability];
        assert_eq!(
            validate_capability_refs(&refs),
            Err("capability_refs names must be unique")
        );
    }

    #[test]
    fn rejects_malformed_capability_name() {
        let refs = vec![CapabilityRef {
            name: "fetch".into(),
            token_ref: "one".into(),
        }];
        assert!(validate_capability_refs(&refs).is_err());
    }

    #[test]
    fn rejects_empty_or_oversized_token_refs() {
        let empty = vec![CapabilityRef {
            name: "ctx.fetch".into(),
            token_ref: String::new(),
        }];
        assert!(validate_capability_refs(&empty).is_err());

        let oversized = vec![CapabilityRef {
            name: "ctx.fetch".into(),
            token_ref: "x".repeat(MAX_CAPABILITY_TOKEN_REF_BYTES + 1),
        }];
        assert!(validate_capability_refs(&oversized).is_err());
    }

    #[test]
    fn rejects_more_than_sixty_four_capability_refs() {
        let refs = (0..=MAX_CAPABILITY_REFS)
            .map(|index| CapabilityRef {
                name: format!("ctx.capability_{index}"),
                token_ref: format!("token-{index}"),
            })
            .collect::<Vec<_>>();
        assert!(validate_capability_refs(&refs).is_err());
    }

    #[test]
    fn canonicalizes_and_validates_build_digests() {
        let digest = "a".repeat(64);
        assert_eq!(normalize_build_digest(&digest).unwrap(), digest);
        assert_eq!(
            normalize_build_digest(&format!("sha256:{digest}")).unwrap(),
            digest
        );
        assert!(normalize_build_digest(&"A".repeat(64)).is_err());
        assert!(normalize_build_digest("../artifact").is_err());
    }

    #[test]
    fn rejects_path_like_runtime_identifiers() {
        assert!(valid_runtime_identifier("tenant-1"));
        assert!(valid_runtime_identifier("shard_1.prod"));
        assert!(!valid_runtime_identifier("../tenant"));
        assert!(!valid_runtime_identifier("tenant/shard"));
        assert!(!valid_runtime_identifier(""));
    }

    #[test]
    fn activation_response_must_ack_exact_digest() {
        let digest = "b".repeat(64);
        let good = serde_json::to_vec(&json!({
            "op": "activate_artifact_result",
            "ok": true,
            "deployment_id": digest,
            "active_deployment_id": digest
        }))
        .unwrap();
        assert!(validate_activation_response(&good, &"b".repeat(64)).is_ok());

        let wrong = serde_json::to_vec(&json!({
            "op": "activate_artifact_result",
            "ok": true,
            "deployment_id": "c".repeat(64),
            "active_deployment_id": "c".repeat(64)
        }))
        .unwrap();
        assert!(validate_activation_response(&wrong, &"b".repeat(64)).is_err());
    }

    #[test]
    fn artifact_response_must_ack_exact_admitted_bytes() {
        let artifact = AdmittedArtifact {
            build_sha256: "d".repeat(64),
            archive_name: "worker.tar.gz".into(),
            archive_sha256: "e".repeat(64),
            archive_bytes: 123,
            bytes: vec![1; 123],
        };
        let good = serde_json::to_vec(&json!({
            "op": "put_artifact_result",
            "ok": true,
            "build_sha256": artifact.build_sha256,
            "archive_sha256": artifact.archive_sha256,
            "archive_bytes": artifact.archive_bytes,
            "state": "stored"
        }))
        .unwrap();
        assert!(validate_put_artifact_response(&good, &artifact).is_ok());

        let wrong = serde_json::to_vec(&json!({
            "op": "put_artifact_result",
            "ok": true,
            "build_sha256": artifact.build_sha256,
            "archive_sha256": "f".repeat(64),
            "archive_bytes": artifact.archive_bytes,
            "state": "stored"
        }))
        .unwrap();
        assert!(validate_put_artifact_response(&wrong, &artifact).is_err());
    }
}
