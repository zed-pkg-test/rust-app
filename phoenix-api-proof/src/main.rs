mod critical_sections;
mod placement;
mod runtime_control;
mod security;

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use critical_sections::{
    validate_request as validate_critical_section_request, CriticalSectionDeployment,
    CriticalSectionDeployments, DeployCriticalSectionRequest, EXECUTION_CLASS, ISOLATION_CLASS,
    PROFILE as CRITICAL_SECTION_PROFILE, TENANCY_CLASS as CRITICAL_SECTION_TENANCY,
};
use placement::{
    ExecutionBackend, ExecutionClass, PlacementError, PlacementService, RuntimePlacement,
};
use reqwest::Client;
use runtime_control::{RuntimeControlSigner, RuntimeControlTarget};
use security::{SecurityClient, SecurityError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{HashMap, HashSet},
    env,
    sync::Arc,
    time::Duration,
};
use tokio::{
    net::TcpListener,
    sync::{Mutex, RwLock},
};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    deployments: Arc<RwLock<HashMap<String, Deployment>>>,
    critical_sections: CriticalSectionDeployments,
    placement: Arc<Mutex<PlacementService>>,
    runtime_client: Client,
    security: SecurityClient,
    runtime_control: RuntimeControlSigner,
}

impl AppState {
    fn from_env() -> Result<Self, PlacementError> {
        let runtime_client = Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(310))
            .build()
            .map_err(|err| PlacementError::Unavailable(err.to_string()))?;
        let security = SecurityClient::from_env(runtime_client.clone())
            .map_err(|err| PlacementError::Unavailable(err.to_string()))?;
        let runtime_control =
            RuntimeControlSigner::from_env().map_err(PlacementError::Unavailable)?;
        Ok(Self {
            deployments: Arc::new(RwLock::new(HashMap::new())),
            critical_sections: CriticalSectionDeployments::default(),
            placement: Arc::new(Mutex::new(PlacementService::from_env()?)),
            runtime_client,
            security,
            runtime_control,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RuntimeLimits {
    max_wall_ms: u64,
    max_reductions: u64,
    max_heap_bytes: u64,
    max_processes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CapabilityGrant {
    name: String,
    #[serde(default)]
    scope: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactManifest {
    format_version: u32,
    runtime: String,
    language: String,
    profile: String,
    source_sha256: String,
    build_sha256: String,
    entrypoint: String,
    capabilities: Vec<CapabilityGrant>,
    runtime_limits: RuntimeLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Deployment {
    deployment_id: String,
    user_id: String,
    tenant_id: String,
    shard_id: String,
    execution_class: ExecutionClass,
    worker_version_id: String,
    manifest: ArtifactManifest,
}

#[derive(Debug, Deserialize)]
struct AdmitRequest {
    deployment_id: Option<String>,
    tenant_id: String,
    #[serde(default = "default_shard_id")]
    shard_id: String,
    #[serde(default = "default_execution_class")]
    execution_class: ExecutionClass,
    manifest: ArtifactManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PhoenixManifest {
    format_version: u32,
    artifact_format: String,
    artifact_root: String,
    runtime: String,
    language: String,
    profile: String,
    execution_class: String,
    isolation_class: String,
    source_sha256: String,
    build_sha256: String,
    provenance_sha256: String,
    app: String,
    version: String,
    router: String,
    endpoint: String,
    route_plan_sha256: String,
}

#[derive(Debug, Deserialize)]
struct PhoenixDeployRequest {
    deployment_id: Option<String>,
    tenant_id: String,
    #[serde(default = "default_shard_id")]
    shard_id: String,
    manifest: PhoenixManifest,
}

#[derive(Debug, Clone, Serialize)]
struct PhoenixDeployment {
    deployment_id: String,
    user_id: String,
    tenant_id: String,
    shard_id: String,
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
    worker_version_id: String,
    runtime_host: String,
    runtime_epoch: u64,
    runtime_state: String,
    manifest: PhoenixManifest,
}

#[derive(Debug, Deserialize)]
struct InvokeRequest {
    request: Value,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct RuntimeInvokeRequest<'a> {
    tenant_id: &'a str,
    shard_id: &'a str,
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
    runtime_epoch: u64,
    invocation_id: &'a str,
    deployment_id: &'a str,
    request: Value,
    context: Value,
    capability_refs: Vec<RuntimeCapabilityRef>,
    timeout_ms: u64,
}

#[derive(Debug, Serialize)]
struct RuntimeCapabilityRef {
    name: String,
    token_ref: String,
}

#[derive(Debug, Serialize)]
struct InvokeCompleted {
    invocation_id: String,
    deployment_id: String,
    user_id: String,
    worker_version_id: String,
    build_sha256: String,
    tenant_id: String,
    shard_id: String,
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
    runtime_host: String,
    runtime_epoch: u64,
    runtime_state: String,
    status: &'static str,
    dispatch_status: &'static str,
    guest_response: Value,
}

#[derive(Debug, Deserialize, Serialize)]
struct CriticalSectionAcquireRequest {
    key: String,
    holder: String,
    request_id: String,
    lease_ms: u64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct CriticalSectionToken {
    runtime_epoch: u64,
    owner_epoch: u64,
    sequence: u64,
}

#[derive(Debug, Deserialize, Serialize)]
struct CriticalSectionRenewRequest {
    key: String,
    holder: String,
    lease_ms: u64,
    token: CriticalSectionToken,
}

#[derive(Debug, Deserialize, Serialize)]
struct CriticalSectionReleaseRequest {
    key: String,
    holder: String,
    token: CriticalSectionToken,
}

struct CriticalSectionOperation<'a> {
    deployment_id: &'a str,
    operation: &'a str,
    key: &'a str,
    holder: &'a str,
    request_id: Option<&'a str>,
    lease_ms: Option<u64>,
    token: Option<&'a CriticalSectionToken>,
}

struct GuestDispatch<'a> {
    runtime: &'a RuntimePlacement,
    invocation_id: &'a str,
    deployment_id: &'a str,
    request: Value,
    context: Value,
    timeout_ms: u64,
}

#[derive(Debug, Serialize)]
struct RuntimeCriticalSectionRequest<'a> {
    tenant_id: &'a str,
    shard_id: &'a str,
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
    runtime_epoch: u64,
    deployment_id: &'a str,
    operation: &'a str,
    namespace: &'a str,
    object_key: &'a str,
    holder: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lease_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<&'a CriticalSectionToken>,
    timeout_ms: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct ErrorBody {
    error: String,
}

type ApiError = (StatusCode, Json<ErrorBody>);

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let state = AppState::from_env().expect("initialize tenant placement/security services");
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/deployments/admit", post(admit_deployment))
        .route("/v1/phoenix/deployments", post(deploy_phoenix))
        .route(
            "/v1/critical-sections/deployments",
            post(deploy_critical_section),
        )
        .route(
            "/v1/critical-sections/{deployment_id}/acquire",
            post(acquire_critical_section),
        )
        .route(
            "/v1/critical-sections/{deployment_id}/renew",
            post(renew_critical_section),
        )
        .route(
            "/v1/critical-sections/{deployment_id}/release",
            post(release_critical_section),
        )
        .route("/v1/deployments/{deployment_id}/invoke", post(invoke))
        .with_state(state);

    let bind = env::var("BMSCL_BIND").unwrap_or_else(|_| "127.0.0.1:8081".into());
    let listener = TcpListener::bind(&bind).await.expect("bind API server");
    tracing::info!(%bind, "bmscl api server listening");
    axum::serve(listener, app).await.expect("serve API");
}

async fn healthz() -> &'static str {
    "ok"
}

async fn deploy_critical_section(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeployCriticalSectionRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_critical_section_request(&request)
        .map_err(|message| api_error(StatusCode::BAD_REQUEST, message))?;

    let principal = state
        .security
        .authorize(&headers, &request.tenant_id)
        .await
        .map_err(security_error)?;

    let deployment_id = request
        .deployment_id
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    validate_identity("deployment_id", &deployment_id)?;

    let runtime = state
        .placement
        .lock()
        .await
        .ensure(
            ExecutionClass::DurableActor,
            &principal.user_id,
            &request.tenant_id,
            &deployment_id,
            &deployment_id,
            &request.build_sha256,
        )
        .await
        .map_err(placement_error)?;

    let deployment = CriticalSectionDeployment {
        deployment_id,
        user_id: principal.user_id,
        tenant_id: request.tenant_id,
        namespace: request.namespace,
        runtime: "beam",
        language: request.language,
        profile: CRITICAL_SECTION_PROFILE,
        build_sha256: request.build_sha256,
        tenancy_class: CRITICAL_SECTION_TENANCY,
        execution_class: EXECUTION_CLASS,
        isolation_class: ISOLATION_CLASS,
        shard_id: runtime.shard_id,
        runtime_host: runtime.runtime_host,
        runtime_epoch: runtime.runtime_epoch,
        runtime_state: runtime.runtime_state,
    };

    state.critical_sections.insert(deployment.clone()).await;

    tracing::info!(
        deployment_id = %deployment.deployment_id,
        tenant_id = %deployment.tenant_id,
        namespace = %deployment.namespace,
        language = %deployment.language,
        runtime_epoch = deployment.runtime_epoch,
        "critical-section deployment activated"
    );

    Ok((StatusCode::CREATED, Json(deployment)))
}

async fn acquire_critical_section(
    Path(deployment_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CriticalSectionAcquireRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_critical_section_call(&input.key, &input.holder, Some(input.lease_ms))?;
    validate_request_id(&input.request_id)?;
    critical_section_operation(
        &state,
        &headers,
        CriticalSectionOperation {
            deployment_id: &deployment_id,
            operation: "acquire",
            key: &input.key,
            holder: &input.holder,
            request_id: Some(&input.request_id),
            lease_ms: Some(input.lease_ms),
            token: None,
        },
    )
    .await
}

async fn renew_critical_section(
    Path(deployment_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CriticalSectionRenewRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_critical_section_call(&input.key, &input.holder, Some(input.lease_ms))?;
    validate_critical_section_token(&input.token)?;
    critical_section_operation(
        &state,
        &headers,
        CriticalSectionOperation {
            deployment_id: &deployment_id,
            operation: "renew",
            key: &input.key,
            holder: &input.holder,
            request_id: None,
            lease_ms: Some(input.lease_ms),
            token: Some(&input.token),
        },
    )
    .await
}

async fn release_critical_section(
    Path(deployment_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<CriticalSectionReleaseRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_critical_section_call(&input.key, &input.holder, None)?;
    validate_critical_section_token(&input.token)?;
    critical_section_operation(
        &state,
        &headers,
        CriticalSectionOperation {
            deployment_id: &deployment_id,
            operation: "release",
            key: &input.key,
            holder: &input.holder,
            request_id: None,
            lease_ms: None,
            token: Some(&input.token),
        },
    )
    .await
}

async fn critical_section_operation(
    state: &AppState,
    headers: &HeaderMap,
    request: CriticalSectionOperation<'_>,
) -> Result<(StatusCode, Json<Value>), ApiError> {
    let CriticalSectionOperation {
        deployment_id,
        operation,
        key,
        holder,
        request_id,
        lease_ms,
        token,
    } = request;
    let deployment = state
        .critical_sections
        .get(deployment_id)
        .await
        .ok_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                "critical-section deployment not found",
            )
        })?;

    let principal = state
        .security
        .authorize(headers, &deployment.tenant_id)
        .await
        .map_err(security_error)?;
    if principal.user_id != deployment.user_id {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "critical-section deployment belongs to another principal",
        ));
    }

    let runtime = state
        .placement
        .lock()
        .await
        .ensure(
            ExecutionClass::DurableActor,
            &deployment.user_id,
            &deployment.tenant_id,
            &deployment.deployment_id,
            &deployment.deployment_id,
            &deployment.build_sha256,
        )
        .await
        .map_err(placement_error)?;

    let body = RuntimeCriticalSectionRequest {
        tenant_id: &deployment.tenant_id,
        shard_id: &runtime.shard_id,
        execution_class: ExecutionClass::DurableActor,
        execution_backend: ExecutionBackend::Firecracker,
        runtime_epoch: runtime.runtime_epoch,
        deployment_id: &deployment.build_sha256,
        operation,
        namespace: &deployment.namespace,
        object_key: key,
        holder,
        request_id,
        lease_ms,
        token,
        timeout_ms: 10_000,
    };
    let signed = state
        .runtime_control
        .sign(
            RuntimeControlTarget {
                operation: "critical-section",
                tenant_id: &deployment.tenant_id,
                shard_id: &runtime.shard_id,
                execution_class: execution_class_name(ExecutionClass::DurableActor),
                execution_backend: execution_backend_name(ExecutionBackend::Firecracker),
                runtime_epoch: runtime.runtime_epoch,
            },
            &body,
        )
        .map_err(|message| api_error(StatusCode::SERVICE_UNAVAILABLE, message))?;

    let url = format!(
        "{}/v1/shards/critical-section",
        runtime.runtime_host.trim_end_matches('/')
    );
    let response = state
        .runtime_client
        .post(url)
        .json(&signed)
        .send()
        .await
        .map_err(|err| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("critical-section runtime transport failed: {err}"),
            )
        })?;
    let runtime_status = response.status();
    let value = response.json::<Value>().await.map_err(|err| {
        api_error(
            StatusCode::BAD_GATEWAY,
            format!("runtime host returned invalid critical-section response: {err}"),
        )
    })?;
    if !runtime_status.is_success() {
        return Err(api_error(
            if runtime_status == reqwest::StatusCode::CONFLICT {
                StatusCode::CONFLICT
            } else if runtime_status.is_client_error() {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            value
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("critical-section runtime rejected request"),
        ));
    }

    let ok = value.get("ok").and_then(Value::as_bool).unwrap_or(false);
    let outward = if ok {
        StatusCode::OK
    } else {
        match value.get("error_code").and_then(Value::as_str) {
            Some("busy") | Some("stale_or_not_owner") => StatusCode::CONFLICT,
            _ => StatusCode::BAD_GATEWAY,
        }
    };

    let mut refreshed = deployment;
    refreshed.shard_id = runtime.shard_id;
    refreshed.runtime_host = runtime.runtime_host;
    refreshed.runtime_epoch = runtime.runtime_epoch;
    refreshed.runtime_state = runtime.runtime_state;
    state.critical_sections.insert(refreshed).await;

    Ok((outward, Json(value)))
}

const MAX_CRITICAL_SECTION_SEQUENCE: u64 = 9_007_199_254_740_991;

fn validate_critical_section_token(token: &CriticalSectionToken) -> Result<(), ApiError> {
    if token.runtime_epoch == 0
        || token.owner_epoch == 0
        || token.sequence == 0
        || token.sequence > MAX_CRITICAL_SECTION_SEQUENCE
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "critical-section token fields must be positive and sequence must not exceed 9007199254740991",
        ));
    }
    Ok(())
}

fn validate_request_id(request_id: &str) -> Result<(), ApiError> {
    if request_id.is_empty() || request_id.len() > 256 || request_id.as_bytes().contains(&0) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "request_id must be 1..=256 bytes and contain no NUL",
        ));
    }
    Ok(())
}

fn validate_critical_section_call(
    key: &str,
    holder: &str,
    lease_ms: Option<u64>,
) -> Result<(), ApiError> {
    if key.is_empty() || key.len() > 4096 || key.as_bytes().contains(&0) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "key must be 1..=4096 bytes and contain no NUL",
        ));
    }
    if holder.is_empty() || holder.len() > 256 || holder.as_bytes().contains(&0) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "holder must be 1..=256 bytes and contain no NUL",
        ));
    }
    if lease_ms.is_some_and(|lease| !(1..=300_000).contains(&lease)) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "lease_ms must be 1..=300000",
        ));
    }
    Ok(())
}

async fn admit_deployment(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AdmitRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_manifest(&request.manifest, request.execution_class)?;
    validate_identity("tenant_id", &request.tenant_id)?;
    validate_identity("shard_id", &request.shard_id)?;

    let principal = state
        .security
        .authorize(&headers, &request.tenant_id)
        .await
        .map_err(security_error)?;

    let deployment_id = request
        .deployment_id
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    validate_identity("deployment_id", &deployment_id)?;
    let worker_version_id = format!("sha256:{}", request.manifest.build_sha256);
    let deployment = Deployment {
        deployment_id: deployment_id.clone(),
        user_id: principal.user_id,
        tenant_id: request.tenant_id,
        shard_id: request.shard_id,
        execution_class: request.execution_class,
        worker_version_id,
        manifest: request.manifest,
    };

    tracing::info!(
        deployment_id = %deployment.deployment_id,
        user_id = %deployment.user_id,
        tenant_id = %deployment.tenant_id,
        "deployment admitted for authenticated principal"
    );

    state
        .deployments
        .write()
        .await
        .insert(deployment_id, deployment.clone());

    Ok((StatusCode::CREATED, Json(deployment)))
}

async fn deploy_phoenix(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PhoenixDeployRequest>,
) -> Result<impl IntoResponse, ApiError> {
    validate_phoenix_manifest(&request.manifest)?;
    validate_identity("tenant_id", &request.tenant_id)?;
    validate_identity("shard_id", &request.shard_id)?;

    let principal = state
        .security
        .authorize(&headers, &request.tenant_id)
        .await
        .map_err(security_error)?;

    let deployment_id = request
        .deployment_id
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    validate_identity("deployment_id", &deployment_id)?;
    let worker_version_id = format!("sha256:{}", request.manifest.build_sha256);

    let runtime = state
        .placement
        .lock()
        .await
        .ensure(
            ExecutionClass::Phoenix,
            &principal.user_id,
            &request.tenant_id,
            &request.shard_id,
            &deployment_id,
            &worker_version_id,
        )
        .await
        .map_err(placement_error)?;

    let deployment = PhoenixDeployment {
        deployment_id,
        user_id: principal.user_id,
        tenant_id: request.tenant_id,
        shard_id: request.shard_id,
        execution_class: ExecutionClass::Phoenix,
        execution_backend: ExecutionBackend::Firecracker,
        worker_version_id,
        runtime_host: runtime.runtime_host,
        runtime_epoch: runtime.runtime_epoch,
        runtime_state: runtime.runtime_state,
        manifest: request.manifest,
    };

    tracing::info!(
        deployment_id = %deployment.deployment_id,
        tenant_id = %deployment.tenant_id,
        app = %deployment.manifest.app,
        runtime_epoch = deployment.runtime_epoch,
        "Phoenix deployment activated"
    );

    Ok((StatusCode::CREATED, Json(deployment)))
}

async fn invoke(
    Path(deployment_id): Path<String>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<InvokeRequest>,
) -> Result<impl IntoResponse, ApiError> {
    if !input.request.is_object() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "request must be a JSON object",
        ));
    }

    let deployment = {
        let deployments = state.deployments.read().await;
        deployments.get(&deployment_id).cloned().ok_or_else(|| {
            api_error(
                StatusCode::NOT_FOUND,
                format!("deployment `{deployment_id}` not found"),
            )
        })?
    };

    let principal = state
        .security
        .authorize(&headers, &deployment.tenant_id)
        .await
        .map_err(security_error)?;
    if principal.user_id != deployment.user_id {
        return Err(api_error(
            StatusCode::FORBIDDEN,
            "deployment belongs to a different authenticated principal",
        ));
    }

    // The durable security-block check inside `authorize` intentionally happens
    // before placement. Once authorized, only these trusted server-side identities
    // are propagated to runtime-host for root-owned cgroup attribution records.
    let runtime = state
        .placement
        .lock()
        .await
        .ensure(
            deployment.execution_class,
            &deployment.user_id,
            &deployment.tenant_id,
            &deployment.shard_id,
            &deployment.deployment_id,
            &deployment.worker_version_id,
        )
        .await
        .map_err(placement_error)?;

    let invocation_id = Uuid::new_v4().to_string();
    let timeout_ms = input
        .timeout_ms
        .unwrap_or(deployment.manifest.runtime_limits.max_wall_ms)
        .min(deployment.manifest.runtime_limits.max_wall_ms);
    if timeout_ms == 0 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "timeout_ms must be positive",
        ));
    }

    let context = json!({
        "invocation_id": invocation_id,
        "user_id": principal.user_id,
        "tenant_id": deployment.tenant_id.clone(),
        "shard_id": deployment.shard_id.clone(),
        "execution_class": deployment.execution_class,
        "execution_backend": deployment.execution_class.backend(),
        "deployment_id": deployment.deployment_id.clone(),
        "worker_version_id": deployment.worker_version_id.clone(),
        "capability_grants": deployment.manifest.capabilities.clone(),
        "deadline_ms": timeout_ms
    });

    let guest_response = dispatch_to_guest(
        &state.runtime_client,
        &state.runtime_control,
        GuestDispatch {
            runtime: &runtime,
            invocation_id: &invocation_id,
            deployment_id: &deployment.worker_version_id,
            request: input.request,
            context,
            timeout_ms,
        },
    )
    .await?;

    let response = InvokeCompleted {
        invocation_id,
        deployment_id: deployment.deployment_id,
        user_id: deployment.user_id,
        worker_version_id: deployment.worker_version_id,
        build_sha256: deployment.manifest.build_sha256,
        tenant_id: deployment.tenant_id,
        shard_id: runtime.shard_id,
        execution_class: runtime.execution_class,
        execution_backend: runtime.execution_backend,
        runtime_host: runtime.runtime_host,
        runtime_epoch: runtime.runtime_epoch,
        runtime_state: runtime.runtime_state,
        status: "completed",
        dispatch_status: "guest_response_received",
        guest_response,
    };
    Ok((StatusCode::OK, Json(response)))
}

async fn dispatch_to_guest(
    client: &Client,
    runtime_control: &RuntimeControlSigner,
    dispatch: GuestDispatch<'_>,
) -> Result<Value, ApiError> {
    let GuestDispatch {
        runtime,
        invocation_id,
        deployment_id,
        request,
        context,
        timeout_ms,
    } = dispatch;
    let url = format!(
        "{}/v1/shards/invoke",
        runtime.runtime_host.trim_end_matches('/')
    );
    let body = RuntimeInvokeRequest {
        tenant_id: &runtime.tenant_id,
        shard_id: &runtime.shard_id,
        execution_class: runtime.execution_class,
        execution_backend: runtime.execution_backend,
        runtime_epoch: runtime.runtime_epoch,
        invocation_id,
        deployment_id,
        request,
        context,
        capability_refs: Vec::new(),
        timeout_ms,
    };
    let payload = if runtime.execution_backend == ExecutionBackend::Firecracker {
        let signed = runtime_control
            .sign(
                RuntimeControlTarget {
                    operation: "invoke",
                    tenant_id: &runtime.tenant_id,
                    shard_id: &runtime.shard_id,
                    execution_class: execution_class_name(runtime.execution_class),
                    execution_backend: execution_backend_name(runtime.execution_backend),
                    runtime_epoch: runtime.runtime_epoch,
                },
                &body,
            )
            .map_err(|err| api_error(StatusCode::SERVICE_UNAVAILABLE, err))?;
        serde_json::to_value(signed)
            .map_err(|err| api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    } else {
        serde_json::to_value(&body)
            .map_err(|err| api_error(StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?
    };
    let response = client
        .post(url)
        .json(&payload)
        .send()
        .await
        .map_err(|err| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("guest dispatch transport failed: {err}"),
            )
        })?;

    let status = response.status();
    if status.is_success() {
        return response.json::<Value>().await.map_err(|err| {
            api_error(
                StatusCode::BAD_GATEWAY,
                format!("runtime host returned invalid guest response: {err}"),
            )
        });
    }

    let message = response
        .json::<ErrorBody>()
        .await
        .map(|body| body.error)
        .unwrap_or_else(|_| format!("runtime host returned HTTP {status}"));
    let outward = if status == reqwest::StatusCode::CONFLICT {
        StatusCode::CONFLICT
    } else if status.is_client_error() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    Err(api_error(outward, message))
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

fn validate_phoenix_manifest(manifest: &PhoenixManifest) -> Result<(), ApiError> {
    if manifest.format_version != 1
        || manifest.artifact_format != "bmscl-phoenix-release-v1"
        || manifest.artifact_root != "release"
        || manifest.runtime != "beam_release"
        || manifest.language != "elixir"
        || manifest.profile != "bmscl-phoenix-elixir-v1"
        || manifest.execution_class != "phoenix"
        || manifest.isolation_class != "firecracker"
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid Phoenix release manifest contract",
        ));
    }

    for (name, digest) in [
        ("source_sha256", manifest.source_sha256.as_str()),
        ("build_sha256", manifest.build_sha256.as_str()),
        ("provenance_sha256", manifest.provenance_sha256.as_str()),
        ("route_plan_sha256", manifest.route_plan_sha256.as_str()),
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                format!("invalid Phoenix {name}"),
            ));
        }
    }

    validate_identity("app", &manifest.app)?;
    if manifest.version.is_empty()
        || manifest.version.len() > 128
        || manifest.version.as_bytes().contains(&0)
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "invalid Phoenix version",
        ));
    }
    for (name, module) in [
        ("router", &manifest.router),
        ("endpoint", &manifest.endpoint),
    ] {
        let valid = !module.is_empty()
            && module.len() <= 256
            && module.split('.').all(|segment| {
                !segment.is_empty()
                    && segment
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            });
        if !valid {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                format!("invalid Phoenix {name} module"),
            ));
        }
    }
    Ok(())
}

fn validate_manifest(
    manifest: &ArtifactManifest,
    execution_class: ExecutionClass,
) -> Result<(), ApiError> {
    if manifest.format_version != 1 {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "unsupported manifest version",
        ));
    }

    match execution_class {
        ExecutionClass::Faas => {
            if manifest.runtime != "beam"
                || manifest.language != "gleam"
                || manifest.profile != "bmscl-hosted-gleam-v1"
            {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "faas requires runtime=beam, language=gleam, profile=bmscl-hosted-gleam-v1",
                ));
            }
            if manifest.runtime_limits.max_processes != 1 {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "faas requires max_processes=1",
                ));
            }
        }
        ExecutionClass::Phoenix => {
            if manifest.runtime != "beam"
                || manifest.language != "elixir"
                || manifest.profile != "bmscl-phoenix-v1"
            {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "phoenix requires runtime=beam, language=elixir, profile=bmscl-phoenix-v1",
                ));
            }
            if !(2..=100_000).contains(&manifest.runtime_limits.max_processes) {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "phoenix requires max_processes in 2..=100000",
                ));
            }
        }
        ExecutionClass::DurableActor => {
            if manifest.runtime != "beam"
                || manifest.language != "gleam"
                || manifest.profile != "bmscl-hosted-gleam-durable-actor-v1"
            {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "durable_actor requires the durable Gleam compiler profile",
                ));
            }
            if manifest.runtime_limits.max_processes != 1 {
                return Err(api_error(
                    StatusCode::BAD_REQUEST,
                    "durable_actor tenant turns require max_processes=1",
                ));
            }
        }
    }

    for (name, digest) in [
        ("source_sha256", manifest.source_sha256.as_str()),
        ("build_sha256", manifest.build_sha256.as_str()),
    ] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                format!("invalid {name}"),
            ));
        }
    }

    let mut capability_names = HashSet::new();
    for grant in &manifest.capabilities {
        if !grant.name.starts_with("ctx.") || !capability_names.insert(grant.name.as_str()) {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "invalid or duplicate capability grant",
            ));
        }
    }

    if manifest.runtime_limits.max_wall_ms == 0
        || manifest.runtime_limits.max_wall_ms > 300_000
        || manifest.runtime_limits.max_reductions == 0
        || manifest.runtime_limits.max_heap_bytes < 1024 * 1024
    {
        return Err(api_error(StatusCode::BAD_REQUEST, "invalid runtime limits"));
    }
    Ok(())
}

fn validate_identity(name: &str, value: &str) -> Result<(), ApiError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(api_error(
            StatusCode::BAD_REQUEST,
            format!("invalid {name}: expected 1..=128 chars of [A-Za-z0-9._-]"),
        ))
    }
}

fn security_error(error: SecurityError) -> ApiError {
    let status = error.status();
    api_error(status, error.to_string())
}

fn placement_error(err: PlacementError) -> ApiError {
    let status = match err {
        PlacementError::Rejected(_) => StatusCode::BAD_REQUEST,
        PlacementError::Conflict(_) => StatusCode::CONFLICT,
        PlacementError::NoHosts(_) | PlacementError::Unavailable(_) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
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

fn default_shard_id() -> String {
    "0".into()
}

fn default_execution_class() -> ExecutionClass {
    ExecutionClass::Faas
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(language: &str, profile: &str, max_processes: u32) -> ArtifactManifest {
        ArtifactManifest {
            format_version: 1,
            runtime: "beam".into(),
            language: language.into(),
            profile: profile.into(),
            source_sha256: "a".repeat(64),
            build_sha256: "b".repeat(64),
            entrypoint: "worker:handle/2".into(),
            capabilities: vec![CapabilityGrant {
                name: "ctx.log".into(),
                scope: None,
            }],
            runtime_limits: RuntimeLimits {
                max_wall_ms: 30_000,
                max_reductions: 50_000_000,
                max_heap_bytes: 64 * 1024 * 1024,
                max_processes,
            },
        }
    }

    fn phoenix_manifest() -> PhoenixManifest {
        PhoenixManifest {
            format_version: 1,
            artifact_format: "bmscl-phoenix-release-v1".into(),
            artifact_root: "release".into(),
            runtime: "beam_release".into(),
            language: "elixir".into(),
            profile: "bmscl-phoenix-elixir-v1".into(),
            execution_class: "phoenix".into(),
            isolation_class: "firecracker".into(),
            source_sha256: "a".repeat(64),
            build_sha256: "b".repeat(64),
            provenance_sha256: "c".repeat(64),
            app: "demo".into(),
            version: "1.0.0".into(),
            router: "DemoWeb.Router".into(),
            endpoint: "DemoWeb.Endpoint".into(),
            route_plan_sha256: "d".repeat(64),
        }
    }

    #[test]
    fn phoenix_manifest_requires_compiler_release_contract() {
        let good = phoenix_manifest();
        assert!(validate_phoenix_manifest(&good).is_ok());

        let mut wrong_profile = phoenix_manifest();
        wrong_profile.profile = "bmscl-phoenix-v1".into();
        assert!(validate_phoenix_manifest(&wrong_profile).is_err());

        let mut wrong_isolation = phoenix_manifest();
        wrong_isolation.isolation_class = "bare_process".into();
        assert!(validate_phoenix_manifest(&wrong_isolation).is_err());
    }

    #[test]
    fn standard_faas_is_single_process_gleam() {
        let good = manifest("gleam", "bmscl-hosted-gleam-v1", 1);
        assert!(validate_manifest(&good, ExecutionClass::Faas).is_ok());

        let fanout = manifest("gleam", "bmscl-hosted-gleam-v1", 2);
        assert!(validate_manifest(&fanout, ExecutionClass::Faas).is_err());
    }

    #[test]
    fn phoenix_requires_elixir_profile_and_process_tree_budget() {
        let good = manifest("elixir", "bmscl-phoenix-v1", 4096);
        assert!(validate_manifest(&good, ExecutionClass::Phoenix).is_ok());

        let wrong_language = manifest("gleam", "bmscl-phoenix-v1", 4096);
        assert!(validate_manifest(&wrong_language, ExecutionClass::Phoenix).is_err());

        let single_process = manifest("elixir", "bmscl-phoenix-v1", 1);
        assert!(validate_manifest(&single_process, ExecutionClass::Phoenix).is_err());
    }

    #[test]
    fn durable_actor_keeps_tenant_turn_single_process() {
        let good = manifest("gleam", "bmscl-hosted-gleam-durable-actor-v1", 1);
        assert!(validate_manifest(&good, ExecutionClass::DurableActor).is_ok());

        let wrong_profile = manifest("gleam", "bmscl-hosted-gleam-v1", 1);
        assert!(validate_manifest(&wrong_profile, ExecutionClass::DurableActor).is_err());
    }

    #[test]
    fn execution_class_selects_security_backend() {
        assert_eq!(
            ExecutionClass::Faas.backend(),
            ExecutionBackend::BareProcess
        );
        assert_eq!(
            ExecutionClass::Phoenix.backend(),
            ExecutionBackend::Firecracker
        );
        assert_eq!(
            ExecutionClass::DurableActor.backend(),
            ExecutionBackend::Firecracker
        );
    }

    #[test]
    fn critical_section_request_id_is_bounded_and_nonempty() {
        assert!(validate_request_id("request-1").is_ok());
        assert!(validate_request_id("").is_err());
        assert!(validate_request_id(&"r".repeat(257)).is_err());
        assert!(validate_request_id("request\0bad").is_err());
    }

    #[test]
    fn rejects_path_traversal_tenant_identity() {
        assert!(validate_identity("tenant_id", "../root").is_err());
        assert!(validate_identity("tenant_id", "acme-prod").is_ok());
    }
}
