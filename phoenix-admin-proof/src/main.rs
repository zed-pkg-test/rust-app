mod archive;

use anyhow::{bail, Context, Result};
use archive::{extract_artifact, ArchiveLimits};
use axum::{
    extract::{Multipart, Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, process::Command, sync::Mutex};

const META_FILE: &str = ".deployment.json";
const TARGETS_DIR: &str = ".targets";
const DEFAULT_MAX_UPLOAD_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone)]
struct AppState {
    artifact_root: PathBuf,
    compiler: String,
    trusted_signing_keys: BTreeMap<String, String>,
    max_upload_bytes: usize,
    targets_lock: Arc<Mutex<()>>,
}

struct StagingGuard {
    path: PathBuf,
    armed: bool,
}

impl StagingGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

#[derive(Serialize)]
struct AdminRuntime {
    service: &'static str,
    network_domain: &'static str,
    public: bool,
    artifact_ingest: &'static str,
    activation_bridge: &'static str,
}

#[derive(Debug, Deserialize)]
struct ManifestSummary {
    build_sha256: String,
    source_sha256: String,
    runtime: String,
    language: String,
    profile: String,
}

#[derive(Debug, Deserialize)]
struct AttestationSummary {
    format: String,
    algorithm: String,
    key_id: String,
    build_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeploymentRecord {
    build_sha256: String,
    source_sha256: String,
    runtime: String,
    language: String,
    profile: String,
    key_id: String,
    archive_sha256: String,
    archive_name: String,
    archive_bytes: usize,
    accepted_unix_seconds: u64,
    verification_state: String,
    activation_state: String,
}

#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
enum DeploymentUnitKind {
    #[default]
    Lambda,
    Middleware,
}

impl DeploymentUnitKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Lambda => "lambda",
            Self::Middleware => "middleware",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LambdaCandidate {
    name: String,
    build_sha256: String,
    source_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeploymentUnitCandidate {
    kind: DeploymentUnitKind,
    name: String,
    build_sha256: String,
    source_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeploymentUnitTombstone {
    kind: DeploymentUnitKind,
    name: String,
}

#[derive(Debug, Clone, Deserialize)]
struct DeploymentPlanRequest {
    project: String,
    environment: String,
    #[serde(default)]
    git_commit: Option<String>,
    #[serde(default)]
    force: bool,
    #[serde(default)]
    expected_revision: Option<u64>,
    #[serde(default)]
    lambdas: Vec<LambdaCandidate>,
    #[serde(default)]
    units: Vec<DeploymentUnitCandidate>,
    #[serde(default)]
    tombstones: Vec<DeploymentUnitTombstone>,
}

#[derive(Debug, Clone, Serialize)]
struct PlannedDeploymentUnit {
    kind: DeploymentUnitKind,
    name: String,
    tombstone: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    build_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    current_build_sha256: Option<String>,
    artifact_present: bool,
    reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct DeploymentPlanResponse {
    project: String,
    environment: String,
    revision: u64,
    changed: Vec<PlannedDeploymentUnit>,
    unchanged: Vec<PlannedDeploymentUnit>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeploymentTarget {
    #[serde(default)]
    kind: DeploymentUnitKind,
    name: String,
    build_sha256: String,
    source_sha256: String,
    git_commit: Option<String>,
    updated_unix_seconds: u64,
    activation_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeploymentTombstoneRecord {
    kind: DeploymentUnitKind,
    name: String,
    git_commit: Option<String>,
    updated_unix_seconds: u64,
    activation_state: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DeploymentTargetState {
    format_version: u32,
    project: String,
    environment: String,
    revision: u64,
    lambdas: BTreeMap<String, DeploymentTarget>,
    #[serde(default)]
    middleware: BTreeMap<String, DeploymentTarget>,
    #[serde(default)]
    tombstones: BTreeMap<String, DeploymentTombstoneRecord>,
}

#[derive(Debug, Serialize)]
struct DeploymentApplyResponse {
    project: String,
    environment: String,
    previous_revision: u64,
    revision: u64,
    applied: Vec<PlannedDeploymentUnit>,
    unchanged: Vec<PlannedDeploymentUnit>,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn unprocessable(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            message: message.into(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
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
            eprintln!("invalid bmscl admin API configuration: {error:#}");
            std::process::exit(2);
        }
    };
    if let Err(error) = tokio::fs::create_dir_all(&state.artifact_root).await {
        eprintln!("create artifact root failed: {error}");
        std::process::exit(2);
    }

    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/admin/runtime", get(runtime))
        .route(
            "/v1/admin/deployments",
            get(list_deployments).post(upload_deployment),
        )
        .route("/v1/admin/deployments/{build_sha256}", get(get_deployment))
        .route("/v1/admin/deployment-plans", post(plan_deployment))
        .route(
            "/v1/admin/deployment-targets/{project}/{environment}",
            get(get_deployment_target_state),
        )
        .route(
            "/v1/admin/deployment-targets/apply",
            post(apply_deployment_targets),
        )
        .with_state(state);

    let bind = env::var("BMSCL_BIND").unwrap_or_else(|_| "127.0.0.1:8181".into());
    let listener = TcpListener::bind(&bind).await.expect("bind admin api");
    tracing::info!(%bind, "bmscl admin api listening");
    axum::serve(listener, app).await.expect("serve admin api");
}

async fn runtime() -> Json<AdminRuntime> {
    Json(AdminRuntime {
        service: "bmscl-admin-api-server",
        network_domain: "admin",
        public: false,
        artifact_ingest: "signed-bundle-v2",
        activation_bridge: "not-connected",
    })
}

async fn list_deployments(
    State(state): State<AppState>,
) -> Result<Json<Vec<DeploymentRecord>>, ApiError> {
    let root = state.artifact_root.clone();
    let mut deployments = tokio::task::spawn_blocking(move || read_all_records(&root))
        .await
        .map_err(|error| ApiError::internal(format!("deployment registry task failed: {error}")))?
        .map_err(|error| ApiError::internal(format!("read deployment registry: {error:#}")))?;
    deployments.sort_by_key(|deployment| std::cmp::Reverse(deployment.accepted_unix_seconds));
    Ok(Json(deployments))
}

async fn get_deployment(
    State(state): State<AppState>,
    AxumPath(build_sha256): AxumPath<String>,
) -> Result<Json<DeploymentRecord>, ApiError> {
    validate_sha256(&build_sha256).map_err(ApiError::bad_request)?;
    let record = read_record(&state.artifact_root.join(&build_sha256))
        .map_err(|_| ApiError::not_found("deployment not found"))?;
    Ok(Json(record))
}

async fn plan_deployment(
    State(state): State<AppState>,
    Json(request): Json<DeploymentPlanRequest>,
) -> Result<Json<DeploymentPlanResponse>, ApiError> {
    validate_deployment_request(&request).map_err(ApiError::bad_request)?;
    let _guard = state.targets_lock.lock().await;
    build_deployment_plan(&state.artifact_root, &request).map(Json)
}

async fn get_deployment_target_state(
    State(state): State<AppState>,
    AxumPath((project, environment)): AxumPath<(String, String)>,
) -> Result<Json<DeploymentTargetState>, ApiError> {
    validate_target_segment("project", &project).map_err(ApiError::bad_request)?;
    validate_target_segment("environment", &environment).map_err(ApiError::bad_request)?;
    let _guard = state.targets_lock.lock().await;
    let targets = read_target_state(&state.artifact_root, &project, &environment)
        .map_err(|error| ApiError::internal(format!("read deployment targets: {error:#}")))?;
    Ok(Json(targets))
}

async fn apply_deployment_targets(
    State(state): State<AppState>,
    Json(request): Json<DeploymentPlanRequest>,
) -> Result<(StatusCode, Json<DeploymentApplyResponse>), ApiError> {
    validate_deployment_request(&request).map_err(ApiError::bad_request)?;
    let _guard = state.targets_lock.lock().await;
    let mut targets =
        read_target_state(&state.artifact_root, &request.project, &request.environment)
            .map_err(|error| ApiError::internal(format!("read deployment targets: {error:#}")))?;
    let expected = request.expected_revision.ok_or_else(|| {
        ApiError::bad_request("expected_revision is required when applying deployment targets")
    })?;
    if expected != targets.revision {
        return Err(ApiError::conflict(format!(
            "deployment state advanced from revision {expected} to {}; re-plan before applying",
            targets.revision
        )));
    }

    let plan = build_deployment_plan_from_state(&state.artifact_root, &request, &targets);
    let previous_revision = targets.revision;
    let now = unix_seconds().map_err(ApiError::internal)?;
    apply_plan_changes(&state.artifact_root, &request, &plan, &mut targets, now)?;

    if !plan.changed.is_empty() {
        targets.revision = targets
            .revision
            .checked_add(1)
            .ok_or_else(|| ApiError::internal("deployment target revision overflow"))?;
        write_target_state(&state.artifact_root, &targets)
            .map_err(|error| ApiError::internal(format!("write deployment targets: {error:#}")))?;
    }
    let status = if plan.changed.is_empty() {
        StatusCode::OK
    } else {
        StatusCode::CREATED
    };
    Ok((
        status,
        Json(DeploymentApplyResponse {
            project: request.project,
            environment: request.environment,
            previous_revision,
            revision: targets.revision,
            applied: plan.changed,
            unchanged: plan.unchanged,
        }),
    ))
}

fn apply_plan_changes(
    artifact_root: &Path,
    request: &DeploymentPlanRequest,
    plan: &DeploymentPlanResponse,
    targets: &mut DeploymentTargetState,
    now: u64,
) -> Result<(), ApiError> {
    for planned in &plan.changed {
        let key = tombstone_key(planned.kind, &planned.name);
        if planned.tombstone {
            target_map_mut(targets, planned.kind).remove(&planned.name);
            targets.tombstones.insert(
                key,
                DeploymentTombstoneRecord {
                    kind: planned.kind,
                    name: planned.name.clone(),
                    git_commit: request.git_commit.clone(),
                    updated_unix_seconds: now,
                    activation_state: "not-connected".into(),
                },
            );
            continue;
        }

        let build_sha256 = planned
            .build_sha256
            .as_deref()
            .ok_or_else(|| ApiError::internal("planned active unit is missing build_sha256"))?;
        let source_sha256 = planned
            .source_sha256
            .as_deref()
            .ok_or_else(|| ApiError::internal("planned active unit is missing source_sha256"))?;
        let artifact = read_record(&artifact_root.join(build_sha256)).map_err(|_| {
            ApiError::unprocessable(format!(
                "artifact {build_sha256} for {} `{}` is not present; upload it before applying",
                planned.kind.as_str(),
                planned.name
            ))
        })?;
        if artifact.build_sha256 != build_sha256 {
            return Err(ApiError::internal(format!(
                "artifact registry key does not match stored digest for {build_sha256}"
            )));
        }
        if artifact.source_sha256 != source_sha256 {
            return Err(ApiError::unprocessable(format!(
                "artifact source digest for {} `{}` does not match the planned source digest",
                planned.kind.as_str(),
                planned.name
            )));
        }

        target_map_mut(targets, planned.kind).insert(
            planned.name.clone(),
            DeploymentTarget {
                kind: planned.kind,
                name: planned.name.clone(),
                build_sha256: artifact.build_sha256,
                source_sha256: artifact.source_sha256,
                git_commit: request.git_commit.clone(),
                updated_unix_seconds: now,
                activation_state: "not-connected".into(),
            },
        );
        targets.tombstones.remove(&key);
    }
    Ok(())
}

async fn upload_deployment(
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> Result<(StatusCode, Json<DeploymentRecord>), ApiError> {
    let mut upload: Option<(String, Vec<u8>)> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|error| ApiError::bad_request(format!("invalid multipart upload: {error}")))?
    {
        if field.name() != Some("artifact") {
            continue;
        }
        let filename = field
            .file_name()
            .unwrap_or("worker.zip")
            .rsplit('/')
            .next()
            .unwrap_or("worker.zip")
            .rsplit('\\')
            .next()
            .unwrap_or("worker.zip")
            .to_string();
        let bytes = field
            .bytes()
            .await
            .map_err(|error| ApiError::bad_request(format!("read artifact upload: {error}")))?;
        if bytes.len() > state.max_upload_bytes {
            return Err(ApiError {
                status: StatusCode::PAYLOAD_TOO_LARGE,
                message: format!(
                    "artifact is {} bytes; maximum is {} bytes",
                    bytes.len(),
                    state.max_upload_bytes
                ),
            });
        }
        upload = Some((filename, bytes.to_vec()));
        break;
    }

    let (filename, bytes) =
        upload.ok_or_else(|| ApiError::bad_request("missing multipart field `artifact`"))?;
    let archive_sha256 = sha256_hex(&bytes);
    let staging = state
        .artifact_root
        .join(format!(".staging-{archive_sha256}-{}", std::process::id()));
    if staging.exists() {
        tokio::fs::remove_dir_all(&staging).await.map_err(|error| {
            ApiError::internal(format!("clean stale staging directory: {error}"))
        })?;
    }
    tokio::fs::create_dir_all(&staging)
        .await
        .map_err(|error| ApiError::internal(format!("create staging directory: {error}")))?;
    let mut staging_guard = StagingGuard::new(staging.clone());

    let extract_bytes = bytes.clone();
    let extract_name = filename.clone();
    let extract_dir = staging.clone();
    let limits = ArchiveLimits::for_upload_ceiling(state.max_upload_bytes);
    let extract_result = tokio::task::spawn_blocking(move || {
        extract_artifact(&extract_name, &extract_bytes, &extract_dir, limits)
    })
    .await
    .map_err(|error| ApiError::internal(format!("artifact extraction task failed: {error}")))?;
    if let Err(error) = extract_result {
        return Err(ApiError::unprocessable(format!(
            "invalid deployment archive: {error:#}"
        )));
    }

    let manifest: ManifestSummary = read_json(&staging.join("manifest.json"))
        .map_err(|error| ApiError::unprocessable(format!("invalid manifest: {error:#}")))?;
    let attestation: AttestationSummary = read_json(&staging.join("attestation.json"))
        .map_err(|error| ApiError::unprocessable(format!("invalid attestation: {error:#}")))?;
    validate_sha256(&manifest.build_sha256).map_err(ApiError::unprocessable)?;
    validate_sha256(&manifest.source_sha256).map_err(ApiError::unprocessable)?;
    if manifest.build_sha256 != attestation.build_sha256 {
        return Err(ApiError::unprocessable(
            "manifest and attestation build_sha256 values differ",
        ));
    }
    if attestation.format != "bmscl-artifact-attestation-v2" || attestation.algorithm != "ed25519" {
        return Err(ApiError::unprocessable(
            "unsupported artifact attestation format",
        ));
    }

    let public_key = state
        .trusted_signing_keys
        .get(&attestation.key_id)
        .ok_or_else(|| {
            ApiError::forbidden(format!("untrusted signing key `{}`", attestation.key_id))
        })?;
    verify_with_compiler(&state.compiler, &staging, public_key, &attestation.key_id).await?;

    let archive_name = canonical_archive_name(&filename, &bytes)?;
    tokio::fs::write(staging.join(&archive_name), &bytes)
        .await
        .map_err(|error| ApiError::internal(format!("persist uploaded archive: {error}")))?;
    let record = DeploymentRecord {
        build_sha256: manifest.build_sha256.clone(),
        source_sha256: manifest.source_sha256,
        runtime: manifest.runtime,
        language: manifest.language,
        profile: manifest.profile,
        key_id: attestation.key_id,
        archive_sha256,
        archive_name,
        archive_bytes: bytes.len(),
        accepted_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                ApiError::internal(format!("system clock before Unix epoch: {error}"))
            })?
            .as_secs(),
        verification_state: "verified".into(),
        activation_state: "not-connected".into(),
    };
    tokio::fs::write(
        staging.join(META_FILE),
        serde_json::to_vec_pretty(&record).map_err(|error| {
            ApiError::internal(format!("serialize deployment metadata: {error}"))
        })?,
    )
    .await
    .map_err(|error| ApiError::internal(format!("write deployment metadata: {error}")))?;

    let final_dir = state.artifact_root.join(&record.build_sha256);
    if final_dir.exists() {
        let existing = read_record(&final_dir)
            .map_err(|error| ApiError::internal(format!("read existing deployment: {error:#}")))?;
        return Ok((StatusCode::OK, Json(existing)));
    }
    tokio::fs::rename(&staging, &final_dir)
        .await
        .map_err(|error| ApiError::internal(format!("commit immutable deployment: {error}")))?;
    staging_guard.disarm();
    Ok((StatusCode::CREATED, Json(record)))
}

async fn verify_with_compiler(
    compiler: &str,
    artifact_dir: &Path,
    public_key: &str,
    key_id: &str,
) -> Result<(), ApiError> {
    let output = Command::new(compiler)
        .arg("verify")
        .arg(artifact_dir)
        .arg("--public-key")
        .arg(public_key)
        .arg("--key-id")
        .arg(key_id)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|error| ApiError::internal(format!("launch {compiler} verifier: {error}")))?;
    if !output.status.success() {
        return Err(ApiError::unprocessable(format!(
            "artifact verification failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn state_from_env() -> Result<AppState> {
    let artifact_root = env::var_os("BMSCL_ARTIFACT_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("./var/deployments"));
    let compiler = env::var("BMSCL_COMPILER").unwrap_or_else(|_| "bmscl-compiler".into());
    let trusted_signing_keys: BTreeMap<String, String> =
        match env::var("BMSCL_TRUSTED_SIGNING_KEYS_JSON") {
            Ok(value) => serde_json::from_str(&value).context(
                "BMSCL_TRUSTED_SIGNING_KEYS_JSON must be a JSON object of key_id -> public-key-hex",
            )?,
            Err(_) => BTreeMap::new(),
        };
    for (key_id, public_key) in &trusted_signing_keys {
        validate_key_id(key_id)?;
        if public_key.len() != 64 || !public_key.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!("trusted public key `{key_id}` must be 64 hexadecimal characters");
        }
    }
    let max_upload_bytes = env::var("BMSCL_MAX_ARTIFACT_BYTES")
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .context("BMSCL_MAX_ARTIFACT_BYTES must be an integer")?
        .unwrap_or(DEFAULT_MAX_UPLOAD_BYTES);
    Ok(AppState {
        artifact_root,
        compiler,
        trusted_signing_keys,
        max_upload_bytes,
        targets_lock: Arc::new(Mutex::new(())),
    })
}

fn canonical_units(request: &DeploymentPlanRequest) -> Vec<DeploymentUnitCandidate> {
    let mut units = Vec::with_capacity(request.lambdas.len() + request.units.len());
    units.extend(
        request
            .lambdas
            .iter()
            .map(|lambda| DeploymentUnitCandidate {
                kind: DeploymentUnitKind::Lambda,
                name: lambda.name.clone(),
                build_sha256: lambda.build_sha256.clone(),
                source_sha256: lambda.source_sha256.clone(),
            }),
    );
    units.extend(request.units.iter().cloned());
    units
}

fn validate_deployment_request(request: &DeploymentPlanRequest) -> Result<(), String> {
    validate_target_segment("project", &request.project)?;
    validate_target_segment("environment", &request.environment)?;
    let total = request.lambdas.len() + request.units.len() + request.tombstones.len();
    if total == 0 {
        return Err("deployment request must contain at least one unit or tombstone".into());
    }
    if total > 1_000 {
        return Err("deployment request may contain at most 1000 units and tombstones".into());
    }
    if let Some(commit) = &request.git_commit {
        if commit.len() < 7
            || commit.len() > 64
            || !commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("git_commit must be 7-64 lowercase hexadecimal characters".into());
        }
    }

    let mut active = BTreeSet::new();
    for unit in canonical_units(request) {
        validate_deployment_unit_name(unit.kind, &unit.name)?;
        validate_sha256(&unit.build_sha256)?;
        validate_sha256(&unit.source_sha256)?;
        let identity = (unit.kind, unit.name.clone());
        if !active.insert(identity) {
            return Err(format!(
                "duplicate {} unit name `{}`",
                unit.kind.as_str(),
                unit.name
            ));
        }
    }

    let mut tombstones = BTreeSet::new();
    for tombstone in &request.tombstones {
        validate_deployment_unit_name(tombstone.kind, &tombstone.name)?;
        let identity = (tombstone.kind, tombstone.name.clone());
        if active.contains(&identity) {
            return Err(format!(
                "{} `{}` cannot be both active and tombstoned in one request",
                tombstone.kind.as_str(),
                tombstone.name
            ));
        }
        if !tombstones.insert(identity) {
            return Err(format!(
                "duplicate {} tombstone `{}`",
                tombstone.kind.as_str(),
                tombstone.name
            ));
        }
    }
    Ok(())
}

fn validate_target_segment(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!(
            "{label} must contain only ASCII letters, digits, '.', '_' or '-' and be at most 128 characters"
        ));
    }
    Ok(())
}

fn validate_deployment_unit_name(kind: DeploymentUnitKind, value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 256 || value.starts_with('/') || value.ends_with('/') {
        return Err(format!(
            "{} name must be 1-256 characters and cannot start or end with '/'",
            kind.as_str()
        ));
    }
    for segment in value.split('/') {
        validate_target_segment(&format!("{} path segment", kind.as_str()), segment)?;
        if segment == "." || segment == ".." {
            return Err(format!(
                "{} name cannot contain '.' or '..' path segments",
                kind.as_str()
            ));
        }
    }
    Ok(())
}

fn build_deployment_plan(
    artifact_root: &Path,
    request: &DeploymentPlanRequest,
) -> Result<DeploymentPlanResponse, ApiError> {
    let targets = read_target_state(artifact_root, &request.project, &request.environment)
        .map_err(|error| ApiError::internal(format!("read deployment targets: {error:#}")))?;
    Ok(build_deployment_plan_from_state(
        artifact_root,
        request,
        &targets,
    ))
}

fn build_deployment_plan_from_state(
    artifact_root: &Path,
    request: &DeploymentPlanRequest,
    targets: &DeploymentTargetState,
) -> DeploymentPlanResponse {
    let mut changed = Vec::new();
    let mut unchanged = Vec::new();

    for unit in canonical_units(request) {
        let current = target_map(targets, unit.kind).get(&unit.name);
        let artifact_present = read_record(&artifact_root.join(&unit.build_sha256)).is_ok();
        let reason = if request.force {
            "forced"
        } else if current.is_none() {
            "not_deployed"
        } else if current.map(|target| target.build_sha256.as_str())
            != Some(unit.build_sha256.as_str())
        {
            "build_changed"
        } else if !artifact_present {
            "artifact_missing"
        } else {
            "up_to_date"
        };
        let planned = PlannedDeploymentUnit {
            kind: unit.kind,
            name: unit.name,
            tombstone: false,
            build_sha256: Some(unit.build_sha256),
            source_sha256: Some(unit.source_sha256),
            current_build_sha256: current.map(|target| target.build_sha256.clone()),
            artifact_present,
            reason,
        };
        if reason == "up_to_date" {
            unchanged.push(planned);
        } else {
            changed.push(planned);
        }
    }

    for tombstone in &request.tombstones {
        let current = target_map(targets, tombstone.kind).get(&tombstone.name);
        let key = tombstone_key(tombstone.kind, &tombstone.name);
        let already_tombstoned = targets.tombstones.contains_key(&key);
        let reason = if request.force {
            "forced"
        } else if current.is_some() || !already_tombstoned {
            "deleted"
        } else {
            "already_deleted"
        };
        let planned = PlannedDeploymentUnit {
            kind: tombstone.kind,
            name: tombstone.name.clone(),
            tombstone: true,
            build_sha256: None,
            source_sha256: None,
            current_build_sha256: current.map(|target| target.build_sha256.clone()),
            artifact_present: false,
            reason,
        };
        if reason == "already_deleted" {
            unchanged.push(planned);
        } else {
            changed.push(planned);
        }
    }

    DeploymentPlanResponse {
        project: request.project.clone(),
        environment: request.environment.clone(),
        revision: targets.revision,
        changed,
        unchanged,
    }
}

fn target_map(
    state: &DeploymentTargetState,
    kind: DeploymentUnitKind,
) -> &BTreeMap<String, DeploymentTarget> {
    match kind {
        DeploymentUnitKind::Lambda => &state.lambdas,
        DeploymentUnitKind::Middleware => &state.middleware,
    }
}

fn target_map_mut(
    state: &mut DeploymentTargetState,
    kind: DeploymentUnitKind,
) -> &mut BTreeMap<String, DeploymentTarget> {
    match kind {
        DeploymentUnitKind::Lambda => &mut state.lambdas,
        DeploymentUnitKind::Middleware => &mut state.middleware,
    }
}

fn tombstone_key(kind: DeploymentUnitKind, name: &str) -> String {
    format!("{}/{}", kind.as_str(), name)
}

fn target_state_path(root: &Path, project: &str, environment: &str) -> PathBuf {
    let key = sha256_hex(format!("{project}\0{environment}").as_bytes());
    root.join(TARGETS_DIR).join(format!("{key}.json"))
}

fn read_target_state(
    root: &Path,
    project: &str,
    environment: &str,
) -> Result<DeploymentTargetState> {
    let path = target_state_path(root, project, environment);
    if !path.exists() {
        return Ok(DeploymentTargetState {
            format_version: 1,
            project: project.into(),
            environment: environment.into(),
            revision: 0,
            lambdas: BTreeMap::new(),
            middleware: BTreeMap::new(),
            tombstones: BTreeMap::new(),
        });
    }
    let state: DeploymentTargetState = read_json(&path)?;
    if state.format_version != 1 || state.project != project || state.environment != environment {
        bail!(
            "deployment target state identity or format mismatch in {}",
            path.display()
        );
    }
    validate_target_state(&state).with_context(|| format!("validate {}", path.display()))?;
    Ok(state)
}

fn validate_target_state(state: &DeploymentTargetState) -> Result<()> {
    for (name, target) in &state.lambdas {
        if target.kind != DeploymentUnitKind::Lambda || target.name != *name {
            bail!("lambda target map contains inconsistent identity `{name}`");
        }
    }
    for (name, target) in &state.middleware {
        if target.kind != DeploymentUnitKind::Middleware || target.name != *name {
            bail!("middleware target map contains inconsistent identity `{name}`");
        }
    }
    for (key, tombstone) in &state.tombstones {
        if *key != tombstone_key(tombstone.kind, &tombstone.name) {
            bail!("deployment tombstone map contains inconsistent identity `{key}`");
        }
        if target_map(state, tombstone.kind).contains_key(&tombstone.name) {
            bail!(
                "{} `{}` cannot be both active and tombstoned in target state",
                tombstone.kind.as_str(),
                tombstone.name
            );
        }
    }
    Ok(())
}

fn write_target_state(root: &Path, state: &DeploymentTargetState) -> Result<()> {
    validate_target_state(state)?;
    let directory = root.join(TARGETS_DIR);
    fs::create_dir_all(&directory)?;
    let path = target_state_path(root, &state.project, &state.environment);
    let temporary = directory.join(format!(
        ".tmp-{}-{}-{}",
        std::process::id(),
        state.revision,
        sha256_hex(path.to_string_lossy().as_bytes())
    ));
    fs::write(&temporary, serde_json::to_vec_pretty(state)?)?;
    fs::rename(&temporary, &path)?;
    Ok(())
}

fn unix_seconds() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock before Unix epoch: {error}"))
}

#[cfg(test)]
fn validate_artifact_path(path: &Path) -> Result<()> {
    archive::validate_artifact_path(path)
}

fn canonical_archive_name(filename: &str, bytes: &[u8]) -> Result<String, ApiError> {
    if bytes.starts_with(b"PK\x03\x04") || filename.ends_with(".zip") {
        Ok("worker.zip".into())
    } else if bytes.starts_with(&[0x1f, 0x8b])
        || filename.ends_with(".tar.gz")
        || filename.ends_with(".tgz")
    {
        if filename.ends_with("phoenix-release.tar.gz") {
            Ok("phoenix-release.tar.gz".into())
        } else {
            Ok("worker.tar.gz".into())
        }
    } else {
        Err(ApiError::bad_request("unsupported artifact archive format"))
    }
}

fn read_all_records(root: &Path) -> Result<Vec<DeploymentRecord>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut records = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() || entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        if let Ok(record) = read_record(&entry.path()) {
            records.push(record);
        }
    }
    Ok(records)
}

fn read_record(directory: &Path) -> Result<DeploymentRecord> {
    read_json(&directory.join(META_FILE))
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

fn validate_sha256(value: &str) -> Result<(), String> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("expected lowercase 64-character SHA-256 hexadecimal value".into());
    }
    Ok(())
}

fn validate_key_id(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        bail!("invalid trusted signing key id `{value}`");
    }
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn candidate(name: &str, build: char, source: char) -> LambdaCandidate {
        LambdaCandidate {
            name: name.into(),
            build_sha256: build.to_string().repeat(64),
            source_sha256: source.to_string().repeat(64),
        }
    }

    fn typed_candidate(
        kind: DeploymentUnitKind,
        name: &str,
        build: char,
        source: char,
    ) -> DeploymentUnitCandidate {
        DeploymentUnitCandidate {
            kind,
            name: name.into(),
            build_sha256: build.to_string().repeat(64),
            source_sha256: source.to_string().repeat(64),
        }
    }

    fn request(lambdas: Vec<LambdaCandidate>) -> DeploymentPlanRequest {
        DeploymentPlanRequest {
            project: "payments".into(),
            environment: "production".into(),
            git_commit: Some("a".repeat(40)),
            force: false,
            expected_revision: None,
            lambdas,
            units: Vec::new(),
            tombstones: Vec::new(),
        }
    }

    fn target(kind: DeploymentUnitKind, name: &str, build: char, source: char) -> DeploymentTarget {
        DeploymentTarget {
            kind,
            name: name.into(),
            build_sha256: build.to_string().repeat(64),
            source_sha256: source.to_string().repeat(64),
            git_commit: None,
            updated_unix_seconds: 1,
            activation_state: "not-connected".into(),
        }
    }

    fn write_artifact(root: &Path, build: char, source: char) {
        let build_sha256 = build.to_string().repeat(64);
        let directory = root.join(&build_sha256);
        fs::create_dir_all(&directory).unwrap();
        let record = DeploymentRecord {
            build_sha256,
            source_sha256: source.to_string().repeat(64),
            runtime: "beam".into(),
            language: "gleam".into(),
            profile: "bmscl-hosted-gleam-v1".into(),
            key_id: "test-key".into(),
            archive_sha256: "f".repeat(64),
            archive_name: "worker.zip".into(),
            archive_bytes: 3,
            accepted_unix_seconds: 1,
            verification_state: "verified".into(),
            activation_state: "not-connected".into(),
        };
        fs::write(
            directory.join(META_FILE),
            serde_json::to_vec_pretty(&record).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn only_compiler_artifact_paths_are_accepted() {
        assert!(validate_artifact_path(Path::new("manifest.json")).is_ok());
        assert!(validate_artifact_path(Path::new("provenance.json")).is_ok());
        assert!(validate_artifact_path(Path::new("beam/worker.beam")).is_ok());
        assert!(validate_artifact_path(Path::new("beam/helper.beam")).is_ok());
        assert!(validate_artifact_path(Path::new("../etc/passwd")).is_err());
        assert!(validate_artifact_path(Path::new("beam/../../escape.beam")).is_err());
        assert!(validate_artifact_path(Path::new("random.txt")).is_err());
        assert!(validate_artifact_path(Path::new("beam/nested/helper.beam")).is_err());
    }

    #[test]
    fn validates_key_ids_and_hashes() {
        assert!(validate_key_id("build-2026-q3").is_ok());
        assert!(validate_key_id("../build-key").is_err());
        assert!(validate_sha256(&"ab".repeat(32)).is_ok());
        assert!(validate_sha256("ABC").is_err());
    }

    #[test]
    fn plans_only_new_or_changed_lambda_digests() {
        let directory = tempdir().unwrap();
        write_artifact(directory.path(), 'a', 'b');
        let mut state = read_target_state(directory.path(), "payments", "production").unwrap();
        state.lambdas.insert(
            "unchanged".into(),
            target(DeploymentUnitKind::Lambda, "unchanged", 'a', 'b'),
        );
        let plan = build_deployment_plan_from_state(
            directory.path(),
            &request(vec![
                candidate("unchanged", 'a', 'b'),
                candidate("new", 'c', 'd'),
            ]),
            &state,
        );
        assert_eq!(plan.unchanged.len(), 1);
        assert_eq!(plan.unchanged[0].name, "unchanged");
        assert_eq!(plan.unchanged[0].kind, DeploymentUnitKind::Lambda);
        assert_eq!(plan.changed.len(), 1);
        assert_eq!(plan.changed[0].name, "new");
        assert_eq!(plan.changed[0].reason, "not_deployed");
    }

    #[test]
    fn force_reapplies_an_identical_lambda() {
        let directory = tempdir().unwrap();
        write_artifact(directory.path(), 'a', 'b');
        let mut state = read_target_state(directory.path(), "payments", "production").unwrap();
        state.lambdas.insert(
            "worker".into(),
            target(DeploymentUnitKind::Lambda, "worker", 'a', 'b'),
        );
        let mut deploy = request(vec![candidate("worker", 'a', 'b')]);
        deploy.force = true;
        let plan = build_deployment_plan_from_state(directory.path(), &deploy, &state);
        assert_eq!(plan.changed.len(), 1);
        assert_eq!(plan.changed[0].reason, "forced");
    }

    #[test]
    fn changed_build_digest_is_selected_for_deployment() {
        let directory = tempdir().unwrap();
        write_artifact(directory.path(), 'c', 'd');
        let mut state = read_target_state(directory.path(), "payments", "production").unwrap();
        state.lambdas.insert(
            "worker".into(),
            target(DeploymentUnitKind::Lambda, "worker", 'a', 'b'),
        );
        let plan = build_deployment_plan_from_state(
            directory.path(),
            &request(vec![candidate("worker", 'c', 'd')]),
            &state,
        );
        assert_eq!(plan.changed.len(), 1);
        assert_eq!(plan.changed[0].reason, "build_changed");
        assert!(plan.changed[0].artifact_present);
    }

    #[test]
    fn typed_middleware_is_planned_separately_from_lambda() {
        let directory = tempdir().unwrap();
        write_artifact(directory.path(), 'c', 'd');
        let mut deploy = request(Vec::new());
        deploy.units.push(typed_candidate(
            DeploymentUnitKind::Middleware,
            "auth/request",
            'c',
            'd',
        ));
        validate_deployment_request(&deploy).unwrap();
        let state = read_target_state(directory.path(), "payments", "production").unwrap();
        let plan = build_deployment_plan_from_state(directory.path(), &deploy, &state);
        assert_eq!(plan.changed.len(), 1);
        assert_eq!(plan.changed[0].kind, DeploymentUnitKind::Middleware);
        assert_eq!(plan.changed[0].name, "auth/request");
        assert_eq!(plan.changed[0].reason, "not_deployed");
    }

    #[test]
    fn tombstone_deletes_active_middleware_and_is_persisted() {
        let directory = tempdir().unwrap();
        let mut state = read_target_state(directory.path(), "payments", "production").unwrap();
        state.middleware.insert(
            "auth/request".into(),
            target(DeploymentUnitKind::Middleware, "auth/request", 'a', 'b'),
        );
        let mut deploy = request(Vec::new());
        deploy.tombstones.push(DeploymentUnitTombstone {
            kind: DeploymentUnitKind::Middleware,
            name: "auth/request".into(),
        });
        let plan = build_deployment_plan_from_state(directory.path(), &deploy, &state);
        assert_eq!(plan.changed.len(), 1);
        assert!(plan.changed[0].tombstone);
        assert_eq!(plan.changed[0].reason, "deleted");
        apply_plan_changes(directory.path(), &deploy, &plan, &mut state, 99).unwrap();
        assert!(!state.middleware.contains_key("auth/request"));
        let stored = state
            .tombstones
            .get("middleware/auth/request")
            .expect("middleware tombstone");
        assert_eq!(stored.kind, DeploymentUnitKind::Middleware);
        assert_eq!(stored.updated_unix_seconds, 99);
    }

    #[test]
    fn redeploy_clears_matching_tombstone() {
        let directory = tempdir().unwrap();
        write_artifact(directory.path(), 'c', 'd');
        let mut state = read_target_state(directory.path(), "payments", "production").unwrap();
        state.tombstones.insert(
            "lambda/worker".into(),
            DeploymentTombstoneRecord {
                kind: DeploymentUnitKind::Lambda,
                name: "worker".into(),
                git_commit: None,
                updated_unix_seconds: 1,
                activation_state: "not-connected".into(),
            },
        );
        let deploy = request(vec![candidate("worker", 'c', 'd')]);
        let plan = build_deployment_plan_from_state(directory.path(), &deploy, &state);
        apply_plan_changes(directory.path(), &deploy, &plan, &mut state, 2).unwrap();
        assert!(state.lambdas.contains_key("worker"));
        assert!(!state.tombstones.contains_key("lambda/worker"));
    }

    #[test]
    fn repeated_tombstone_becomes_unchanged() {
        let directory = tempdir().unwrap();
        let mut state = read_target_state(directory.path(), "payments", "production").unwrap();
        state.tombstones.insert(
            "lambda/worker".into(),
            DeploymentTombstoneRecord {
                kind: DeploymentUnitKind::Lambda,
                name: "worker".into(),
                git_commit: None,
                updated_unix_seconds: 1,
                activation_state: "not-connected".into(),
            },
        );
        let mut deploy = request(Vec::new());
        deploy.tombstones.push(DeploymentUnitTombstone {
            kind: DeploymentUnitKind::Lambda,
            name: "worker".into(),
        });
        let plan = build_deployment_plan_from_state(directory.path(), &deploy, &state);
        assert!(plan.changed.is_empty());
        assert_eq!(plan.unchanged.len(), 1);
        assert_eq!(plan.unchanged[0].reason, "already_deleted");
    }

    #[test]
    fn missing_target_state_is_empty_and_typed() {
        let directory = tempdir().unwrap();
        let state = read_target_state(directory.path(), "payments", "dev").unwrap();
        assert_eq!(state.format_version, 1);
        assert_eq!(state.project, "payments");
        assert_eq!(state.environment, "dev");
        assert_eq!(state.revision, 0);
        assert!(state.lambdas.is_empty());
        assert!(state.middleware.is_empty());
        assert!(state.tombstones.is_empty());
    }

    #[test]
    fn target_state_round_trips_by_project_and_environment() {
        let directory = tempdir().unwrap();
        let mut state = read_target_state(directory.path(), "payments", "stage").unwrap();
        state.revision = 4;
        state.middleware.insert(
            "auth".into(),
            target(DeploymentUnitKind::Middleware, "auth", 'a', 'b'),
        );
        write_target_state(directory.path(), &state).unwrap();
        let loaded = read_target_state(directory.path(), "payments", "stage").unwrap();
        assert_eq!(loaded.revision, 4);
        assert_eq!(loaded.project, "payments");
        assert_eq!(loaded.environment, "stage");
        assert!(loaded.middleware.contains_key("auth"));
    }

    #[test]
    fn old_lambda_only_target_state_remains_readable() {
        let directory = tempdir().unwrap();
        let path = target_state_path(directory.path(), "payments", "production");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(
            &path,
            serde_json::to_vec_pretty(&json!({
                "format_version": 1,
                "project": "payments",
                "environment": "production",
                "revision": 3,
                "lambdas": {
                    "worker": {
                        "name": "worker",
                        "build_sha256": "a".repeat(64),
                        "source_sha256": "b".repeat(64),
                        "git_commit": null,
                        "updated_unix_seconds": 1,
                        "activation_state": "not-connected"
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let loaded = read_target_state(directory.path(), "payments", "production").unwrap();
        assert_eq!(loaded.revision, 3);
        assert_eq!(loaded.lambdas["worker"].kind, DeploymentUnitKind::Lambda);
        assert!(loaded.middleware.is_empty());
        assert!(loaded.tombstones.is_empty());
    }

    #[test]
    fn rejects_duplicate_identities_across_legacy_and_typed_units() {
        let mut deploy = request(vec![candidate("same", 'a', 'b')]);
        deploy.units.push(typed_candidate(
            DeploymentUnitKind::Lambda,
            "same",
            'c',
            'd',
        ));
        assert!(validate_deployment_request(&deploy)
            .unwrap_err()
            .contains("duplicate lambda unit"));
    }

    #[test]
    fn rejects_active_and_tombstoned_identity_in_same_request() {
        let mut deploy = request(vec![candidate("same", 'a', 'b')]);
        deploy.tombstones.push(DeploymentUnitTombstone {
            kind: DeploymentUnitKind::Lambda,
            name: "same".into(),
        });
        assert!(validate_deployment_request(&deploy)
            .unwrap_err()
            .contains("both active and tombstoned"));
    }
}
