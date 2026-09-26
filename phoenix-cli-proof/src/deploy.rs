use anyhow::{bail, Context, Result};
use reqwest::blocking::{multipart, Client, RequestBuilder, Response};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Component, Path, PathBuf},
    process::Command,
    time::Duration,
};
use walkdir::WalkDir;

#[derive(
    Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash,
)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeploymentUnitKind {
    #[default]
    Lambda,
    Middleware,
}

impl DeploymentUnitKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Lambda => "lambda",
            Self::Middleware => "middleware",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestSummary {
    pub(crate) build_sha256: String,
    source_sha256: String,
}

#[derive(Debug, Clone)]
pub(crate) struct DeploymentArtifact {
    pub(crate) kind: DeploymentUnitKind,
    pub(crate) name: String,
    pub(crate) directory: PathBuf,
    archive: PathBuf,
    pub(crate) candidate: DeploymentUnitCandidate,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DeploymentUnitCandidate {
    pub(crate) kind: DeploymentUnitKind,
    pub(crate) name: String,
    pub(crate) build_sha256: String,
    pub(crate) source_sha256: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct DeploymentUnitTombstone {
    kind: DeploymentUnitKind,
    name: String,
}

#[derive(Debug, Clone, Serialize)]
struct DeploymentPlanRequest {
    project: String,
    environment: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    git_commit: Option<String>,
    force: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_revision: Option<u64>,
    units: Vec<DeploymentUnitCandidate>,
    tombstones: Vec<DeploymentUnitTombstone>,
}

#[derive(Debug, Clone, Deserialize)]
struct PlannedDeploymentUnit {
    #[serde(default)]
    kind: DeploymentUnitKind,
    name: String,
    #[serde(default)]
    tombstone: bool,
    build_sha256: Option<String>,
    current_build_sha256: Option<String>,
    artifact_present: bool,
    reason: String,
}

#[derive(Debug, Deserialize)]
struct DeploymentPlanResponse {
    project: String,
    environment: String,
    revision: u64,
    changed: Vec<PlannedDeploymentUnit>,
    unchanged: Vec<PlannedDeploymentUnit>,
}

#[derive(Debug, Deserialize)]
struct DeploymentApplyResponse {
    previous_revision: u64,
    revision: u64,
    applied: Vec<PlannedDeploymentUnit>,
    unchanged: Vec<PlannedDeploymentUnit>,
}

#[derive(Debug, Deserialize)]
struct DeploymentTargetState {
    #[serde(default)]
    lambdas: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    middleware: BTreeMap<String, serde_json::Value>,
}

pub struct VerifyOptions {
    pub artifact_dir: PathBuf,
    pub lambdas: Vec<String>,
    pub middleware: Vec<String>,
    pub public_key: String,
    pub key_id: Option<String>,
}

pub struct DeployOptions {
    pub artifact_dir: PathBuf,
    pub project: String,
    pub environment: String,
    pub lambdas: Vec<String>,
    pub middleware: Vec<String>,
    pub force: bool,
    pub dry_run: bool,
    pub prune: bool,
    pub git_commit: Option<String>,
    pub api_url: String,
    pub token: Option<String>,
    pub public_key: String,
    pub key_id: Option<String>,
}

pub fn verify(options: VerifyOptions) -> Result<()> {
    let artifacts = discover_artifacts(
        &options.artifact_dir,
        &options.lambdas,
        &options.middleware,
        false,
    )?;
    verify_artifacts(&artifacts, &options.public_key, options.key_id.as_deref())
}

pub fn deploy(options: DeployOptions) -> Result<()> {
    validate_target_segment("project", &options.project)?;
    validate_target_segment("environment", &options.environment)?;
    if options.prune && (!options.lambdas.is_empty() || !options.middleware.is_empty()) {
        bail!("--prune requires a full-tree deploy and cannot be combined with --lambda or --middleware");
    }

    let artifacts = discover_artifacts(
        &options.artifact_dir,
        &options.lambdas,
        &options.middleware,
        options.prune,
    )?;
    verify_artifacts(&artifacts, &options.public_key, options.key_id.as_deref())?;

    let client = Client::builder()
        .timeout(Duration::from_secs(300))
        .build()
        .context("build HTTP client")?;
    let api_url = options.api_url.trim_end_matches('/');
    if api_url.is_empty() {
        bail!("admin API URL must not be empty");
    }

    let tombstones = if options.prune {
        let state: DeploymentTargetState = send_json(
            authorize(
                client.get(format!(
                    "{api_url}/v1/admin/deployment-targets/{}/{}",
                    options.project, options.environment
                )),
                options.token.as_deref(),
            ),
            "read deployment targets for prune",
        )?;
        let tombstones = compute_tombstones(&artifacts, &state);
        for tombstone in &tombstones {
            println!(
                "prune  {}/{} -> tombstone",
                tombstone.kind.label(),
                tombstone.name
            );
        }
        tombstones
    } else {
        Vec::new()
    };

    let units = artifacts
        .iter()
        .map(|artifact| artifact.candidate.clone())
        .collect::<Vec<_>>();
    if units.is_empty() && tombstones.is_empty() {
        println!("no local or remote deployment units require a plan");
        return Ok(());
    }

    let mut request = DeploymentPlanRequest {
        project: options.project,
        environment: options.environment,
        git_commit: options.git_commit,
        force: options.force,
        expected_revision: None,
        units,
        tombstones,
    };

    let plan: DeploymentPlanResponse = send_json(
        authorize(
            client
                .post(format!("{api_url}/v1/admin/deployment-plans"))
                .json(&request),
            options.token.as_deref(),
        ),
        "plan deployment",
    )?;
    print_plan(&plan);

    if plan.changed.is_empty() {
        println!("no selected deployment units changed; nothing was uploaded or re-applied");
        return Ok(());
    }
    if options.dry_run {
        println!("dry run: no artifacts uploaded and no deployment targets changed");
        return Ok(());
    }

    let artifacts_by_identity: BTreeMap<_, _> = artifacts
        .iter()
        .map(|artifact| ((artifact.kind, artifact.name.as_str()), artifact))
        .collect();
    for changed in &plan.changed {
        if changed.tombstone {
            continue;
        }
        let build_sha256 = changed
            .build_sha256
            .as_deref()
            .context("active deployment plan item is missing build_sha256")?;
        if changed.artifact_present {
            println!(
                "reuse  {}/{} sha256:{}",
                changed.kind.label(),
                changed.name,
                build_sha256
            );
            continue;
        }
        let artifact = artifacts_by_identity
            .get(&(changed.kind, changed.name.as_str()))
            .with_context(|| {
                format!(
                    "deployment plan returned unknown {} `{}`",
                    changed.kind.label(),
                    changed.name
                )
            })?;
        upload_artifact(&client, api_url, options.token.as_deref(), artifact)?;
    }

    request.expected_revision = Some(plan.revision);
    let applied: DeploymentApplyResponse = send_json(
        authorize(
            client
                .post(format!("{api_url}/v1/admin/deployment-targets/apply"))
                .json(&request),
            options.token.as_deref(),
        ),
        "apply deployment targets",
    )?;
    print_applied(&applied);
    Ok(())
}

pub fn trusted_public_key(explicit: Option<String>) -> Result<String> {
    let value = explicit
        .or_else(|| env::var("BMSCL_BUILD_PUBLIC_KEY").ok())
        .context("pass --public-key or set BMSCL_BUILD_PUBLIC_KEY")?;
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("trusted public key must be exactly 64 hexadecimal characters");
    }
    Ok(value)
}

pub fn current_git_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let commit = String::from_utf8(output.stdout).ok()?.trim().to_string();
    (!commit.is_empty()).then_some(commit)
}

pub(crate) fn discover_artifacts(
    root: &Path,
    requested_lambdas: &[String],
    requested_middleware: &[String],
    allow_empty: bool,
) -> Result<Vec<DeploymentArtifact>> {
    if !root.is_dir() {
        bail!(
            "artifact root does not exist or is not a directory: {}",
            root.display()
        );
    }

    let mut manifests = BTreeMap::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !ignored_dir(entry.path()))
    {
        let entry = entry.with_context(|| format!("walk artifact root {}", root.display()))?;
        if !entry.file_type().is_file() || entry.file_name().to_str() != Some("manifest.json") {
            continue;
        }
        let directory = entry.path().parent().context("manifest parent directory")?;
        let Some((kind, name)) = canonical_artifact_identity(root, directory)? else {
            continue;
        };
        if manifests
            .insert((kind, name.clone()), entry.path().to_path_buf())
            .is_some()
        {
            bail!("duplicate {} artifact name `{name}`", kind.label());
        }
    }
    if manifests.is_empty() {
        if allow_empty && requested_lambdas.is_empty() && requested_middleware.is_empty() {
            return Ok(Vec::new());
        }
        bail!(
            "no Lambda or middleware artifacts found under {}; expected manifest.json plus worker.zip or worker.tar.gz",
            root.display()
        );
    }

    let lambdas = normalized_selection(DeploymentUnitKind::Lambda, requested_lambdas)?;
    let middleware = normalized_selection(DeploymentUnitKind::Middleware, requested_middleware)?;
    validate_requested(&manifests, DeploymentUnitKind::Lambda, &lambdas)?;
    validate_requested(&manifests, DeploymentUnitKind::Middleware, &middleware)?;
    let focused = !lambdas.is_empty() || !middleware.is_empty();

    let mut artifacts = Vec::new();
    for ((kind, name), manifest_path) in manifests {
        if focused {
            let selected = match kind {
                DeploymentUnitKind::Lambda => lambdas.contains(&name),
                DeploymentUnitKind::Middleware => middleware.contains(&name),
            };
            if !selected {
                continue;
            }
        }

        let directory = manifest_path
            .parent()
            .context("manifest parent directory")?;
        let archive = [
            directory.join("worker.zip"),
            directory.join("worker.tar.gz"),
        ]
        .into_iter()
        .find(|path| path.is_file())
        .with_context(|| {
            format!(
                "{} `{}` has manifest.json but no worker.zip or worker.tar.gz",
                kind.label(),
                name
            )
        })?;
        let manifest: ManifestSummary = serde_json::from_slice(
            &fs::read(&manifest_path)
                .with_context(|| format!("read {}", manifest_path.display()))?,
        )
        .with_context(|| format!("parse {}", manifest_path.display()))?;
        validate_sha256("build_sha256", &manifest.build_sha256)?;
        validate_sha256("source_sha256", &manifest.source_sha256)?;
        artifacts.push(DeploymentArtifact {
            kind,
            name: name.clone(),
            directory: directory.to_path_buf(),
            archive,
            candidate: DeploymentUnitCandidate {
                kind,
                name,
                build_sha256: manifest.build_sha256,
                source_sha256: manifest.source_sha256,
            },
        });
    }
    artifacts.sort_by(|left, right| {
        (left.kind, left.name.as_str()).cmp(&(right.kind, right.name.as_str()))
    });
    if artifacts.is_empty() {
        bail!("selectors did not select any deployment units");
    }
    Ok(artifacts)
}

fn canonical_artifact_identity(
    root: &Path,
    directory: &Path,
) -> Result<Option<(DeploymentUnitKind, String)>> {
    let relative = directory.strip_prefix(root).with_context(|| {
        format!(
            "artifact directory {} is not beneath {}",
            directory.display(),
            root.display()
        )
    })?;
    if relative.as_os_str().is_empty() {
        return Ok(Some((DeploymentUnitKind::Lambda, "default".into())));
    }

    let mut segments = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => segments.push(
                value
                    .to_str()
                    .context("artifact path must be valid UTF-8")?
                    .to_string(),
            ),
            _ => bail!("invalid artifact path {}", relative.display()),
        }
    }
    let identity = match segments.as_slice() {
        [bucket] if bucket == "lambdas" => (DeploymentUnitKind::Lambda, "default".into()),
        [bucket, rest @ ..] if bucket == "lambdas" && !rest.is_empty() => {
            (DeploymentUnitKind::Lambda, rest.join("/"))
        }
        [bucket] if bucket == "middleware" => (DeploymentUnitKind::Middleware, "default".into()),
        [bucket, rest @ ..] if bucket == "middleware" && !rest.is_empty() => {
            (DeploymentUnitKind::Middleware, rest.join("/"))
        }
        // Preserve the Rust CLI's legacy unbucketed Lambda artifact layout.
        _ => (DeploymentUnitKind::Lambda, segments.join("/")),
    };
    if identity.1.is_empty() {
        Ok(None)
    } else {
        Ok(Some(identity))
    }
}

fn normalized_selection(kind: DeploymentUnitKind, values: &[String]) -> Result<BTreeSet<String>> {
    let prefix = format!("{}/", kind.label());
    let mut result = BTreeSet::new();
    for value in values {
        let value = value.strip_prefix(&prefix).unwrap_or(value).to_string();
        if value.is_empty() {
            bail!("--{} requires a non-empty value", kind.label());
        }
        result.insert(value);
    }
    Ok(result)
}

fn validate_requested(
    manifests: &BTreeMap<(DeploymentUnitKind, String), PathBuf>,
    kind: DeploymentUnitKind,
    requested: &BTreeSet<String>,
) -> Result<()> {
    if requested.is_empty() {
        return Ok(());
    }
    let available: BTreeSet<String> = manifests
        .keys()
        .filter(|(candidate_kind, _)| *candidate_kind == kind)
        .map(|(_, name)| name.clone())
        .collect();
    let unknown: Vec<_> = requested.difference(&available).cloned().collect();
    if !unknown.is_empty() {
        bail!(
            "unknown {} selection(s): {}; available: {}",
            kind.label(),
            unknown.join(", "),
            available.into_iter().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}

fn compute_tombstones(
    artifacts: &[DeploymentArtifact],
    state: &DeploymentTargetState,
) -> Vec<DeploymentUnitTombstone> {
    let local: BTreeSet<(DeploymentUnitKind, &str)> = artifacts
        .iter()
        .map(|artifact| (artifact.kind, artifact.name.as_str()))
        .collect();
    let mut tombstones = Vec::new();
    for name in state.lambdas.keys() {
        if !local.contains(&(DeploymentUnitKind::Lambda, name.as_str())) {
            tombstones.push(DeploymentUnitTombstone {
                kind: DeploymentUnitKind::Lambda,
                name: name.clone(),
            });
        }
    }
    for name in state.middleware.keys() {
        if !local.contains(&(DeploymentUnitKind::Middleware, name.as_str())) {
            tombstones.push(DeploymentUnitTombstone {
                kind: DeploymentUnitKind::Middleware,
                name: name.clone(),
            });
        }
    }
    tombstones.sort_by(|left, right| {
        (left.kind, left.name.as_str()).cmp(&(right.kind, right.name.as_str()))
    });
    tombstones
}

pub(crate) fn verify_artifacts(
    artifacts: &[DeploymentArtifact],
    public_key: &str,
    key_id: Option<&str>,
) -> Result<()> {
    let compiler = compiler_binary();
    for artifact in artifacts {
        let mut command = Command::new(&compiler);
        command
            .arg("verify")
            .arg(&artifact.directory)
            .arg("--public-key")
            .arg(public_key);
        if let Some(key_id) = key_id.filter(|value| !value.is_empty()) {
            command.arg("--key-id").arg(key_id);
        }
        let status = command.status().with_context(|| {
            format!(
                "launch {compiler} verifier for {}/{}",
                artifact.kind.label(),
                artifact.name
            )
        })?;
        if !status.success() {
            bail!(
                "artifact verification failed for {} `{}`",
                artifact.kind.label(),
                artifact.name
            );
        }
        println!(
            "verify {}/{} sha256:{}",
            artifact.kind.label(),
            artifact.name,
            artifact.candidate.build_sha256
        );
    }
    Ok(())
}

fn upload_artifact(
    client: &Client,
    api_url: &str,
    token: Option<&str>,
    artifact: &DeploymentArtifact,
) -> Result<()> {
    let bytes = fs::read(&artifact.archive)
        .with_context(|| format!("read {}", artifact.archive.display()))?;
    let filename = artifact
        .archive
        .file_name()
        .and_then(|name| name.to_str())
        .context("artifact filename must be valid UTF-8")?
        .to_string();
    let part = multipart::Part::bytes(bytes)
        .file_name(filename)
        .mime_str("application/octet-stream")?;
    let response = authorize(
        client
            .post(format!("{api_url}/v1/admin/deployments"))
            .multipart(multipart::Form::new().part("artifact", part)),
        token,
    )
    .send()
    .with_context(|| format!("upload {} `{}`", artifact.kind.label(), artifact.name))?;
    ensure_success(
        response,
        &format!("upload {} `{}`", artifact.kind.label(), artifact.name),
    )?;
    println!(
        "upload {}/{} sha256:{}",
        artifact.kind.label(),
        artifact.name,
        artifact.candidate.build_sha256
    );
    Ok(())
}

fn authorize(request: RequestBuilder, token: Option<&str>) -> RequestBuilder {
    match token {
        Some(token) if !token.is_empty() => request.bearer_auth(token),
        _ => request,
    }
}

fn send_json<T: for<'de> Deserialize<'de>>(request: RequestBuilder, action: &str) -> Result<T> {
    let response = request
        .send()
        .with_context(|| format!("{action}: request failed"))?;
    ensure_success(response, action)?
        .json()
        .with_context(|| format!("{action}: decode response"))
}

fn ensure_success(response: Response, action: &str) -> Result<Response> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }
    let body = response
        .text()
        .unwrap_or_else(|_| "<unreadable response>".into());
    bail!("{action} failed with HTTP {status}: {body}")
}

fn print_plan(plan: &DeploymentPlanResponse) {
    println!(
        "deployment plan for {}/{} at revision {}: {} changed, {} unchanged",
        plan.project,
        plan.environment,
        plan.revision,
        plan.changed.len(),
        plan.unchanged.len()
    );
    for unit in &plan.changed {
        let previous = unit
            .current_build_sha256
            .as_deref()
            .map(|digest| format!("sha256:{digest}"))
            .unwrap_or_else(|| "none".into());
        if unit.tombstone {
            println!(
                "delete {}/{} {} -> tombstone ({})",
                unit.kind.label(),
                unit.name,
                previous,
                unit.reason
            );
        } else if let Some(build) = unit.build_sha256.as_deref() {
            println!(
                "change {}/{} {} -> sha256:{} ({})",
                unit.kind.label(),
                unit.name,
                previous,
                build,
                unit.reason
            );
        }
    }
}

fn print_applied(applied: &DeploymentApplyResponse) {
    for unit in &applied.applied {
        if unit.tombstone {
            println!(
                "delete {}/{} ({})",
                unit.kind.label(),
                unit.name,
                unit.reason
            );
        } else if let Some(build) = unit.build_sha256.as_deref() {
            println!(
                "apply  {}/{} sha256:{} ({})",
                unit.kind.label(),
                unit.name,
                build,
                unit.reason
            );
        }
    }
    println!(
        "deployment target revision {} -> {}; {} applied, {} unchanged",
        applied.previous_revision,
        applied.revision,
        applied.applied.len(),
        applied.unchanged.len()
    );
}

fn validate_sha256(label: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{label} must be a lowercase 64-character SHA-256 hexadecimal value");
    }
    Ok(())
}

fn validate_target_segment(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        bail!(
            "{label} must use only ASCII letters, digits, '.', '_' or '-' and be at most 128 characters"
        );
    }
    Ok(())
}

fn compiler_binary() -> String {
    env::var("BMSCL_COMPILER").unwrap_or_else(|_| "bmscl-compiler".into())
}

fn ignored_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            matches!(
                name,
                ".git" | "build" | "node_modules" | "_build" | ".cache" | ".bmscl"
            )
        })
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_artifact(root: &Path, path: &str, build: char, source: char) {
        let directory = if path.is_empty() {
            root.to_path_buf()
        } else {
            root.join(path)
        };
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("manifest.json"),
            format!(
                "{{\"build_sha256\":\"{}\",\"source_sha256\":\"{}\"}}",
                build.to_string().repeat(64),
                source.to_string().repeat(64)
            ),
        )
        .unwrap();
        fs::write(directory.join("worker.zip"), b"zip").unwrap();
    }

    fn target_state(lambdas: &[&str], middleware: &[&str]) -> DeploymentTargetState {
        DeploymentTargetState {
            lambdas: lambdas
                .iter()
                .map(|name| ((*name).to_string(), serde_json::Value::Null))
                .collect(),
            middleware: middleware
                .iter()
                .map(|name| ((*name).to_string(), serde_json::Value::Null))
                .collect(),
        }
    }

    #[test]
    fn discovers_typed_lambda_and_middleware_artifacts() {
        let root = tempdir().unwrap();
        write_artifact(root.path(), "lambdas/users/create", 'a', 'b');
        write_artifact(root.path(), "middleware/auth", 'c', 'd');
        let artifacts = discover_artifacts(root.path(), &[], &[], false).unwrap();
        assert_eq!(artifacts.len(), 2);
        assert!(artifacts
            .iter()
            .any(|a| { a.kind == DeploymentUnitKind::Lambda && a.name == "users/create" }));
        assert!(artifacts
            .iter()
            .any(|a| { a.kind == DeploymentUnitKind::Middleware && a.name == "auth" }));
    }

    #[test]
    fn focused_lambda_does_not_select_middleware() {
        let root = tempdir().unwrap();
        write_artifact(root.path(), "lambdas/users/create", 'a', 'b');
        write_artifact(root.path(), "middleware/auth", 'c', 'd');
        let artifacts =
            discover_artifacts(root.path(), &["users/create".into()], &[], false).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].kind, DeploymentUnitKind::Lambda);
    }

    #[test]
    fn middleware_prefix_is_normalized() {
        let root = tempdir().unwrap();
        write_artifact(root.path(), "middleware/auth", 'c', 'd');
        let artifacts =
            discover_artifacts(root.path(), &[], &["middleware/auth".into()], false).unwrap();
        assert_eq!(artifacts.len(), 1);
        assert_eq!(artifacts[0].name, "auth");
    }

    #[test]
    fn unknown_middleware_is_kind_specific() {
        let root = tempdir().unwrap();
        write_artifact(root.path(), "middleware/auth", 'c', 'd');
        let error = discover_artifacts(root.path(), &[], &["missing".into()], false).unwrap_err();
        assert!(error.to_string().contains("unknown middleware"));
    }

    #[test]
    fn prune_allows_an_empty_but_existing_artifact_root() {
        let root = tempdir().unwrap();
        let artifacts = discover_artifacts(root.path(), &[], &[], true).unwrap();
        assert!(artifacts.is_empty());
    }

    #[test]
    fn prune_computes_typed_tombstones_only_for_missing_remote_units() {
        let root = tempdir().unwrap();
        write_artifact(root.path(), "lambdas/keep", 'a', 'b');
        write_artifact(root.path(), "middleware/keep", 'c', 'd');
        let artifacts = discover_artifacts(root.path(), &[], &[], false).unwrap();
        let state = target_state(&["keep", "remove"], &["keep", "remove"]);
        let tombstones = compute_tombstones(&artifacts, &state);
        assert_eq!(
            tombstones,
            vec![
                DeploymentUnitTombstone {
                    kind: DeploymentUnitKind::Lambda,
                    name: "remove".into(),
                },
                DeploymentUnitTombstone {
                    kind: DeploymentUnitKind::Middleware,
                    name: "remove".into(),
                },
            ]
        );
    }

    #[test]
    fn target_segments_match_admin_path_contract() {
        assert!(validate_target_segment("project", "billing.prod_1").is_ok());
        assert!(validate_target_segment("project", "../billing").is_err());
        assert!(validate_target_segment("environment", "").is_err());
        assert!(validate_target_segment("environment", &"a".repeat(129)).is_err());
    }

    #[test]
    fn normalizes_trusted_public_key() {
        let key = "A".repeat(64);
        let normalized = trusted_public_key(Some(key)).unwrap();
        assert_eq!(normalized, "a".repeat(64));
    }
}
