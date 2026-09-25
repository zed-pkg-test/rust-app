use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Component, Path, PathBuf},
};

use crate::deploy::{self, DeploymentArtifact, DeploymentUnitKind};

const SCHEMA_V2: &str = "bmscl.provider.bundle.v2";
const MAX_BUNDLE_BYTES: u64 = 1024 * 1024;
const MAX_ROUTE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct BundleUnit {
    pub kind: String,
    pub name: String,
    pub build_sha256: String,
    pub artifact_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ProviderBundle {
    pub schema_version: String,
    pub generation: u64,
    pub bundle_sha256: String,
    pub routing_path: String,
    pub routing_sha256: String,
    pub middleware_order: Vec<String>,
    pub units: Vec<BundleUnit>,
}

pub(crate) struct BuildOptions {
    pub artifact_dir: PathBuf,
    pub routes: Option<PathBuf>,
    pub out_dir: PathBuf,
    pub generation: u64,
    pub middleware_order: Vec<String>,
    pub public_key: String,
    pub key_id: Option<String>,
}

pub(crate) fn build(options: BuildOptions) -> Result<ProviderBundle> {
    if options.generation == 0 {
        bail!("provider bundle generation must be positive");
    }
    let root = project_root()?;
    let artifact_dir = confined_existing_dir(&root, &options.artifact_dir)?;
    let routes = match options.routes.as_deref() {
        Some(path) => Some(confined_existing_file(&root, path, MAX_ROUTE_BYTES)?),
        None => None,
    };
    let out_dir = confined_new_path(&root, &options.out_dir)?;
    if out_dir.exists() {
        bail!(
            "provider bundle output already exists: {}; remove it explicitly before rebuilding",
            out_dir.display()
        );
    }

    let artifacts = deploy::discover_artifacts(&artifact_dir, &[], &[], false)?;
    deploy::verify_artifacts(&artifacts, &options.public_key, options.key_id.as_deref())?;

    let route_bytes = match routes.as_deref() {
        Some(path) => fs::read(path).with_context(|| format!("read {}", path.display()))?,
        None => generated_route_bytes(&artifacts, options.generation)?,
    };
    let routing: Value = serde_json::from_slice(&route_bytes)
        .context("parse provider route manifest")?;
    validate_route_targets(&routing, &artifacts)?;

    let middleware_order = resolve_middleware_order(&options.middleware_order, &artifacts)?;
    let routing_sha256 = sha256_hex(&route_bytes);
    let units = bundle_units(&artifacts);
    let bundle_sha256 = compute_bundle_sha256_v2(&units, &routing_sha256, &middleware_order)?;

    let bundle = ProviderBundle {
        schema_version: SCHEMA_V2.to_owned(),
        generation: options.generation,
        bundle_sha256,
        routing_path: "routes.json".to_owned(),
        routing_sha256,
        middleware_order,
        units,
    };

    write_bundle_atomically(&out_dir, &route_bytes, &bundle, &artifacts)?;
    println!("provider bundle sha256:{}", bundle.bundle_sha256);
    println!(
        "provider bundle manifest: {}",
        out_dir.join("provider-bundle.json").display()
    );
    Ok(bundle)
}

pub(crate) fn verify_for_deploy(
    manifest_path: &Path,
    artifact_dir: &Path,
) -> Result<String> {
    let root = project_root()?;
    let manifest_path = confined_existing_file(&root, manifest_path, MAX_BUNDLE_BYTES)?;
    let artifact_dir = confined_existing_dir(&root, artifact_dir)?;
    let bytes = fs::read(&manifest_path)
        .with_context(|| format!("read {}", manifest_path.display()))?;
    let bundle: ProviderBundle = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {}", manifest_path.display()))?;
    if bundle.schema_version != SCHEMA_V2 {
        bail!(
            "Rust bmscl off-platform deploy requires {SCHEMA_V2}; regenerate the provider bundle"
        );
    }
    if bundle.generation == 0
        || !valid_sha256(&bundle.routing_sha256)
        || !valid_sha256(&bundle.bundle_sha256)
    {
        bail!("provider bundle has invalid generation or digest fields");
    }

    let bundle_root = manifest_path
        .parent()
        .context("provider bundle manifest has no parent directory")?;
    let routing_path = resolve_bundle_path(bundle_root, &bundle.routing_path)?;
    let route_bytes = read_regular(&routing_path, MAX_ROUTE_BYTES)?;
    let actual_route_sha = sha256_hex(&route_bytes);
    if actual_route_sha != bundle.routing_sha256 {
        bail!(
            "provider bundle routing digest mismatch: expected {}, found {}",
            bundle.routing_sha256,
            actual_route_sha
        );
    }
    let routing: Value = serde_json::from_slice(&route_bytes)
        .context("provider bundle routes.json is invalid JSON")?;

    let artifacts = deploy::discover_artifacts(&artifact_dir, &[], &[], false)?;
    validate_bundle_units(&bundle, bundle_root, &artifacts)?;
    validate_route_targets(&routing, &artifacts)?;
    validate_middleware_order(&bundle.middleware_order, &artifacts)?;

    let actual = compute_bundle_sha256_v2(
        &bundle.units,
        &bundle.routing_sha256,
        &bundle.middleware_order,
    )?;
    if actual != bundle.bundle_sha256 {
        bail!(
            "provider bundle digest mismatch: expected {}, found {}",
            bundle.bundle_sha256,
            actual
        );
    }
    Ok(actual)
}

fn bundle_units(artifacts: &[DeploymentArtifact]) -> Vec<BundleUnit> {
    let mut units = artifacts
        .iter()
        .map(|artifact| BundleUnit {
            kind: artifact.kind.label().to_owned(),
            name: artifact.name.clone(),
            build_sha256: artifact.candidate.build_sha256.clone(),
            artifact_path: format!(
                "artifacts/{}/{}",
                artifact.kind.label(),
                artifact.candidate.build_sha256
            ),
        })
        .collect::<Vec<_>>();
    units.sort();
    units
}

fn validate_bundle_units(
    bundle: &ProviderBundle,
    bundle_root: &Path,
    artifacts: &[DeploymentArtifact],
) -> Result<()> {
    if bundle.units.is_empty() || bundle.units.len() > 256 {
        bail!("provider bundle must contain 1..=256 units");
    }
    let mut manifest_identity = BTreeSet::new();
    for unit in &bundle.units {
        if !matches!(unit.kind.as_str(), "lambda" | "middleware")
            || unit.name.is_empty()
            || unit.name.len() > 256
            || unit.name.contains('\0')
            || !valid_sha256(&unit.build_sha256)
        {
            bail!("provider bundle contains an invalid unit");
        }
        let artifact_path = resolve_bundle_path(bundle_root, &unit.artifact_path)?;
        let metadata = fs::symlink_metadata(&artifact_path)
            .with_context(|| format!("inspect {}", artifact_path.display()))?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            bail!(
                "provider bundle artifact path must be a regular directory: {}",
                artifact_path.display()
            );
        }
        if !manifest_identity.insert((
            unit.kind.clone(),
            unit.name.clone(),
            unit.build_sha256.clone(),
        )) {
            bail!("provider bundle contains duplicate unit identity");
        }
    }

    let expected = artifacts
        .iter()
        .map(|artifact| {
            (
                (
                    artifact.kind.label().to_owned(),
                    artifact.name.clone(),
                    artifact.candidate.build_sha256.clone(),
                ),
                artifact.directory.as_path(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    if manifest_identity != expected.keys().cloned().collect::<BTreeSet<_>>() {
        bail!("provider bundle artifact set does not match the verified local artifact tree");
    }

    for unit in &bundle.units {
        let key = (
            unit.kind.clone(),
            unit.name.clone(),
            unit.build_sha256.clone(),
        );
        let local = expected
            .get(&key)
            .context("provider bundle unit disappeared from local artifact index")?;
        let bundled = resolve_bundle_path(bundle_root, &unit.artifact_path)?;
        let local_digest = tree_sha256(local)?;
        let bundled_digest = tree_sha256(&bundled)?;
        if local_digest != bundled_digest {
            bail!(
                "provider bundle artifact tree differs from verified local artifact {}/{}",
                unit.kind,
                unit.name
            );
        }
    }
    Ok(())
}

fn resolve_middleware_order(
    requested: &[String],
    artifacts: &[DeploymentArtifact],
) -> Result<Vec<String>> {
    let available = artifacts
        .iter()
        .filter(|artifact| artifact.kind == DeploymentUnitKind::Middleware)
        .map(|artifact| artifact.name.clone())
        .collect::<BTreeSet<_>>();
    let order = if requested.is_empty() {
        available.iter().cloned().collect::<Vec<_>>()
    } else {
        requested.to_vec()
    };
    validate_middleware_order(&order, artifacts)?;
    Ok(order)
}

fn validate_middleware_order(order: &[String], artifacts: &[DeploymentArtifact]) -> Result<()> {
    if order.len() > 64 {
        bail!("provider bundle middleware order exceeds 64 entries");
    }
    let available = artifacts
        .iter()
        .filter(|artifact| artifact.kind == DeploymentUnitKind::Middleware)
        .map(|artifact| artifact.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut seen = BTreeSet::new();
    for name in order {
        if name.is_empty()
            || name.len() > 256
            || !available.contains(name.as_str())
            || !seen.insert(name.as_str())
        {
            bail!("middleware order contains a duplicate or unknown middleware unit");
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct ArtifactRuntimeManifest {
    entrypoint: String,
}

fn generated_route_bytes(
    artifacts: &[DeploymentArtifact],
    routing_version: u64,
) -> Result<Vec<u8>> {
    let mut routes = Vec::new();
    for artifact in artifacts
        .iter()
        .filter(|artifact| artifact.kind == DeploymentUnitKind::Lambda)
    {
        let manifest_path = artifact.directory.join("manifest.json");
        let manifest: ArtifactRuntimeManifest = serde_json::from_slice(
            &fs::read(&manifest_path)
                .with_context(|| format!("read {}", manifest_path.display()))?,
        )
        .with_context(|| format!("parse {}", manifest_path.display()))?;
        if manifest.entrypoint.is_empty() {
            bail!("{} has an empty BEAM entrypoint", manifest_path.display());
        }
        let path = if artifact.name == "default" {
            "/".to_owned()
        } else {
            let normalized = artifact.name.replace('\\', "/");
            if normalized.is_empty()
                || normalized.starts_with('/')
                || normalized.ends_with('/')
                || normalized.contains("//")
                || normalized.contains('?')
                || normalized.contains('#')
                || normalized.bytes().any(|byte| byte < 32 || byte == 127)
            {
                bail!(
                    "Lambda name {:?} cannot be projected to a safe HTTP route",
                    artifact.name
                );
            }
            format!("/{normalized}")
        };
        routes.push(serde_json::json!({
            "route_id": artifact.name,
            "method": "ANY",
            "path": path,
            "target": {
                "function_id": artifact.name,
                "deployment_id": artifact.candidate.build_sha256,
                "artifact_digest": format!("sha256:{}", artifact.candidate.build_sha256),
                "runtime": {
                    "kind": "beam",
                    "entrypoint": manifest.entrypoint
                }
            }
        }));
    }
    routes.sort_by(|left, right| {
        left.get("route_id")
            .and_then(Value::as_str)
            .cmp(&right.get("route_id").and_then(Value::as_str))
    });
    if routes.is_empty() {
        bail!("provider bundle requires at least one Lambda route");
    }
    let manifest = serde_json::json!({
        "schema_version": "ores.routes.v1",
        "routing_version": routing_version,
        "routes": routes
    });
    let mut bytes = serde_json::to_vec_pretty(&manifest)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn validate_route_targets(routing: &Value, artifacts: &[DeploymentArtifact]) -> Result<()> {
    let lambda_builds = artifacts
        .iter()
        .filter(|artifact| artifact.kind == DeploymentUnitKind::Lambda)
        .map(|artifact| artifact.candidate.build_sha256.as_str())
        .collect::<BTreeSet<_>>();
    let routes = routing
        .get("routes")
        .and_then(Value::as_array)
        .filter(|routes| !routes.is_empty())
        .context("route manifest must contain at least one route")?;
    for route in routes {
        let target = route
            .get("target")
            .and_then(Value::as_object)
            .context("route target must be an object")?;
        let deployment = target
            .get("deployment_id")
            .and_then(Value::as_str)
            .and_then(normalize_sha)
            .context("route target has invalid deployment_id")?;
        let digest = target
            .get("artifact_digest")
            .and_then(Value::as_str)
            .and_then(normalize_sha)
            .context("route target has invalid artifact_digest")?;
        if deployment != digest || !lambda_builds.contains(deployment) {
            bail!("route target does not resolve to a verified Lambda artifact digest");
        }
    }
    Ok(())
}

fn normalize_sha(value: &str) -> Option<&str> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    valid_sha256(value).then_some(value)
}

pub(crate) fn compute_bundle_sha256_v2(
    units: &[BundleUnit],
    routing_sha256: &str,
    middleware_order: &[String],
) -> Result<String> {
    if !valid_sha256(routing_sha256) {
        bail!("routing_sha256 must be 64 lowercase hexadecimal characters");
    }
    let mut canonical = units.to_vec();
    canonical.sort_by(|left, right| {
        (&left.kind, &left.name, &left.build_sha256)
            .cmp(&(&right.kind, &right.name, &right.build_sha256))
    });

    let mut hash = Sha256::new();
    hash.update(SCHEMA_V2.as_bytes());
    hash.update([0]);
    for unit in canonical {
        if !matches!(unit.kind.as_str(), "lambda" | "middleware")
            || unit.name.is_empty()
            || !valid_sha256(&unit.build_sha256)
        {
            bail!("invalid unit passed to provider bundle digest");
        }
        hash.update(unit.kind.as_bytes());
        hash.update([0]);
        hash.update(unit.name.as_bytes());
        hash.update([0]);
        hash.update(unit.build_sha256.as_bytes());
        hash.update([0]);
    }
    hash.update(b"routing");
    hash.update([0]);
    hash.update(routing_sha256.as_bytes());
    hash.update([0]);
    for name in middleware_order {
        if name.is_empty() {
            bail!("middleware name must not be empty");
        }
        hash.update(b"middleware");
        hash.update([0]);
        hash.update(name.as_bytes());
        hash.update([0]);
    }
    Ok(hex_lower(&hash.finalize()))
}

fn write_bundle_atomically(
    out_dir: &Path,
    route_bytes: &[u8],
    bundle: &ProviderBundle,
    artifacts: &[DeploymentArtifact],
) -> Result<()> {
    let parent = out_dir
        .parent()
        .context("provider bundle output has no parent directory")?;
    fs::create_dir_all(parent)
        .with_context(|| format!("create {}", parent.display()))?;
    let file_name = out_dir
        .file_name()
        .and_then(|name| name.to_str())
        .context("provider bundle output name must be UTF-8")?;
    let stage = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    if stage.exists() {
        bail!("provider bundle staging path already exists: {}", stage.display());
    }

    let result = (|| -> Result<()> {
        fs::create_dir(&stage).with_context(|| format!("create {}", stage.display()))?;
        fs::create_dir(stage.join("artifacts"))
            .with_context(|| format!("create {}", stage.join("artifacts").display()))?;
        for artifact in artifacts {
            let destination = stage
                .join("artifacts")
                .join(artifact.kind.label())
                .join(&artifact.candidate.build_sha256);
            copy_tree_no_symlinks(&artifact.directory, &destination)?;
        }
        fs::write(stage.join("routes.json"), route_bytes)
            .context("write provider routes.json")?;
        let bytes = serde_json::to_vec_pretty(bundle).context("encode provider bundle")?;
        fs::write(stage.join("provider-bundle.json"), bytes)
            .context("write provider-bundle.json")?;
        fs::rename(&stage, out_dir).with_context(|| {
            format!(
                "atomically publish provider bundle {} -> {}",
                stage.display(),
                out_dir.display()
            )
        })?;
        Ok(())
    })();

    if result.is_err() && stage.exists() {
        let _ = fs::remove_dir_all(&stage);
    }
    result
}

fn copy_tree_no_symlinks(source: &Path, destination: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(source)
        .with_context(|| format!("inspect {}", source.display()))?;
    if metadata.file_type().is_symlink() {
        bail!("symlink is not allowed in provider bundle: {}", source.display());
    }
    if metadata.is_file() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create {}", parent.display()))?;
        }
        fs::copy(source, destination).with_context(|| {
            format!("copy {} -> {}", source.display(), destination.display())
        })?;
        return Ok(());
    }
    if !metadata.is_dir() {
        bail!("unsupported file type in provider bundle: {}", source.display());
    }
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create {}", parent.display()))?;
    }
    fs::create_dir(destination)
        .with_context(|| format!("create {}", destination.display()))?;
    let mut entries = fs::read_dir(source)
        .with_context(|| format!("read directory {}", source.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("read directory entries {}", source.display()))?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        copy_tree_no_symlinks(&entry.path(), &destination.join(entry.file_name()))?;
    }
    Ok(())
}

fn tree_sha256(root: &Path) -> Result<String> {
    let metadata = fs::symlink_metadata(root)
        .with_context(|| format!("inspect {}", root.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("artifact tree root must be a regular directory: {}", root.display());
    }

    fn visit(base: &Path, path: &Path, hash: &mut Sha256) -> Result<()> {
        let mut entries = fs::read_dir(path)
            .with_context(|| format!("read directory {}", path.display()))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .with_context(|| format!("read directory entries {}", path.display()))?;
        entries.sort_by_key(|entry| entry.file_name());
        for entry in entries {
            let child = entry.path();
            let metadata = fs::symlink_metadata(&child)
                .with_context(|| format!("inspect {}", child.display()))?;
            if metadata.file_type().is_symlink() {
                bail!("symlink is not allowed in artifact tree: {}", child.display());
            }
            let relative = child
                .strip_prefix(base)
                .context("artifact tree path escaped its root")?
                .to_string_lossy()
                .replace('\\', "/");
            if metadata.is_dir() {
                hash.update(b"dir");
                hash.update([0]);
                hash.update(relative.as_bytes());
                hash.update([0]);
                visit(base, &child, hash)?;
            } else if metadata.is_file() {
                hash.update(b"file");
                hash.update([0]);
                hash.update(relative.as_bytes());
                hash.update([0]);
                let bytes = fs::read(&child)
                    .with_context(|| format!("read {}", child.display()))?;
                hash.update(Sha256::digest(&bytes));
                hash.update([0]);
            } else {
                bail!("unsupported special file in artifact tree: {}", child.display());
            }
        }
        Ok(())
    }

    let mut hash = Sha256::new();
    visit(root, root, &mut hash)?;
    Ok(hex_lower(&hash.finalize()))
}

fn project_root() -> Result<PathBuf> {
    std::env::current_dir()?
        .canonicalize()
        .context("canonicalize current project directory")
}

fn confined_existing_dir(root: &Path, configured: &Path) -> Result<PathBuf> {
    let path = confined_existing(root, configured)?;
    if !path.is_dir() {
        bail!("{} is not a directory", path.display());
    }
    Ok(path)
}

fn confined_existing_file(root: &Path, configured: &Path, max_bytes: u64) -> Result<PathBuf> {
    let path = confined_existing(root, configured)?;
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{} must be a regular non-symlink file", path.display());
    }
    if metadata.len() > max_bytes {
        bail!("{} exceeds the {} byte limit", path.display(), max_bytes);
    }
    Ok(path)
}

fn confined_existing(root: &Path, configured: &Path) -> Result<PathBuf> {
    if configured.as_os_str().is_empty() {
        bail!("path must not be empty");
    }
    let candidate = if configured.is_absolute() {
        configured.to_path_buf()
    } else {
        root.join(configured)
    };
    let canonical = candidate
        .canonicalize()
        .with_context(|| format!("resolve {}", candidate.display()))?;
    if !canonical.starts_with(root) {
        bail!("path escapes project root: {}", candidate.display());
    }
    Ok(canonical)
}

fn confined_new_path(root: &Path, configured: &Path) -> Result<PathBuf> {
    if configured.as_os_str().is_empty() || configured.is_absolute() {
        bail!("new output path must be a non-empty project-relative path");
    }
    if configured.components().any(|component| {
        !matches!(component, Component::Normal(_))
    }) {
        bail!("new output path must not contain . or .. components");
    }
    let candidate = root.join(configured);
    let parent = candidate
        .parent()
        .context("new output path has no parent")?;
    let existing_parent = nearest_existing(parent)?;
    let canonical_parent = existing_parent
        .canonicalize()
        .with_context(|| format!("resolve {}", existing_parent.display()))?;
    if !canonical_parent.starts_with(root) {
        bail!("new output path escapes project root");
    }
    Ok(candidate)
}

fn nearest_existing(path: &Path) -> Result<PathBuf> {
    let mut current = path.to_path_buf();
    loop {
        if current.exists() {
            return Ok(current);
        }
        current = current
            .parent()
            .context("output path has no existing ancestor")?
            .to_path_buf();
    }
}

fn resolve_bundle_path(base: &Path, relative: &str) -> Result<PathBuf> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || relative.contains('\\')
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("unsafe provider bundle relative path {relative:?}");
    }
    let candidate = base.join(path);
    let canonical = candidate
        .canonicalize()
        .with_context(|| format!("resolve {}", candidate.display()))?;
    let canonical_base = base
        .canonicalize()
        .with_context(|| format!("resolve {}", base.display()))?;
    if !canonical.starts_with(&canonical_base) {
        bail!("provider bundle path escapes its root");
    }
    Ok(canonical)
}

fn read_regular(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("{} must be a regular non-symlink file", path.display());
    }
    if metadata.len() > max_bytes {
        bail!("{} exceeds the {} byte limit", path.display(), max_bytes);
    }
    fs::read(path).with_context(|| format!("read {}", path.display()))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&Sha256::digest(bytes))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_bundle_v2_digest_matches_shared_vector() {
        let units = vec![
            BundleUnit {
                kind: "lambda".into(),
                name: "users/create".into(),
                build_sha256: "a".repeat(64),
                artifact_path: "ignored/a".into(),
            },
            BundleUnit {
                kind: "middleware".into(),
                name: "auth".into(),
                build_sha256: "b".repeat(64),
                artifact_path: "ignored/b".into(),
            },
        ];
        let digest =
            compute_bundle_sha256_v2(&units, &"c".repeat(64), &["auth".into()]).unwrap();
        assert_eq!(
            digest,
            "9673611180aca58df4a7d8a51816a9501152e545388e298c1d84836e26d7a755"
        );
    }

    #[test]
    fn digest_does_not_bind_packaging_paths() {
        let mut left = BundleUnit {
            kind: "lambda".into(),
            name: "x".into(),
            build_sha256: "a".repeat(64),
            artifact_path: "one".into(),
        };
        let first = compute_bundle_sha256_v2(&[left.clone()], &"b".repeat(64), &[]).unwrap();
        left.artifact_path = "two".into();
        let second = compute_bundle_sha256_v2(&[left], &"b".repeat(64), &[]).unwrap();
        assert_eq!(first, second);
    }
}
