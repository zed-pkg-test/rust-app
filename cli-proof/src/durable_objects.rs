use anyhow::{bail, Context, Result};
use reqwest::blocking::{multipart, Client};
use serde::{Deserialize, Serialize};
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableObjectsConfig {
    pub schema_version: u32,
    pub tenant_id: String,
    pub namespace: String,
    pub language: String,
    #[serde(default = "dedicated")]
    pub tenancy_class: String,
    pub artifact: ArtifactConfig,
    #[serde(default)]
    pub build: Option<BuildConfig>,
    #[serde(default)]
    pub deployment: DeploymentConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactConfig {
    #[serde(default)]
    pub build_sha256: Option<String>,
    /// Optional compiler artifact directory. When present the CLI uploads the
    /// signed worker bundle to the BeamScale admin admission service first.
    pub directory: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildConfig {
    #[serde(default = "default_project")]
    pub project: PathBuf,
    #[serde(default = "default_out_dir")]
    pub out_dir: PathBuf,
    #[serde(default)]
    pub policy: Option<PathBuf>,
    #[serde(default)]
    pub worker_config: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    pub id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BuildOptions {
    pub config: PathBuf,
    pub signing_key: Option<PathBuf>,
    pub key_id: Option<String>,
    pub unsigned: bool,
}

#[derive(Debug, Clone)]
pub struct DeployOptions {
    pub config: PathBuf,
    pub api_url: String,
    pub admin_api_url: String,
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
struct DeployRequest<'a> {
    deployment_id: Option<&'a str>,
    tenant_id: &'a str,
    namespace: &'a str,
    language: &'a str,
    build_sha256: &'a str,
    tenancy_class: &'a str,
}

fn dedicated() -> String {
    "tenant_dedicated".into()
}

fn default_project() -> PathBuf {
    PathBuf::from(".")
}

fn default_out_dir() -> PathBuf {
    PathBuf::from("dist")
}

#[derive(Debug, Deserialize)]
struct ArtifactManifest {
    language: String,
    profile: String,
    build_sha256: String,
}

pub fn build(options: BuildOptions) -> Result<()> {
    let config = load_config(&options.config)?;
    validate_common(&config)?;

    if options.unsigned && (options.signing_key.is_some() || options.key_id.is_some()) {
        bail!("--unsigned cannot be combined with --signing-key or --key-id");
    }
    if !options.unsigned && (options.signing_key.is_none() || options.key_id.is_none()) {
        bail!("production Durable Object build requires --signing-key and --key-id; use --unsigned only for local development");
    }

    let build = config
        .build
        .as_ref()
        .context("Durable Object config requires [build] for the build command")?;
    let project = resolve_from_config(&options.config, &build.project);
    let out_dir = resolve_from_config(&options.config, &build.out_dir);
    let policy = build
        .policy
        .as_ref()
        .map(|path| resolve_from_config(&options.config, path));
    let worker_config = build
        .worker_config
        .as_ref()
        .map(|path| resolve_from_config(&options.config, path));

    let compiler = env::var("BMSCL_COMPILER").unwrap_or_else(|_| "bmscl-compiler".into());
    let subcommand = match config.language.as_str() {
        "erlang" => "package-erlang-critical",
        "gleam" => "package",
        _ => unreachable!("validated language"),
    };
    let mut command = Command::new(&compiler);
    command
        .arg(subcommand)
        .arg(&project)
        .arg("--out-dir")
        .arg(&out_dir);
    if let Some(policy) = policy.as_deref() {
        command.arg("--policy").arg(policy);
    }
    if let Some(worker_config) = worker_config.as_deref() {
        command.arg("--worker-config").arg(worker_config);
    }
    if let (Some(signing_key), Some(key_id)) =
        (options.signing_key.as_deref(), options.key_id.as_deref())
    {
        command
            .arg("--signing-key")
            .arg(signing_key)
            .arg("--key-id")
            .arg(key_id);
    }

    let status = command
        .status()
        .with_context(|| format!("launch {compiler} {subcommand}"))?;
    if !status.success() {
        bail!("{compiler} {subcommand} failed with {status}");
    }

    let manifest = read_artifact_manifest(&out_dir)?;
    validate_manifest_for_language(&manifest, &config.language)?;
    if let Some(expected) = config.artifact.build_sha256.as_deref() {
        validate_digest(expected)?;
        if expected != manifest.build_sha256 {
            bail!(
                "configured artifact.build_sha256 {} does not match newly built {}",
                expected,
                manifest.build_sha256
            );
        }
    }
    locate_bundle(&out_dir)?;
    println!(
        "built Durable Object artifact sha256:{}",
        manifest.build_sha256
    );
    println!("artifact directory: {}", out_dir.display());
    Ok(())
}

pub fn deploy(options: DeployOptions) -> Result<()> {
    let config = load_config(&options.config)?;
    validate_common(&config)?;

    let artifact_dir = configured_artifact_dir(&options.config, &config);
    let build_sha256 = resolve_build_sha256(&config, artifact_dir.as_deref())?;

    let request = DeployRequest {
        deployment_id: config.deployment.id.as_deref(),
        tenant_id: &config.tenant_id,
        namespace: &config.namespace,
        language: &config.language,
        build_sha256: &build_sha256,
        tenancy_class: &config.tenancy_class,
    };

    if options.dry_run {
        if let Some(directory) = artifact_dir.as_deref() {
            println!(
                "dry-run: would upload admitted artifact from {}",
                directory.display()
            );
        } else {
            println!("dry-run: using already-admitted artifact sha256:{build_sha256}");
        }
        println!("{}", serde_json::to_string_pretty(&request)?);
        return Ok(());
    }

    let client = Client::new();
    if let Some(directory) = artifact_dir.as_deref() {
        upload_artifact(
            &client,
            &options.admin_api_url,
            directory,
            &build_sha256,
            &config.language,
        )?;
    }

    let token = env::var("BMSCL_TOKEN")
        .context("set BMSCL_TOKEN for critical-section deployment authentication")?;

    let url = format!(
        "{}/v1/critical-sections/deployments",
        options.api_url.trim_end_matches('/')
    );
    let response = client
        .post(&url)
        .bearer_auth(token)
        .json(&request)
        .send()
        .with_context(|| format!("POST {url}"))?;

    let status = response.status();
    let body = response
        .text()
        .context("read BeamScale deployment response")?;
    if !status.is_success() {
        bail!("BeamScale deployment failed with HTTP {status}: {body}");
    }

    println!("{body}");
    Ok(())
}

fn load_config(path: &Path) -> Result<DurableObjectsConfig> {
    let source = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    toml::from_str(&source).with_context(|| format!("parse {}", path.display()))
}

fn configured_artifact_dir(config_path: &Path, config: &DurableObjectsConfig) -> Option<PathBuf> {
    config
        .artifact
        .directory
        .as_ref()
        .or_else(|| config.build.as_ref().map(|build| &build.out_dir))
        .map(|directory| resolve_from_config(config_path, directory))
}

fn resolve_build_sha256(
    config: &DurableObjectsConfig,
    artifact_dir: Option<&Path>,
) -> Result<String> {
    let configured = config.artifact.build_sha256.as_deref();
    if let Some(digest) = configured {
        validate_digest(digest)?;
    }

    match artifact_dir {
        Some(directory) => {
            let manifest = read_artifact_manifest(directory)?;
            validate_manifest_for_language(&manifest, &config.language)?;
            if let Some(expected) = configured {
                if expected != manifest.build_sha256 {
                    bail!(
                        "artifact manifest build_sha256 {} does not match config {}",
                        manifest.build_sha256,
                        expected
                    );
                }
            }
            locate_bundle(directory)?;
            Ok(manifest.build_sha256)
        }
        None => configured
            .map(str::to_owned)
            .context("set artifact.build_sha256 or artifact.directory/[build].out_dir"),
    }
}

fn read_artifact_manifest(directory: &Path) -> Result<ArtifactManifest> {
    let manifest_path = directory.join("manifest.json");
    serde_json::from_slice(
        &fs::read(&manifest_path).with_context(|| format!("read {}", manifest_path.display()))?,
    )
    .with_context(|| format!("parse {}", manifest_path.display()))
}

fn validate_manifest_for_language(manifest: &ArtifactManifest, language: &str) -> Result<()> {
    validate_digest(&manifest.build_sha256)?;
    if manifest.language != language {
        bail!(
            "artifact language {} does not match config {}",
            manifest.language,
            language
        );
    }
    match language {
        "erlang" if manifest.profile != "bmscl-critical-section-erlang-v1" => bail!(
            "Erlang Durable Object artifact must use profile=bmscl-critical-section-erlang-v1"
        ),
        "gleam" if manifest.profile != "bmscl-hosted-gleam-durable-actor-v1" => bail!(
            "Gleam Durable Object artifact must use profile=bmscl-hosted-gleam-durable-actor-v1"
        ),
        _ => Ok(()),
    }
}

fn locate_bundle(directory: &Path) -> Result<PathBuf> {
    ["worker.tar.gz", "worker.zip"]
        .into_iter()
        .map(|name| directory.join(name))
        .find(|path| path.is_file())
        .with_context(|| {
            format!(
                "{} contains no worker.tar.gz or worker.zip",
                directory.display()
            )
        })
}

fn upload_artifact(
    client: &Client,
    admin_api_url: &str,
    directory: &Path,
    expected_build: &str,
    expected_language: &str,
) -> Result<()> {
    let manifest = read_artifact_manifest(directory)?;
    validate_manifest_for_language(&manifest, expected_language)?;
    if manifest.build_sha256 != expected_build {
        bail!(
            "artifact manifest build_sha256 {} does not match deployment {}",
            manifest.build_sha256,
            expected_build
        );
    }
    let bundle = locate_bundle(directory)?;
    let filename = bundle
        .file_name()
        .and_then(|name| name.to_str())
        .context("artifact bundle filename must be UTF-8")?
        .to_string();
    let bytes = fs::read(&bundle).with_context(|| format!("read {}", bundle.display()))?;
    let token = env::var("BMSCL_ADMIN_TOKEN")
        .context("set BMSCL_ADMIN_TOKEN to upload a Durable Object artifact")?;
    let url = format!(
        "{}/v1/admin/deployments",
        admin_api_url.trim_end_matches('/')
    );
    let response = client
        .post(&url)
        .bearer_auth(token)
        .multipart(
            multipart::Form::new().part(
                "artifact",
                multipart::Part::bytes(bytes)
                    .file_name(filename)
                    .mime_str("application/octet-stream")?,
            ),
        )
        .send()
        .with_context(|| format!("POST {url}"))?;
    let status = response.status();
    let body = response
        .text()
        .context("read BeamScale admission response")?;
    if !status.is_success() {
        bail!("BeamScale artifact admission failed with HTTP {status}: {body}");
    }
    println!("admitted artifact sha256:{expected_build}");
    Ok(())
}

fn validate_common(config: &DurableObjectsConfig) -> Result<()> {
    if config.schema_version != 1 {
        bail!("unsupported .bmscl-durable-objects.toml schema_version");
    }
    validate_identity("tenant_id", &config.tenant_id)?;
    validate_identity("namespace", &config.namespace)?;
    if !matches!(config.language.as_str(), "erlang" | "gleam") {
        bail!("language must be erlang or gleam");
    }
    if config.tenancy_class != "tenant_dedicated" {
        bail!("Durable Objects require tenancy_class=tenant_dedicated");
    }
    if let Some(digest) = config.artifact.build_sha256.as_deref() {
        validate_digest(digest)?;
    }
    if let Some(id) = config.deployment.id.as_deref() {
        validate_identity("deployment.id", id)?;
    }
    Ok(())
}

fn validate_digest(digest: &str) -> Result<()> {
    if digest.len() == 64
        && digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        bail!("build SHA-256 must be 64 lowercase hex characters")
    }
}

fn resolve_from_config(config_path: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path)
    }
}

fn validate_identity(name: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        bail!("invalid {name}: expected [A-Za-z0-9._-], length 1..=128")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(tenancy_class: &str) -> DurableObjectsConfig {
        DurableObjectsConfig {
            schema_version: 1,
            tenant_id: "acme".into(),
            namespace: "critical".into(),
            language: "gleam".into(),
            tenancy_class: tenancy_class.into(),
            artifact: ArtifactConfig {
                build_sha256: Some("a".repeat(64)),
                directory: None,
            },
            build: None,
            deployment: DeploymentConfig::default(),
        }
    }

    #[test]
    fn durable_objects_are_always_dedicated() {
        assert!(validate_common(&config("mixed_tenants")).is_err());
        assert!(validate_common(&config("tenant_dedicated")).is_ok());
    }

    #[test]
    fn profile_is_bound_to_language() {
        let erlang = ArtifactManifest {
            language: "erlang".into(),
            profile: "bmscl-critical-section-erlang-v1".into(),
            build_sha256: "a".repeat(64),
        };
        assert!(validate_manifest_for_language(&erlang, "erlang").is_ok());
        assert!(validate_manifest_for_language(&erlang, "gleam").is_err());
    }

    #[test]
    fn config_rejects_unknown_fields() {
        let source = r#"
schema_version = 1
tenant_id = "acme"
namespace = "critical"
language = "gleam"
tenancy_class = "tenant_dedicated"
project = "silently-dropped-before-this-test"

[artifact]
build_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
"#;
        assert!(toml::from_str::<DurableObjectsConfig>(source).is_err());
    }
}
