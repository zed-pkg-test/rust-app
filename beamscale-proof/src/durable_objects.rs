use anyhow::{bail, Context, Result};
use reqwest::blocking::{multipart, Client};
use serde::{Deserialize, Serialize};
use std::{env, fs, path::PathBuf};

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
    pub deployment: DeploymentConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactConfig {
    pub build_sha256: String,
    /// Optional compiler artifact directory. When present the CLI uploads the
    /// signed worker bundle to the BeamScale admin admission service first.
    pub directory: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    pub id: Option<String>,
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

pub fn deploy(options: DeployOptions) -> Result<()> {
    let source = fs::read_to_string(&options.config)
        .with_context(|| format!("read {}", options.config.display()))?;
    let config: DurableObjectsConfig =
        toml::from_str(&source).with_context(|| format!("parse {}", options.config.display()))?;
    validate(&config)?;

    let artifact_dir = config.artifact.directory.as_ref().map(|directory| {
        if directory.is_absolute() {
            directory.clone()
        } else {
            options
                .config
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join(directory)
        }
    });
    if let Some(directory) = artifact_dir.as_deref() {
        validate_local_artifact(directory, &config.artifact.build_sha256)?;
    }

    let request = DeployRequest {
        deployment_id: config.deployment.id.as_deref(),
        tenant_id: &config.tenant_id,
        namespace: &config.namespace,
        language: &config.language,
        build_sha256: &config.artifact.build_sha256,
        tenancy_class: &config.tenancy_class,
    };

    if options.dry_run {
        if let Some(directory) = artifact_dir.as_deref() {
            println!(
                "dry-run: would upload admitted artifact from {}",
                directory.display()
            );
        } else {
            println!(
                "dry-run: using already-admitted artifact sha256:{}",
                config.artifact.build_sha256
            );
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
            &config.artifact.build_sha256,
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

fn validate_local_artifact(directory: &std::path::Path, expected_build: &str) -> Result<()> {
    let manifest_path = directory.join("manifest.json");
    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest_path).with_context(|| format!("read {}", manifest_path.display()))?,
    )
    .with_context(|| format!("parse {}", manifest_path.display()))?;
    let actual = manifest
        .get("build_sha256")
        .and_then(serde_json::Value::as_str)
        .context("artifact manifest is missing build_sha256")?;
    if actual != expected_build {
        bail!(
            "artifact manifest build_sha256 {} does not match config {}",
            actual,
            expected_build
        );
    }
    locate_bundle(directory)?;
    Ok(())
}

fn locate_bundle(directory: &std::path::Path) -> Result<PathBuf> {
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
    directory: &std::path::Path,
    expected_build: &str,
) -> Result<()> {
    validate_local_artifact(directory, expected_build)?;
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

fn validate(config: &DurableObjectsConfig) -> Result<()> {
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
    let digest = &config.artifact.build_sha256;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        bail!("artifact.build_sha256 must be 64 lowercase hex characters");
    }
    if let Some(id) = config.deployment.id.as_deref() {
        validate_identity("deployment.id", id)?;
    }
    Ok(())
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
                build_sha256: "a".repeat(64),
                directory: None,
            },
            deployment: DeploymentConfig::default(),
        }
    }

    #[test]
    fn durable_objects_are_always_dedicated() {
        assert!(validate(&config("mixed_tenants")).is_err());
        assert!(validate(&config("tenant_dedicated")).is_ok());
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
