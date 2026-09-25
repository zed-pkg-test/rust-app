use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};
use walkdir::WalkDir;

const DOCS_SCHEMA_VERSION: &str = "ores.api-docs.lambda-deployment.v1";
const ROUTE_SCHEMA_VERSION: &str = "ores.routes.v1";

pub struct DocsManifestOptions {
    pub artifact_dir: PathBuf,
    pub route_manifest: PathBuf,
    pub service: String,
    pub contract_sha256: String,
    pub output: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct ArtifactManifest {
    runtime: String,
    language: String,
    build_sha256: String,
    entrypoint: String,
}

#[derive(Debug, Deserialize)]
struct BuildProvenance {
    policy_sha256: String,
}

#[derive(Debug, Deserialize)]
struct RouteManifest {
    schema_version: String,
    routes: Vec<Route>,
}

#[derive(Debug, Deserialize)]
struct Route {
    route_id: String,
    target: RouteTarget,
}

#[derive(Debug, Deserialize)]
struct RouteTarget {
    function_id: String,
    artifact_digest: String,
    runtime: RouteRuntime,
}

#[derive(Debug, Deserialize)]
struct RouteRuntime {
    kind: String,
    entrypoint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdmittedArtifact {
    runtime: String,
    language: String,
    build_sha256: String,
    policy_sha256: String,
    entrypoint: String,
}

#[derive(Debug)]
struct FunctionAccumulator {
    artifact: AdmittedArtifact,
    operation_keys: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeploymentDocsManifest {
    schema_version: &'static str,
    service: String,
    contract_sha256: String,
    functions: Vec<DeploymentDocsFunction>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DeploymentDocsFunction {
    id: String,
    producer: &'static str,
    runtime_family: &'static str,
    runtime_language: String,
    carrier: &'static str,
    architecture: &'static str,
    entrypoint: String,
    artifact_sha256: String,
    policy_sha256: String,
    operation_keys: Vec<String>,
    deploy_targets: [&'static str; 2],
}

pub fn emit(options: DocsManifestOptions) -> Result<()> {
    validate_service(&options.service)?;
    validate_sha256("contractSha256", &options.contract_sha256)?;

    let artifacts = discover_artifacts(&options.artifact_dir)?;
    if artifacts.is_empty() {
        bail!(
            "no admitted BeamScale artifact manifests found under {}",
            options.artifact_dir.display()
        );
    }

    let route_bytes = fs::read(&options.route_manifest)
        .with_context(|| format!("read route manifest {}", options.route_manifest.display()))?;
    let routes: RouteManifest = serde_json::from_slice(&route_bytes)
        .with_context(|| format!("parse route manifest {}", options.route_manifest.display()))?;
    if routes.schema_version != ROUTE_SCHEMA_VERSION {
        bail!(
            "unsupported route schema {:?}; expected {:?}",
            routes.schema_version,
            ROUTE_SCHEMA_VERSION
        );
    }

    let mut functions: BTreeMap<String, FunctionAccumulator> = BTreeMap::new();
    let mut route_ids = BTreeSet::new();

    for route in routes.routes {
        if route.route_id.is_empty() {
            bail!("route_id must not be empty");
        }
        if !route_ids.insert(route.route_id.clone()) {
            bail!("duplicate route_id {:?}", route.route_id);
        }
        if route.target.function_id.is_empty() {
            bail!("route {:?} has an empty function_id", route.route_id);
        }
        if route.target.runtime.kind != "beam" {
            bail!(
                "route {:?} targets runtime kind {:?}; BeamScale docs require beam",
                route.route_id,
                route.target.runtime.kind
            );
        }

        let digest = route
            .target
            .artifact_digest
            .strip_prefix("sha256:")
            .with_context(|| {
                format!(
                    "route {:?} artifact_digest must use sha256:<hex>",
                    route.route_id
                )
            })?;
        validate_sha256("artifact_digest", digest)?;

        let artifact = artifacts.get(digest).with_context(|| {
            format!(
                "route {:?} references artifact {} but no admitted manifest/provenance pair exists under {}",
                route.route_id,
                route.target.artifact_digest,
                options.artifact_dir.display()
            )
        })?;

        if artifact.runtime != "beam" {
            bail!(
                "artifact {} declares runtime {:?}; BeamScale docs require beam",
                digest,
                artifact.runtime
            );
        }
        if route.target.runtime.entrypoint != artifact.entrypoint {
            bail!(
                "route {:?} entrypoint {:?} does not match admitted artifact entrypoint {:?}",
                route.route_id,
                route.target.runtime.entrypoint,
                artifact.entrypoint
            );
        }

        let entry = functions
            .entry(route.target.function_id.clone())
            .or_insert_with(|| FunctionAccumulator {
                artifact: artifact.clone(),
                operation_keys: BTreeSet::new(),
            });
        if entry.artifact != *artifact {
            bail!(
                "function {:?} resolves to more than one admitted artifact in one route snapshot",
                route.target.function_id
            );
        }
        entry.operation_keys.insert(route.route_id);
    }

    if functions.is_empty() {
        bail!("route manifest contains no deployable BeamScale functions");
    }

    let functions = functions
        .into_iter()
        .map(|(id, function)| DeploymentDocsFunction {
            id,
            producer: "bmscl-compiler",
            runtime_family: "beam",
            runtime_language: function.artifact.language,
            carrier: "beam_process",
            architecture: "portable",
            entrypoint: function.artifact.entrypoint,
            artifact_sha256: function.artifact.build_sha256,
            policy_sha256: function.artifact.policy_sha256,
            operation_keys: function.operation_keys.into_iter().collect(),
            // A BeamScale-admitted portable BEAM artifact can also be hosted by
            // Scintilla; the inverse is intentionally not implied.
            deploy_targets: ["beamscale", "scintilla"],
        })
        .collect();

    let manifest = DeploymentDocsManifest {
        schema_version: DOCS_SCHEMA_VERSION,
        service: options.service,
        contract_sha256: options.contract_sha256,
        functions,
    };
    let mut json = serde_json::to_string_pretty(&manifest)?;
    json.push('\n');

    match options.output {
        Some(path) => {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!("create docs output directory {}", parent.display())
                })?;
            }
            fs::write(&path, json)
                .with_context(|| format!("write deployment docs manifest {}", path.display()))?;
        }
        None => print!("{json}"),
    }
    Ok(())
}

fn discover_artifacts(root: &Path) -> Result<BTreeMap<String, AdmittedArtifact>> {
    if !root.is_dir() {
        bail!("artifact directory {} does not exist", root.display());
    }

    let mut artifacts = BTreeMap::new();
    for entry in WalkDir::new(root).follow_links(false) {
        let entry = entry.with_context(|| format!("walk {}", root.display()))?;
        if !entry.file_type().is_file() || entry.file_name().to_str() != Some("manifest.json") {
            continue;
        }
        let manifest_path = entry.path();
        let parent = manifest_path
            .parent()
            .context("manifest parent directory")?;
        let provenance_path = parent.join("provenance.json");
        if !provenance_path.is_file() {
            continue;
        }

        let manifest: ArtifactManifest = serde_json::from_slice(
            &fs::read(manifest_path)
                .with_context(|| format!("read {}", manifest_path.display()))?,
        )
        .with_context(|| format!("parse {}", manifest_path.display()))?;
        let provenance: BuildProvenance = serde_json::from_slice(
            &fs::read(&provenance_path)
                .with_context(|| format!("read {}", provenance_path.display()))?,
        )
        .with_context(|| format!("parse {}", provenance_path.display()))?;

        validate_sha256("build_sha256", &manifest.build_sha256)?;
        validate_sha256("policy_sha256", &provenance.policy_sha256)?;
        if manifest.entrypoint.is_empty() {
            bail!("{} has an empty entrypoint", manifest_path.display());
        }

        let admitted = AdmittedArtifact {
            runtime: manifest.runtime,
            language: manifest.language,
            build_sha256: manifest.build_sha256.clone(),
            policy_sha256: provenance.policy_sha256,
            entrypoint: manifest.entrypoint,
        };
        match artifacts.get(&manifest.build_sha256) {
            Some(existing) if existing != &admitted => {
                bail!(
                    "build digest {} appears with inconsistent artifact metadata",
                    manifest.build_sha256
                );
            }
            Some(_) => {}
            None => {
                artifacts.insert(manifest.build_sha256, admitted);
            }
        }
    }
    Ok(artifacts)
}

fn validate_service(service: &str) -> Result<()> {
    let mut chars = service.chars();
    let Some(first) = chars.next() else {
        bail!("service must not be empty");
    };
    if !first.is_ascii_alphabetic()
        || service.len() > 128
        || !chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        bail!("service must match ^[A-Za-z][A-Za-z0-9._-]{{0,127}}$");
    }
    Ok(())
}

fn validate_sha256(field: &str, value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        bail!("{field} must be exactly 64 lowercase hexadecimal characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    const A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn write_fixture(root: &Path, route_digest: &str) {
        let artifact = root.join("dist/lambdas/users/get");
        fs::create_dir_all(&artifact).unwrap();
        fs::write(
            artifact.join("manifest.json"),
            format!(
                r#"{{"runtime":"beam","language":"gleam","build_sha256":"{A}","entrypoint":"worker:handle/2"}}"#
            ),
        )
        .unwrap();
        fs::write(
            artifact.join("provenance.json"),
            format!(r#"{{"policy_sha256":"{B}"}}"#),
        )
        .unwrap();
        fs::write(
            root.join("routes.json"),
            format!(
                r#"{{
  "schema_version":"ores.routes.v1",
  "release_id":"r1",
  "routing_version":1,
  "routes":[
    {{"route_id":"users.get","method":"GET","path":"/users/:id","target":{{"function_id":"users.get","deployment_id":"d1","artifact_digest":"sha256:{route_digest}","runtime":{{"kind":"beam","entrypoint":"worker:handle/2"}}}}}},
    {{"route_id":"users.head","method":"HEAD","path":"/users/:id","target":{{"function_id":"users.get","deployment_id":"d1","artifact_digest":"sha256:{route_digest}","runtime":{{"kind":"beam","entrypoint":"worker:handle/2"}}}}}}
  ]
}}"#
            ),
        )
        .unwrap();
    }

    #[test]
    fn emits_api_docs_contract_in_deterministic_order() {
        let root = tempdir().unwrap();
        write_fixture(root.path(), A);
        let output = root.path().join("lambda-deployment.json");

        emit(DocsManifestOptions {
            artifact_dir: root.path().join("dist"),
            route_manifest: root.path().join("routes.json"),
            service: "users-api".into(),
            contract_sha256: B.into(),
            output: Some(output.clone()),
        })
        .unwrap();

        let value: serde_json::Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
        assert_eq!(value["schemaVersion"], DOCS_SCHEMA_VERSION);
        assert_eq!(value["functions"][0]["producer"], "bmscl-compiler");
        assert_eq!(value["functions"][0]["runtimeFamily"], "beam");
        assert_eq!(value["functions"][0]["carrier"], "beam_process");
        assert_eq!(
            value["functions"][0]["operationKeys"],
            serde_json::json!(["users.get", "users.head"])
        );
        assert_eq!(
            value["functions"][0]["deployTargets"],
            serde_json::json!(["beamscale", "scintilla"])
        );
    }

    #[test]
    fn refuses_route_artifact_drift() {
        let root = tempdir().unwrap();
        write_fixture(root.path(), B);
        let error = emit(DocsManifestOptions {
            artifact_dir: root.path().join("dist"),
            route_manifest: root.path().join("routes.json"),
            service: "users-api".into(),
            contract_sha256: B.into(),
            output: Some(root.path().join("out.json")),
        })
        .unwrap_err();
        assert!(error.to_string().contains("no admitted manifest"));
    }
}
