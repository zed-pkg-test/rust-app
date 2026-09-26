use anyhow::{bail, Context, Result};
use reqwest::blocking::{multipart, Client};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

const ROUTE_PROBE: &str = r#"
router =
  System.fetch_env!("BMSCL_PHOENIX_ROUTER")
  |> String.split(".", trim: true)
  |> Module.concat()

unless Code.ensure_loaded?(router) do
  raise "router module not available: #{inspect(router)}"
end

for route <- Phoenix.Router.routes(router) do
  fields = [
    route.verb |> to_string() |> String.upcase(),
    route.path |> to_string(),
    inspect(route.plug, limit: :infinity),
    inspect(route.plug_opts, limit: :infinity)
  ]

  IO.puts("BMSCL_ROUTE\t" <> Enum.join(fields, "\t"))
end
"#;

const SOCKET_PROBE: &str = r#"
endpoint =
  System.fetch_env!("BMSCL_PHOENIX_ENDPOINT")
  |> String.split(".", trim: true)
  |> Module.concat()

unless Code.ensure_loaded?(endpoint) do
  raise "endpoint module not available: #{inspect(endpoint)}"
end

unless function_exported?(endpoint, :__sockets__, 0) do
  raise "endpoint does not export __sockets__/0; use --socket-path fallback"
end

for {path, _socket, opts} <- endpoint.__sockets__() do
  websocket = Keyword.get(opts, :websocket, true)

  if websocket != false do
    IO.puts("BMSCL_SOCKET\t" <> to_string(path))
  end
end
"#;

#[derive(Debug, Clone)]
pub struct PhoenixPlanOptions {
    pub project: PathBuf,
    pub router: String,
    pub endpoint: Option<String>,
    pub socket_paths: Vec<String>,
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct PhoenixDeployOptions {
    pub artifact_dir: PathBuf,
    pub tenant_id: String,
    pub shard_id: String,
    pub deployment_id: Option<String>,
    pub api_url: String,
    pub admin_api_url: String,
    pub dry_run: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PhoenixArtifactManifest {
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

#[derive(Debug, Serialize)]
struct PhoenixDeployRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    deployment_id: Option<&'a str>,
    tenant_id: &'a str,
    shard_id: &'a str,
    manifest: &'a PhoenixArtifactManifest,
}

pub struct PhoenixPackageOptions {
    pub release_dir: PathBuf,
    pub out_dir: PathBuf,
    pub app: String,
    pub version: String,
    pub router: String,
    pub endpoint: String,
    pub route_plan: PathBuf,
    pub source_sha256: String,
    pub builder_image_digest: String,
    pub signing_key: Option<PathBuf>,
    pub key_id: Option<String>,
    pub unsigned: bool,
}

pub fn deploy(options: PhoenixDeployOptions) -> Result<()> {
    validate_identity("tenant_id", &options.tenant_id)?;
    validate_identity("shard_id", &options.shard_id)?;
    if let Some(id) = options.deployment_id.as_deref() {
        validate_identity("deployment_id", id)?;
    }

    let manifest_path = options.artifact_dir.join("manifest.json");
    let manifest: PhoenixArtifactManifest = serde_json::from_slice(
        &fs::read(&manifest_path).with_context(|| format!("read {}", manifest_path.display()))?,
    )
    .with_context(|| format!("parse {}", manifest_path.display()))?;
    validate_artifact_manifest(&manifest)?;

    let route_plan = options.artifact_dir.join("route-plan.json");
    let release = options.artifact_dir.join("release");
    if !route_plan.is_file() || !release.is_dir() {
        bail!(
            "{} is not a complete Phoenix artifact directory",
            options.artifact_dir.display()
        );
    }

    let request = PhoenixDeployRequest {
        deployment_id: options.deployment_id.as_deref(),
        tenant_id: &options.tenant_id,
        shard_id: &options.shard_id,
        manifest: &manifest,
    };

    let archive = options.artifact_dir.join("phoenix-release.tar.gz");
    if !archive.is_file() {
        bail!(
            "{} is missing phoenix-release.tar.gz",
            options.artifact_dir.display()
        );
    }

    if options.dry_run {
        eprintln!(
            "dry-run: would upload admitted Phoenix archive from {}",
            archive.display()
        );
        println!("{}", serde_json::to_string_pretty(&request)?);
        return Ok(());
    }

    let client = Client::new();
    upload_phoenix_artifact(&client, &options.admin_api_url, &archive)?;
    let token =
        env::var("BMSCL_TOKEN").context("set BMSCL_TOKEN for Phoenix deployment authentication")?;
    let url = format!(
        "{}/v1/phoenix/deployments",
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
        .context("read BeamScale Phoenix deployment response")?;
    if !status.is_success() {
        bail!("BeamScale Phoenix deployment failed with HTTP {status}: {body}");
    }
    println!("{body}");
    Ok(())
}

fn upload_phoenix_artifact(client: &Client, admin_api_url: &str, archive: &Path) -> Result<()> {
    let bytes = fs::read(archive).with_context(|| format!("read {}", archive.display()))?;
    let token = env::var("BMSCL_ADMIN_TOKEN")
        .context("set BMSCL_ADMIN_TOKEN to upload a Phoenix release artifact")?;
    let filename = archive
        .file_name()
        .and_then(|name| name.to_str())
        .context("Phoenix archive filename must be UTF-8")?
        .to_owned();
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
                    .mime_str("application/gzip")?,
            ),
        )
        .send()
        .with_context(|| format!("POST {url}"))?;
    let status = response.status();
    let body = response
        .text()
        .context("read BeamScale Phoenix artifact admission response")?;
    if !status.is_success() {
        bail!("BeamScale Phoenix artifact admission failed with HTTP {status}: {body}");
    }
    Ok(())
}

fn validate_artifact_manifest(manifest: &PhoenixArtifactManifest) -> Result<()> {
    if manifest.format_version != 1
        || manifest.artifact_format != "bmscl-phoenix-release-v1"
        || manifest.artifact_root != "release"
        || manifest.runtime != "beam_release"
        || manifest.language != "elixir"
        || manifest.profile != "bmscl-phoenix-elixir-v1"
        || manifest.execution_class != "phoenix"
        || manifest.isolation_class != "firecracker"
    {
        bail!("artifact is not a BeamScale Phoenix Firecracker release");
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
            bail!("invalid {name}");
        }
    }
    validate_identity("app", &manifest.app)?;
    validate_module_name("router", &manifest.router)?;
    validate_module_name("endpoint", &manifest.endpoint)?;
    if manifest.version.is_empty()
        || manifest.version.len() > 128
        || manifest.version.as_bytes().contains(&0)
    {
        bail!("invalid Phoenix version");
    }
    Ok(())
}

fn validate_identity(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    {
        bail!("{label} must be 1..=128 chars of [A-Za-z0-9._-]");
    }
    Ok(())
}

pub fn package(options: PhoenixPackageOptions) -> Result<()> {
    let compiler = env::var("BMSCL_COMPILER").unwrap_or_else(|_| "bmscl-compiler".into());
    let args = package_args(&options)?;
    let status = Command::new(&compiler)
        .args(&args)
        .status()
        .with_context(|| format!("launch {compiler} phoenix-package"))?;
    if !status.success() {
        bail!("{compiler} phoenix-package failed with {status}");
    }
    Ok(())
}

fn package_args(options: &PhoenixPackageOptions) -> Result<Vec<OsString>> {
    if options.unsigned && (options.signing_key.is_some() || options.key_id.is_some()) {
        bail!("--unsigned cannot be combined with --signing-key or --key-id");
    }
    if !options.unsigned && (options.signing_key.is_none() || options.key_id.is_none()) {
        bail!(
            "production Phoenix package requires --signing-key and --key-id; use --unsigned only for local development"
        );
    }

    let mut args = vec![
        OsString::from("phoenix-package"),
        OsString::from("--release-dir"),
        options.release_dir.as_os_str().to_owned(),
        OsString::from("--out-dir"),
        options.out_dir.as_os_str().to_owned(),
        OsString::from("--app"),
        OsString::from(&options.app),
        OsString::from("--version"),
        OsString::from(&options.version),
        OsString::from("--router"),
        OsString::from(&options.router),
        OsString::from("--endpoint"),
        OsString::from(&options.endpoint),
        OsString::from("--route-plan"),
        options.route_plan.as_os_str().to_owned(),
        OsString::from("--source-sha256"),
        OsString::from(&options.source_sha256),
        OsString::from("--builder-image-digest"),
        OsString::from(&options.builder_image_digest),
    ];
    if let (Some(signing_key), Some(key_id)) =
        (options.signing_key.as_deref(), options.key_id.as_deref())
    {
        args.push(OsString::from("--signing-key"));
        args.push(signing_key.as_os_str().to_owned());
        args.push(OsString::from("--key-id"));
        args.push(OsString::from(key_id));
    }
    Ok(args)
}

#[derive(Debug, Serialize)]
struct PhoenixDiscoveryPlan {
    schema_version: &'static str,
    router: String,
    endpoint: Option<String>,
    build_granularity: &'static str,
    isolation_class: &'static str,
    routes: Vec<RequestRoute>,
    connections: Vec<ConnectionRoute>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct RequestRoute {
    method: String,
    path: String,
    execution_class: &'static str,
    protocol: &'static str,
    handler: String,
    action: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ConnectionRoute {
    method: &'static str,
    path: String,
    execution_class: &'static str,
    protocol: &'static str,
}

pub fn emit(options: PhoenixPlanOptions) -> Result<()> {
    let project = absolute_path(&options.project)?;
    let mix_exs = project.join("mix.exs");
    if !mix_exs.is_file() {
        bail!(
            "Phoenix discovery requires a Mix project; {} does not exist",
            mix_exs.display()
        );
    }
    validate_module_name("--router", &options.router)?;
    if let Some(endpoint) = options.endpoint.as_deref() {
        validate_module_name("--endpoint", endpoint)?;
    }

    let route_stdout = run_mix_probe(
        &project,
        ROUTE_PROBE,
        &[("BMSCL_PHOENIX_ROUTER", options.router.as_str())],
        "route",
    )?;
    let mut routes = parse_route_lines(&route_stdout)?;
    routes.sort_by(|left, right| {
        (&left.method, &left.path, &left.handler, &left.action).cmp(&(
            &right.method,
            &right.path,
            &right.handler,
            &right.action,
        ))
    });

    let mut socket_paths = BTreeSet::new();
    if let Some(endpoint) = options.endpoint.as_deref() {
        let socket_stdout = run_mix_probe(
            &project,
            SOCKET_PROBE,
            &[("BMSCL_PHOENIX_ENDPOINT", endpoint)],
            "endpoint socket",
        )?;
        for line in socket_stdout.lines() {
            let Some(raw) = line.strip_prefix("BMSCL_SOCKET\t") else {
                continue;
            };
            if !raw.trim().is_empty() {
                socket_paths.insert(normalize_socket_path(raw)?);
            }
        }
    }
    for raw in options.socket_paths {
        socket_paths.insert(normalize_socket_path(&raw)?);
    }

    let connections = socket_paths
        .into_iter()
        .map(|path| ConnectionRoute {
            method: "GET",
            path,
            execution_class: "connection",
            protocol: "websocket",
        })
        .collect::<Vec<_>>();

    let plan = PhoenixDiscoveryPlan {
        schema_version: "bmscl.phoenix.discovery.v2",
        router: options.router,
        endpoint: options.endpoint,
        build_granularity: "application_generation",
        isolation_class: "firecracker",
        routes,
        connections,
    };
    let mut json =
        serde_json::to_string_pretty(&plan).context("serialize Phoenix discovery plan")?;
    json.push('\n');

    match options.output {
        Some(path) => {
            let path = if path.is_absolute() {
                path
            } else {
                project.join(path)
            };
            ensure_output_confined(&project, &path)?;
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("create {}", parent.display()))?;
            }
            fs::write(&path, json).with_context(|| format!("write {}", path.display()))?;
            eprintln!("[bmscl] wrote Phoenix discovery plan to {}", path.display());
        }
        None => print!("{json}"),
    }
    Ok(())
}

fn run_mix_probe(
    project: &Path,
    probe: &str,
    envs: &[(&str, &str)],
    label: &str,
) -> Result<String> {
    let mut command = Command::new("mix");
    command
        .args(["run", "--no-start", "-e", probe])
        .current_dir(project)
        .env(
            "MIX_ENV",
            env::var("MIX_ENV").unwrap_or_else(|_| "prod".into()),
        );
    for (name, value) in envs {
        command.env(name, value);
    }
    let output = command
        .output()
        .with_context(|| format!("run Phoenix {label} discovery in {}", project.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "Phoenix {label} discovery failed with {}: {}",
            output.status,
            stderr.trim()
        );
    }
    String::from_utf8(output.stdout).context("mix discovery output was not UTF-8")
}

fn parse_route_lines(stdout: &str) -> Result<Vec<RequestRoute>> {
    let mut routes = Vec::new();
    for (index, line) in stdout.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let Some(payload) = line.strip_prefix("BMSCL_ROUTE\t") else {
            continue;
        };
        let fields = payload.splitn(4, '\t').collect::<Vec<_>>();
        if fields.len() != 4 {
            bail!(
                "invalid Phoenix route probe output on line {}: expected 4 tab-separated fields",
                index + 1
            );
        }
        let method = fields[0].trim().to_ascii_uppercase();
        let path = fields[1].trim();
        if !valid_http_method(&method) || !valid_route_path(path) {
            bail!("invalid Phoenix route on line {}", index + 1);
        }
        routes.push(RequestRoute {
            method,
            path: path.to_string(),
            execution_class: "request",
            protocol: "http",
            handler: fields[2].trim().to_string(),
            action: fields[3].trim().to_string(),
        });
    }
    Ok(routes)
}

fn validate_module_name(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || value.split('.').any(|segment| {
            segment.is_empty()
                || !segment
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    {
        bail!("{label} must be a dotted Elixir module name");
    }
    Ok(())
}

fn valid_http_method(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 16
        && value.bytes().all(|b| b.is_ascii_uppercase() || b == b'*')
}

fn valid_route_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 4096
        && !path.contains('?')
        && !path.contains('#')
        && !path.contains('\0')
        && !path.contains('\r')
        && !path.contains('\n')
}

fn normalize_socket_path(value: &str) -> Result<String> {
    let path = value.trim();
    if !valid_route_path(path) {
        bail!("invalid Phoenix socket path: {value}");
    }
    Ok(path.trim_end_matches('/').to_string().replace("//", "/"))
}

fn ensure_output_confined(project: &Path, output: &Path) -> Result<()> {
    let parent = output
        .parent()
        .context("Phoenix plan output has no parent")?;
    let mut probe = parent;
    while !probe.exists() {
        probe = probe
            .parent()
            .context("Phoenix plan output has no existing ancestor")?;
    }
    let project = project
        .canonicalize()
        .with_context(|| format!("resolve {}", project.display()))?;
    let parent = probe
        .canonicalize()
        .with_context(|| format!("resolve {}", probe.display()))?;
    if !parent.starts_with(&project) {
        bail!("Phoenix plan output must remain within the project directory");
    }
    Ok(())
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        env::current_dir()?.join(path)
    };
    candidate
        .canonicalize()
        .with_context(|| format!("resolve Phoenix project {}", candidate.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn package_options() -> PhoenixPackageOptions {
        PhoenixPackageOptions {
            release_dir: PathBuf::from("_build/prod/rel/demo"),
            out_dir: PathBuf::from("dist-phoenix"),
            app: "demo".into(),
            version: "0.1.0".into(),
            router: "DemoWeb.Router".into(),
            endpoint: "DemoWeb.Endpoint".into(),
            route_plan: PathBuf::from("dist/phoenix-routes.json"),
            source_sha256: "a".repeat(64),
            builder_image_digest: format!("sha256:{}", "b".repeat(64)),
            signing_key: Some(PathBuf::from("customer-key.hex")),
            key_id: Some("customer-q3".into()),
            unsigned: false,
        }
    }

    #[test]
    fn phoenix_package_is_signed_by_default() {
        let args = package_args(&package_options()).unwrap();
        assert_eq!(args[0], OsString::from("phoenix-package"));
        assert!(args.contains(&OsString::from("--signing-key")));
        assert!(args.contains(&OsString::from("--builder-image-digest")));
    }

    #[test]
    fn phoenix_package_unsigned_is_explicit() {
        let mut options = package_options();
        options.signing_key = None;
        options.key_id = None;
        assert!(package_args(&options).is_err());
        options.unsigned = true;
        assert!(package_args(&options).is_ok());
    }

    #[test]
    fn phoenix_package_rejects_ambiguous_signing_mode() {
        let mut options = package_options();
        options.unsigned = true;
        assert!(package_args(&options).is_err());
    }

    #[test]
    fn validates_compiler_phoenix_manifest() {
        let manifest = PhoenixArtifactManifest {
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
        };
        assert!(validate_artifact_manifest(&manifest).is_ok());

        let mut bad = manifest;
        bad.isolation_class = "bare_process".into();
        assert!(validate_artifact_manifest(&bad).is_err());
    }

    #[test]
    fn parses_request_routes() {
        let routes = parse_route_lines(
            "Compiling 2 files (.ex)\nBMSCL_ROUTE\tGET\t/users/:id\tMyAppWeb.UserController\t:show\nBMSCL_ROUTE\tPOST\t/users\tMyAppWeb.UserController\t:create\nGenerated app\n",
        )
        .unwrap();
        assert_eq!(routes.len(), 2);
        assert_eq!(routes[0].execution_class, "request");
        assert_eq!(routes[0].protocol, "http");
        assert_eq!(routes[0].path, "/users/:id");
        assert_eq!(routes[0].action, ":show");
    }

    #[test]
    fn rejects_malformed_probe_output() {
        let error = parse_route_lines("BMSCL_ROUTE\tGET /users\n").unwrap_err();
        assert!(error.to_string().contains("tab-separated"));
    }

    #[test]
    fn ignores_unframed_mix_stdout() {
        let routes = parse_route_lines(
            "Compiling 4 files (.ex)\nGenerated app\nBMSCL_ROUTE\tGET\t/ok\tMyApp.Controller\t:index\n",
        )
        .unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].path, "/ok");
    }

    #[test]
    fn validates_socket_paths() {
        assert_eq!(normalize_socket_path("/socket").unwrap(), "/socket");
        assert_eq!(normalize_socket_path("/live/").unwrap(), "/live");
        assert!(normalize_socket_path("socket").is_err());
        assert!(normalize_socket_path("/socket?token=x").is_err());
    }

    #[test]
    fn validates_elixir_modules() {
        assert!(validate_module_name("--router", "MyAppWeb.Router").is_ok());
        assert!(validate_module_name("--router", "Elixir.My_App.Router2").is_ok());
        assert!(validate_module_name("--router", "My App.Router").is_err());
        assert!(validate_module_name("--router", "MyApp..Router").is_err());
    }
}
