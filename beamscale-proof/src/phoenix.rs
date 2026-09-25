use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::{
    collections::BTreeSet,
    env, fs,
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

  IO.puts(Enum.join(fields, "\t"))
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
    IO.puts(to_string(path))
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
        (&left.method, &left.path, &left.handler, &left.action)
            .cmp(&(&right.method, &right.path, &right.handler, &right.action))
    });

    let mut socket_paths = BTreeSet::new();
    if let Some(endpoint) = options.endpoint.as_deref() {
        let socket_stdout = run_mix_probe(
            &project,
            SOCKET_PROBE,
            &[("BMSCL_PHOENIX_ENDPOINT", endpoint)],
            "endpoint socket",
        )?;
        for raw in socket_stdout.lines().filter(|line| !line.trim().is_empty()) {
            socket_paths.insert(normalize_socket_path(raw)?);
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
    let mut json = serde_json::to_string_pretty(&plan).context("serialize Phoenix discovery plan")?;
    json.push('\n');

    match options.output {
        Some(path) => {
            let path = if path.is_absolute() { path } else { project.join(path) };
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
        .env("MIX_ENV", env::var("MIX_ENV").unwrap_or_else(|_| "prod".into()));
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
        let fields = line.splitn(4, '\t').collect::<Vec<_>>();
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
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b == b'*')
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
    let parent = output.parent().context("Phoenix plan output has no parent")?;
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

    #[test]
    fn parses_request_routes() {
        let routes = parse_route_lines(
            "GET\t/users/:id\tMyAppWeb.UserController\t:show\nPOST\t/users\tMyAppWeb.UserController\t:create\n",
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
        let error = parse_route_lines("GET /users\n").unwrap_err();
        assert!(error.to_string().contains("tab-separated"));
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
