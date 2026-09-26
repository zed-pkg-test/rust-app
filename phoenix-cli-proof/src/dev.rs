use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{
    collections::{hash_map::DefaultHasher, BTreeMap, BTreeSet},
    env, fs,
    hash::{Hash, Hasher},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    thread,
    time::Duration,
};
use walkdir::WalkDir;

const BRIDGE_SOURCE: &str = include_str!("../support/bmscl_dev_bridge.erl");
const BRIDGE_PREFIX: &str = "BMSCL_DEV_JSON ";

pub struct DevOptions {
    pub project: PathBuf,
    pub poll_ms: u64,
    /// Compatibility flag from the original `gleam run --module` dev mode.
    /// In persistent-runtime mode it focuses one discovered Lambda by name.
    pub module: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum UnitKind {
    Lambda,
    Middleware,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UnitState {
    kind: UnitKind,
    name: String,
    path: PathBuf,
    files: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DevSnapshot {
    lambdas: BTreeMap<String, UnitState>,
    middleware: BTreeMap<String, UnitState>,
    root: BTreeMap<String, u64>,
}

#[derive(Debug, PartialEq, Eq)]
enum Change {
    None,
    RestartP2,
    Hot {
        rebuild: Vec<String>,
        removed: Vec<String>,
    },
}

struct DevBridge {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

pub fn run(options: DevOptions) -> Result<()> {
    let project = options
        .project
        .canonicalize()
        .with_context(|| format!("resolve dev project {}", options.project.display()))?;
    let compiler = env::var("BMSCL_COMPILER").unwrap_or_else(|_| "bmscl-compiler".into());
    let focus = options
        .module
        .or_else(|| env::var("BMSCL_DEV_LAMBDA").ok())
        .filter(|value| !value.is_empty());

    eprintln!("[bmscl] dev root: {}", project.display());
    let supervisor_ebin = resolve_supervisor_ebin(&project)?;
    let snapshot0 = dev_snapshot(&project, focus.as_deref())?;
    validate_snapshot(&compiler, &snapshot0)?;
    let artifacts0 = prebuild_all(&compiler, &project, &snapshot0)?;

    let mut bridge = DevBridge::start(&project, &supervisor_ebin)?;
    eprintln!("[bmscl] P1/grandaddy: stable outer supervisor + BEAM VM");
    eprintln!("[bmscl] P2/daddy: replaceable routing/middleware runtime subtree");
    eprintln!("[bmscl] P3/workers: immutable Lambda generations with fresh invocation actors");

    activate_artifacts(&mut bridge, &artifacts0)?;
    let mut route_version = 1_u64;
    bridge.publish(route_version)?;
    eprintln!(
        "[bmscl] dev ready: {} Lambda route(s), {} middleware unit(s); P1 stays alive",
        snapshot0.lambdas.len(),
        snapshot0.middleware.len()
    );

    let mut snapshot = snapshot0;
    let poll = Duration::from_millis(options.poll_ms.max(25));

    loop {
        thread::sleep(poll);
        bridge.health()?;

        let next = match dev_snapshot(&project, focus.as_deref()) {
            Ok(next) => next,
            Err(error) => {
                eprintln!(
                    "[bmscl] dev discovery failed; keeping last-known-good runtime: {error:#}"
                );
                continue;
            }
        };

        match classify_change(&snapshot, &next) {
            Change::None => {}
            Change::RestartP2 => {
                eprintln!(
                    "[bmscl] middleware/config/runtime-shape change detected; validating before P2 replacement while P1 stays up"
                );
                if let Err(error) = validate_snapshot(&compiler, &next) {
                    eprintln!(
                        "[bmscl] rejected P2 change; last-known-good P2 remains active: {error:#}"
                    );
                    continue;
                }
                let artifacts = match prebuild_all(&compiler, &project, &next) {
                    Ok(artifacts) => artifacts,
                    Err(error) => {
                        eprintln!(
                            "[bmscl] rejected P2 change before restart; prebuild failed and existing P2 remains active: {error:#}"
                        );
                        continue;
                    }
                };

                eprintln!("[bmscl] draining and replacing P2; P1/granddaddy remains alive");
                bridge.restart_p2()?;
                activate_artifacts(&mut bridge, &artifacts)?;
                route_version += 1;
                bridge.publish(route_version)?;
                snapshot = next;
                eprintln!(
                    "[bmscl] P2 replacement complete; same P1/BEAM VM, Lambda generations reactivated, routes rehydrated"
                );
            }
            Change::Hot { rebuild, removed } => {
                let mut accepted = next.clone();
                let mut applied = Vec::new();

                for name in &removed {
                    bridge.remove(name)?;
                }

                for name in &rebuild {
                    let Some(unit) = next.lambdas.get(name) else {
                        continue;
                    };
                    eprintln!(
                        "[bmscl] Lambda {name} changed; compiling a new generation without restarting P2"
                    );
                    match build_artifact(&compiler, &project, unit) {
                        Ok(path) => {
                            bridge.activate(name, &path)?;
                            applied.push(name.clone());
                            eprintln!("[bmscl] hot activated lambda/{name}");
                        }
                        Err(error) => {
                            eprintln!(
                                "[bmscl] rejected lambda/{name}; keeping its last-known-good generation: {error:#}"
                            );
                            if let Some(previous) = snapshot.lambdas.get(name) {
                                accepted.lambdas.insert(name.clone(), previous.clone());
                            } else {
                                accepted.lambdas.remove(name);
                            }
                        }
                    }
                }

                if !removed.is_empty() || !applied.is_empty() {
                    route_version += 1;
                    if let Err(error) = bridge.publish(route_version) {
                        eprintln!(
                            "[bmscl] route swap rejected; retaining prior source snapshot for retry: {error:#}"
                        );
                        route_version -= 1;
                        continue;
                    }
                    eprintln!(
                        "[bmscl] route generation {route_version} installed; P1/P2 stayed up and new requests use fresh P3 actors"
                    );
                }
                snapshot = accepted;
            }
        }
    }
}

impl DevBridge {
    fn start(project: &Path, supervisor_ebin: &Path) -> Result<Self> {
        let bridge_root = project.join(".bmscl/dev/runtime-bridge");
        let source_dir = bridge_root.join("src");
        let ebin_dir = bridge_root.join("ebin");
        fs::create_dir_all(&source_dir)?;
        fs::create_dir_all(&ebin_dir)?;
        let source = source_dir.join("bmscl_dev_bridge.erl");
        fs::write(&source, BRIDGE_SOURCE)?;

        let status = Command::new("erlc")
            .arg("-o")
            .arg(&ebin_dir)
            .arg(&source)
            .status()
            .context("compile persistent BeamScale dev bridge with erlc")?;
        if !status.success() {
            bail!("erlc failed while compiling the BeamScale dev bridge: {status}");
        }

        let lib_root = supervisor_ebin
            .parent()
            .and_then(Path::parent)
            .context("derive Erlang library root from supervisor ebin")?;
        let mut child = Command::new("erl")
            .args(["-noshell", "-noinput"])
            .arg("-pa")
            .arg(&ebin_dir)
            .arg("-pa")
            .arg(supervisor_ebin)
            .args(["-s", "bmscl_dev_bridge", "main"])
            .env("ERL_LIBS", lib_root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .context("start long-lived BeamScale Erlang dev runtime")?;
        let input = child.stdin.take().context("capture dev bridge stdin")?;
        let output = child.stdout.take().context("capture dev bridge stdout")?;
        let mut bridge = Self {
            child,
            input,
            output: BufReader::new(output),
        };
        let ready = bridge.read_response()?;
        require_ok(&ready, "start dev runtime")?;
        if ready.get("event").and_then(Value::as_str) != Some("ready") {
            bail!("dev runtime did not emit a ready event: {ready}");
        }
        Ok(bridge)
    }

    fn request(&mut self, command: Value) -> Result<Value> {
        serde_json::to_writer(&mut self.input, &command)?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        self.read_response()
    }

    fn read_response(&mut self) -> Result<Value> {
        loop {
            let mut line = String::new();
            let count = self.output.read_line(&mut line)?;
            if count == 0 {
                let status = self.child.try_wait()?;
                bail!("persistent Erlang dev runtime closed its control channel: {status:?}");
            }
            let trimmed = line.trim_end();
            if let Some(payload) = trimmed.strip_prefix(BRIDGE_PREFIX) {
                return serde_json::from_str(payload)
                    .context("parse BeamScale dev bridge response");
            }
            if !trimmed.is_empty() {
                eprintln!("[bmscl:erl] {trimmed}");
            }
        }
    }

    fn health(&mut self) -> Result<()> {
        if let Some(status) = self.child.try_wait()? {
            bail!(
                "P1/granddaddy Erlang runtime exited with {status}; dev mode will not silently replace it"
            );
        }
        let response = self.request(json!({"cmd": "health"}))?;
        require_ok(&response, "check P1/P2 health")?;
        if response.get("p1_stable").and_then(Value::as_bool) != Some(true) {
            bail!("P1/granddaddy identity changed unexpectedly: {response}");
        }
        Ok(())
    }

    fn activate(&mut self, name: &str, path: &Path) -> Result<()> {
        let response = self.request(json!({
            "cmd": "activate",
            "name": name,
            "path": path.to_string_lossy(),
        }))?;
        require_ok(&response, &format!("activate lambda/{name}"))
    }

    fn remove(&mut self, name: &str) -> Result<()> {
        let response = self.request(json!({"cmd": "remove", "name": name}))?;
        require_ok(&response, &format!("remove lambda/{name}"))
    }

    fn publish(&mut self, version: u64) -> Result<()> {
        let response = self.request(json!({"cmd": "publish", "version": version}))?;
        require_ok(&response, "publish route generation")
    }

    fn restart_p2(&mut self) -> Result<()> {
        let response = self.request(json!({"cmd": "restart_p2"}))?;
        require_ok(&response, "restart P2/daddy")?;
        if response.get("p1_stable").and_then(Value::as_bool) != Some(true) {
            bail!("P2 restart changed P1/granddaddy identity: {response}");
        }
        Ok(())
    }
}

impl Drop for DevBridge {
    fn drop(&mut self) {
        let _ = serde_json::to_writer(&mut self.input, &json!({"cmd": "shutdown"}));
        let _ = self.input.write_all(b"\n");
        let _ = self.input.flush();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn require_ok(response: &Value, operation: &str) -> Result<()> {
    if response.get("ok").and_then(Value::as_bool) == Some(true) {
        return Ok(());
    }
    bail!("{operation} failed: {response}")
}

fn dev_snapshot(project: &Path, focus: Option<&str>) -> Result<DevSnapshot> {
    let mut lambdas = discover_units(UnitKind::Lambda, &project.join("lambdas"))?;
    let middleware = discover_units(UnitKind::Middleware, &project.join("middleware"))?;

    if lambdas.is_empty() && middleware.is_empty() && project.join("gleam.toml").is_file() {
        let state = unit_state(UnitKind::Lambda, "default".into(), project.to_path_buf())?;
        lambdas.insert("default".into(), state);
    }

    if let Some(name) = focus {
        let unit = lambdas
            .get(name)
            .cloned()
            .with_context(|| format!("unknown dev Lambda `{name}`"))?;
        lambdas.clear();
        lambdas.insert(name.to_string(), unit);
    }
    if lambdas.is_empty() {
        bail!("dev mode requires at least one Lambda unit");
    }

    Ok(DevSnapshot {
        lambdas,
        middleware,
        root: root_control_fingerprint(project)?,
    })
}

fn discover_units(kind: UnitKind, base: &Path) -> Result<BTreeMap<String, UnitState>> {
    let mut out = BTreeMap::new();
    if !base.is_dir() {
        return Ok(out);
    }
    for entry in WalkDir::new(base)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !ignored_directory(entry.path()))
    {
        let entry = entry.with_context(|| format!("walk dev units under {}", base.display()))?;
        if !entry.file_type().is_file() || entry.file_name().to_str() != Some("gleam.toml") {
            continue;
        }
        let dir = entry.path().parent().context("gleam.toml parent")?;
        let relative = dir.strip_prefix(base)?;
        let name = if relative.as_os_str().is_empty() {
            "default".into()
        } else {
            path_name(relative)?
        };
        let state = unit_state(kind, name.clone(), dir.to_path_buf())?;
        if out.insert(name.clone(), state).is_some() {
            bail!("duplicate dev unit name `{name}`");
        }
    }
    Ok(out)
}

fn unit_state(kind: UnitKind, name: String, path: PathBuf) -> Result<UnitState> {
    Ok(UnitState {
        kind,
        name,
        files: source_fingerprint(&path)?,
        path,
    })
}

fn classify_change(before: &DevSnapshot, after: &DevSnapshot) -> Change {
    if before == after {
        return Change::None;
    }
    if before.middleware != after.middleware || before.root != after.root {
        return Change::RestartP2;
    }

    let before_names = before.lambdas.keys().cloned().collect::<BTreeSet<_>>();
    let after_names = after.lambdas.keys().cloned().collect::<BTreeSet<_>>();
    let removed = before_names
        .difference(&after_names)
        .cloned()
        .collect::<Vec<_>>();
    let mut rebuild = after_names
        .difference(&before_names)
        .cloned()
        .collect::<Vec<_>>();

    for name in before_names.intersection(&after_names) {
        let left = &before.lambdas[name];
        let right = &after.lambdas[name];
        if left.files == right.files {
            continue;
        }
        if !lambda_source_only_change(&left.files, &right.files) {
            return Change::RestartP2;
        }
        rebuild.push(name.clone());
    }

    if rebuild.is_empty() && removed.is_empty() {
        Change::None
    } else {
        Change::Hot { rebuild, removed }
    }
}

fn lambda_source_only_change(
    before: &BTreeMap<String, u64>,
    after: &BTreeMap<String, u64>,
) -> bool {
    let keys = before
        .keys()
        .chain(after.keys())
        .cloned()
        .collect::<BTreeSet<_>>();
    let changed = keys
        .into_iter()
        .filter(|key| before.get(key) != after.get(key))
        .collect::<Vec<_>>();
    !changed.is_empty()
        && changed
            .iter()
            .all(|path| Path::new(path).extension().and_then(|ext| ext.to_str()) == Some("gleam"))
}

fn validate_snapshot(compiler: &str, snapshot: &DevSnapshot) -> Result<()> {
    for unit in snapshot
        .lambdas
        .values()
        .chain(snapshot.middleware.values())
    {
        eprintln!("[bmscl] check {}/{}", kind_label(unit.kind), unit.name);
        compiler_check(compiler, &unit.path).with_context(|| {
            format!(
                "admission check failed for {}/{}",
                kind_label(unit.kind),
                unit.name
            )
        })?;
    }
    Ok(())
}

fn compiler_check(compiler: &str, project: &Path) -> Result<()> {
    let mut command = Command::new(compiler);
    command.arg("check").arg(project);
    append_compiler_policy_args(&mut command);
    let status = command
        .status()
        .with_context(|| format!("launch {compiler} check for {}", project.display()))?;
    if !status.success() {
        bail!("{compiler} check failed with {status}");
    }
    Ok(())
}

fn prebuild_all(
    compiler: &str,
    project: &Path,
    snapshot: &DevSnapshot,
) -> Result<Vec<(String, PathBuf)>> {
    snapshot
        .lambdas
        .values()
        .map(|unit| {
            build_artifact(compiler, project, unit)
                .map(|path| (unit.name.clone(), path))
                .with_context(|| format!("prebuild lambda/{}", unit.name))
        })
        .collect()
}

fn build_artifact(compiler: &str, project: &Path, unit: &UnitState) -> Result<PathBuf> {
    let out = artifact_dir(project, &unit.name);
    if out.exists() {
        fs::remove_dir_all(&out)
            .with_context(|| format!("clean dev artifact {}", out.display()))?;
    }
    fs::create_dir_all(&out)?;
    let mut command = Command::new(compiler);
    command
        .arg("build")
        .arg(&unit.path)
        .arg("--out-dir")
        .arg(&out)
        .current_dir(&unit.path);
    append_compiler_policy_args(&mut command);
    let status = command
        .status()
        .with_context(|| format!("build lambda/{}", unit.name))?;
    if !status.success() {
        bail!("compiler build failed with {status}");
    }
    Ok(out)
}

fn activate_artifacts(bridge: &mut DevBridge, artifacts: &[(String, PathBuf)]) -> Result<()> {
    for (name, path) in artifacts {
        bridge.activate(name, path)?;
    }
    Ok(())
}

fn append_compiler_policy_args(command: &mut Command) {
    if let Ok(policy) = env::var("BMSCL_POLICY") {
        if !policy.is_empty() {
            command.arg("--policy").arg(policy);
        }
    }
    if let Ok(worker) = env::var("BMSCL_WORKER_CONFIG") {
        if !worker.is_empty() {
            command.arg("--worker-config").arg(worker);
        }
    }
}

fn resolve_supervisor_ebin(project: &Path) -> Result<PathBuf> {
    if let Ok(ebin) = env::var("BMSCL_SUPERVISOR_EBIN") {
        if !ebin.is_empty() {
            return validate_supervisor_ebin(PathBuf::from(ebin));
        }
    }

    let mut roots = Vec::new();
    if let Ok(root) = env::var("BMSCL_SUPERVISOR_ROOT") {
        if !root.is_empty() {
            roots.push(PathBuf::from(root));
        }
    }
    if let Some(parent) = project.parent() {
        roots.push(parent.join("bmscl-supervisor"));
    }
    roots.push(project.join("../bmscl-supervisor"));

    for root in roots {
        let root = root.canonicalize().unwrap_or(root);
        let ebin = supervisor_ebin_for_root(&root);
        if ebin.is_dir() {
            if let Ok(ebin) = validate_supervisor_ebin(ebin) {
                return Ok(ebin);
            }
        }
        if root.join("rebar.config").is_file() {
            let status = Command::new("rebar3")
                .arg("compile")
                .current_dir(&root)
                .status()
                .with_context(|| format!("compile supervisor runtime at {}", root.display()))?;
            if status.success() {
                let ebin = supervisor_ebin_for_root(&root);
                if let Ok(ebin) = validate_supervisor_ebin(ebin) {
                    return Ok(ebin);
                }
            }
        }
    }

    bail!(
        "BeamScale supervisor runtime not found; set BMSCL_SUPERVISOR_EBIN or BMSCL_SUPERVISOR_ROOT. Rust dev mode will not silently downgrade to whole-VM restart semantics"
    )
}

fn supervisor_ebin_for_root(root: &Path) -> PathBuf {
    root.join("_build/default/lib/bmscl_supervisor/ebin")
}

fn validate_supervisor_ebin(path: PathBuf) -> Result<PathBuf> {
    let path = path.canonicalize().unwrap_or(path);
    for module in [
        "bmscl_deployment_manager.beam",
        "bmscl_route_table.beam",
        "bmscl_runtime.beam",
    ] {
        if !path.join(module).is_file() {
            bail!("supervisor ebin {} is missing {module}", path.display());
        }
    }
    Ok(path)
}

fn artifact_dir(project: &Path, name: &str) -> PathBuf {
    let mut out = project.join(".bmscl/dev/lambdas");
    for part in name.split('/') {
        out.push(part);
    }
    out
}

fn source_fingerprint(root: &Path) -> Result<BTreeMap<String, u64>> {
    let mut files = BTreeMap::new();
    for entry in WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !ignored_directory(entry.path()))
    {
        let entry = entry.with_context(|| format!("walk dev tree {}", root.display()))?;
        if !entry.file_type().is_file() || !watched_file(entry.path()) {
            continue;
        }
        let relative = entry
            .path()
            .strip_prefix(root)?
            .to_string_lossy()
            .replace('\\', "/");
        files.insert(relative, hash_file(entry.path())?);
    }
    Ok(files)
}

fn root_control_fingerprint(root: &Path) -> Result<BTreeMap<String, u64>> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() && watched_file(&path) {
            let name = entry.file_name().to_string_lossy().to_string();
            files.insert(name, hash_file(&path)?);
        }
    }
    Ok(files)
}

fn hash_file(path: &Path) -> Result<u64> {
    let mut hasher = DefaultHasher::new();
    fs::read(path)
        .with_context(|| format!("read watched source {}", path.display()))?
        .hash(&mut hasher);
    Ok(hasher.finish())
}

fn path_name(path: &Path) -> Result<String> {
    let mut parts = Vec::new();
    for component in path.components() {
        let std::path::Component::Normal(value) = component else {
            bail!("invalid unit path {}", path.display());
        };
        parts.push(
            value
                .to_str()
                .context("unit path must be UTF-8")?
                .to_string(),
        );
    }
    Ok(parts.join("/"))
}

fn kind_label(kind: UnitKind) -> &'static str {
    match kind {
        UnitKind::Lambda => "lambda",
        UnitKind::Middleware => "middleware",
    }
}

fn ignored_directory(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| {
            matches!(
                name,
                ".git" | "build" | "dist" | "node_modules" | "_build" | ".cache" | ".bmscl"
            )
        })
        .unwrap_or(false)
}

fn watched_file(path: &Path) -> bool {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("gleam.toml" | "manifest.toml") => true,
        _ => matches!(
            path.extension().and_then(|ext| ext.to_str()),
            Some("gleam" | "toml" | "json" | "yaml" | "yml")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unit(name: &str, files: &[(&str, u64)]) -> UnitState {
        UnitState {
            kind: UnitKind::Lambda,
            name: name.into(),
            path: PathBuf::from(name),
            files: files.iter().map(|(k, v)| ((*k).into(), *v)).collect(),
        }
    }

    fn snapshot(unit: UnitState) -> DevSnapshot {
        DevSnapshot {
            lambdas: BTreeMap::from([(unit.name.clone(), unit)]),
            middleware: BTreeMap::new(),
            root: BTreeMap::new(),
        }
    }

    #[test]
    fn gleam_only_lambda_edit_is_hot() {
        let before = snapshot(unit("home", &[("src/worker.gleam", 1)]));
        let after = snapshot(unit("home", &[("src/worker.gleam", 2)]));
        assert_eq!(
            classify_change(&before, &after),
            Change::Hot {
                rebuild: vec!["home".into()],
                removed: vec![]
            }
        );
    }

    #[test]
    fn lambda_manifest_change_restarts_only_p2() {
        let before = snapshot(unit("home", &[("src/worker.gleam", 1), ("gleam.toml", 1)]));
        let after = snapshot(unit("home", &[("src/worker.gleam", 1), ("gleam.toml", 2)]));
        assert_eq!(classify_change(&before, &after), Change::RestartP2);
    }

    #[test]
    fn root_control_change_restarts_only_p2() {
        let before = snapshot(unit("home", &[("src/worker.gleam", 1)]));
        let mut after = before.clone();
        after.root.insert(".ores-lambda.toml".into(), 2);
        assert_eq!(classify_change(&before, &after), Change::RestartP2);
    }
}
