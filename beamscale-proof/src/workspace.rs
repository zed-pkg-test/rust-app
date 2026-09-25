use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnitKind {
    Lambda,
    Middleware,
}

impl UnitKind {
    fn label(self) -> &'static str {
        match self {
            Self::Lambda => "lambda",
            Self::Middleware => "middleware",
        }
    }

    fn bucket(self) -> &'static str {
        match self {
            Self::Lambda => "lambdas",
            Self::Middleware => "middleware",
        }
    }
}

#[derive(Debug, Clone)]
struct SourceUnit {
    kind: UnitKind,
    name: String,
    path: PathBuf,
}

pub struct BuildOptions {
    pub project: PathBuf,
    pub out_dir: PathBuf,
    pub policy: Option<PathBuf>,
    pub worker_config: Option<PathBuf>,
    pub deny_cpu_loops: bool,
    /// Continue a multi-unit workspace build when (and only when) the canonical
    /// compiler emitted a current `admission-report.json` with `admitted=false`.
    /// The compiler remains fail-closed and final Erlang/BEAM verification is
    /// never downgraded by this option.
    pub filter_unsafe: bool,
}

pub fn build_tree(options: BuildOptions) -> Result<()> {
    let project = absolute_path(&options.project)?;
    let out_dir = if options.out_dir.is_absolute() {
        options.out_dir.clone()
    } else {
        project.join(&options.out_dir)
    };
    let units = discover_units(&project)?;
    if units.is_empty() {
        bail!(
            "no Gleam project, lambdas/, or middleware/ units found under {}",
            project.display()
        );
    }

    let compiler = env::var("BMSCL_COMPILER").unwrap_or_else(|_| "bmscl-compiler".into());
    if units.len() == 1
        && units[0].kind == UnitKind::Lambda
        && units[0].name == "default"
        && units[0].path == project
    {
        match build_unit(&compiler, &units[0], &out_dir, &options) {
            Ok(()) => return Ok(()),
            Err(error) if options.filter_unsafe => {
                if let Some(summary) = admission_rejection_summary(&out_dir)? {
                    warn_filtered_unit(&units[0], &summary);
                    bail!(
                        "all discovered units were rejected by admission policy; no deployable artifact was produced"
                    );
                }
                return Err(error);
            }
            Err(error) => return Err(error),
        }
    }

    eprintln!(
        "[bmscl] building {} units into {}",
        units.len(),
        out_dir.display()
    );
    let mut built = 0usize;
    let mut filtered = 0usize;
    for unit in &units {
        let unit_out = out_dir.join(unit.kind.bucket()).join(&unit.name);
        eprintln!(
            "[bmscl] build {}/{} <- {}",
            unit.kind.label(),
            unit.name,
            unit.path.display()
        );
        match build_unit(&compiler, unit, &unit_out, &options) {
            Ok(()) => built += 1,
            Err(error) if options.filter_unsafe => {
                if let Some(summary) = admission_rejection_summary(&unit_out)? {
                    filtered += 1;
                    warn_filtered_unit(unit, &summary);
                    continue;
                }
                return Err(error).with_context(|| {
                    format!(
                        "build stopped after {}/{} failed outside admission policy",
                        unit.kind.label(),
                        unit.name
                    )
                });
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "build stopped after {}/{} failed",
                        unit.kind.label(),
                        unit.name
                    )
                })
            }
        }
    }

    if built == 0 {
        bail!(
            "all {} discovered units were rejected; no deployable artifact was produced",
            units.len()
        );
    }
    if filtered > 0 {
        eprintln!(
            "[bmscl] WARNING: filtered {filtered} admission-rejected unit(s); built {built} deployable unit(s)"
        );
        eprintln!(
            "[bmscl] WARNING: rejected unit directories contain admission evidence only and no manifest.json, so deploy discovery ignores them"
        );
    }
    Ok(())
}

fn discover_units(root: &Path) -> Result<Vec<SourceUnit>> {
    let mut units = Vec::new();
    collect_units(UnitKind::Lambda, &root.join("lambdas"), &mut units)?;
    collect_units(UnitKind::Middleware, &root.join("middleware"), &mut units)?;

    if units.is_empty() && root.join("gleam.toml").is_file() {
        units.push(SourceUnit {
            kind: UnitKind::Lambda,
            name: "default".into(),
            path: root.to_path_buf(),
        });
    }
    units.sort_by(|left, right| {
        (left.kind.label(), left.name.as_str()).cmp(&(right.kind.label(), right.name.as_str()))
    });
    Ok(units)
}

fn collect_units(kind: UnitKind, base: &Path, out: &mut Vec<SourceUnit>) -> Result<()> {
    if !base.is_dir() {
        return Ok(());
    }
    for entry in WalkDir::new(base)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !ignored_dir(entry.path()))
    {
        let entry = entry.with_context(|| format!("walk source units under {}", base.display()))?;
        if !entry.file_type().is_file() || entry.file_name().to_str() != Some("gleam.toml") {
            continue;
        }
        let dir = entry
            .path()
            .parent()
            .context("gleam.toml parent directory")?;
        let relative = dir
            .strip_prefix(base)
            .with_context(|| format!("unit {} escaped {}", dir.display(), base.display()))?;
        let name = if relative.as_os_str().is_empty() {
            "default".to_string()
        } else {
            path_name(relative)?
        };
        out.push(SourceUnit {
            kind,
            name,
            path: dir.to_path_buf(),
        });
    }
    Ok(())
}

fn build_unit(
    compiler: &str,
    unit: &SourceUnit,
    out_dir: &Path,
    options: &BuildOptions,
) -> Result<()> {
    // Never let a rejected rebuild inherit a stale manifest/BEAM tree from a
    // previously admitted generation.  A rejected unit may leave its fresh
    // admission-report.json for evidence, but it must not remain deployable.
    if out_dir.exists() {
        fs::remove_dir_all(out_dir)
            .with_context(|| format!("clean build output {}", out_dir.display()))?;
    }
    fs::create_dir_all(out_dir)
        .with_context(|| format!("create build output {}", out_dir.display()))?;

    let mut command = Command::new(compiler);
    command
        .arg("build")
        .arg(&unit.path)
        .arg("--out-dir")
        .arg(out_dir)
        .current_dir(&unit.path);
    if let Some(policy) = options.policy.as_deref() {
        command.arg("--policy").arg(policy);
    } else if let Ok(policy) = env::var("BMSCL_POLICY") {
        if !policy.is_empty() {
            command.arg("--policy").arg(policy);
        }
    }
    if let Some(worker) = options.worker_config.as_deref() {
        command.arg("--worker-config").arg(worker);
    } else if let Ok(worker) = env::var("BMSCL_WORKER_CONFIG") {
        if !worker.is_empty() {
            command.arg("--worker-config").arg(worker);
        }
    }
    if options.deny_cpu_loops {
        command.arg("--deny-cpu-loops");
    }
    let status = command
        .status()
        .with_context(|| format!("launch {compiler} build for {}", unit.path.display()))?;
    if !status.success() {
        bail!("{compiler} build failed with {status}");
    }
    Ok(())
}

fn admission_rejection_summary(out_dir: &Path) -> Result<Option<String>> {
    let report_path = out_dir.join("admission-report.json");
    if !report_path.is_file() {
        return Ok(None);
    }
    let bytes =
        fs::read(&report_path).with_context(|| format!("read {}", report_path.display()))?;
    let report: Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse {}", report_path.display()))?;
    if report.get("admitted").and_then(Value::as_bool) != Some(false) {
        return Ok(None);
    }

    let mut codes = report
        .get("findings")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|finding| finding.get("code").and_then(Value::as_str))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    codes.sort();
    codes.dedup();
    let summary = if codes.is_empty() {
        "admitted=false".to_string()
    } else {
        format!("admitted=false; findings={}", codes.join(","))
    };
    Ok(Some(summary))
}

fn warn_filtered_unit(unit: &SourceUnit, summary: &str) {
    eprintln!(
        "[bmscl] WARNING: filtering {}/{} from deployment: {}",
        unit.kind.label(),
        unit.name,
        summary
    );
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(env::current_dir()?.join(path))
    }
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
                .context("source unit path must be valid UTF-8")?
                .to_string(),
        );
    }
    Ok(parts.join("/"))
}

fn ignored_dir(path: &Path) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn gleam_project(path: &Path) {
        fs::create_dir_all(path).unwrap();
        fs::write(path.join("gleam.toml"), "name = \"fixture\"\n").unwrap();
    }

    #[test]
    fn root_project_is_default_lambda() {
        let root = tempdir().unwrap();
        gleam_project(root.path());
        let units = discover_units(root.path()).unwrap();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].kind, UnitKind::Lambda);
        assert_eq!(units[0].name, "default");
    }

    #[test]
    fn discovers_nested_lambda_and_middleware_units() {
        let root = tempdir().unwrap();
        gleam_project(&root.path().join("lambdas/users/create"));
        gleam_project(&root.path().join("middleware/auth"));
        let units = discover_units(root.path()).unwrap();
        assert_eq!(units.len(), 2);
        assert!(units
            .iter()
            .any(|u| u.kind == UnitKind::Lambda && u.name == "users/create"));
        assert!(units
            .iter()
            .any(|u| u.kind == UnitKind::Middleware && u.name == "auth"));
    }

    #[test]
    fn only_explicit_admission_rejection_is_filterable() {
        let root = tempdir().unwrap();
        fs::write(
            root.path().join("admission-report.json"),
            r#"{"admitted":false,"findings":[{"code":"PROCESS_CREATION"},{"code":"PROCESS_CREATION"},{"code":"FFI"}]}"#,
        )
        .unwrap();
        let summary = admission_rejection_summary(root.path()).unwrap().unwrap();
        assert_eq!(summary, "admitted=false; findings=FFI,PROCESS_CREATION");

        fs::write(
            root.path().join("admission-report.json"),
            r#"{"admitted":true,"findings":[]}"#,
        )
        .unwrap();
        assert!(admission_rejection_summary(root.path()).unwrap().is_none());
    }

    #[test]
    fn missing_report_is_not_filterable() {
        let root = tempdir().unwrap();
        assert!(admission_rejection_summary(root.path()).unwrap().is_none());
    }
}
