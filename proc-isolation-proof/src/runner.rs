//! High-level command execution.

use serde::Serialize;

use crate::config::Config;
use crate::error::Result;
use crate::flags::{Cli, CliCommand};
use crate::platform::{self, SandboxPlan};

/// Execute one parsed CLI invocation and return the desired process exit code.
pub fn run(cli: Cli) -> Result<i32> {
    let config = Config::load(&cli.config_path)?;

    match cli.command {
        CliCommand::Check => {
            let report = CheckReport {
                ok: true,
                config: cli.config_path.display().to_string(),
                version: config.version,
                groups: config.groups.len(),
                processes: config.processes.len(),
                beamscale_honeypot: cli.beamscale_honeypot,
            };
            emit(&report, cli.json, || {
                format!(
                    "policy ok: {} group(s), {} process(es), schema v{}, beamscale_honeypot={}",
                    report.groups, report.processes, report.version, report.beamscale_honeypot
                )
            })?;
            Ok(0)
        }
        CliCommand::Doctor => {
            let report = platform::doctor(&config, cli.beamscale_honeypot);
            let ok = report.ok;
            emit(&report, cli.json, || {
                let mut text = format!(
                    "backend={} platform={} status={}\n",
                    report.backend,
                    report.platform,
                    if report.ok { "ok" } else { "not-ready" }
                );
                for check in &report.checks {
                    text.push_str(&format!(
                        "  [{}] {}: {}\n",
                        if check.available { "ok" } else { "missing" },
                        check.name,
                        check.detail
                    ));
                }
                for note in &report.notes {
                    text.push_str(&format!("  note: {note}\n"));
                }
                text.trim_end().to_owned()
            })?;
            Ok(if ok { 0 } else { 2 })
        }
        CliCommand::Explain { process } => {
            let resolved = config.resolve_process(&process, None)?;
            let members = config.processes_for_group(&resolved.group)?;
            let report = ExplainReport {
                process: resolved.name,
                group: resolved.group,
                executable: resolved.executable.display().to_string(),
                fixed_args: resolved.args,
                read_only: resolved
                    .policy
                    .filesystem
                    .read_only
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect(),
                network: resolved.policy.network,
                limits: resolved.policy.limits,
                environment_keys: resolved.environment.keys().cloned().collect(),
                group_members: members,
                beamscale_honeypot: cli.beamscale_honeypot,
            };
            emit(&report, cli.json, || {
                format!(
                    "process={} group={} executable={} members=[{}] beamscale_honeypot={}",
                    report.process,
                    report.group,
                    report.executable,
                    report.group_members.join(","),
                    report.beamscale_honeypot
                )
            })?;
            Ok(0)
        }
        CliCommand::Run {
            process,
            extra_args,
        } => {
            let resolved = config.resolve_process(&process, None)?;
            let plan = platform::prepare_plan(resolved, &extra_args, cli.beamscale_honeypot)?;
            if cli.dry_run {
                emit_plan(&plan, cli.json)?;
                return Ok(0);
            }
            platform::launch(&plan)
        }
    }
}

fn emit_plan(plan: &SandboxPlan, json: bool) -> Result<()> {
    emit(plan, json, || {
        format!(
            "dry-run: backend={} process={} group={} executable={} args={:?} read_only={} env_keys={:?} beamscale_honeypot={}",
            plan.backend,
            plan.process,
            plan.group,
            plan.executable.display(),
            plan.args,
            plan.read_only.len(),
            plan.environment_keys,
            plan.beamscale_honeypot
        )
    })
}

fn emit<T, F>(value: &T, json: bool, plain: F) -> Result<()>
where
    T: Serialize,
    F: FnOnce() -> String,
{
    if json {
        println!("{}", serde_json::to_string(value)?);
    } else {
        println!("{}", plain());
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct CheckReport {
    ok: bool,
    config: String,
    version: u32,
    groups: usize,
    processes: usize,
    beamscale_honeypot: bool,
}

#[derive(Debug, Serialize)]
struct ExplainReport {
    process: String,
    group: String,
    executable: String,
    fixed_args: Vec<String>,
    read_only: Vec<String>,
    network: crate::config::NetworkPolicy,
    limits: crate::config::ResourceLimits,
    environment_keys: Vec<String>,
    group_members: Vec<String>,
    beamscale_honeypot: bool,
}
