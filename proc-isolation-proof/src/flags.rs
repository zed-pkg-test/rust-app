//! `flags-2-env` adapter. `.cli-flags.toml` is the only public argv authority.

use std::collections::HashMap;
use std::env;
use std::io::Write;
use std::path::PathBuf;

use flags2env::BundledFlags2Env;
use serde::Deserialize;
use tempfile::NamedTempFile;

use crate::error::{Error, Result};

const BUNDLED_CONTRACT: &str = include_str!("../.cli-flags.toml");

/// Typed command selected by the canonical flag contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliCommand {
    /// Validate configuration.
    Check,
    /// Validate configuration and host dependencies.
    Doctor,
    /// Explain one process.
    Explain {
        /// Configured process name.
        process: String,
    },
    /// Run one process with optional appended arguments.
    Run {
        /// Configured process name.
        process: String,
        /// Arguments appended after the configured fixed arguments.
        extra_args: Vec<String>,
    },
}

/// Fully resolved CLI options.
#[derive(Debug, Clone)]
pub struct Cli {
    /// Policy path.
    pub config_path: PathBuf,
    /// Do not launch; report the plan.
    pub dry_run: bool,
    /// Emit JSON output.
    pub json: bool,
    /// Enable the fixed BeamScale tripwire mount/PATH contract on Linux.
    pub beamscale_honeypot: bool,
    /// Selected command.
    pub command: CliCommand,
}

#[derive(Debug, Default, Deserialize)]
struct ResolvedFlags {
    #[serde(rename = "ORES_PI_CONFIG", default = "default_policy_path")]
    config: String,
    #[serde(rename = "ORES_PI_DRY_RUN", default)]
    dry_run: bool,
    #[serde(rename = "ORES_PI_JSON", default)]
    json: bool,
    #[serde(rename = "ORES_PI_BEAMSCALE_HONEYPOT", default)]
    beamscale_honeypot: bool,
}

fn default_policy_path() -> String {
    ".ores-proc-isolation.yaml".to_owned()
}

/// Parse the process argv using the audited, bundled `flags-2-env` contract.
pub fn parse() -> Result<Cli> {
    parse_from(env::args().collect())
}

/// Parse a supplied argv vector. Exposed for tests and embedding.
pub fn parse_from(argv: Vec<String>) -> Result<Cli> {
    let parser = BundledFlags2Env::new();
    let mut contract_file = NamedTempFile::new().map_err(Error::HelperIo)?;
    contract_file
        .write_all(BUNDLED_CONTRACT.as_bytes())
        .map_err(Error::HelperIo)?;
    let contract = contract_file.path().to_string_lossy().into_owned();

    parser
        .audit_config(Some(&contract))
        .map_err(|error| Error::Cli(format!("flag contract audit failed: {error}")))?;
    let structured = parser
        .parse_structured(&argv, Some(&contract))
        .map_err(|error| Error::Cli(format!("flag parsing failed: {error}")))?;

    if !structured.unknown_options.is_empty() {
        return Err(Error::Cli(format!(
            "unknown options were rejected: {:?}",
            structured.unknown_options
        )));
    }
    if !structured.errors.is_empty() {
        return Err(Error::Cli(format!(
            "invalid arguments were rejected: {:?}",
            structured.errors
        )));
    }

    let resolved_commands = parser
        .resolve_commands(&argv, Some(&contract))
        .map_err(|error| Error::Cli(format!("command resolution failed: {error}")))?;
    let values = coerce_values(
        &parser,
        &structured.dotenv,
        &structured.dotenv_overrides,
        &structured.provided_flags,
        &contract,
    )?;
    let path = if resolved_commands.path.is_empty() {
        let mut fallback = Vec::new();
        if !structured.command.trim().is_empty() {
            fallback.push(structured.command.trim().to_owned());
        }
        fallback.extend(
            structured
                .subcommands
                .iter()
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned),
        );
        fallback
    } else {
        resolved_commands.path
    };

    let mut extras = structured.extras;
    if extras.first().is_some_and(|value| value == "--") {
        extras.remove(0);
    }

    let command = match path.as_slice() {
        [name] if name == "check" => {
            reject_extras("check", &extras)?;
            CliCommand::Check
        }
        [name] if name == "doctor" => {
            reject_extras("doctor", &extras)?;
            CliCommand::Doctor
        }
        [name] if name == "explain" => {
            if extras.len() != 1 {
                return Err(Error::Cli(
                    "usage: ores-proc-isolation explain <process>".to_owned(),
                ));
            }
            CliCommand::Explain {
                process: extras.remove(0),
            }
        }
        [name] if name == "run" => {
            if extras.is_empty() {
                return Err(Error::Cli(
                    "usage: ores-proc-isolation run <process> -- [extra args...]".to_owned(),
                ));
            }
            let process = extras.remove(0);
            if extras.first().is_some_and(|value| value == "--") {
                extras.remove(0);
            }
            CliCommand::Run {
                process,
                extra_args: extras,
            }
        }
        [] => {
            return Err(Error::Cli(
                "missing command: expected check, doctor, explain, or run".to_owned(),
            ));
        }
        _ => {
            return Err(Error::Cli(format!(
                "unknown command path: {}",
                path.join(" ")
            )));
        }
    };

    Ok(Cli {
        config_path: PathBuf::from(values.config),
        dry_run: values.dry_run,
        json: values.json,
        beamscale_honeypot: values.beamscale_honeypot,
        command,
    })
}

fn reject_extras(command: &str, extras: &[String]) -> Result<()> {
    if extras.is_empty() {
        Ok(())
    } else {
        Err(Error::Cli(format!(
            "{command} does not accept positional arguments: {extras:?}"
        )))
    }
}

fn coerce_values(
    parser: &BundledFlags2Env,
    dotenv: &HashMap<String, String>,
    dotenv_overrides: &HashMap<String, String>,
    provided_flags: &HashMap<String, String>,
    contract: &str,
) -> Result<ResolvedFlags> {
    let mut values = dotenv.clone();
    values.extend(env::vars());
    values.extend(dotenv_overrides.clone());
    values.extend(provided_flags.clone());
    parser
        .coerce(&values, Some(contract))
        .map_err(|error| Error::Cli(format!("invalid typed flag/environment value: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_group_cannot_be_overridden_from_cli() {
        let result = parse_from(vec![
            "ores-proc-isolation".to_owned(),
            "check".to_owned(),
            "--group".to_owned(),
            "weaker-policy".to_owned(),
        ]);
        assert!(result.is_err());
    }

    #[test]
    fn bundled_contract_has_no_group_override_flag() {
        assert!(!BUNDLED_CONTRACT.contains("[flags.group]"));
        assert!(!BUNDLED_CONTRACT.contains("ORES_PI_GROUP"));
    }

    #[test]
    fn beamscale_honeypot_flag_is_explicit_and_typed() {
        let cli = parse_from(vec![
            "ores-proc-isolation".to_owned(),
            "--beamscale-honeypot".to_owned(),
            "check".to_owned(),
        ])
        .expect("honeypot flag should parse");
        assert!(cli.beamscale_honeypot);
    }
}
