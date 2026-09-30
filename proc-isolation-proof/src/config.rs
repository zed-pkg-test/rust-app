//! YAML policy schema and deterministic process/group resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use ores_reactive_maps::ReactiveMap;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const SUPPORTED_VERSION: u32 = 1;
const DEFAULT_LAYER: &str = "defaults";
const GROUP_LAYER: &str = "group-members";
const PROCESS_LAYER: &str = "process-explicit";

/// Root policy loaded from `.ores-proc-isolation.yaml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Policy schema version.
    pub version: u32,
    /// Global defaults.
    #[serde(default)]
    pub defaults: Defaults,
    /// Named policy groups.
    #[serde(default)]
    pub groups: BTreeMap<String, Group>,
    /// Named process definitions.
    #[serde(default)]
    pub processes: BTreeMap<String, Process>,
}

/// Global policy defaults.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    /// Group used when a process is not assigned elsewhere.
    #[serde(default = "default_group")]
    pub group: String,
}

impl Default for Defaults {
    fn default() -> Self {
        Self {
            group: default_group(),
        }
    }
}

fn default_group() -> String {
    "external-only".to_owned()
}

/// Shared policy assigned to one or more processes.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    /// Process names that belong to the group.
    #[serde(default)]
    pub members: Vec<String>,
    /// Filesystem visibility for the target.
    #[serde(default)]
    pub filesystem: FilesystemPolicy,
    /// Network visibility for the target.
    #[serde(default)]
    pub network: NetworkPolicy,
    /// Resource bounds inherited by the target and its children.
    #[serde(default)]
    pub limits: ResourceLimits,
    /// Explicit environment variables injected after host environment clearing.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

/// One configured process.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Process {
    /// Explicit group assignment. May duplicate `groups.<name>.members` if it agrees.
    #[serde(default)]
    pub group: Option<String>,
    /// Absolute executable followed by fixed arguments.
    pub command: Vec<String>,
    /// Process-specific environment variables layered over group variables.
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
}

/// Filesystem policy. Host paths are invisible unless explicitly named here.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FilesystemPolicy {
    /// Additional host paths exposed read-only inside the sandbox.
    #[serde(default)]
    pub read_only: Vec<PathBuf>,
}

/// Network mode for a process group.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    /// No network namespace connectivity at all.
    None,
    /// Outbound IP networking with host/local/private destinations blocked.
    #[default]
    External,
}

/// Network restrictions for a process group.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkPolicy {
    /// Whether the sandbox has no network or outbound external networking.
    #[serde(default)]
    pub mode: NetworkMode,
    /// Deny host/self loopback reachability.
    #[serde(default = "default_true")]
    pub deny_loopback: bool,
    /// Deny RFC1918, link-local, CGNAT, and other host-local destinations.
    #[serde(default = "default_true")]
    pub deny_private_networks: bool,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self {
            mode: NetworkMode::External,
            deny_loopback: true,
            deny_private_networks: true,
        }
    }
}

const fn default_true() -> bool {
    true
}

/// Resource limits inherited by the sandbox target.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// RLIMIT_NOFILE-style descriptor ceiling.
    #[serde(default = "default_max_open_files")]
    pub max_open_files: u64,
    /// RLIMIT_CPU-style CPU time ceiling.
    #[serde(default = "default_cpu_seconds")]
    pub cpu_seconds: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_open_files: default_max_open_files(),
            cpu_seconds: default_cpu_seconds(),
        }
    }
}

const fn default_max_open_files() -> u64 {
    128
}

const fn default_cpu_seconds() -> u64 {
    300
}

/// Effective process plus its resolved shared policy.
#[derive(Debug, Clone, Serialize)]
pub struct ResolvedProcess {
    /// Process key in the YAML file.
    pub name: String,
    /// Effective group name.
    pub group: String,
    /// Absolute configured executable before canonicalization.
    pub executable: PathBuf,
    /// Fixed configured arguments (extra invocation arguments are appended later).
    pub args: Vec<String>,
    /// Effective policy group.
    pub policy: Group,
    /// Sanitized environment that will be injected into the target.
    pub environment: BTreeMap<String, String>,
}

impl Config {
    /// Load and validate a YAML policy from disk.
    pub fn load(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| Error::PolicyRead {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Self = serde_yaml::from_str(&text).map_err(|error| Error::PolicyInvalid {
            path: path.to_path_buf(),
            message: error.to_string(),
        })?;
        config.validate().map_err(|message| Error::PolicyInvalid {
            path: path.to_path_buf(),
            message,
        })?;
        Ok(config)
    }

    /// Validate policy invariants without resolving a specific process.
    pub fn validate(&self) -> std::result::Result<(), String> {
        if self.version != SUPPORTED_VERSION {
            return Err(format!(
                "unsupported version {}; expected {SUPPORTED_VERSION}",
                self.version
            ));
        }
        if self.groups.is_empty() {
            return Err("at least one group is required".to_owned());
        }
        if !self.groups.contains_key(&self.defaults.group) {
            return Err(format!(
                "defaults.group references unknown group {:?}",
                self.defaults.group
            ));
        }
        if self.processes.is_empty() {
            return Err("at least one process is required".to_owned());
        }

        let mut declared_by_group = BTreeMap::<String, String>::new();
        for (group_name, group) in &self.groups {
            validate_name("group", group_name)?;
            validate_environment(&group.environment)?;
            validate_group_policy(group_name, group)?;
            for member in &group.members {
                if !self.processes.contains_key(member) {
                    return Err(format!(
                        "group {group_name:?} names unknown process {member:?}"
                    ));
                }
                if let Some(previous) = declared_by_group.insert(member.clone(), group_name.clone())
                {
                    if previous != *group_name {
                        return Err(format!(
                            "process {member:?} belongs to multiple groups: {previous:?} and {group_name:?}"
                        ));
                    }
                }
            }
        }

        for (process_name, process) in &self.processes {
            validate_name("process", process_name)?;
            validate_environment(&process.environment)?;
            if process.command.is_empty() {
                return Err(format!("process {process_name:?} has an empty command"));
            }
            let executable = Path::new(&process.command[0]);
            if !executable.is_absolute() {
                return Err(format!(
                    "process {process_name:?} executable must be absolute: {:?}",
                    process.command[0]
                ));
            }
            if process.command[0].contains('\0') {
                return Err(format!("process {process_name:?} executable contains NUL"));
            }
            if let Some(explicit_group) = &process.group {
                if !self.groups.contains_key(explicit_group) {
                    return Err(format!(
                        "process {process_name:?} references unknown group {explicit_group:?}"
                    ));
                }
                if let Some(member_group) = declared_by_group.get(process_name) {
                    if member_group != explicit_group {
                        return Err(format!(
                            "process {process_name:?} says group {explicit_group:?} but group membership says {member_group:?}"
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    /// Resolve one process to exactly one effective group using layered reactive maps.
    pub fn resolve_process(
        &self,
        process_name: &str,
        group_override: Option<&str>,
    ) -> Result<ResolvedProcess> {
        let process = self.processes.get(process_name).ok_or_else(|| {
            Error::Resolution(format!("unknown configured process {process_name:?}"))
        })?;

        let group_name =
            if let Some(override_name) = group_override.filter(|value| !value.is_empty()) {
                if !self.groups.contains_key(override_name) {
                    return Err(Error::Resolution(format!(
                        "group override references unknown group {override_name:?}"
                    )));
                }
                override_name.to_owned()
            } else {
                self.membership_map().get_val(process_name).ok_or_else(|| {
                    Error::Resolution(format!("no group resolved for {process_name:?}"))
                })?
            };

        let policy = self.groups.get(&group_name).cloned().ok_or_else(|| {
            Error::Resolution(format!("resolved group {group_name:?} does not exist"))
        })?;

        let mut environment = policy.environment.clone();
        environment.extend(process.environment.clone());
        validate_environment(&environment).map_err(Error::Resolution)?;

        Ok(ResolvedProcess {
            name: process_name.to_owned(),
            group: group_name,
            executable: PathBuf::from(&process.command[0]),
            args: process.command.iter().skip(1).cloned().collect(),
            policy,
            environment,
        })
    }

    /// Return all processes that resolve to a particular group.
    pub fn processes_for_group(&self, group_name: &str) -> Result<Vec<String>> {
        if !self.groups.contains_key(group_name) {
            return Err(Error::Resolution(format!("unknown group {group_name:?}")));
        }
        let memberships = self.membership_map();
        Ok(self
            .processes
            .keys()
            .filter(|name| memberships.get_val(name).as_deref() == Some(group_name))
            .cloned()
            .collect())
    }

    fn membership_map(&self) -> ReactiveMap {
        let map = ReactiveMap::new();

        let defaults = self
            .processes
            .keys()
            .map(|name| (name.clone(), self.defaults.group.clone()))
            .collect();
        map.replace_string_layer(DEFAULT_LAYER, "config.defaults.group", 10, defaults);

        let mut group_members = BTreeMap::new();
        for (group_name, group) in &self.groups {
            for member in &group.members {
                group_members.insert(member.clone(), group_name.clone());
            }
        }
        map.replace_string_layer(GROUP_LAYER, "config.groups.*.members", 20, group_members);

        let explicit = self
            .processes
            .iter()
            .filter_map(|(name, process)| {
                process
                    .group
                    .as_ref()
                    .map(|group| (name.clone(), group.clone()))
            })
            .collect();
        map.replace_string_layer(PROCESS_LAYER, "config.processes.*.group", 30, explicit);

        map
    }
}

fn validate_name(kind: &str, value: &str) -> std::result::Result<(), String> {
    if value.is_empty() {
        return Err(format!("{kind} name must not be empty"));
    }
    if value.len() > 128 {
        return Err(format!("{kind} name is too long: {value:?}"));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(format!(
            "{kind} name contains unsupported characters: {value:?}"
        ));
    }
    Ok(())
}

fn validate_group_policy(name: &str, group: &Group) -> std::result::Result<(), String> {
    if group.limits.max_open_files < 3 {
        return Err(format!("group {name:?} max_open_files must be >= 3"));
    }
    if group.limits.cpu_seconds == 0 {
        return Err(format!("group {name:?} cpu_seconds must be > 0"));
    }
    if group.network.mode == NetworkMode::External && !group.network.deny_loopback {
        return Err(format!(
            "group {name:?} external networking must keep deny_loopback=true"
        ));
    }
    if group.network.mode == NetworkMode::External && !group.network.deny_private_networks {
        return Err(format!(
            "group {name:?} external networking must keep deny_private_networks=true"
        ));
    }

    let mut seen = BTreeSet::new();
    for path in &group.filesystem.read_only {
        if !path.is_absolute() {
            return Err(format!(
                "group {name:?} read_only path must be absolute: {}",
                path.display()
            ));
        }
        if path == Path::new("/") {
            return Err(format!(
                "group {name:?} may not expose host root as read_only"
            ));
        }
        if !seen.insert(path) {
            return Err(format!(
                "group {name:?} has duplicate read_only path: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_environment(environment: &BTreeMap<String, String>) -> std::result::Result<(), String> {
    for (key, value) in environment {
        let valid_key = !key.is_empty()
            && key.bytes().enumerate().all(|(index, byte)| match byte {
                b'A'..=b'Z' | b'_' => true,
                b'0'..=b'9' => index > 0,
                _ => false,
            });
        if !valid_key {
            return Err(format!("invalid environment key {key:?}"));
        }
        if value.contains('\0') {
            return Err(format!("environment value for {key:?} contains NUL"));
        }
        if key.starts_with("DYLD_")
            || key.starts_with("LD_")
            || matches!(key.as_str(), "BASH_ENV" | "ENV" | "SHELLOPTS")
        {
            return Err(format!(
                "environment key {key:?} is forbidden at the sandbox boundary"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> Config {
        serde_yaml::from_str(
            r#"
version: 1
defaults:
  group: base
groups:
  base:
    members: [worker]
  strict:
    members: []
processes:
  worker:
    group: base
    command: [/usr/bin/true]
  inherited:
    command: [/usr/bin/false]
"#,
        )
        .expect("fixture must parse")
    }

    #[test]
    fn explicit_and_group_membership_may_agree() {
        let config = fixture();
        config.validate().expect("fixture must validate");
        assert_eq!(
            config.resolve_process("worker", None).unwrap().group,
            "base"
        );
    }

    #[test]
    fn default_membership_is_resolved_through_reactive_map() {
        let config = fixture();
        assert_eq!(
            config.resolve_process("inherited", None).unwrap().group,
            "base"
        );
    }

    #[test]
    fn group_override_must_exist() {
        let config = fixture();
        assert!(config.resolve_process("worker", Some("missing")).is_err());
    }

    #[test]
    fn dangerous_loader_environment_is_rejected() {
        let mut config = fixture();
        config
            .processes
            .get_mut("worker")
            .unwrap()
            .environment
            .insert("LD_PRELOAD".into(), "/tmp/x.so".into());
        assert!(config.validate().is_err());
    }

    #[test]
    fn external_network_defaults_are_strict() {
        let policy = NetworkPolicy::default();
        assert_eq!(policy.mode, NetworkMode::External);
        assert!(policy.deny_loopback);
        assert!(policy.deny_private_networks);
    }
}
