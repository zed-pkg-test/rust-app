//! Platform-specific sandbox preparation and launch.

mod linux;
mod macos;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::config::{Config, NetworkMode, NetworkPolicy, ResolvedProcess, ResourceLimits};
use crate::error::{Error, Result};

pub(crate) const BEAMSCALE_TRIPWIRE_DIR: &str = "/opt/beamscale/honeypot-bin";
pub(crate) const BEAMSCALE_TRIPWIRE_SOCKET: &str = "/run/bmscl-honeypot/tripwire.sock";

/// Platform selected for this build/host.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HostPlatform {
    /// Linux namespace/bubblewrap backend.
    Linux,
    /// macOS Seatbelt backend.
    Macos,
}

/// One host dependency check.
#[derive(Debug, Clone, Serialize)]
pub struct DependencyCheck {
    /// Executable or facility name.
    pub name: String,
    /// Whether it is available.
    pub available: bool,
    /// Resolved trusted path or diagnostic.
    pub detail: String,
}

/// Result of host capability inspection.
#[derive(Debug, Clone, Serialize)]
pub struct DoctorReport {
    /// Host platform.
    pub platform: String,
    /// Chosen backend.
    pub backend: String,
    /// Whether all required capabilities are available.
    pub ok: bool,
    /// Individual dependency checks.
    pub checks: Vec<DependencyCheck>,
    /// Important backend notes/limitations.
    pub notes: Vec<String>,
}

/// Fully prepared sandbox launch plan.
#[derive(Debug, Clone, Serialize)]
pub struct SandboxPlan {
    /// Platform backend.
    pub platform: HostPlatform,
    /// Backend implementation name.
    pub backend: String,
    /// Configured process key.
    pub process: String,
    /// Resolved policy group.
    pub group: String,
    /// Canonical host executable path exposed into the sandbox.
    pub executable: PathBuf,
    /// Complete target argv excluding argv[0].
    pub args: Vec<String>,
    /// Canonical explicit read-only host paths.
    pub read_only: Vec<PathBuf>,
    /// Effective network policy.
    pub network: NetworkPolicy,
    /// Effective resource bounds.
    pub limits: ResourceLimits,
    /// Enable the fixed BeamScale tripwire directory/socket/PATH contract.
    pub beamscale_honeypot: bool,
    /// Environment keys injected into the target. Values are intentionally omitted from reports.
    pub environment_keys: Vec<String>,
    /// Secret-capable environment values passed only to the helper at launch.
    #[serde(skip_serializing)]
    pub environment: BTreeMap<String, String>,
}

/// Detect the supported host platform.
pub fn host_platform() -> Result<HostPlatform> {
    if cfg!(target_os = "linux") {
        Ok(HostPlatform::Linux)
    } else if cfg!(target_os = "macos") {
        Ok(HostPlatform::Macos)
    } else {
        Err(Error::SandboxUnavailable(
            "only Linux and macOS are supported".to_owned(),
        ))
    }
}

/// Resolve and canonicalize the process launch plan before any sandbox helper runs.
pub fn prepare_plan(
    resolved: ResolvedProcess,
    extra_args: &[String],
    beamscale_honeypot: bool,
) -> Result<SandboxPlan> {
    let platform = host_platform()?;
    if beamscale_honeypot && platform != HostPlatform::Linux {
        return Err(Error::SandboxUnavailable(
            "BeamScale honeypot integration requires the Linux cgroup/namespace backend".to_owned(),
        ));
    }
    if platform == HostPlatform::Macos
        && resolved.policy.network.mode == NetworkMode::External
        && resolved.policy.network.deny_private_networks
    {
        return Err(Error::SandboxUnavailable(
            "macOS Seatbelt cannot express strict Internet-only destination filtering; use network.mode=none on macOS or run external mode on Linux"
                .to_owned(),
        ));
    }

    let executable = fs::canonicalize(&resolved.executable).map_err(|error| {
        Error::Executable(format!(
            "cannot canonicalize {}: {error}",
            resolved.executable.display()
        ))
    })?;
    if !executable.is_absolute() || !executable.is_file() {
        return Err(Error::Executable(format!(
            "target must be an absolute regular file: {}",
            executable.display()
        )));
    }

    let mut read_only = Vec::new();
    let mut seen = BTreeSet::new();
    for path in &resolved.policy.filesystem.read_only {
        let canonical = fs::canonicalize(path).map_err(|error| {
            Error::Executable(format!(
                "cannot canonicalize read-only path {}: {error}",
                path.display()
            ))
        })?;
        if canonical == Path::new("/") {
            return Err(Error::Executable(
                "refusing to expose host root as read-only".to_owned(),
            ));
        }
        if seen.insert(canonical.clone()) {
            read_only.push(canonical);
        }
    }

    let mut args = resolved.args.clone();
    args.extend(extra_args.iter().cloned());
    let environment_keys = resolved.environment.keys().cloned().collect();
    let backend = match platform {
        HostPlatform::Linux => "linux-bwrap-slirp4netns",
        HostPlatform::Macos => "macos-seatbelt",
    }
    .to_owned();

    Ok(SandboxPlan {
        platform,
        backend,
        process: resolved.name,
        group: resolved.group,
        executable,
        args,
        read_only,
        network: resolved.policy.network,
        limits: resolved.policy.limits,
        beamscale_honeypot,
        environment_keys,
        environment: resolved.environment,
    })
}

/// Launch a prepared plan and return the target exit code.
pub fn launch(plan: &SandboxPlan) -> Result<i32> {
    match plan.platform {
        HostPlatform::Linux => linux::launch(plan),
        HostPlatform::Macos => macos::launch(plan),
    }
}

/// Inspect helper availability and policy/backend compatibility.
pub fn doctor(config: &Config, beamscale_honeypot: bool) -> DoctorReport {
    match host_platform() {
        Ok(HostPlatform::Linux) => linux::doctor(config, beamscale_honeypot),
        Ok(HostPlatform::Macos) => {
            let mut report = macos::doctor(config);
            if beamscale_honeypot {
                report.ok = false;
                report.notes.push(
                    "BeamScale honeypot integration is Linux-only and is unavailable on macOS."
                        .to_owned(),
                );
            }
            report
        }
        Err(error) => DoctorReport {
            platform: std::env::consts::OS.to_owned(),
            backend: "unsupported".to_owned(),
            ok: false,
            checks: Vec::new(),
            notes: vec![error.to_string()],
        },
    }
}

pub(crate) fn any_external_network(config: &Config) -> bool {
    config
        .groups
        .values()
        .any(|group| group.network.mode == NetworkMode::External)
}

pub(crate) fn any_private_network_denial(config: &Config) -> bool {
    config.groups.values().any(|group| {
        group.network.mode == NetworkMode::External && group.network.deny_private_networks
    })
}

pub(crate) fn trusted_lookup(name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains('/') {
        return None;
    }

    // NixOS exposes system packages through /run/current-system/sw/bin while
    // conventional distributions use /usr/{s,}bin and /{s,}bin. Never consult
    // the caller's PATH: every accepted helper must resolve to a root-owned,
    // executable, non-writable regular file. The NixOS profile gets an
    // additional invariant that its canonical target lives in the immutable
    // /nix/store.
    const DIRS: &[(&str, bool)] = &[
        ("/usr/sbin", false),
        ("/usr/bin", false),
        ("/sbin", false),
        ("/bin", false),
        ("/run/current-system/sw/bin", true),
    ];

    DIRS.iter().find_map(|(dir, require_nix_store)| {
        let candidate = Path::new(dir).join(name);
        let canonical = fs::canonicalize(&candidate).ok()?;
        let metadata = fs::metadata(&canonical).ok()?;
        let safe_file = metadata.is_file()
            && metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.mode() & 0o111 != 0;
        if !safe_file {
            return None;
        }
        if *require_nix_store && !canonical.starts_with("/nix/store/") {
            return None;
        }
        Some(canonical)
    })
}
