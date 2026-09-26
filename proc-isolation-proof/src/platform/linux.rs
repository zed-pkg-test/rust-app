//! Linux bubblewrap + slirp4netns backend.

use std::io::Write;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;
use std::process::Command;

use tempfile::NamedTempFile;

use super::{
    BEAMSCALE_TRIPWIRE_DIR, BEAMSCALE_TRIPWIRE_SOCKET, DependencyCheck, DoctorReport, SandboxPlan,
    any_external_network, trusted_lookup,
};
use crate::config::{Config, NetworkMode};
use crate::error::{Error, Result};

const HELPER: &str = include_str!("../../scripts/linux/ores-proc-isolate.sh");
const TRUSTED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin:/run/current-system/sw/bin";

fn validate_honeypot_boundary() -> Result<()> {
    let dir = Path::new(BEAMSCALE_TRIPWIRE_DIR);
    let dir_metadata = std::fs::symlink_metadata(dir).map_err(|error| {
        Error::SandboxUnavailable(format!(
            "BeamScale tripwire directory {BEAMSCALE_TRIPWIRE_DIR} is unavailable: {error}"
        ))
    })?;
    if !dir_metadata.file_type().is_dir()
        || dir_metadata.file_type().is_symlink()
        || dir_metadata.uid() != 0
        || dir_metadata.mode() & 0o022 != 0
    {
        return Err(Error::SandboxUnavailable(format!(
            "BeamScale tripwire directory must be a root-owned, non-writable real directory: {BEAMSCALE_TRIPWIRE_DIR}"
        )));
    }

    let socket = Path::new(BEAMSCALE_TRIPWIRE_SOCKET);
    let socket_metadata = std::fs::symlink_metadata(socket).map_err(|error| {
        Error::SandboxUnavailable(format!(
            "BeamScale tripwire socket {BEAMSCALE_TRIPWIRE_SOCKET} is unavailable: {error}"
        ))
    })?;
    if !socket_metadata.file_type().is_socket()
        || socket_metadata.file_type().is_symlink()
        || socket_metadata.uid() != 0
    {
        return Err(Error::SandboxUnavailable(format!(
            "BeamScale tripwire socket must be a root-owned Unix socket: {BEAMSCALE_TRIPWIRE_SOCKET}"
        )));
    }

    Ok(())
}

pub(super) fn launch(plan: &SandboxPlan) -> Result<i32> {
    if plan.beamscale_honeypot {
        validate_honeypot_boundary()?;
    }

    let mut helper = NamedTempFile::new().map_err(Error::HelperIo)?;
    helper
        .write_all(HELPER.as_bytes())
        .map_err(Error::HelperIo)?;

    let bash = trusted_lookup("bash").ok_or_else(|| {
        Error::SandboxUnavailable("trusted bash is unavailable in system helper paths".to_owned())
    })?;
    let mut command = Command::new(bash);
    command
        .env_clear()
        .env("PATH", TRUSTED_PATH)
        .env("LANG", "C")
        .arg(helper.path())
        .arg("--exe")
        .arg(&plan.executable)
        .arg("--network")
        .arg(match plan.network.mode {
            NetworkMode::None => "none",
            NetworkMode::External => "external",
        })
        .arg("--max-open-files")
        .arg(plan.limits.max_open_files.to_string())
        .arg("--cpu-seconds")
        .arg(plan.limits.cpu_seconds.to_string());

    if plan.network.deny_loopback {
        command.arg("--deny-loopback");
    } else {
        command.arg("--allow-loopback");
    }
    if plan.network.deny_private_networks {
        command.arg("--deny-private");
    }
    if plan.beamscale_honeypot {
        command.arg("--beamscale-honeypot");
    }
    for path in &plan.read_only {
        command.arg("--ro").arg(path);
    }
    for (key, value) in &plan.environment {
        command.arg("--env").arg(key).arg(value);
    }
    command.arg("--").args(&plan.args);

    let status = command
        .status()
        .map_err(|error| Error::Launch(format!("failed to start Linux helper: {error}")))?;
    Ok(status.code().unwrap_or(128))
}

pub(super) fn doctor(config: &Config, beamscale_honeypot: bool) -> DoctorReport {
    let mut checks = Vec::new();
    push_binary(&mut checks, "bash");
    let bwrap_available = trusted_lookup("bwrap").is_some();
    push_binary(&mut checks, "bwrap");
    if any_external_network(config) {
        for name in ["slirp4netns", "nsenter", "ip", "iptables", "ip6tables"] {
            push_binary(&mut checks, name);
        }
    }
    if beamscale_honeypot {
        push_honeypot_checks(&mut checks);
    }

    let mut notes = vec![
        "Target rootfs is an empty bubblewrap mount namespace; host /, home, cwd, /tmp, /proc, /sys, and /run are not shared.".to_owned(),
        "External networking uses a new network namespace and slirp4netns with host loopback disabled; there is no host-network fallback.".to_owned(),
        "IPv4/IPv6 loopback, private/link-local space, CGNAT, and the host's own interface addresses are denied before target exec.".to_owned(),
    ];
    if beamscale_honeypot {
        notes.push(format!(
            "BeamScale honeypot mode exposes only {BEAMSCALE_TRIPWIRE_DIR} read-only and {BEAMSCALE_TRIPWIRE_SOCKET}; PATH contains only the inert tripwire directory."
        ));
    }

    checks.push(user_namespace_status());
    if bwrap_available {
        checks.push(bubblewrap_namespace_status());
    }
    if config
        .groups
        .values()
        .any(|group| !group.network.deny_loopback)
    {
        notes.push(
            "Configuration requests loopback access, which strict validation rejects before launch."
                .to_owned(),
        );
    }

    let ok = checks.iter().all(|check| check.available);
    DoctorReport {
        platform: "linux".to_owned(),
        backend: "linux-bwrap-slirp4netns".to_owned(),
        ok,
        checks,
        notes,
    }
}

fn push_honeypot_checks(checks: &mut Vec<DependencyCheck>) {
    let dir = Path::new(BEAMSCALE_TRIPWIRE_DIR);
    let dir_check = match std::fs::symlink_metadata(dir) {
        Ok(metadata)
            if metadata.file_type().is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0 =>
        {
            DependencyCheck {
                name: "beamscale-tripwire-directory".to_owned(),
                available: true,
                detail: format!("{BEAMSCALE_TRIPWIRE_DIR} is a root-owned non-writable directory"),
            }
        }
        Ok(metadata) => DependencyCheck {
            name: "beamscale-tripwire-directory".to_owned(),
            available: false,
            detail: format!(
                "{BEAMSCALE_TRIPWIRE_DIR} has unsafe type/ownership/mode uid={} mode={:o}",
                metadata.uid(),
                metadata.mode() & 0o7777
            ),
        },
        Err(error) => DependencyCheck {
            name: "beamscale-tripwire-directory".to_owned(),
            available: false,
            detail: format!("{BEAMSCALE_TRIPWIRE_DIR} is unavailable: {error}"),
        },
    };
    checks.push(dir_check);

    let socket = Path::new(BEAMSCALE_TRIPWIRE_SOCKET);
    let socket_check = match std::fs::symlink_metadata(socket) {
        Ok(metadata) if metadata.file_type().is_socket() && metadata.uid() == 0 => {
            DependencyCheck {
                name: "beamscale-tripwire-socket".to_owned(),
                available: true,
                detail: format!("{BEAMSCALE_TRIPWIRE_SOCKET} is a root-owned Unix socket"),
            }
        }
        Ok(metadata) => DependencyCheck {
            name: "beamscale-tripwire-socket".to_owned(),
            available: false,
            detail: format!(
                "{BEAMSCALE_TRIPWIRE_SOCKET} has unsafe type/ownership uid={} mode={:o}",
                metadata.uid(),
                metadata.mode() & 0o7777
            ),
        },
        Err(error) => DependencyCheck {
            name: "beamscale-tripwire-socket".to_owned(),
            available: false,
            detail: format!("{BEAMSCALE_TRIPWIRE_SOCKET} is unavailable: {error}"),
        },
    };
    checks.push(socket_check);
}

fn push_binary(checks: &mut Vec<DependencyCheck>, name: &str) {
    let path = trusted_lookup(name);
    checks.push(DependencyCheck {
        name: name.to_owned(),
        available: path.is_some(),
        detail: path
            .map(|value| value.display().to_string())
            .unwrap_or_else(|| "not found in trusted system paths".to_owned()),
    });
}

fn user_namespace_status() -> DependencyCheck {
    let clone_gate = std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone")
        .ok()
        .map(|value| value.trim() != "0")
        .unwrap_or(true);
    let max_namespaces = std::fs::read_to_string("/proc/sys/user/max_user_namespaces")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(1);
    let available = clone_gate && max_namespaces > 0;
    DependencyCheck {
        name: "unprivileged-user-namespaces".to_owned(),
        available,
        detail: format!(
            "unprivileged_userns_clone={}, max_user_namespaces={max_namespaces}",
            if clone_gate { "enabled" } else { "disabled" }
        ),
    }
}

fn bubblewrap_namespace_status() -> DependencyCheck {
    let Some(bwrap) = trusted_lookup("bwrap") else {
        return DependencyCheck {
            name: "bubblewrap-namespace-probe".to_owned(),
            available: false,
            detail: "bwrap is unavailable".to_owned(),
        };
    };

    let output = Command::new(bwrap)
        .env_clear()
        .env("PATH", TRUSTED_PATH)
        .env("LANG", "C")
        .args([
            "--die-with-parent",
            "--new-session",
            "--unshare-user",
            "--unshare-ipc",
            "--unshare-pid",
            "--unshare-net",
            "--unshare-uts",
            "--unshare-cgroup",
            "--disable-userns",
            "--cap-drop",
            "ALL",
            "--ro-bind",
            "/",
            "/",
            "--",
            "/bin/true",
        ])
        .output();

    match output {
        Ok(output) if output.status.success() => DependencyCheck {
            name: "bubblewrap-namespace-probe".to_owned(),
            available: true,
            detail: "mandatory user/network/cgroup namespace setup succeeded".to_owned(),
        },
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let apparmor_restricted =
                std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
                    .ok()
                    .is_some_and(|value| value.trim() == "1");
            let apparmor_hint = if apparmor_restricted {
                " Ubuntu AppArmor user-namespace mediation is enabled; install/load a narrowly scoped bwrap userns profile rather than disabling the restriction host-wide."
            } else {
                ""
            };
            DependencyCheck {
                name: "bubblewrap-namespace-probe".to_owned(),
                available: false,
                detail: format!("mandatory namespace setup failed: {stderr}.{apparmor_hint}"),
            }
        }
        Err(error) => DependencyCheck {
            name: "bubblewrap-namespace-probe".to_owned(),
            available: false,
            detail: format!("failed to execute bwrap probe: {error}"),
        },
    }
}
