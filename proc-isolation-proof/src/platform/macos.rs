//! macOS Seatbelt backend.

use std::io::Write;
use std::path::Path;
use std::process::Command;

use tempfile::NamedTempFile;

use super::{DependencyCheck, DoctorReport, SandboxPlan, any_private_network_denial};
use crate::config::{Config, NetworkMode};
use crate::error::{Error, Result};

const HELPER: &str = include_str!("../../scripts/macos/ores-proc-isolate.sh");
const TRUSTED_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

pub(super) fn launch(plan: &SandboxPlan) -> Result<i32> {
    if plan.network.mode == NetworkMode::External && !plan.network.deny_loopback {
        return Err(Error::SandboxUnavailable(
            "macOS strict backend refuses external networking with loopback enabled".to_owned(),
        ));
    }
    if plan.network.mode == NetworkMode::External && plan.network.deny_private_networks {
        return Err(Error::SandboxUnavailable(
            "macOS Seatbelt cannot enforce strict Internet-only CIDR/host-address denial"
                .to_owned(),
        ));
    }

    let mut helper = NamedTempFile::new().map_err(Error::HelperIo)?;
    helper
        .write_all(HELPER.as_bytes())
        .map_err(Error::HelperIo)?;

    let mut command = Command::new("/bin/bash");
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
        .arg(plan.limits.cpu_seconds.to_string())
        .arg("--deny-loopback");

    for path in &plan.read_only {
        command.arg("--ro").arg(path);
    }
    for (key, value) in &plan.environment {
        command.arg("--env").arg(key).arg(value);
    }
    command.arg("--").args(&plan.args);

    let status = command
        .status()
        .map_err(|error| Error::Launch(format!("failed to start macOS helper: {error}")))?;
    Ok(status.code().unwrap_or(128))
}

pub(super) fn doctor(config: &Config) -> DoctorReport {
    let sandbox_exec = Path::new("/usr/bin/sandbox-exec");
    let env = Path::new("/usr/bin/env");
    let unsupported_external = any_private_network_denial(config);
    let checks = vec![
        DependencyCheck {
            name: "/usr/bin/sandbox-exec".to_owned(),
            available: sandbox_exec.is_file(),
            detail: sandbox_exec.display().to_string(),
        },
        DependencyCheck {
            name: "/usr/bin/env".to_owned(),
            available: env.is_file(),
            detail: env.display().to_string(),
        },
        DependencyCheck {
            name: "strict external-network compatibility".to_owned(),
            available: !unsupported_external,
            detail: if unsupported_external {
                "an external group requires private/local destination denial, which macOS Seatbelt cannot express equivalently"
                    .to_owned()
            } else {
                "configuration uses only network modes enforceable by this backend".to_owned()
            },
        },
    ];
    let ok = checks.iter().all(|check| check.available);
    DoctorReport {
        platform: "macos".to_owned(),
        backend: "macos-seatbelt".to_owned(),
        ok,
        checks,
        notes: vec![
            "Seatbelt starts from (deny default); the target gets system runtime reads, its executable, and explicitly configured read-only paths only.".to_owned(),
            "network.mode=none is supported; strict Internet-only external mode fails closed because equivalent destination filtering is unavailable.".to_owned(),
            "sandbox-exec is deprecated by Apple but remains the available kernel Seatbelt launcher on current macOS; this backend fails closed if it is absent.".to_owned(),
        ],
    }
}
