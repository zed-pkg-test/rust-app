//! Contract tests for the fixed BeamScale honeypot worker profile.

use std::path::{Path, PathBuf};

use ores_proc_isolation::Config;
use ores_proc_isolation::config::NetworkMode;

fn profile_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("examples")
        .join("beamscale-hosted-gleam.yaml")
}

#[test]
fn beamscale_profile_exposes_only_exact_tripwire_paths() {
    let config = Config::load(profile_path()).expect("BeamScale profile must validate");
    let resolved = config
        .resolve_process("beamscale-worker", None)
        .expect("BeamScale worker must resolve");

    let mounts = &resolved.policy.filesystem.read_only;
    assert_eq!(
        mounts.as_slice(),
        &[
            PathBuf::from("/opt/beamscale/honeypot-bin"),
            PathBuf::from("/run/bmscl-honeypot/tripwire.sock"),
        ]
    );
    for forbidden in ["/", "/bin", "/usr/bin", "/run", "/opt"] {
        assert!(
            !mounts.iter().any(|path| path == Path::new(forbidden)),
            "BeamScale profile must not expose broad host path {forbidden}"
        );
    }
}

#[test]
fn beamscale_profile_replaces_path_with_inert_tripwires() {
    let config = Config::load(profile_path()).expect("BeamScale profile must validate");
    let resolved = config
        .resolve_process("beamscale-worker", None)
        .expect("BeamScale worker must resolve");

    assert_eq!(
        resolved.environment.get("PATH").map(String::as_str),
        Some("/opt/beamscale/honeypot-bin")
    );
    assert_eq!(resolved.policy.network.mode, NetworkMode::External);
    assert!(resolved.policy.network.deny_loopback);
    assert!(resolved.policy.network.deny_private_networks);
}

#[test]
fn beamscale_profile_keeps_worker_executable_absolute() {
    let config = Config::load(profile_path()).expect("BeamScale profile must validate");
    let resolved = config
        .resolve_process("beamscale-worker", None)
        .expect("BeamScale worker must resolve");

    assert!(resolved.executable.is_absolute());
    assert_eq!(
        resolved.executable,
        PathBuf::from("/opt/beamscale/runtime/beam.smp")
    );
}
