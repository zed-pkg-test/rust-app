//! Contract tests for trusted NixOS helper resolution without regressing the single Bubblewrap boundary.

const PLATFORM: &str = include_str!("../src/platform/mod.rs");
const LINUX: &str = include_str!("../src/platform/linux.rs");
const HELPER: &str = include_str!("../scripts/linux/ores-proc-isolate.sh");

#[test]
fn nixos_profile_is_explicit_and_canonicalized_into_nix_store() {
    assert!(PLATFORM.contains("(\"/run/current-system/sw/bin\", true)"));
    assert!(PLATFORM.contains("fs::canonicalize(&candidate)"));
    assert!(PLATFORM.contains("metadata.uid() == 0"));
    assert!(PLATFORM.contains("metadata.mode() & 0o022 == 0"));
    assert!(PLATFORM.contains("metadata.mode() & 0o111 != 0"));
    assert!(PLATFORM.contains("canonical.starts_with(\"/nix/store/\")"));
}

#[test]
fn helper_lookup_never_uses_inherited_path() {
    assert!(PLATFORM.contains("if name.is_empty() || name.contains('/')"));
    assert!(!PLATFORM.contains("std::env::var(\"PATH\")"));
    assert!(LINUX.contains("env_clear()"));
    assert!(LINUX.contains("/run/current-system/sw/bin"));
}

#[test]
fn bash_is_resolved_through_the_same_trusted_lookup() {
    assert!(LINUX.contains("trusted_lookup(\"bash\")"));
    assert!(LINUX.contains("push_binary(&mut checks, \"bash\")"));
    assert!(!LINUX.contains("Command::new(\"/bin/bash\")"));
}

#[test]
fn single_bubblewrap_boundary_from_main_is_preserved() {
    assert!(!HELPER.contains("ORES_PI_SUPERVISOR_USERNS"));
    assert!(HELPER.contains("--unshare-user"));
    assert!(HELPER.contains("--cap-drop ALL"));
    assert!(HELPER.contains("--netns-type=path"));
    assert!(!HELPER.contains("--userns-path="));
    assert!(!HELPER.contains("-U --user-parent"));
    assert!(HELPER.contains("--preserve-credentials"));
    assert!(HELPER.contains("--userns-block-fd 6"));
    assert!(HELPER.contains("--assert-userns-disabled"));
    assert!(HELPER.contains("/proc/sys/user/max_user_namespaces"));
    assert!(HELPER.contains("-U --preserve-credentials -- \"$BASH\""));
    assert!(HELPER.contains("-U --preserve-credentials -n --"));
}
