//! Contract tests for the Linux helper's fixed BeamScale tripwire boundary.

const HELPER: &str = include_str!("../scripts/linux/ores-proc-isolate.sh");

#[test]
fn exact_read_only_paths_are_bound_without_parent_directory_expansion() {
    assert!(HELPER.contains("BWRAP_ARGS+=(--ro-bind \"$ro_path\" \"$ro_path\")"));
    assert!(!HELPER.contains("--ro-bind /run /run"));
    assert!(!HELPER.contains("--ro-bind /opt /opt"));
    assert!(!HELPER.contains("--ro-bind /bin /bin"));
    assert!(!HELPER.contains("--ro-bind /usr/bin /usr/bin"));
}

#[test]
fn tenant_path_is_fail_closed_unless_beamscale_tripwire_mode_is_explicit() {
    assert!(HELPER.contains("TARGET_PATH='/nonexistent'"));
    assert!(HELPER.contains("TARGET_PATH=$BEAMSCALE_TRIPWIRE_DIR"));
    assert!(HELPER.contains("--setenv PATH \"$TARGET_PATH\""));
    assert!(HELPER.contains("--beamscale-honeypot"));
}

#[test]
fn beamscale_mode_reasserts_tripwire_path_after_generic_environment() {
    let environment_loop = HELPER
        .find("BWRAP_ARGS+=(--setenv \"${ENV_KEYS[$i]}\" \"${ENV_VALUES[$i]}\")")
        .expect("generic environment injection must remain explicit");
    let strict_path = HELPER
        .rfind("BWRAP_ARGS+=(--setenv PATH \"$BEAMSCALE_TRIPWIRE_DIR\")")
        .expect("BeamScale mode must re-assert its canary-only PATH");
    assert!(strict_path > environment_loop);
}

#[test]
fn beamscale_mode_exposes_only_fixed_tripwire_paths() {
    assert!(HELPER.contains("BEAMSCALE_TRIPWIRE_DIR='/opt/beamscale/honeypot-bin'"));
    assert!(HELPER.contains("BEAMSCALE_TRIPWIRE_SOCKET='/run/bmscl-honeypot/tripwire.sock'"));
    assert!(HELPER.contains("--ro-bind \"$BEAMSCALE_TRIPWIRE_DIR\" \"$BEAMSCALE_TRIPWIRE_DIR\""));
    assert!(
        HELPER.contains("--ro-bind \"$BEAMSCALE_TRIPWIRE_SOCKET\" \"$BEAMSCALE_TRIPWIRE_SOCKET\"")
    );
    assert!(!HELPER.contains("--ro-bind /run /run"));
    assert!(!HELPER.contains("--ro-bind /opt /opt"));
}

#[test]
fn beamscale_mode_rejects_broad_utility_mounts() {
    assert!(HELPER.contains("/bin|/sbin|/usr/bin|/usr/sbin|/run|/opt"));
    assert!(HELPER.contains("BeamScale honeypot mode refuses broad utility/runtime mount"));
}

#[test]
fn one_bubblewrap_setup_owns_all_tenant_namespaces() {
    assert!(!HELPER.contains("ORES_PI_SUPERVISOR_USERNS"));
    assert!(!HELPER.contains("need unshare"));
    assert!(!HELPER.contains("--map-root-user"));

    let tenant = HELPER
        .find("BWRAP_ARGS=(")
        .expect("tenant Bubblewrap boundary must exist");
    let tenant_slice = &HELPER[tenant..];
    assert!(tenant_slice.contains("--unshare-user"));
    assert!(tenant_slice.contains("--uid 0"));
    assert!(tenant_slice.contains("--gid 0"));
    assert!(tenant_slice.contains("--unshare-ipc"));
    assert!(tenant_slice.contains("--unshare-pid"));
    assert!(tenant_slice.contains("--unshare-net"));
    assert!(tenant_slice.contains("--unshare-uts"));
    assert!(tenant_slice.contains("--unshare-cgroup"));
    assert!(tenant_slice.contains("--cap-drop ALL"));
}

#[test]
fn no_network_path_keeps_bubblewrap_nested_userns_lockdown() {
    assert!(HELPER.contains("BWRAP_ARGS+=(--disable-userns)"));
}

#[test]
fn external_network_preconfigures_one_userns_and_disables_nested_userns() {
    assert!(HELPER.contains("--userns-block-fd 6"));
    assert!(HELPER.contains("--assert-userns-disabled"));
    assert!(HELPER.contains("/proc/$setup_pid/setgroups"));
    assert!(HELPER.contains("/proc/$setup_pid/uid_map"));
    assert!(HELPER.contains("/proc/$setup_pid/gid_map"));
    assert!(HELPER.contains("/proc/sys/user/max_user_namespaces"));
    assert!(HELPER.contains("printf '0 %s 1\\n' \"$HOST_UID\""));
    assert!(HELPER.contains("printf '0 %s 1\\n' \"$HOST_GID\""));
}

#[test]
fn bubblewrap_info_stream_is_consumed_until_child_pid_is_seen() {
    assert!(HELPER.contains("while IFS= read -r info_line <&10; do"));
    assert!(HELPER.contains("if [[ -n \"$candidate\" ]]; then"));
    assert!(HELPER.contains("setup_pid=$candidate"));
}

#[test]
fn host_network_supervisor_enters_same_owned_user_and_network_namespaces() {
    assert!(HELPER.contains("NETNS_PATH=\"/proc/$child_pid/ns/net\""));
    assert!(HELPER.contains("--netns-type=path"));
    assert!(HELPER.contains("\"$NETNS_PATH\" tap0"));
    assert!(!HELPER.contains("--userns-path="));
    assert!(!HELPER.contains("-U --user-parent"));
    assert!(HELPER.contains("--preserve-credentials"));
    assert!(HELPER.contains("-U --preserve-credentials -- \"$BASH\""));
    assert!(HELPER.contains("-U --preserve-credentials -n --"));
    assert!(!HELPER.contains("--keep-caps"));
}

#[test]
fn host_root_and_runtime_directories_are_not_shared_wholesale() {
    assert!(HELPER.contains("[[ \"$ro_path\" != / ]] || fatal 'refusing to expose host root'"));
    assert!(HELPER.contains("--clearenv"));
    assert!(HELPER.contains("--unshare-pid"));
    assert!(HELPER.contains("--unshare-net"));
    assert!(HELPER.contains("--unshare-cgroup"));
    assert!(HELPER.contains("--cap-drop ALL"));
}

#[test]
fn single_boundary_never_readds_caps_before_tenant_exec() {
    assert!(!HELPER.contains("--cap-add ALL"));
    assert!(HELPER.contains("--cap-drop ALL"));
}
