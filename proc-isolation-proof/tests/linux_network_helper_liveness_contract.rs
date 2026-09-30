//! Contract tests for Linux external-network helper liveness supervision.

const HELPER: &str = include_str!("../scripts/linux/ores-proc-isolate.sh");

#[test]
fn external_network_helper_is_supervised_with_tenant() {
    assert!(HELPER.contains("wait -n -p finished_pid \"$BWRAP_PID\" \"$SLIRP_PID\""));
    assert!(HELPER.contains("network helper exited while tenant was still running"));
    assert!(HELPER.contains("kill \"$BWRAP_PID\""));
    assert!(HELPER.contains("rc=125"));
}

#[test]
fn cleanup_reaps_both_network_helper_and_tenant() {
    let cleanup = HELPER
        .split("cleanup() {")
        .nth(1)
        .and_then(|tail| tail.split("trap cleanup").next())
        .expect("cleanup function");
    assert!(cleanup.contains("kill \"$SLIRP_PID\""));
    assert!(cleanup.contains("wait \"$SLIRP_PID\""));
    assert!(cleanup.contains("kill \"$BWRAP_PID\""));
    assert!(cleanup.contains("wait \"$BWRAP_PID\""));
}
