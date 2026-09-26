//! Regression tests for fail-closed process-isolation policy loading.

use std::fs;

use ores_proc_isolation::Config;
use tempfile::tempdir;

#[test]
fn unknown_yaml_keys_fail_closed() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    fs::write(
        &path,
        r#"
version: 1
defaults:
  group: strict
groups:
  strict:
    members: [job]
    unexpected_escape_hatch: true
processes:
  job:
    command: [/usr/bin/true]
"#,
    )
    .unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn contradictory_bidirectional_membership_fails_closed() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    fs::write(
        &path,
        r#"
version: 1
defaults:
  group: a
groups:
  a:
    members: [job]
  b:
    members: []
processes:
  job:
    group: b
    command: [/usr/bin/true]
"#,
    )
    .unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn host_root_cannot_be_allowlisted() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    fs::write(
        &path,
        r#"
version: 1
defaults:
  group: strict
groups:
  strict:
    filesystem:
      read_only: [/]
processes:
  job:
    command: [/usr/bin/true]
"#,
    )
    .unwrap();
    assert!(Config::load(&path).is_err());
}

#[test]
fn external_network_cannot_disable_private_destination_denial() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("policy.yaml");
    fs::write(
        &path,
        r#"
version: 1
defaults:
  group: external
groups:
  external:
    network:
      mode: external
      deny_loopback: true
      deny_private_networks: false
processes:
  job:
    command: [/usr/bin/true]
"#,
    )
    .unwrap();
    assert!(Config::load(&path).is_err());
}
