//! Durable single-use nonce index for signed host incident ingestion.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

use crate::incident::{AuthenticatedHost, ContainedIncident};

const REPLAY_DIR: &str = ".security/replay/host-nonces";
const MAX_RECORD_BYTES: u64 = 16 * 1024;
const MAX_LIVE_NONCES_PER_HOST: usize = 4096;
const RETENTION_GRACE_SECONDS: u64 = 60;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct NonceReceipt {
    host_id: String,
    nonce: String,
    timestamp: u64,
    incident_id: String,
    body_sha256: String,
    recorded_unix_seconds: u64,
}

/// Reserve a valid host nonce or accept an exact idempotent replay.
///
/// Conflicting reuse is rejected. Expired entries are removed only after their
/// signed timestamp is outside the configured replay window plus a small grace
/// period. A hard per-host live-entry ceiling prevents unbounded durable growth.
pub fn reserve(
    artifact_root: &Path,
    auth: &AuthenticatedHost,
    incident: &ContainedIncident,
    now: u64,
    max_skew_seconds: u64,
) -> Result<()> {
    let root = artifact_root.join(REPLAY_DIR);
    ensure_private_directory_tree(artifact_root, Path::new(REPLAY_DIR))?;
    let host_dir = root.join(sha256_hex(auth.host_id.as_bytes()));
    ensure_private_child_directory(&root, &host_dir)?;

    let live = prune_and_count_live(&host_dir, now, max_skew_seconds)?;
    let path = host_dir.join(format!("{}.json", sha256_hex(auth.nonce.as_bytes())));
    let expected = NonceReceipt {
        host_id: auth.host_id.clone(),
        nonce: auth.nonce.clone(),
        timestamp: auth.timestamp,
        incident_id: incident.incident_id.clone(),
        body_sha256: auth.body_sha256.clone(),
        recorded_unix_seconds: now,
    };

    // Preserve exact-retry idempotency even when the live replay index is at
    // capacity. A new nonce is rejected before creating another durable entry.
    if path.exists() {
        let existing = read_record(&path)?;
        if same_binding(&existing, &expected) {
            return Ok(());
        }
        bail!("host incident nonce already exists with a conflicting binding");
    }
    if live >= MAX_LIVE_NONCES_PER_HOST {
        bail!("host incident replay index is at capacity");
    }

    match write_new(&path, &expected) {
        Ok(()) => {
            sync_dir(&host_dir)?;
            sync_dir(&root)?;
            Ok(())
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) =>
        {
            // Another receiver process won the same nonce race after our
            // existence check. Only the exact same signed binding is allowed.
            let existing = read_record(&path)?;
            if same_binding(&existing, &expected) {
                Ok(())
            } else {
                bail!("host incident nonce already exists with a conflicting binding");
            }
        }
        Err(error) => Err(error),
    }
}

fn ensure_private_directory_tree(root: &Path, relative: &Path) -> Result<()> {
    validate_directory(root, "artifact root")?;
    let mut current = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(name) = component else {
            bail!("replay directory path must contain only normal components");
        };
        current.push(name);
        match fs::symlink_metadata(&current) {
            Ok(_) => validate_directory(&current, "replay directory")?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                builder.mode(0o700);
                match builder.create(&current) {
                    Ok(()) => {
                        sync_dir(current.parent().context("replay directory has no parent")?)?;
                        validate_directory(&current, "replay directory")?;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                        validate_directory(&current, "replay directory")?;
                    }
                    Err(error) => {
                        return Err(error).with_context(|| {
                            format!("create replay directory {}", current.display())
                        })
                    }
                }
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("inspect replay directory {}", current.display()))
            }
        }
    }
    Ok(())
}

fn ensure_private_child_directory(parent: &Path, path: &Path) -> Result<()> {
    validate_directory(parent, "replay parent directory")?;
    match fs::symlink_metadata(path) {
        Ok(_) => validate_directory(path, "host replay directory"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(path) {
                Ok(()) => {
                    sync_dir(parent)?;
                    validate_directory(path, "host replay directory")
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    validate_directory(path, "host replay directory")
                }
                Err(error) => Err(error)
                    .with_context(|| format!("create host replay directory {}", path.display())),
            }
        }
        Err(error) => {
            Err(error).with_context(|| format!("inspect host replay directory {}", path.display()))
        }
    }
}

fn validate_directory(path: &Path, label: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("{label} {} must be a real directory", path.display());
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        bail!(
            "{label} {} must not be group/world writable",
            path.display()
        );
    }
    if metadata.uid() != unsafe { libc::geteuid() } {
        bail!(
            "{label} {} must be owned by the incident-ingest uid",
            path.display()
        );
    }
    Ok(())
}

fn same_binding(existing: &NonceReceipt, expected: &NonceReceipt) -> bool {
    existing.host_id == expected.host_id
        && existing.nonce == expected.nonce
        && existing.timestamp == expected.timestamp
        && existing.incident_id == expected.incident_id
        && existing.body_sha256 == expected.body_sha256
}

fn prune_and_count_live(host_dir: &Path, now: u64, max_skew_seconds: u64) -> Result<usize> {
    let horizon = max_skew_seconds.saturating_add(RETENTION_GRACE_SECONDS);
    let mut live = 0usize;
    let mut removed = false;
    for entry in fs::read_dir(host_dir)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            bail!("host incident replay index contains a non-file entry");
        }
        let path = entry.path();
        let receipt = read_record(&path)?;
        let expired = now > receipt.timestamp.saturating_add(horizon);
        if expired {
            fs::remove_file(&path)
                .with_context(|| format!("remove expired replay receipt {}", path.display()))?;
            removed = true;
        } else {
            live = live
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("host incident replay count overflow"))?;
        }
    }
    if removed {
        sync_dir(host_dir)?;
    }
    Ok(live)
}

fn write_new(path: &Path, receipt: &NonceReceipt) -> Result<()> {
    let mut body = serde_json::to_vec_pretty(receipt)?;
    body.push(b'\n');
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(&body)?;
    file.sync_all()?;
    Ok(())
}

fn read_record(path: &Path) -> Result<NonceReceipt> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("open replay receipt {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_RECORD_BYTES {
        bail!("host incident replay receipt is malformed or oversized");
    }
    let mut body = Vec::new();
    (&mut file)
        .take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut body)?;
    if body.len() as u64 > MAX_RECORD_BYTES {
        bail!("host incident replay receipt exceeds size limit");
    }
    serde_json::from_slice(&body)
        .with_context(|| format!("parse replay receipt {}", path.display()))
}

fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::incident::{Attribution, RuntimeIdentity};

    fn auth(nonce: &str, timestamp: u64, digest: &str) -> AuthenticatedHost {
        AuthenticatedHost {
            host_id: "host_1".into(),
            timestamp,
            nonce: nonce.into(),
            body_sha256: digest.into(),
        }
    }

    fn incident(id: &str) -> ContainedIncident {
        ContainedIncident {
            incident_id: id.into(),
            sensor: "command-wrapper".into(),
            stage: "contained".into(),
            frozen: true,
            attribution: Attribution {
                identity: RuntimeIdentity {
                    runtime_id: "rt_1".into(),
                    user_id: "usr_1".into(),
                    tenant_id: "ten_1".into(),
                    deployment_id: "dep_1".into(),
                    invocation_id: None,
                },
            },
        }
    }

    #[test]
    fn exact_replay_is_idempotent_across_fresh_reservations() {
        let temp = tempfile::tempdir().unwrap();
        let auth = auth("0123456789abcdef", 100, &"a".repeat(64));
        let incident = incident("inc_1");
        reserve(temp.path(), &auth, &incident, 100, 300).unwrap();
        reserve(temp.path(), &auth, &incident, 101, 300).unwrap();
    }

    #[test]
    fn nonce_reuse_with_different_body_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let incident = incident("inc_1");
        reserve(
            temp.path(),
            &auth("0123456789abcdef", 100, &"a".repeat(64)),
            &incident,
            100,
            300,
        )
        .unwrap();
        let error = reserve(
            temp.path(),
            &auth("0123456789abcdef", 100, &"b".repeat(64)),
            &incident,
            101,
            300,
        )
        .unwrap_err();
        assert!(error.to_string().contains("conflicting binding"));
    }

    #[test]
    fn nonce_reuse_with_different_incident_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let auth = auth("0123456789abcdef", 100, &"a".repeat(64));
        reserve(temp.path(), &auth, &incident("inc_1"), 100, 300).unwrap();
        let error = reserve(temp.path(), &auth, &incident("inc_2"), 101, 300).unwrap_err();
        assert!(error.to_string().contains("conflicting binding"));
    }

    #[test]
    fn replay_tree_rejects_symlinked_security_directory() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        symlink(outside.path(), temp.path().join(".security")).unwrap();
        let error = reserve(
            temp.path(),
            &auth("0123456789abcdef", 100, &"a".repeat(64)),
            &incident("inc_1"),
            100,
            300,
        )
        .unwrap_err();
        assert!(error.to_string().contains("must be a real directory"));
    }

    #[test]
    fn replay_tree_rejects_group_writable_artifact_root() {
        let temp = tempfile::tempdir().unwrap();
        let original = fs::metadata(temp.path()).unwrap().permissions().mode();
        let mut permissions = fs::metadata(temp.path()).unwrap().permissions();
        permissions.set_mode(original | 0o020);
        fs::set_permissions(temp.path(), permissions).unwrap();
        let error = reserve(
            temp.path(),
            &auth("0123456789abcdef", 100, &"a".repeat(64)),
            &incident("inc_1"),
            100,
            300,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("must not be group/world writable"));
    }

    #[test]
    fn expired_nonce_can_be_reused_after_safe_horizon() {
        let temp = tempfile::tempdir().unwrap();
        reserve(
            temp.path(),
            &auth("0123456789abcdef", 100, &"a".repeat(64)),
            &incident("inc_1"),
            100,
            300,
        )
        .unwrap();
        reserve(
            temp.path(),
            &auth("0123456789abcdef", 1000, &"b".repeat(64)),
            &incident("inc_2"),
            1000,
            300,
        )
        .unwrap();
    }
}
