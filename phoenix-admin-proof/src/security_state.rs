//! Read-only security-block lookup over durable host-incident receipts.

use anyhow::{bail, Context, Result};
use axum::http::{header::AUTHORIZATION, HeaderMap};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

const SECURITY_DIR: &str = ".security";
const MAX_BLOCK_RECEIPT_BYTES: u64 = 64 * 1024;

#[derive(Debug, Deserialize)]
pub struct SecurityStateRequest {
    pub user_id: String,
    pub tenant_id: String,
}

#[derive(Debug, Serialize)]
pub struct SecurityStateResponse {
    pub blocked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub incident_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BlockReceipt {
    incident_id: String,
    subject_type: String,
    subject_id: String,
    security_state: String,
    received_unix_seconds: u64,
}

pub fn authenticate_service(headers: &HeaderMap, expected_token_sha256: &[u8; 32]) -> Result<()> {
    let value = headers
        .get(AUTHORIZATION)
        .context("missing service authorization")?
        .to_str()
        .context("service authorization is not valid ASCII")?;
    let token = value
        .strip_prefix("Bearer ")
        .filter(|value| !value.is_empty())
        .context("service authorization must use Bearer")?;
    if token.len() > 4096 || token.bytes().any(|byte| byte.is_ascii_control()) {
        bail!("service authorization is malformed");
    }
    let actual: [u8; 32] = Sha256::digest(token.as_bytes()).into();
    if !constant_time_eq(&actual, expected_token_sha256) {
        bail!("service authorization rejected");
    }
    Ok(())
}

pub fn lookup(
    artifact_root: &Path,
    request: &SecurityStateRequest,
) -> Result<SecurityStateResponse> {
    validate_id("user_id", &request.user_id)?;
    validate_id("tenant_id", &request.tenant_id)?;
    let security_root = artifact_root.join(SECURITY_DIR).join("blocks");

    let user = latest_active_block(&security_root, "users", &request.user_id)?;
    let tenant = latest_active_block(&security_root, "tenants", &request.tenant_id)?;
    let incident_id = match (user, tenant) {
        (Some(user), Some(tenant)) => Some(
            if user.received_unix_seconds >= tenant.received_unix_seconds {
                user.incident_id
            } else {
                tenant.incident_id
            },
        ),
        (Some(receipt), None) | (None, Some(receipt)) => Some(receipt.incident_id),
        (None, None) => None,
    };
    Ok(SecurityStateResponse {
        blocked: incident_id.is_some(),
        incident_id,
    })
}

fn latest_active_block(
    root: &Path,
    subject_type: &str,
    subject_id: &str,
) -> Result<Option<BlockReceipt>> {
    let path = root
        .join(subject_type)
        .join(sha256_hex(subject_id.as_bytes()));

    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_dir() {
                bail!("block path {} must be a real directory", path.display());
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error)
                .with_context(|| format!("inspect block directory {}", path.display()))
        }
    }

    let entries =
        fs::read_dir(&path).with_context(|| format!("read block directory {}", path.display()))?;

    let mut latest: Option<BlockReceipt> = None;
    for entry in entries {
        let entry = entry?;
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            bail!(
                "block directory {} contains a non-regular entry",
                path.display()
            );
        }
        let name = entry.file_name();
        let name = name
            .to_str()
            .context("block receipt filename is not UTF-8")?;
        if !name.ends_with(".json") {
            bail!(
                "block directory {} contains an unexpected file",
                path.display()
            );
        }

        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&entry_path)
            .with_context(|| format!("open block receipt {}", entry_path.display()))?;
        let mut bytes = Vec::new();
        (&mut file)
            .take(MAX_BLOCK_RECEIPT_BYTES + 1)
            .read_to_end(&mut bytes)
            .with_context(|| format!("read block receipt {}", entry_path.display()))?;
        if bytes.len() as u64 > MAX_BLOCK_RECEIPT_BYTES {
            bail!("block receipt exceeds 64 KiB");
        }
        let receipt: BlockReceipt = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse block receipt {}", entry_path.display()))?;
        validate_id("incident_id", &receipt.incident_id)?;
        if receipt.subject_type != subject_type || receipt.subject_id != subject_id {
            bail!("block receipt subject identity mismatch");
        }
        if receipt.security_state != "blocked" {
            bail!("unsupported security block state");
        }
        let expected_name = format!("{}.json", receipt.incident_id);
        if name != expected_name {
            bail!("block receipt incident id does not match filename");
        }
        if latest
            .as_ref()
            .map(|value| receipt.received_unix_seconds > value.received_unix_seconds)
            .unwrap_or(true)
        {
            latest = Some(receipt);
        }
    }
    Ok(latest)
}

fn validate_id(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        bail!("invalid {label}");
    }
    Ok(())
}

fn sha256_hex(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write;
        write!(&mut output, "{byte:02x}").expect("write to String");
    }
    output
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    #[test]
    fn missing_ledger_is_clear() {
        let root = tempfile::tempdir().unwrap();
        let response = lookup(
            root.path(),
            &SecurityStateRequest {
                user_id: "usr_1".into(),
                tenant_id: "ten_1".into(),
            },
        )
        .unwrap();
        assert!(!response.blocked);
        assert!(response.incident_id.is_none());
    }

    #[test]
    fn user_block_is_returned() {
        let root = tempfile::tempdir().unwrap();
        let subject = "usr_1";
        let directory = root
            .path()
            .join(SECURITY_DIR)
            .join("blocks/users")
            .join(sha256_hex(subject.as_bytes()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("inc_1.json"),
            serde_json::to_vec(&serde_json::json!({
                "incident_id":"inc_1",
                "subject_type":"users",
                "subject_id":subject,
                "security_state":"blocked",
                "received_unix_seconds":10
            }))
            .unwrap(),
        )
        .unwrap();
        let response = lookup(
            root.path(),
            &SecurityStateRequest {
                user_id: subject.into(),
                tenant_id: "ten_1".into(),
            },
        )
        .unwrap();
        assert!(response.blocked);
        assert_eq!(response.incident_id.as_deref(), Some("inc_1"));
    }

    #[test]
    fn corrupt_receipt_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let subject = "ten_1";
        let directory = root
            .path()
            .join(SECURITY_DIR)
            .join("blocks/tenants")
            .join(sha256_hex(subject.as_bytes()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("bad.json"), b"not json").unwrap();
        assert!(lookup(
            root.path(),
            &SecurityStateRequest {
                user_id: "usr_1".into(),
                tenant_id: subject.into(),
            }
        )
        .is_err());
    }

    #[test]
    fn symlinked_receipt_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let subject = "usr_2";
        let directory = root
            .path()
            .join(SECURITY_DIR)
            .join("blocks/users")
            .join(sha256_hex(subject.as_bytes()));
        fs::create_dir_all(&directory).unwrap();
        let outside = root.path().join("outside.json");
        fs::write(
            &outside,
            serde_json::to_vec(&serde_json::json!({
                "incident_id":"inc_2",
                "subject_type":"users",
                "subject_id":subject,
                "security_state":"blocked",
                "received_unix_seconds":11
            }))
            .unwrap(),
        )
        .unwrap();
        symlink(&outside, directory.join("inc_2.json")).unwrap();
        assert!(lookup(
            root.path(),
            &SecurityStateRequest {
                user_id: subject.into(),
                tenant_id: "ten_1".into(),
            }
        )
        .is_err());
    }

    #[test]
    fn symlinked_subject_directory_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let subject = "ten_2";
        let parent = root.path().join(SECURITY_DIR).join("blocks/tenants");
        fs::create_dir_all(&parent).unwrap();
        let outside = root.path().join("outside-dir");
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, parent.join(sha256_hex(subject.as_bytes()))).unwrap();
        assert!(lookup(
            root.path(),
            &SecurityStateRequest {
                user_id: "usr_1".into(),
                tenant_id: subject.into(),
            }
        )
        .is_err());
    }
}
