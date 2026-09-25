//! Authenticated host-incident ingestion and durable security-block receipts.

use anyhow::{bail, Context, Result};
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

const AUTH_VERSION: &str = "bmscl-host-incident-v1";
const HEADER_HOST_ID: &str = "x-bmscl-host-id";
const HEADER_TIMESTAMP: &str = "x-bmscl-timestamp";
const HEADER_NONCE: &str = "x-bmscl-nonce";
const HEADER_BODY_SHA256: &str = "x-bmscl-body-sha256";
const HEADER_SIGNATURE: &str = "x-bmscl-signature";
const SECURITY_DIR: &str = ".security";
static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub struct AuthenticatedHost {
    pub host_id: String,
    pub timestamp: u64,
    pub nonce: String,
    pub body_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuntimeIdentity {
    pub runtime_id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub deployment_id: String,
    #[serde(default)]
    pub invocation_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Attribution {
    pub identity: RuntimeIdentity,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ContainedIncident {
    pub incident_id: String,
    pub sensor: String,
    pub stage: String,
    pub frozen: bool,
    pub attribution: Attribution,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IncidentReceipt {
    pub incident_id: String,
    pub body_sha256: String,
    pub host_id: String,
    pub received_unix_seconds: u64,
    pub user_id: String,
    pub tenant_id: String,
    pub deployment_id: String,
    pub runtime_id: String,
    pub security_state: String,
    pub notification_state: String,
    pub duplicate: bool,
}

#[derive(Debug, Serialize)]
struct BlockReceipt<'a> {
    incident_id: &'a str,
    subject_type: &'a str,
    subject_id: &'a str,
    security_state: &'static str,
    received_unix_seconds: u64,
}

#[derive(Debug, Serialize)]
struct RevocationIntent<'a> {
    incident_id: &'a str,
    user_id: &'a str,
    tenant_id: &'a str,
    state: &'static str,
    reason: &'static str,
    requested_unix_seconds: u64,
    actions: [&'static str; 3],
}

#[derive(Debug, Serialize)]
struct NotificationIntent<'a> {
    incident_id: &'a str,
    user_id: &'a str,
    tenant_id: &'a str,
    deployment_id: &'a str,
    runtime_id: &'a str,
    channels: [&'static str; 4],
    state: &'static str,
    note: &'static str,
}

pub fn authenticate(
    headers: &HeaderMap,
    body: &[u8],
    keys: &BTreeMap<String, Vec<u8>>,
    now: u64,
    max_skew_seconds: u64,
) -> Result<AuthenticatedHost> {
    let host_id = required_header(headers, HEADER_HOST_ID)?;
    validate_id("host_id", &host_id)?;
    let timestamp_raw = required_header(headers, HEADER_TIMESTAMP)?;
    let timestamp = timestamp_raw
        .parse::<u64>()
        .context("x-bmscl-timestamp must be an unsigned Unix timestamp")?;
    let skew = now.abs_diff(timestamp);
    if skew > max_skew_seconds {
        bail!("host incident timestamp is outside the replay window");
    }
    let nonce = required_header(headers, HEADER_NONCE)?;
    if nonce.len() < 16 || nonce.len() > 128 || !nonce.bytes().all(is_token_byte) {
        bail!("host incident nonce is malformed");
    }

    let body_sha256 = sha256_hex(body);
    let supplied_digest = required_header(headers, HEADER_BODY_SHA256)?;
    if !constant_time_eq(body_sha256.as_bytes(), supplied_digest.as_bytes()) {
        bail!("host incident body digest mismatch");
    }

    let key = keys
        .get(&host_id)
        .ok_or_else(|| anyhow::anyhow!("host incident signer is not trusted"))?;
    if key.len() != 32 {
        bail!("configured host incident HMAC key must be exactly 32 bytes");
    }
    let canonical = format!("{AUTH_VERSION}\n{host_id}\n{timestamp}\n{nonce}\n{body_sha256}\n");
    let expected = hmac_sha256(key, canonical.as_bytes());
    let supplied_signature = required_header(headers, HEADER_SIGNATURE)?;
    let supplied =
        hex::decode(&supplied_signature).context("host incident signature is not hex")?;
    if !constant_time_eq(&expected, &supplied) {
        bail!("host incident signature verification failed");
    }

    Ok(AuthenticatedHost {
        host_id,
        timestamp,
        nonce,
        body_sha256,
    })
}

pub fn parse_contained(body: &[u8]) -> Result<ContainedIncident> {
    let incident: ContainedIncident =
        serde_json::from_slice(body).context("host incident body is invalid JSON")?;
    validate_id("incident_id", &incident.incident_id)?;
    validate_id("sensor", &incident.sensor)?;
    if incident.stage != "contained" || !incident.frozen {
        bail!("only finalized contained incidents may enter the control plane");
    }
    let identity = &incident.attribution.identity;
    validate_id("runtime_id", &identity.runtime_id)?;
    validate_id("user_id", &identity.user_id)?;
    validate_id("tenant_id", &identity.tenant_id)?;
    validate_id("deployment_id", &identity.deployment_id)?;
    if let Some(invocation_id) = &identity.invocation_id {
        validate_id("invocation_id", invocation_id)?;
    }
    Ok(incident)
}

pub fn commit(
    artifact_root: &Path,
    incident: &ContainedIncident,
    auth: &AuthenticatedHost,
    body: &[u8],
    received_unix_seconds: u64,
) -> Result<IncidentReceipt> {
    let security_root = artifact_root.join(SECURITY_DIR);
    let incidents_root = security_root.join("incidents");
    fs::create_dir_all(&incidents_root)?;

    let final_dir = incidents_root.join(&incident.incident_id);
    if final_dir.exists() {
        let mut receipt: IncidentReceipt = read_json(&final_dir.join("receipt.json"))?;
        if receipt.body_sha256 != auth.body_sha256 || receipt.host_id != auth.host_id {
            bail!("incident id already exists with a different digest or host identity");
        }
        ensure_side_effect_receipts(&security_root, incident, received_unix_seconds)?;
        receipt.duplicate = true;
        return Ok(receipt);
    }

    let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let staging = incidents_root.join(format!(
        ".tmp-{}-{}-{sequence}",
        incident.incident_id,
        std::process::id()
    ));
    // Never delete an existing staging directory here. A concurrent ingest or a
    // crash residue must fail closed rather than letting one request erase another
    // request's in-progress evidence.
    fs::create_dir(&staging)?;

    let identity = &incident.attribution.identity;
    let receipt = IncidentReceipt {
        incident_id: incident.incident_id.clone(),
        body_sha256: auth.body_sha256.clone(),
        host_id: auth.host_id.clone(),
        received_unix_seconds,
        user_id: identity.user_id.clone(),
        tenant_id: identity.tenant_id.clone(),
        deployment_id: identity.deployment_id.clone(),
        runtime_id: identity.runtime_id.clone(),
        security_state: "blocked".to_owned(),
        notification_state: "alert_pending".to_owned(),
        duplicate: false,
    };

    // Preserve the exact authenticated request bytes. The body digest and HMAC
    // cover this byte sequence, including any final newline from the host daemon.
    write_exact_new_synced(&staging.join("incident.json"), body)?;
    write_json_new_synced(&staging.join("receipt.json"), &receipt)?;
    write_json_new_synced(
        &staging.join("auth.json"),
        &serde_json::json!({
            "version": AUTH_VERSION,
            "host_id": auth.host_id,
            "timestamp": auth.timestamp,
            "nonce": auth.nonce,
            "body_sha256": auth.body_sha256,
        }),
    )?;
    sync_dir(&staging)?;
    fs::rename(&staging, &final_dir)?;
    sync_dir(&incidents_root)?;

    ensure_side_effect_receipts(&security_root, incident, received_unix_seconds)?;
    Ok(receipt)
}

fn ensure_side_effect_receipts(
    security_root: &Path,
    incident: &ContainedIncident,
    received_unix_seconds: u64,
) -> Result<()> {
    let identity = &incident.attribution.identity;
    for (subject_type, subject_id) in [
        ("users", identity.user_id.as_str()),
        ("tenants", identity.tenant_id.as_str()),
        ("deployments", identity.deployment_id.as_str()),
        ("runtimes", identity.runtime_id.as_str()),
    ] {
        let subject_hash = sha256_hex(subject_id.as_bytes());
        let directory = security_root
            .join("blocks")
            .join(subject_type)
            .join(subject_hash);
        fs::create_dir_all(&directory)?;
        let path = directory.join(format!("{}.json", incident.incident_id));
        if !path.exists() {
            write_json_new_synced(
                &path,
                &BlockReceipt {
                    incident_id: &incident.incident_id,
                    subject_type,
                    subject_id,
                    security_state: "blocked",
                    received_unix_seconds,
                },
            )?;
            sync_dir(&directory)?;
        }
    }

    let revocations = security_root.join("revocations").join("pending");
    fs::create_dir_all(&revocations)?;
    let revocation = revocations.join(format!("{}.json", incident.incident_id));
    if !revocation.exists() {
        write_json_new_synced(
            &revocation,
            &RevocationIntent {
                incident_id: &incident.incident_id,
                user_id: &identity.user_id,
                tenant_id: &identity.tenant_id,
                state: "pending",
                reason: "verified_host_escape_incident",
                requested_unix_seconds: received_unix_seconds,
                actions: [
                    "revoke_sessions",
                    "revoke_api_credentials",
                    "deny_new_tokens",
                ],
            },
        )?;
        sync_dir(&revocations)?;
    }

    let notifications = security_root.join("notifications").join("pending");
    fs::create_dir_all(&notifications)?;
    let notification = notifications.join(format!("{}.json", incident.incident_id));
    if !notification.exists() {
        write_json_new_synced(
            &notification,
            &NotificationIntent {
                incident_id: &incident.incident_id,
                user_id: &identity.user_id,
                tenant_id: &identity.tenant_id,
                deployment_id: &identity.deployment_id,
                runtime_id: &identity.runtime_id,
                channels: ["warning_email", "pager", "chat", "siem"],
                state: "pending",
                note: "Resolve destinations from trusted account/control-plane data; never trust an incident-supplied email address.",
            },
        )?;
        sync_dir(&notifications)?;
    }
    sync_dir(security_root)?;
    Ok(())
}

fn required_header(headers: &HeaderMap, name: &str) -> Result<String> {
    let value = headers
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("missing required host incident header {name}"))?;
    Ok(value
        .to_str()
        .with_context(|| format!("host incident header {name} is not ASCII"))?
        .to_owned())
}

fn validate_id(label: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 256 || !value.bytes().all(is_token_byte) {
        bail!("{label} is malformed");
    }
    Ok(())
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':')
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key_block = [0_u8; BLOCK];
    if key.len() > BLOCK {
        key_block[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36_u8; BLOCK];
    let mut opad = [0x5c_u8; BLOCK];
    for index in 0..BLOCK {
        ipad[index] ^= key_block[index];
        opad[index] ^= key_block[index];
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(message);
    let inner_digest = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (&a, &b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn write_exact_new_synced(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(path)
        .with_context(|| format!("create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_json_new_synced<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let mut body = serde_json::to_vec_pretty(value)?;
    body.push(b'\n');
    write_exact_new_synced(path, &body)
}

fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc_4231_case_one() {
        let key = [0x0b_u8; 20];
        let mac = hmac_sha256(&key, b"Hi There");
        assert_eq!(
            hex::encode(mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn rejects_detection_receipt_that_is_not_finalized() {
        let body = br#"{
          "incident_id":"inc_1",
          "sensor":"command-wrapper",
          "stage":"detected",
          "frozen":false,
          "attribution":{"identity":{"runtime_id":"rt_1","user_id":"usr_1","tenant_id":"ten_1","deployment_id":"dep_1"}}
        }"#;
        assert!(parse_contained(body).is_err());
    }

    #[test]
    fn commit_is_idempotent_and_creates_block_and_alert_receipts() {
        let temp = tempfile::tempdir().unwrap();
        let body = br#"{
          "incident_id":"inc_1",
          "sensor":"command-wrapper",
          "stage":"contained",
          "frozen":true,
          "attribution":{"identity":{"runtime_id":"rt_1","user_id":"usr_1","tenant_id":"ten_1","deployment_id":"dep_1"}}
        }"#;
        let incident = parse_contained(body).unwrap();
        let auth = AuthenticatedHost {
            host_id: "host_1".into(),
            timestamp: 10,
            nonce: "0123456789abcdef".into(),
            body_sha256: sha256_hex(body),
        };
        let first = commit(temp.path(), &incident, &auth, body, 11).unwrap();
        assert!(!first.duplicate);
        let stored = fs::read(temp.path().join(".security/incidents/inc_1/incident.json")).unwrap();
        assert_eq!(stored, body);
        assert_eq!(sha256_hex(&stored), first.body_sha256);
        let second = commit(temp.path(), &incident, &auth, body, 12).unwrap();
        assert!(second.duplicate);
        assert!(temp
            .path()
            .join(".security/notifications/pending/inc_1.json")
            .is_file());
        let revocation_path = temp.path().join(".security/revocations/pending/inc_1.json");
        assert!(revocation_path.is_file());
        let revocation: serde_json::Value =
            serde_json::from_slice(&fs::read(&revocation_path).unwrap()).unwrap();
        assert_eq!(revocation["user_id"], "usr_1");
        assert_eq!(revocation["tenant_id"], "ten_1");
        assert_eq!(revocation["state"], "pending");
        assert_eq!(revocation["reason"], "verified_host_escape_incident");
        assert_eq!(
            revocation["actions"],
            serde_json::json!([
                "revoke_sessions",
                "revoke_api_credentials",
                "deny_new_tokens"
            ])
        );
        let user_hash = sha256_hex(b"usr_1");
        assert!(temp
            .path()
            .join(".security/blocks/users")
            .join(user_hash)
            .join("inc_1.json")
            .is_file());
    }
}
