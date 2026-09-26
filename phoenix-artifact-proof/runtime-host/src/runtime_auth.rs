use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{env, time::{SystemTime, UNIX_EPOCH}};

pub const CONTRACT_VERSION: &str = "bmscl.runtime-control.v1";
const MAX_TTL_SECONDS: u64 = 60;
const CLOCK_SKEW_SECONDS: u64 = 5;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRequest<T> {
    pub contract: RuntimeContract,
    pub request: T,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuntimeContract {
    pub version: String,
    pub operation: String,
    pub tenant_id: String,
    pub shard_id: String,
    pub execution_class: String,
    pub execution_backend: String,
    pub runtime_epoch: u64,
    pub request_sha256: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
    pub nonce: String,
    pub signature: String,
}

#[derive(Debug, Clone, Copy)]
pub struct ExpectedRuntimeRequest<'a> {
    pub operation: &'a str,
    pub tenant_id: &'a str,
    pub shard_id: &'a str,
    pub execution_class: &'a str,
    pub execution_backend: &'a str,
    pub runtime_epoch: u64,
}

pub fn load_secret() -> Result<Vec<u8>, String> {
    let value = env::var("BMSCL_RUNTIME_CONTROL_SECRET")
        .map_err(|_| "BMSCL_RUNTIME_CONTROL_SECRET is required".to_string())?;
    let bytes = value.into_bytes();
    if bytes.len() < 32 {
        return Err("BMSCL_RUNTIME_CONTROL_SECRET must be at least 32 bytes".into());
    }
    Ok(bytes)
}

pub fn verify<T: Serialize>(
    secret: &[u8],
    expected: &ExpectedRuntimeRequest<'_>,
    request: &T,
    contract: &RuntimeContract,
) -> Result<u64, String> {
    if secret.len() < 32 {
        return Err("runtime control secret is invalid".into());
    }
    let now = now_unix()?;
    if contract.version != CONTRACT_VERSION {
        return Err("unsupported runtime control contract".into());
    }
    if contract.operation != expected.operation
        || contract.tenant_id != expected.tenant_id
        || contract.shard_id != expected.shard_id
        || contract.execution_class != expected.execution_class
        || contract.execution_backend != expected.execution_backend
        || contract.runtime_epoch != expected.runtime_epoch
    {
        return Err("runtime control contract identity mismatch".into());
    }
    if contract.issued_at_unix > now.saturating_add(CLOCK_SKEW_SECONDS)
        || contract.expires_at_unix < now
        || contract.expires_at_unix <= contract.issued_at_unix
        || contract.expires_at_unix.saturating_sub(contract.issued_at_unix) > MAX_TTL_SECONDS
    {
        return Err("runtime control contract expired or invalid".into());
    }
    if contract.nonce.len() < 16
        || contract.nonce.len() > 128
        || !contract.nonce.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err("runtime control contract nonce is invalid".into());
    }
    let request_sha256 = request_sha256(request)?;
    if !constant_time_eq(
        contract.request_sha256.as_bytes(),
        request_sha256.as_bytes(),
    ) {
        return Err("runtime control request digest mismatch".into());
    }
    let expected_signature = signature_for(secret, contract, &request_sha256);
    if !constant_time_eq(
        contract.signature.as_bytes(),
        expected_signature.as_bytes(),
    ) {
        return Err("runtime control signature mismatch".into());
    }
    Ok(contract.expires_at_unix)
}

pub fn request_sha256<T: Serialize>(request: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(request)
        .map_err(|err| format!("serialize runtime control request: {err}"))?;
    Ok(hex_lower(&Sha256::digest(bytes)))
}

pub fn signature_for(
    secret: &[u8],
    contract: &RuntimeContract,
    request_sha256: &str,
) -> String {
    let canonical = format!(
        "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
        contract.version,
        contract.operation,
        contract.tenant_id,
        contract.shard_id,
        contract.execution_class,
        contract.execution_backend,
        contract.runtime_epoch,
        request_sha256,
        contract.issued_at_unix,
        contract.expires_at_unix,
        contract.nonce
    );
    hex_lower(&hmac_sha256(secret, canonical.as_bytes()))
}

pub fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| "system clock is before UNIX epoch".into())
}

fn hmac_sha256(secret: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut key = [0u8; BLOCK];
    if secret.len() > BLOCK {
        let digest = Sha256::digest(secret);
        key[..32].copy_from_slice(&digest);
    } else {
        key[..secret.len()].copy_from_slice(secret);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for index in 0..BLOCK {
        ipad[index] ^= key[index];
        opad[index] ^= key[index];
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

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Request {
        value: u64,
    }

    fn signed(secret: &[u8], request: &Request) -> RuntimeContract {
        let issued = now_unix().unwrap();
        let request_sha256 = request_sha256(request).unwrap();
        let mut contract = RuntimeContract {
            version: CONTRACT_VERSION.into(),
            operation: "invoke".into(),
            tenant_id: "tenant-a".into(),
            shard_id: "0".into(),
            execution_class: "phoenix".into(),
            execution_backend: "firecracker".into(),
            runtime_epoch: 7,
            request_sha256: request_sha256.clone(),
            issued_at_unix: issued,
            expires_at_unix: issued + 30,
            nonce: "nonce-1234567890".into(),
            signature: String::new(),
        };
        contract.signature = signature_for(secret, &contract, &request_sha256);
        contract
    }

    #[test]
    fn verifies_exact_body_and_identity() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let request = Request { value: 42 };
        let contract = signed(secret, &request);
        assert!(verify(
            secret,
            &ExpectedRuntimeRequest {
                operation: "invoke",
                tenant_id: "tenant-a",
                shard_id: "0",
                execution_class: "phoenix",
                execution_backend: "firecracker",
                runtime_epoch: 7,
            },
            &request,
            &contract
        )
        .is_ok());
    }

    #[test]
    fn rejects_body_tampering() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let request = Request { value: 42 };
        let contract = signed(secret, &request);
        assert!(verify(
            secret,
            &ExpectedRuntimeRequest {
                operation: "invoke",
                tenant_id: "tenant-a",
                shard_id: "0",
                execution_class: "phoenix",
                execution_backend: "firecracker",
                runtime_epoch: 7,
            },
            &Request { value: 43 },
            &contract
        )
        .is_err());
    }

    #[test]
    fn matches_cross_repo_runtime_control_v1_vector() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let request = Request { value: 42 };
        let request_sha256 = request_sha256(&request).unwrap();
        assert_eq!(
            request_sha256,
            "dc60e632a90329ccfd34fbe904d94704dbbb6669575185e26389854ff64139c3"
        );
        let contract = RuntimeContract {
            version: CONTRACT_VERSION.into(),
            operation: "invoke".into(),
            tenant_id: "tenant-a".into(),
            shard_id: "0".into(),
            execution_class: "phoenix".into(),
            execution_backend: "firecracker".into(),
            runtime_epoch: 7,
            request_sha256: request_sha256.clone(),
            issued_at_unix: 1_700_000_000,
            expires_at_unix: 1_700_000_030,
            nonce: "nonce-1234567890".into(),
            signature: String::new(),
        };
        assert_eq!(
            signature_for(secret, &contract, &request_sha256),
            "e55da196d53024c61f189b3aaaec564bf564c6394e991024a50e03543c08e7dd"
        );
    }

    #[test]
    fn rejects_cross_tenant_reuse() {
        let secret = b"0123456789abcdef0123456789abcdef";
        let request = Request { value: 42 };
        let contract = signed(secret, &request);
        assert!(verify(
            secret,
            &ExpectedRuntimeRequest {
                operation: "invoke",
                tenant_id: "tenant-b",
                shard_id: "0",
                execution_class: "phoenix",
                execution_backend: "firecracker",
                runtime_epoch: 7,
            },
            &request,
            &contract
        )
        .is_err());
    }
}
