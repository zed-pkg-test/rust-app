use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    env,
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

pub const CONTRACT_VERSION: &str = "bmscl.runtime-control.v1";
const DEFAULT_TTL_SECONDS: u64 = 30;
const MAX_TTL_SECONDS: u64 = 60;

#[derive(Debug, Clone)]
pub struct RuntimeControlSigner {
    secret: Option<Vec<u8>>,
    ttl_seconds: u64,
}

#[derive(Debug, Serialize)]
pub struct SignedRequest<'a, T: Serialize + ?Sized> {
    pub contract: RuntimeContract,
    pub request: &'a T,
}

#[derive(Debug, Clone, Copy)]
pub struct RuntimeControlTarget<'a> {
    pub operation: &'a str,
    pub tenant_id: &'a str,
    pub shard_id: &'a str,
    pub execution_class: &'a str,
    pub execution_backend: &'a str,
    pub runtime_epoch: u64,
}

#[derive(Debug, Clone, Serialize)]
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

impl RuntimeControlSigner {
    #[cfg(test)]
    pub fn disabled() -> Self {
        Self {
            secret: None,
            ttl_seconds: DEFAULT_TTL_SECONDS,
        }
    }

    pub fn from_env() -> Result<Self, String> {
        let secret = match env::var("BMSCL_RUNTIME_CONTROL_SECRET") {
            Ok(value) if value.len() >= 32 => Some(value.into_bytes()),
            Ok(_) => return Err("BMSCL_RUNTIME_CONTROL_SECRET must be at least 32 bytes".into()),
            Err(env::VarError::NotPresent) => None,
            Err(err) => return Err(format!("read BMSCL_RUNTIME_CONTROL_SECRET: {err}")),
        };
        let ttl_seconds = env::var("BMSCL_RUNTIME_CONTROL_TTL_SECONDS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(DEFAULT_TTL_SECONDS);
        if ttl_seconds == 0 || ttl_seconds > MAX_TTL_SECONDS {
            return Err(format!(
                "BMSCL_RUNTIME_CONTROL_TTL_SECONDS must be 1..={MAX_TTL_SECONDS}"
            ));
        }
        Ok(Self {
            secret,
            ttl_seconds,
        })
    }

    pub fn require_configured(&self) -> Result<(), String> {
        if self.secret.is_some() {
            Ok(())
        } else {
            Err("BMSCL_RUNTIME_CONTROL_SECRET is required for Firecracker runtime hosts".into())
        }
    }

    pub fn sign<'a, T: Serialize + ?Sized>(
        &self,
        target: RuntimeControlTarget<'_>,
        request: &'a T,
    ) -> Result<SignedRequest<'a, T>, String> {
        let secret = self.secret.as_deref().ok_or_else(|| {
            "BMSCL_RUNTIME_CONTROL_SECRET is required for Firecracker runtime hosts".to_string()
        })?;
        let issued_at_unix = now_unix()?;
        let request_sha256 = request_sha256(request)?;
        let mut contract = RuntimeContract {
            version: CONTRACT_VERSION.into(),
            operation: target.operation.into(),
            tenant_id: target.tenant_id.into(),
            shard_id: target.shard_id.into(),
            execution_class: target.execution_class.into(),
            execution_backend: target.execution_backend.into(),
            runtime_epoch: target.runtime_epoch,
            request_sha256: request_sha256.clone(),
            issued_at_unix,
            expires_at_unix: issued_at_unix.saturating_add(self.ttl_seconds),
            nonce: Uuid::new_v4().simple().to_string(),
            signature: String::new(),
        };
        contract.signature = signature_for(secret, &contract, &request_sha256);
        Ok(SignedRequest { contract, request })
    }
}

pub fn request_sha256<T: Serialize + ?Sized>(request: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(request)
        .map_err(|err| format!("serialize runtime control request: {err}"))?;
    Ok(hex_lower(&Sha256::digest(bytes)))
}

pub fn signature_for(secret: &[u8], contract: &RuntimeContract, request_sha256: &str) -> String {
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

fn now_unix() -> Result<u64, String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Serialize)]
    struct Request {
        value: u64,
    }

    fn signer() -> RuntimeControlSigner {
        RuntimeControlSigner {
            secret: Some(b"0123456789abcdef0123456789abcdef".to_vec()),
            ttl_seconds: 30,
        }
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
    fn signs_exact_runtime_host_contract_v1() {
        let request = Request { value: 42 };
        let signed = signer()
            .sign(
                RuntimeControlTarget {
                    operation: "invoke",
                    tenant_id: "tenant-a",
                    shard_id: "0",
                    execution_class: "phoenix",
                    execution_backend: "firecracker",
                    runtime_epoch: 7,
                },
                &request,
            )
            .unwrap();
        assert_eq!(signed.contract.version, CONTRACT_VERSION);
        assert_eq!(signed.contract.operation, "invoke");
        assert_eq!(signed.contract.tenant_id, "tenant-a");
        assert_eq!(signed.contract.execution_backend, "firecracker");
        assert_eq!(
            signed.contract.request_sha256,
            request_sha256(&request).unwrap()
        );
        assert!(!signed.contract.signature.is_empty());
        assert!(signed.contract.expires_at_unix > signed.contract.issued_at_unix);
    }

    #[test]
    fn missing_secret_fails_closed_when_signing() {
        let request = Request { value: 1 };
        assert!(RuntimeControlSigner::disabled()
            .sign(
                RuntimeControlTarget {
                    operation: "invoke",
                    tenant_id: "tenant-a",
                    shard_id: "0",
                    execution_class: "phoenix",
                    execution_backend: "firecracker",
                    runtime_epoch: 1,
                },
                &request,
            )
            .is_err());
    }
}
