use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};
use tokio::sync::RwLock;

pub const PROFILE: &str = "bmscl-critical-section-v1";
pub const TENANCY_CLASS: &str = "tenant_dedicated";
pub const EXECUTION_CLASS: &str = "durable_actor";
pub const ISOLATION_CLASS: &str = "firecracker";

#[derive(Debug, Clone, Deserialize)]
pub struct DeployCriticalSectionRequest {
    pub deployment_id: Option<String>,
    pub tenant_id: String,
    pub namespace: String,
    pub language: String,
    pub build_sha256: String,
    #[serde(default)]
    pub tenancy_class: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CriticalSectionDeployment {
    pub deployment_id: String,
    pub user_id: String,
    pub tenant_id: String,
    pub namespace: String,
    pub runtime: &'static str,
    pub language: String,
    pub profile: &'static str,
    pub build_sha256: String,
    pub tenancy_class: &'static str,
    pub execution_class: &'static str,
    pub isolation_class: &'static str,
    pub shard_id: String,
    pub runtime_host: String,
    pub runtime_epoch: u64,
    pub runtime_state: String,
}

#[derive(Clone, Default)]
pub struct CriticalSectionDeployments {
    inner: Arc<RwLock<HashMap<String, CriticalSectionDeployment>>>,
}

impl CriticalSectionDeployments {
    pub async fn insert(&self, deployment: CriticalSectionDeployment) {
        self.inner
            .write()
            .await
            .insert(deployment.deployment_id.clone(), deployment);
    }

    pub async fn get(&self, deployment_id: &str) -> Option<CriticalSectionDeployment> {
        self.inner.read().await.get(deployment_id).cloned()
    }
}

pub fn validate_request(request: &DeployCriticalSectionRequest) -> Result<(), String> {
    validate_identity("tenant_id", &request.tenant_id)?;
    validate_identity("namespace", &request.namespace)?;

    if !matches!(request.language.as_str(), "erlang" | "gleam") {
        return Err("critical-section language must be erlang or gleam".into());
    }

    if request.build_sha256.len() != 64
        || !request
            .build_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("build_sha256 must be 64 lowercase hex characters".into());
    }

    if request
        .tenancy_class
        .as_deref()
        .is_some_and(|requested| requested != TENANCY_CLASS)
    {
        return Err(
            "Durable Objects/critical sections require tenancy_class=tenant_dedicated".into(),
        );
    }

    if let Some(deployment_id) = request.deployment_id.as_deref() {
        validate_identity("deployment_id", deployment_id)?;
    }

    Ok(())
}

fn validate_identity(name: &str, value: &str) -> Result<(), String> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(format!(
            "invalid {name}: expected 1..=128 chars of [A-Za-z0-9._-]"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(language: &str, tenancy_class: Option<&str>) -> DeployCriticalSectionRequest {
        DeployCriticalSectionRequest {
            deployment_id: Some("critical-orders".into()),
            tenant_id: "acme".into(),
            namespace: "orders".into(),
            language: language.into(),
            build_sha256: "a".repeat(64),
            tenancy_class: tenancy_class.map(str::to_string),
        }
    }

    #[test]
    fn admits_erlang_and_gleam_as_dedicated_tenant() {
        assert!(validate_request(&request("erlang", Some("tenant_dedicated"))).is_ok());
        assert!(validate_request(&request("gleam", None)).is_ok());
    }

    #[test]
    fn rejects_mixed_tenant_durable_object() {
        let error = validate_request(&request("gleam", Some("mixed_tenants"))).unwrap_err();
        assert!(error.contains("tenant_dedicated"));
    }

    #[test]
    fn rejects_other_languages() {
        assert!(validate_request(&request("rust", None)).is_err());
    }
}
