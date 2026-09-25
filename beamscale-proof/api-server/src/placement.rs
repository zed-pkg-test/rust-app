use crate::runtime_control::RuntimeControlSigner;
use reqwest::{Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{cmp::Reverse, collections::HashMap, env, time::Duration};
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionClass {
    Faas,
    Phoenix,
    DurableActor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBackend {
    BareProcess,
    Firecracker,
}

impl ExecutionClass {
    pub fn backend(self) -> ExecutionBackend {
        match self {
            Self::Faas => ExecutionBackend::BareProcess,
            Self::Phoenix | Self::DurableActor => ExecutionBackend::Firecracker,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ShardKey {
    pub execution_class: ExecutionClass,
    pub tenant_id: String,
    pub shard_id: String,
}

#[derive(Debug, Clone)]
struct Placement {
    host: String,
    runtime_epoch: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimePolicy {
    pub vcpu_count: u16,
    pub memory_mib: u32,
    pub snapshot_enabled: bool,
    pub warm_idle_ms: u64,
    pub hibernate_after_ms: u64,
    pub destroy_after_ms: u64,
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self {
            vcpu_count: 1,
            memory_mib: 128,
            snapshot_enabled: true,
            warm_idle_ms: 10_000,
            hibernate_after_ms: 60_000,
            destroy_after_ms: 15 * 60_000,
        }
    }
}

#[derive(Debug, Serialize)]
struct EnsureShardRequest<'a> {
    user_id: &'a str,
    tenant_id: &'a str,
    shard_id: &'a str,
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
    tenant_isolation: &'static str,
    runtime_epoch: u64,
    root_deployment_id: &'a str,
    deployment_digest: &'a str,
    policy: RuntimePolicy,
}

#[derive(Debug, Serialize)]
struct EpochRequest<'a> {
    tenant_id: &'a str,
    shard_id: &'a str,
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
    runtime_epoch: u64,
}

#[derive(Debug, Serialize)]
struct ActivateShardRequest<'a> {
    tenant_id: &'a str,
    shard_id: &'a str,
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
    runtime_epoch: u64,
    deployment_id: &'a str,
    timeout_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct RuntimeHostStatus {
    runtime_epoch: u64,
    state: String,
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
}

#[derive(Debug, Deserialize)]
struct ActivationHostStatus {
    runtime_epoch: u64,
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
    observed: bool,
    root_active_deployment_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuntimePlacement {
    pub runtime_host: String,
    pub tenant_id: String,
    pub shard_id: String,
    pub execution_class: ExecutionClass,
    pub execution_backend: ExecutionBackend,
    pub runtime_epoch: u64,
    pub runtime_state: String,
}

#[derive(Debug, Error)]
pub enum PlacementError {
    #[error("no runtime hosts configured for {0:?}")]
    NoHosts(ExecutionBackend),
    #[error("runtime host rejected placement: {0}")]
    Rejected(String),
    #[error("runtime host conflict: {0}")]
    Conflict(String),
    #[error("all runtime hosts unavailable: {0}")]
    Unavailable(String),
}

pub struct PlacementService {
    client: Client,
    faas_hosts: Vec<String>,
    firecracker_hosts: Vec<String>,
    placements: HashMap<ShardKey, Placement>,
    runtime_control: RuntimeControlSigner,
}

impl PlacementService {
    pub fn from_env() -> Result<Self, PlacementError> {
        let faas_raw = env::var("BMSCL_RUNTIME_HOSTS_FAAS")
            .or_else(|_| env::var("BMSCL_RUNTIME_HOSTS"))
            .unwrap_or_else(|_| "http://127.0.0.1:9090".into());
        let firecracker_raw = env::var("BMSCL_RUNTIME_HOSTS_FIRECRACKER").unwrap_or_default();
        let faas_hosts = parse_hosts(&faas_raw);
        let firecracker_hosts = parse_hosts(&firecracker_raw);
        let runtime_control = RuntimeControlSigner::from_env()
            .map_err(PlacementError::Unavailable)?;
        if !firecracker_hosts.is_empty() {
            runtime_control
                .require_configured()
                .map_err(PlacementError::Unavailable)?;
        }
        Self::new_with_runtime_control(faas_hosts, firecracker_hosts, runtime_control)
    }

    pub fn new(
        faas_hosts: Vec<String>,
        firecracker_hosts: Vec<String>,
    ) -> Result<Self, PlacementError> {
        Self::new_with_runtime_control(
            faas_hosts,
            firecracker_hosts,
            RuntimeControlSigner::disabled(),
        )
    }

    fn new_with_runtime_control(
        mut faas_hosts: Vec<String>,
        mut firecracker_hosts: Vec<String>,
        runtime_control: RuntimeControlSigner,
    ) -> Result<Self, PlacementError> {
        normalize_hosts(&mut faas_hosts);
        normalize_hosts(&mut firecracker_hosts);
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(75))
            .build()
            .map_err(|e| PlacementError::Unavailable(e.to_string()))?;
        Ok(Self {
            client,
            faas_hosts,
            firecracker_hosts,
            placements: HashMap::new(),
            runtime_control,
        })
    }

    pub async fn ensure(
        &mut self,
        execution_class: ExecutionClass,
        user_id: &str,
        tenant_id: &str,
        shard_id: &str,
        root_deployment_id: &str,
        deployment_digest: &str,
    ) -> Result<RuntimePlacement, PlacementError> {
        validate_runtime_identity("user_id", user_id)?;
        validate_runtime_identity("root_deployment_id", root_deployment_id)?;
        let key = ShardKey {
            execution_class,
            tenant_id: tenant_id.to_string(),
            shard_id: shard_id.to_string(),
        };

        if let Some(existing) = self.placements.get(&key).cloned() {
            match self
                .ensure_ready_on_host(
                    &key,
                    &existing.host,
                    existing.runtime_epoch,
                    user_id,
                    root_deployment_id,
                    deployment_digest,
                )
                .await
            {
                Ok(status) => {
                    self.record(&key, &existing.host, &status);
                    return Ok(to_placement(&key, &existing.host, status));
                }
                Err(HostAttemptError::Rejected(message)) => {
                    return Err(PlacementError::Rejected(message));
                }
                Err(HostAttemptError::Conflict(message)) => {
                    return Err(PlacementError::Conflict(message));
                }
                Err(HostAttemptError::Unavailable(_)) => {
                    let next_epoch = existing.runtime_epoch.saturating_add(1);
                    return self
                        .failover(
                            &key,
                            Some(&existing.host),
                            next_epoch,
                            user_id,
                            root_deployment_id,
                            deployment_digest,
                        )
                        .await;
                }
            }
        }

        let ordered = self.host_order(&key);
        let first = ordered
            .first()
            .ok_or(PlacementError::NoHosts(execution_class.backend()))?
            .clone();
        match self
            .ensure_ready_on_host(
                &key,
                &first,
                1,
                user_id,
                root_deployment_id,
                deployment_digest,
            )
            .await
        {
            Ok(status) => {
                self.record(&key, &first, &status);
                Ok(to_placement(&key, &first, status))
            }
            Err(HostAttemptError::Rejected(message)) => Err(PlacementError::Rejected(message)),
            Err(HostAttemptError::Conflict(message)) => Err(PlacementError::Conflict(message)),
            Err(HostAttemptError::Unavailable(_)) => {
                self.failover(
                    &key,
                    Some(&first),
                    2,
                    user_id,
                    root_deployment_id,
                    deployment_digest,
                )
                .await
            }
        }
    }

    async fn failover(
        &mut self,
        key: &ShardKey,
        exclude_host: Option<&str>,
        runtime_epoch: u64,
        user_id: &str,
        root_deployment_id: &str,
        deployment_digest: &str,
    ) -> Result<RuntimePlacement, PlacementError> {
        let mut errors = Vec::new();
        for host in self.host_order(key) {
            if exclude_host.is_some_and(|excluded| excluded == host) {
                continue;
            }
            match self
                .ensure_ready_on_host(
                    key,
                    &host,
                    runtime_epoch,
                    user_id,
                    root_deployment_id,
                    deployment_digest,
                )
                .await
            {
                Ok(status) => {
                    self.record(key, &host, &status);
                    return Ok(to_placement(key, &host, status));
                }
                Err(HostAttemptError::Rejected(message)) => {
                    return Err(PlacementError::Rejected(message));
                }
                Err(HostAttemptError::Conflict(message)) => {
                    return Err(PlacementError::Conflict(message));
                }
                Err(HostAttemptError::Unavailable(message)) => {
                    errors.push(format!("{host}: {message}"));
                }
            }
        }
        if errors.is_empty() {
            Err(PlacementError::NoHosts(key.execution_class.backend()))
        } else {
            Err(PlacementError::Unavailable(errors.join("; ")))
        }
    }

    async fn ensure_ready_on_host(
        &self,
        key: &ShardKey,
        host: &str,
        runtime_epoch: u64,
        user_id: &str,
        root_deployment_id: &str,
        deployment_digest: &str,
    ) -> Result<RuntimeHostStatus, HostAttemptError> {
        let existing = self.get_shard_status(host, key).await?;
        let ready = match existing {
            Some(status) if status.runtime_epoch == runtime_epoch => {
                self.ensure_running(host, key, status).await?
            }
            Some(_) | None => {
                let ensured = self
                    .post_status(
                        format!("{host}/v1/shards/ensure"),
                        "ensure",
                        key,
                        runtime_epoch,
                        &EnsureShardRequest {
                            user_id,
                            tenant_id: &key.tenant_id,
                            shard_id: &key.shard_id,
                            execution_class: key.execution_class,
                            execution_backend: key.execution_class.backend(),
                            tenant_isolation: tenant_isolation(key.execution_class),
                            runtime_epoch,
                            root_deployment_id,
                            deployment_digest,
                            policy: runtime_policy(key.execution_class),
                        },
                    )
                    .await?;
                self.ensure_running(host, key, ensured).await?
            }
        };

        validate_host_status(&ready, key)?;
        self.activate_on_host(host, key, ready.runtime_epoch, deployment_digest)
            .await?;
        Ok(ready)
    }

    async fn ensure_running(
        &self,
        host: &str,
        key: &ShardKey,
        status: RuntimeHostStatus,
    ) -> Result<RuntimeHostStatus, HostAttemptError> {
        match status.state.as_str() {
            "hot" | "warm_idle" => Ok(status),
            "cold" | "hibernated" | "terminated" => {
                self.post_status(
                    format!("{host}/v1/shards/start"),
                    "start",
                    key,
                    status.runtime_epoch,
                    &EpochRequest {
                        tenant_id: &key.tenant_id,
                        shard_id: &key.shard_id,
                        execution_class: key.execution_class,
                        execution_backend: key.execution_class.backend(),
                        runtime_epoch: status.runtime_epoch,
                    },
                )
                .await
            }
            "starting" => Err(HostAttemptError::Unavailable(
                "runtime host returned starting without a ready barrier".into(),
            )),
            "draining" => Err(HostAttemptError::Conflict(
                "runtime shard is draining and cannot accept a new root generation".into(),
            )),
            other => Err(HostAttemptError::Unavailable(format!(
                "runtime host returned non-runnable state `{other}`"
            ))),
        }
    }

    async fn activate_on_host(
        &self,
        host: &str,
        key: &ShardKey,
        runtime_epoch: u64,
        deployment_digest: &str,
    ) -> Result<(), HostAttemptError> {
        let body = ActivateShardRequest {
            tenant_id: &key.tenant_id,
            shard_id: &key.shard_id,
            execution_class: key.execution_class,
            execution_backend: key.execution_class.backend(),
            runtime_epoch,
            deployment_id: deployment_digest,
            timeout_ms: 60_000,
        };
        let payload = self.runtime_request_payload("activate", key, runtime_epoch, &body)?;
        let response = self
            .client
            .post(format!("{host}/v1/shards/activate"))
            .json(&payload)
            .send()
            .await
            .map_err(|e| HostAttemptError::Unavailable(e.to_string()))?;

        let status = response.status();
        if status.is_success() {
            let activation = response
                .json::<ActivationHostStatus>()
                .await
                .map_err(|e| HostAttemptError::Unavailable(e.to_string()))?;
            if !activation_ack_matches(&activation, key, runtime_epoch, deployment_digest) {
                return Err(HostAttemptError::Unavailable(
                    "runtime host returned an activation acknowledgement for the wrong generation"
                        .into(),
                ));
            }
            return Ok(());
        }
        Err(classify_response_error(status, response).await)
    }

    async fn get_shard_status(
        &self,
        host: &str,
        key: &ShardKey,
    ) -> Result<Option<RuntimeHostStatus>, HostAttemptError> {
        let url = shard_status_url(host, key)?;
        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| HostAttemptError::Unavailable(e.to_string()))?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if status.is_success() {
            return response
                .json::<RuntimeHostStatus>()
                .await
                .map(Some)
                .map_err(|e| HostAttemptError::Unavailable(e.to_string()));
        }
        Err(classify_response_error(status, response).await)
    }

    async fn post_status<T: Serialize + ?Sized>(
        &self,
        url: String,
        operation: &str,
        key: &ShardKey,
        runtime_epoch: u64,
        body: &T,
    ) -> Result<RuntimeHostStatus, HostAttemptError> {
        let payload = self.runtime_request_payload(operation, key, runtime_epoch, body)?;
        let response = self
            .client
            .post(url)
            .json(&payload)
            .send()
            .await
            .map_err(|e| HostAttemptError::Unavailable(e.to_string()))?;

        let status = response.status();
        if status.is_success() {
            return response
                .json::<RuntimeHostStatus>()
                .await
                .map_err(|e| HostAttemptError::Unavailable(e.to_string()));
        }
        Err(classify_response_error(status, response).await)
    }

    fn runtime_request_payload<T: Serialize + ?Sized>(
        &self,
        operation: &str,
        key: &ShardKey,
        runtime_epoch: u64,
        body: &T,
    ) -> Result<Value, HostAttemptError> {
        if key.execution_class.backend() == ExecutionBackend::Firecracker {
            let signed = self
                .runtime_control
                .sign(
                    operation,
                    &key.tenant_id,
                    &key.shard_id,
                    execution_class_name(key.execution_class),
                    execution_backend_name(key.execution_class.backend()),
                    runtime_epoch,
                    body,
                )
                .map_err(HostAttemptError::Unavailable)?;
            serde_json::to_value(signed)
                .map_err(|err| HostAttemptError::Unavailable(err.to_string()))
        } else {
            serde_json::to_value(body)
                .map_err(|err| HostAttemptError::Unavailable(err.to_string()))
        }
    }

    fn record(&mut self, key: &ShardKey, host: &str, status: &RuntimeHostStatus) {
        self.placements.insert(
            key.clone(),
            Placement {
                host: host.to_string(),
                runtime_epoch: status.runtime_epoch,
            },
        );
    }

    fn host_order(&self, key: &ShardKey) -> Vec<String> {
        let pool = self.hosts_for(key.execution_class.backend());
        let mut assigned_counts: HashMap<&str, usize> =
            pool.iter().map(|host| (host.as_str(), 0)).collect();
        for (placed_key, placement) in &self.placements {
            if placed_key.execution_class.backend() == key.execution_class.backend() {
                if let Some(count) = assigned_counts.get_mut(placement.host.as_str()) {
                    *count += 1;
                }
            }
        }

        let mut hosts = pool.to_vec();
        hosts.sort_by_key(|host| {
            let load = assigned_counts.get(host.as_str()).copied().unwrap_or(0);
            let hash = stable_hash(&key.tenant_id, &key.shard_id, host);
            (load, Reverse(hash))
        });
        hosts
    }

    fn hosts_for(&self, backend: ExecutionBackend) -> &[String] {
        match backend {
            ExecutionBackend::BareProcess => &self.faas_hosts,
            ExecutionBackend::Firecracker => &self.firecracker_hosts,
        }
    }
}

#[derive(Debug)]
enum HostAttemptError {
    Rejected(String),
    Conflict(String),
    Unavailable(String),
}

async fn classify_response_error(
    status: StatusCode,
    response: reqwest::Response,
) -> HostAttemptError {
    let message = response
        .json::<ErrorBody>()
        .await
        .map(|v| v.error)
        .unwrap_or_else(|_| format!("HTTP {status}"));
    if status == StatusCode::CONFLICT {
        HostAttemptError::Conflict(message)
    } else if status.is_client_error() {
        HostAttemptError::Rejected(message)
    } else {
        HostAttemptError::Unavailable(message)
    }
}

fn activation_ack_matches(
    activation: &ActivationHostStatus,
    key: &ShardKey,
    runtime_epoch: u64,
    deployment_digest: &str,
) -> bool {
    activation.runtime_epoch == runtime_epoch
        && activation.execution_class == key.execution_class
        && activation.execution_backend == key.execution_class.backend()
        && activation.observed
        && activation.root_active_deployment_id.as_deref() == Some(deployment_digest)
}

fn validate_host_status(
    status: &RuntimeHostStatus,
    key: &ShardKey,
) -> Result<(), HostAttemptError> {
    if status.execution_class != key.execution_class
        || status.execution_backend != key.execution_class.backend()
    {
        return Err(HostAttemptError::Conflict(
            "runtime host returned the wrong execution class/backend".into(),
        ));
    }
    Ok(())
}

fn shard_status_url(host: &str, key: &ShardKey) -> Result<Url, HostAttemptError> {
    let mut url = Url::parse(host).map_err(|e| HostAttemptError::Unavailable(e.to_string()))?;
    {
        let mut segments = url.path_segments_mut().map_err(|_| {
            HostAttemptError::Unavailable("runtime host URL cannot be a base".into())
        })?;
        segments.pop_if_empty();
        let class = execution_class_name(key.execution_class);
        segments.extend(["v1", "shards", class, &key.tenant_id, &key.shard_id]);
    }
    Ok(url)
}

fn to_placement(key: &ShardKey, host: &str, status: RuntimeHostStatus) -> RuntimePlacement {
    RuntimePlacement {
        runtime_host: host.to_string(),
        tenant_id: key.tenant_id.clone(),
        shard_id: key.shard_id.clone(),
        execution_class: key.execution_class,
        execution_backend: key.execution_class.backend(),
        runtime_epoch: status.runtime_epoch,
        runtime_state: status.state,
    }
}

fn execution_class_name(class: ExecutionClass) -> &'static str {
    match class {
        ExecutionClass::Faas => "faas",
        ExecutionClass::Phoenix => "phoenix",
        ExecutionClass::DurableActor => "durable_actor",
    }
}

fn execution_backend_name(backend: ExecutionBackend) -> &'static str {
    match backend {
        ExecutionBackend::BareProcess => "bare_process",
        ExecutionBackend::Firecracker => "firecracker",
    }
}

fn tenant_isolation(class: ExecutionClass) -> &'static str {
    match class {
        ExecutionClass::Faas => "shared_host_restricted_process",
        ExecutionClass::Phoenix | ExecutionClass::DurableActor => "single_tenant_microvm",
    }
}

fn runtime_policy(class: ExecutionClass) -> RuntimePolicy {
    match class {
        ExecutionClass::Faas => RuntimePolicy {
            vcpu_count: 1,
            memory_mib: 128,
            snapshot_enabled: false,
            warm_idle_ms: 5_000,
            hibernate_after_ms: 0,
            destroy_after_ms: 60_000,
        },
        ExecutionClass::Phoenix => RuntimePolicy {
            vcpu_count: 1,
            memory_mib: 512,
            snapshot_enabled: true,
            warm_idle_ms: 60_000,
            hibernate_after_ms: 15 * 60_000,
            destroy_after_ms: 60 * 60_000,
        },
        ExecutionClass::DurableActor => RuntimePolicy {
            vcpu_count: 1,
            memory_mib: 256,
            snapshot_enabled: true,
            warm_idle_ms: 60_000,
            hibernate_after_ms: 5 * 60_000,
            destroy_after_ms: 30 * 60_000,
        },
    }
}

fn parse_hosts(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(|v| v.trim_end_matches('/').to_string())
        .collect()
}

fn normalize_hosts(hosts: &mut Vec<String>) {
    hosts.sort();
    hosts.dedup();
}

fn validate_runtime_identity(name: &str, value: &str) -> Result<(), PlacementError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(PlacementError::Rejected(format!(
            "invalid trusted {name}: expected 1..=128 chars of [A-Za-z0-9._-]"
        )))
    }
}

fn stable_hash(tenant_id: &str, shard_id: &str, host: &str) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in tenant_id
        .bytes()
        .chain([0xff])
        .chain(shard_id.bytes())
        .chain([0xfe])
        .chain(host.bytes())
    {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firecracker_payload_requires_runtime_control_secret() {
        let service = PlacementService::new(
            vec!["http://faas".into()],
            vec!["http://fc".into()],
        )
        .unwrap();
        let key = ShardKey {
            execution_class: ExecutionClass::Phoenix,
            tenant_id: "tenant".into(),
            shard_id: "0".into(),
        };
        let body = EpochRequest {
            tenant_id: "tenant",
            shard_id: "0",
            execution_class: ExecutionClass::Phoenix,
            execution_backend: ExecutionBackend::Firecracker,
            runtime_epoch: 3,
        };
        assert!(service
            .runtime_request_payload("start", &key, 3, &body)
            .is_err());
    }

    #[test]
    fn standard_faas_payload_remains_unsigned_for_compatibility() {
        let service = PlacementService::new(
            vec!["http://faas".into()],
            vec![],
        )
        .unwrap();
        let key = ShardKey {
            execution_class: ExecutionClass::Faas,
            tenant_id: "tenant".into(),
            shard_id: "0".into(),
        };
        let body = EpochRequest {
            tenant_id: "tenant",
            shard_id: "0",
            execution_class: ExecutionClass::Faas,
            execution_backend: ExecutionBackend::BareProcess,
            runtime_epoch: 1,
        };
        let payload = service
            .runtime_request_payload("start", &key, 1, &body)
            .unwrap();
        assert_eq!(payload["tenant_id"], "tenant");
        assert!(payload.get("contract").is_none());
    }

    #[test]
    fn host_order_prefers_lower_local_load() {
        let mut service = PlacementService::new(
            vec!["http://a".into(), "http://b".into()],
            vec!["http://fc-a".into()],
        )
        .unwrap();
        service.placements.insert(
            ShardKey {
                execution_class: ExecutionClass::Faas,
                tenant_id: "other".into(),
                shard_id: "0".into(),
            },
            Placement {
                host: "http://a".into(),
                runtime_epoch: 1,
            },
        );
        let order = service.host_order(&ShardKey {
            execution_class: ExecutionClass::Faas,
            tenant_id: "acme".into(),
            shard_id: "0".into(),
        });
        assert_eq!(order[0], "http://b");
    }

    #[test]
    fn hashing_is_stable() {
        assert_eq!(
            stable_hash("a", "0", "http://h"),
            stable_hash("a", "0", "http://h")
        );
        assert_ne!(
            stable_hash("a", "0", "http://h"),
            stable_hash("b", "0", "http://h")
        );
    }

    #[test]
    fn activation_ack_is_bound_to_exact_generation() {
        let key = ShardKey {
            execution_class: ExecutionClass::Phoenix,
            tenant_id: "tenant".into(),
            shard_id: "0".into(),
        };
        let matching = ActivationHostStatus {
            runtime_epoch: 7,
            execution_class: ExecutionClass::Phoenix,
            execution_backend: ExecutionBackend::Firecracker,
            observed: true,
            root_active_deployment_id: Some("sha256:requested".into()),
        };
        assert!(activation_ack_matches(
            &matching,
            &key,
            7,
            "sha256:requested"
        ));
        assert!(!activation_ack_matches(&matching, &key, 7, "sha256:other"));

        let wrong_epoch = ActivationHostStatus {
            runtime_epoch: 8,
            execution_class: ExecutionClass::Phoenix,
            execution_backend: ExecutionBackend::Firecracker,
            observed: true,
            root_active_deployment_id: Some("sha256:requested".into()),
        };
        assert!(!activation_ack_matches(
            &wrong_epoch,
            &key,
            7,
            "sha256:requested"
        ));

        let wrong_backend = ActivationHostStatus {
            runtime_epoch: 7,
            execution_class: ExecutionClass::Phoenix,
            execution_backend: ExecutionBackend::BareProcess,
            observed: true,
            root_active_deployment_id: Some("sha256:requested".into()),
        };
        assert!(!activation_ack_matches(
            &wrong_backend,
            &key,
            7,
            "sha256:requested"
        ));

        let unobserved = ActivationHostStatus {
            runtime_epoch: 7,
            execution_class: ExecutionClass::Phoenix,
            execution_backend: ExecutionBackend::Firecracker,
            observed: false,
            root_active_deployment_id: Some("sha256:requested".into()),
        };
        assert!(!activation_ack_matches(
            &unobserved,
            &key,
            7,
            "sha256:requested"
        ));
    }

    #[test]
    fn shard_status_url_percent_encodes_identity_segments() {
        let key = ShardKey {
            execution_class: ExecutionClass::Phoenix,
            tenant_id: "tenant with space".into(),
            shard_id: "shard/with/slash".into(),
        };
        let url = shard_status_url("http://127.0.0.1:9090", &key).unwrap();
        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:9090/v1/shards/phoenix/tenant%20with%20space/shard%2Fwith%2Fslash"
        );
    }

    #[test]
    fn execution_classes_select_distinct_backend_pools() {
        let service = PlacementService::new(
            vec!["http://faas-a".into()],
            vec!["http://fc-a".into(), "http://fc-b".into()],
        )
        .unwrap();

        let faas = service.host_order(&ShardKey {
            execution_class: ExecutionClass::Faas,
            tenant_id: "tenant".into(),
            shard_id: "0".into(),
        });
        assert_eq!(faas, vec!["http://faas-a"]);

        for class in [ExecutionClass::Phoenix, ExecutionClass::DurableActor] {
            let hosts = service.host_order(&ShardKey {
                execution_class: class,
                tenant_id: "tenant".into(),
                shard_id: "0".into(),
            });
            assert!(hosts.iter().all(|host| host.starts_with("http://fc-")));
            assert!(!hosts.iter().any(|host| host == "http://faas-a"));
        }
    }

    #[test]
    fn firecracker_classes_are_single_tenant_and_snapshot_capable() {
        for class in [ExecutionClass::Phoenix, ExecutionClass::DurableActor] {
            assert_eq!(class.backend(), ExecutionBackend::Firecracker);
            assert_eq!(tenant_isolation(class), "single_tenant_microvm");
            assert!(runtime_policy(class).snapshot_enabled);
        }
        assert_eq!(
            ExecutionClass::Faas.backend(),
            ExecutionBackend::BareProcess
        );
        assert!(!runtime_policy(ExecutionClass::Faas).snapshot_enabled);
    }

    #[test]
    fn host_status_must_attest_selected_execution_backend() {
        let key = ShardKey {
            execution_class: ExecutionClass::DurableActor,
            tenant_id: "tenant".into(),
            shard_id: "0".into(),
        };
        let good = RuntimeHostStatus {
            runtime_epoch: 1,
            state: "hot".into(),
            execution_class: ExecutionClass::DurableActor,
            execution_backend: ExecutionBackend::Firecracker,
        };
        assert!(validate_host_status(&good, &key).is_ok());

        let wrong = RuntimeHostStatus {
            execution_backend: ExecutionBackend::BareProcess,
            ..good
        };
        assert!(validate_host_status(&wrong, &key).is_err());
    }

    #[test]
    fn trusted_runtime_identity_is_bounded() {
        assert!(validate_runtime_identity("user_id", "usr_123").is_ok());
        assert!(validate_runtime_identity("user_id", "../root").is_err());
        assert!(validate_runtime_identity("root_deployment_id", "dep_123").is_ok());
    }
}
