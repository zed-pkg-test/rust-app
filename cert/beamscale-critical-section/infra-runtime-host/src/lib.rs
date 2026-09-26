use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    env,
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    fs,
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    process::Command,
    sync::RwLock,
    time::{sleep, Duration, Instant},
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionClass {
    Faas,
    Phoenix,
    DurableActor,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionBackend {
    BareProcess,
    Firecracker,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct ShardKey {
    pub execution_class: ExecutionClass,
    pub tenant_id: String,
    pub shard_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    Cold,
    Starting,
    Hot,
    WarmIdle,
    Hibernated,
    Draining,
    Terminated,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimePolicy {
    pub vcpu_count: u16,
    pub memory_mib: u32,
    #[serde(default = "default_true")]
    pub snapshot_enabled: bool,
    #[serde(default = "default_warm_idle_ms")]
    pub warm_idle_ms: u64,
    #[serde(default = "default_hibernate_ms")]
    pub hibernate_after_ms: u64,
    #[serde(default = "default_destroy_ms")]
    pub destroy_after_ms: u64,
}

fn default_true() -> bool {
    true
}

fn default_warm_idle_ms() -> u64 {
    10_000
}

fn default_hibernate_ms() -> u64 {
    60_000
}

fn default_destroy_ms() -> u64 {
    15 * 60_000
}

fn select_backend(requested: &str, allow_mock: bool) -> BackendKind {
    match requested {
        "mock" if allow_mock => BackendKind::Mock,
        _ => BackendKind::Firecracker,
    }
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self {
            vcpu_count: 1,
            memory_mib: 128,
            snapshot_enabled: true,
            warm_idle_ms: default_warm_idle_ms(),
            hibernate_after_ms: default_hibernate_ms(),
            destroy_after_ms: default_destroy_ms(),
        }
    }
}

impl RuntimePolicy {
    pub fn validate(&self) -> Result<(), HostError> {
        if self.vcpu_count == 0 || self.vcpu_count > 32 {
            return Err(HostError::InvalidPolicy("vcpu_count must be 1..=32".into()));
        }
        if self.memory_mib < 64 {
            return Err(HostError::InvalidPolicy("memory_mib must be >= 64".into()));
        }
        if self.warm_idle_ms == 0
            || self.hibernate_after_ms <= self.warm_idle_ms
            || self.destroy_after_ms <= self.hibernate_after_ms
        {
            return Err(HostError::InvalidPolicy(
                "idle lifecycle thresholds must be strictly increasing".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnsureShardRequest {
    pub user_id: String,
    pub tenant_id: String,
    pub shard_id: String,
    pub execution_class: ExecutionClass,
    pub execution_backend: ExecutionBackend,
    pub tenant_isolation: String,
    pub runtime_epoch: u64,
    pub root_deployment_id: String,
    pub deployment_digest: String,
    #[serde(default)]
    pub policy: RuntimePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRequest {
    pub tenant_id: String,
    pub shard_id: String,
    pub execution_class: ExecutionClass,
    pub execution_backend: ExecutionBackend,
    pub runtime_epoch: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TouchRequest {
    pub tenant_id: String,
    pub shard_id: String,
    pub execution_class: ExecutionClass,
    pub execution_backend: ExecutionBackend,
    pub runtime_epoch: u64,
    #[serde(default)]
    pub active_delta: i32,
    #[serde(default)]
    pub ingress_bytes: u64,
    #[serde(default)]
    pub egress_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardStatus {
    pub tenant_id: String,
    pub shard_id: String,
    pub execution_class: ExecutionClass,
    pub execution_backend: ExecutionBackend,
    pub runtime_epoch: u64,
    pub deployment_digest: String,
    pub state: LifecycleState,
    pub backend: String,
    pub vcpu_count: u16,
    pub memory_mib: u32,
    pub active_invocations: u32,
    pub last_active_unix_ms: u64,
    pub process_pid: Option<u32>,
    pub api_socket: Option<String>,
    pub vsock_path: Option<String>,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeteringSample {
    pub tenant_id: String,
    pub shard_id: String,
    pub execution_class: ExecutionClass,
    pub execution_backend: ExecutionBackend,
    pub runtime_epoch: u64,
    pub request_count: u64,
    pub cpu_ns: u64,
    pub memory_current_bytes: u64,
    pub memory_byte_ms: u128,
    pub ingress_bytes: u64,
    pub egress_bytes: u64,
}

#[derive(Debug, Clone)]
struct ShardRecord {
    key: ShardKey,
    runtime_epoch: u64,
    deployment_digest: String,
    user_id: String,
    root_deployment_id: String,
    state: LifecycleState,
    policy: RuntimePolicy,
    active_invocations: u32,
    last_active_unix_ms: u64,
    process_pid: Option<u32>,
    api_socket: Option<PathBuf>,
    vsock_path: Option<PathBuf>,
    last_error: Option<String>,
    request_count: u64,
    ingress_bytes: u64,
    egress_bytes: u64,
    memory_byte_ms: u128,
    last_meter_unix_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    Firecracker,
    Mock,
}

impl BackendKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::Mock => "mock",
        }
    }
}

#[derive(Debug, Clone)]
pub struct HostConfig {
    pub backend: BackendKind,
    pub firecracker_bin: PathBuf,
    pub jailer_bin: PathBuf,
    pub jailer_chroot_base: PathBuf,
    pub jailer_uid: u32,
    pub jailer_gid: u32,
    pub ip_bin: PathBuf,
    pub netns_root: PathBuf,
    pub kernel_image: PathBuf,
    pub rootfs_image: PathBuf,
    pub runtime_dir: PathBuf,
    pub cgroup_root: PathBuf,
    pub identity_root: PathBuf,
    pub identity_writer_bin: PathBuf,
    pub vmm_overhead_mib: u32,
    pub boot_args: String,
    pub api_socket_timeout_ms: u64,
}

impl HostConfig {
    pub fn from_env() -> Self {
        let requested_backend =
            env::var("BMSCL_RUNTIME_BACKEND").unwrap_or_else(|_| "firecracker".into());
        let allow_mock = env::var("BMSCL_ALLOW_MOCK_BACKEND").as_deref() == Ok("1");
        let backend = select_backend(&requested_backend, allow_mock);
        Self {
            backend,
            firecracker_bin: env::var_os("BMSCL_FIRECRACKER_BIN")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/usr/local/bin/firecracker")),
            jailer_bin: env::var_os("BMSCL_JAILER_BIN")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/usr/local/bin/jailer")),
            jailer_chroot_base: env::var_os("BMSCL_JAILER_CHROOT_BASE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/srv/jailer")),
            jailer_uid: env::var("BMSCL_JAILER_UID")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(65534),
            jailer_gid: env::var("BMSCL_JAILER_GID")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(65534),
            ip_bin: env::var_os("BMSCL_IP_BIN")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/run/current-system/sw/bin/ip")),
            netns_root: env::var_os("BMSCL_NETNS_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/run/netns")),
            kernel_image: env::var_os("BMSCL_GUEST_KERNEL_IMAGE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/opt/beamscale/guest/vmlinux")),
            rootfs_image: env::var_os("BMSCL_GUEST_ROOTFS_IMAGE")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/opt/beamscale/guest/rootfs.ext4")),
            runtime_dir: env::var_os("BMSCL_RUNTIME_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/var/lib/beamscale/runtime")),
            cgroup_root: env::var_os("BMSCL_CGROUP_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/sys/fs/cgroup/beamscale")),
            identity_root: env::var_os("BMSCL_RUNTIME_IDENTITY_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/run/bmscl/runtime-identities")),
            identity_writer_bin: env::var_os("BMSCL_RUNTIME_IDENTITY_WRITER")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("/usr/local/bin/bmscl-runtime-identity-writer")),
            vmm_overhead_mib: env::var("BMSCL_VMM_OVERHEAD_MIB")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(96),
            boot_args: env::var("BMSCL_GUEST_BOOT_ARGS")
                .unwrap_or_else(|_| "console=ttyS0 reboot=k panic=1 pci=off".into()),
            api_socket_timeout_ms: env::var("BMSCL_FIRECRACKER_API_TIMEOUT_MS")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(5_000),
        }
    }
}

#[derive(Debug, Error)]
pub enum HostError {
    #[error("invalid runtime policy: {0}")]
    InvalidPolicy(String),
    #[error("unknown shard")]
    UnknownShard,
    #[error("stale runtime epoch: requested {requested}, current {current}")]
    StaleEpoch { requested: u64, current: u64 },
    #[error("runtime epoch replacement requires terminated state")]
    EpochReplacementConflict,
    #[error("invalid lifecycle transition from {0:?}")]
    InvalidState(LifecycleState),
    #[error("firecracker API error: {0}")]
    Firecracker(String),
    #[error("cgroup error: {0}")]
    Cgroup(String),
    #[error("invalid runtime identity: {0}")]
    InvalidIdentity(String),
    #[error("runtime identity conflict: {0}")]
    IdentityConflict(String),
    #[error("invalid execution target: {0}")]
    InvalidExecutionTarget(String),
    #[error("runtime identity error: {0}")]
    Identity(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Clone)]
pub struct RuntimeHost {
    config: HostConfig,
    shards: Arc<RwLock<HashMap<ShardKey, ShardRecord>>>,
}

impl RuntimeHost {
    pub fn new(config: HostConfig) -> Self {
        Self {
            config,
            shards: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn ensure(&self, req: EnsureShardRequest) -> Result<ShardStatus, HostError> {
        validate_execution_target(
            req.execution_class,
            req.execution_backend,
            &req.tenant_isolation,
        )?;
        req.policy.validate()?;
        validate_digest(&req.deployment_digest)?;
        validate_resource_id("tenant_id", &req.tenant_id)?;
        validate_resource_id("shard_id", &req.shard_id)?;
        validate_runtime_subject("user_id", &req.user_id)?;
        validate_runtime_subject("tenant_id", &req.tenant_id)?;
        validate_runtime_subject("shard_id", &req.shard_id)?;
        validate_runtime_subject("root_deployment_id", &req.root_deployment_id)?;
        let key = ShardKey {
            execution_class: req.execution_class,
            tenant_id: req.tenant_id,
            shard_id: req.shard_id,
        };
        let mut shards = self.shards.write().await;
        if let Some(existing) = shards.get_mut(&key) {
            if req.runtime_epoch < existing.runtime_epoch {
                return Err(HostError::StaleEpoch {
                    requested: req.runtime_epoch,
                    current: existing.runtime_epoch,
                });
            }
            if req.runtime_epoch > existing.runtime_epoch {
                if existing.state != LifecycleState::Terminated {
                    return Err(HostError::EpochReplacementConflict);
                }
                *existing = ShardRecord::new(
                    key,
                    req.runtime_epoch,
                    req.deployment_digest,
                    req.user_id,
                    req.root_deployment_id,
                    req.policy,
                );
            } else {
                if existing.user_id != req.user_id
                    || existing.root_deployment_id != req.root_deployment_id
                {
                    return Err(HostError::IdentityConflict(
                        "immutable runtime identity changed within the same epoch".into(),
                    ));
                }
                existing.deployment_digest = req.deployment_digest;
                existing.policy = req.policy;
                existing.last_active_unix_ms = now_ms();
            }
            return Ok(self.status_from(existing));
        }
        let record = ShardRecord::new(
            key.clone(),
            req.runtime_epoch,
            req.deployment_digest,
            req.user_id,
            req.root_deployment_id,
            req.policy,
        );
        let status = self.status_from(&record);
        shards.insert(key, record);
        Ok(status)
    }

    pub async fn start(&self, req: EpochRequest) -> Result<ShardStatus, HostError> {
        validate_execution_request(req.execution_class, req.execution_backend)?;
        let key = ShardKey {
            execution_class: req.execution_class,
            tenant_id: req.tenant_id,
            shard_id: req.shard_id,
        };
        let (snapshot, should_restore) = {
            let mut shards = self.shards.write().await;
            let record = shards.get_mut(&key).ok_or(HostError::UnknownShard)?;
            check_epoch(record, req.runtime_epoch)?;
            match record.state {
                LifecycleState::Hot | LifecycleState::Starting => {
                    return Ok(self.status_from(record));
                }
                LifecycleState::Cold | LifecycleState::Hibernated | LifecycleState::Terminated => {
                    let should_restore = record.state == LifecycleState::Hibernated;
                    record.state = LifecycleState::Starting;
                    record.last_error = None;
                    (record.clone(), should_restore)
                }
                state => return Err(HostError::InvalidState(state)),
            }
        };
        let restore = should_restore && snapshot_has_files(&self.config, &snapshot);
        let result = if restore {
            self.restore_vm(&snapshot).await
        } else {
            self.boot_vm(&snapshot).await
        };
        let mut shards = self.shards.write().await;
        let record = shards.get_mut(&key).ok_or(HostError::UnknownShard)?;
        match result {
            Ok(runtime) => {
                record.state = LifecycleState::Hot;
                record.process_pid = runtime.pid;
                record.api_socket = runtime.api_socket;
                record.vsock_path = runtime.vsock_path;
                record.last_active_unix_ms = now_ms();
                record.last_meter_unix_ms = record.last_active_unix_ms;
                Ok(self.status_from(record))
            }
            Err(err) => {
                record.state = LifecycleState::Cold;
                record.last_error = Some(err.to_string());
                Err(err)
            }
        }
    }

    pub async fn mark_warm_idle(&self, req: EpochRequest) -> Result<ShardStatus, HostError> {
        validate_execution_request(req.execution_class, req.execution_backend)?;
        let key = ShardKey {
            execution_class: req.execution_class,
            tenant_id: req.tenant_id,
            shard_id: req.shard_id,
        };
        let mut shards = self.shards.write().await;
        let record = shards.get_mut(&key).ok_or(HostError::UnknownShard)?;
        check_epoch(record, req.runtime_epoch)?;
        if record.active_invocations != 0 {
            return Err(HostError::InvalidState(record.state));
        }
        match record.state {
            LifecycleState::Hot | LifecycleState::WarmIdle => {
                record.state = LifecycleState::WarmIdle;
            }
            state => return Err(HostError::InvalidState(state)),
        }
        Ok(self.status_from(record))
    }

    pub async fn touch(&self, req: TouchRequest) -> Result<ShardStatus, HostError> {
        validate_execution_request(req.execution_class, req.execution_backend)?;
        let key = ShardKey {
            execution_class: req.execution_class,
            tenant_id: req.tenant_id,
            shard_id: req.shard_id,
        };
        let mut shards = self.shards.write().await;
        let record = shards.get_mut(&key).ok_or(HostError::UnknownShard)?;
        check_epoch(record, req.runtime_epoch)?;
        if req.active_delta >= 0 {
            let delta = req.active_delta as u32;
            record.active_invocations = record.active_invocations.saturating_add(delta);
            record.request_count = record.request_count.saturating_add(delta as u64);
        } else {
            record.active_invocations = record
                .active_invocations
                .saturating_sub(req.active_delta.unsigned_abs());
        }
        record.ingress_bytes = record.ingress_bytes.saturating_add(req.ingress_bytes);
        record.egress_bytes = record.egress_bytes.saturating_add(req.egress_bytes);
        record.last_active_unix_ms = now_ms();
        if record.active_invocations > 0 && record.state == LifecycleState::WarmIdle {
            record.state = LifecycleState::Hot;
        }
        Ok(self.status_from(record))
    }

    pub async fn hibernate(&self, req: EpochRequest) -> Result<ShardStatus, HostError> {
        validate_execution_request(req.execution_class, req.execution_backend)?;
        let key = ShardKey {
            execution_class: req.execution_class,
            tenant_id: req.tenant_id.clone(),
            shard_id: req.shard_id.clone(),
        };
        let snapshot_enabled = {
            let shards = self.shards.read().await;
            let record = shards.get(&key).ok_or(HostError::UnknownShard)?;
            check_epoch(record, req.runtime_epoch)?;
            record.policy.snapshot_enabled
        };
        if !snapshot_enabled {
            return self.terminate(req).await;
        }
        let snapshot = {
            let mut shards = self.shards.write().await;
            let record = shards.get_mut(&key).ok_or(HostError::UnknownShard)?;
            check_epoch(record, req.runtime_epoch)?;
            if record.active_invocations != 0 {
                return Err(HostError::InvalidState(record.state));
            }
            match record.state {
                LifecycleState::Hot | LifecycleState::WarmIdle => record.clone(),
                LifecycleState::Hibernated => return Ok(self.status_from(record)),
                state => return Err(HostError::InvalidState(state)),
            }
        };
        self.snapshot_and_stop(&snapshot).await?;
        let mut shards = self.shards.write().await;
        let record = shards.get_mut(&key).ok_or(HostError::UnknownShard)?;
        record.state = LifecycleState::Hibernated;
        record.process_pid = None;
        record.api_socket = None;
        record.vsock_path = None;
        Ok(self.status_from(record))
    }

    pub async fn terminate(&self, req: EpochRequest) -> Result<ShardStatus, HostError> {
        validate_execution_request(req.execution_class, req.execution_backend)?;
        let key = ShardKey {
            execution_class: req.execution_class,
            tenant_id: req.tenant_id,
            shard_id: req.shard_id,
        };
        let record_snapshot = {
            let mut shards = self.shards.write().await;
            let record = shards.get_mut(&key).ok_or(HostError::UnknownShard)?;
            check_epoch(record, req.runtime_epoch)?;
            if record.state == LifecycleState::Terminated {
                return Ok(self.status_from(record));
            }
            record.state = LifecycleState::Draining;
            record.clone()
        };
        self.stop_vm(&record_snapshot).await?;
        self.cleanup_terminated_jail(&record_snapshot).await?;
        let mut shards = self.shards.write().await;
        let record = shards.get_mut(&key).ok_or(HostError::UnknownShard)?;
        record.state = LifecycleState::Terminated;
        record.process_pid = None;
        record.api_socket = None;
        record.vsock_path = None;
        Ok(self.status_from(record))
    }

    pub async fn get(
        &self,
        execution_class: ExecutionClass,
        tenant_id: &str,
        shard_id: &str,
    ) -> Result<ShardStatus, HostError> {
        let shards = self.shards.read().await;
        let key = ShardKey {
            execution_class,
            tenant_id: tenant_id.to_owned(),
            shard_id: shard_id.to_owned(),
        };
        shards
            .get(&key)
            .map(|record| self.status_from(record))
            .ok_or(HostError::UnknownShard)
    }

    pub async fn metering(
        &self,
        execution_class: ExecutionClass,
        tenant_id: &str,
        shard_id: &str,
    ) -> Result<MeteringSample, HostError> {
        let key = ShardKey {
            execution_class,
            tenant_id: tenant_id.to_owned(),
            shard_id: shard_id.to_owned(),
        };
        let mut shards = self.shards.write().await;
        let record = shards.get_mut(&key).ok_or(HostError::UnknownShard)?;
        let (cpu_ns, memory_current_bytes) = match self.config.backend {
            BackendKind::Mock => (0, 0),
            BackendKind::Firecracker => read_cgroup_metering(&self.config, record).await?,
        };
        let now = now_ms();
        let delta_ms = now.saturating_sub(record.last_meter_unix_ms);
        record.memory_byte_ms = record
            .memory_byte_ms
            .saturating_add((memory_current_bytes as u128).saturating_mul(delta_ms as u128));
        record.last_meter_unix_ms = now;
        Ok(MeteringSample {
            tenant_id: record.key.tenant_id.clone(),
            shard_id: record.key.shard_id.clone(),
            execution_class: record.key.execution_class,
            execution_backend: ExecutionBackend::Firecracker,
            runtime_epoch: record.runtime_epoch,
            request_count: record.request_count,
            cpu_ns,
            memory_current_bytes,
            memory_byte_ms: record.memory_byte_ms,
            ingress_bytes: record.ingress_bytes,
            egress_bytes: record.egress_bytes,
        })
    }

    pub async fn sweep_once(&self) {
        let now = now_ms();
        let actions = {
            let shards = self.shards.read().await;
            shards
                .values()
                .filter_map(|record| {
                    if record.active_invocations != 0 {
                        return None;
                    }
                    let idle = now.saturating_sub(record.last_active_unix_ms);
                    let req = EpochRequest {
                        tenant_id: record.key.tenant_id.clone(),
                        shard_id: record.key.shard_id.clone(),
                        execution_class: record.key.execution_class,
                        execution_backend: ExecutionBackend::Firecracker,
                        runtime_epoch: record.runtime_epoch,
                    };
                    match record.state {
                        LifecycleState::Hot if idle >= record.policy.warm_idle_ms => {
                            Some((0u8, req))
                        }
                        LifecycleState::WarmIdle if idle >= record.policy.hibernate_after_ms => {
                            Some((1u8, req))
                        }
                        LifecycleState::Hibernated if idle >= record.policy.destroy_after_ms => {
                            Some((2u8, req))
                        }
                        _ => None,
                    }
                })
                .collect::<Vec<_>>()
        };
        for (kind, req) in actions {
            let result = match kind {
                0 => self.mark_warm_idle(req).await,
                1 => self.hibernate(req).await,
                _ => self.terminate(req).await,
            };
            if let Err(err) = result {
                tracing::warn!(error = %err, "tenant runtime lifecycle sweep action failed");
            }
        }
    }

    fn status_from(&self, record: &ShardRecord) -> ShardStatus {
        ShardStatus {
            tenant_id: record.key.tenant_id.clone(),
            shard_id: record.key.shard_id.clone(),
            execution_class: record.key.execution_class,
            execution_backend: ExecutionBackend::Firecracker,
            runtime_epoch: record.runtime_epoch,
            deployment_digest: record.deployment_digest.clone(),
            state: record.state,
            backend: self.config.backend.as_str().into(),
            vcpu_count: record.policy.vcpu_count,
            memory_mib: record.policy.memory_mib,
            active_invocations: record.active_invocations,
            last_active_unix_ms: record.last_active_unix_ms,
            process_pid: record.process_pid,
            api_socket: record
                .api_socket
                .as_ref()
                .map(|path| path.display().to_string()),
            vsock_path: record
                .vsock_path
                .as_ref()
                .map(|path| path.display().to_string()),
            last_error: record.last_error.clone(),
        }
    }

    async fn boot_vm(&self, record: &ShardRecord) -> Result<RuntimeHandles, HostError> {
        if self.config.backend == BackendKind::Mock {
            return Ok(RuntimeHandles::mock());
        }
        require_file(&self.config.kernel_image).await?;
        require_file(&self.config.rootfs_image).await?;
        let runtime_paths = RuntimePaths::new(&self.config.runtime_dir, record);
        fs::create_dir_all(&runtime_paths.dir).await?;
        let jailed = spawn_firecracker(&self.config, record).await?;
        if let Err(err) = prepare_cgroup(&self.config, record, jailed.pid).await {
            let _ = terminate_pid(jailed.pid).await;
            let _ = cleanup_jail(&self.config, &jailed).await;
            return Err(err);
        }
        if let Err(err) = publish_runtime_identity(&self.config, record).await {
            let _ = terminate_pid(jailed.pid).await;
            let _ = cleanup_jail(&self.config, &jailed).await;
            return Err(err);
        }
        if let Err(err) =
            wait_for_socket(&jailed.api_socket, self.config.api_socket_timeout_ms).await
        {
            let _ = terminate_pid(jailed.pid).await;
            let _ = cleanup_jail(&self.config, &jailed).await;
            return Err(err);
        }
        if let Err(err) = stage_guest_boot_files(&self.config, &jailed).await {
            let _ = terminate_pid(jailed.pid).await;
            let _ = cleanup_jail(&self.config, &jailed).await;
            return Err(err);
        }
        let client = FcClient::new(jailed.api_socket.clone());
        let configured = async {
            client
                .put(
                    "/machine-config",
                    json!({
                        "vcpu_count": record.policy.vcpu_count,
                        "mem_size_mib": record.policy.memory_mib,
                        "smt": false
                    }),
                )
                .await?;
            client
                .put(
                    "/boot-source",
                    json!({
                        "kernel_image_path": "/vmlinux",
                        "boot_args": guest_boot_args(&self.config, record)
                    }),
                )
                .await?;
            client
                .put(
                    "/drives/rootfs",
                    json!({
                        "drive_id": "rootfs",
                        "path_on_host": "/rootfs.ext4",
                        "is_root_device": true,
                        "is_read_only": true
                    }),
                )
                .await?;
            client
                .put(
                    "/vsock",
                    json!({
                        "vsock_id": "control",
                        "guest_cid": 3,
                        "uds_path": "/control.vsock"
                    }),
                )
                .await?;
            client
                .put("/actions", json!({"action_type": "InstanceStart"}))
                .await
        }
        .await;
        if let Err(err) = configured {
            let _ = terminate_pid(jailed.pid).await;
            let _ = cleanup_jail(&self.config, &jailed).await;
            return Err(err);
        }
        Ok(RuntimeHandles {
            pid: Some(jailed.pid),
            api_socket: Some(jailed.api_socket),
            vsock_path: Some(jailed.vsock_path),
        })
    }

    async fn restore_vm(&self, record: &ShardRecord) -> Result<RuntimeHandles, HostError> {
        if self.config.backend == BackendKind::Mock {
            return Ok(RuntimeHandles::mock());
        }
        let runtime_paths = RuntimePaths::new(&self.config.runtime_dir, record);
        if !runtime_paths.snapshot_state.exists() || !runtime_paths.snapshot_mem.exists() {
            return self.boot_vm(record).await;
        }
        require_file(&self.config.rootfs_image).await?;
        let jailed = spawn_firecracker(&self.config, record).await?;
        if let Err(err) = prepare_cgroup(&self.config, record, jailed.pid).await {
            let _ = terminate_pid(jailed.pid).await;
            let _ = cleanup_jail(&self.config, &jailed).await;
            return Err(err);
        }
        if let Err(err) = publish_runtime_identity(&self.config, record).await {
            let _ = terminate_pid(jailed.pid).await;
            let _ = cleanup_jail(&self.config, &jailed).await;
            return Err(err);
        }
        if let Err(err) =
            wait_for_socket(&jailed.api_socket, self.config.api_socket_timeout_ms).await
        {
            let _ = terminate_pid(jailed.pid).await;
            let _ = cleanup_jail(&self.config, &jailed).await;
            return Err(err);
        }
        if let Err(err) = stage_guest_restore_files(&self.config, &runtime_paths, &jailed).await {
            let _ = terminate_pid(jailed.pid).await;
            let _ = cleanup_jail(&self.config, &jailed).await;
            return Err(err);
        }
        let client = FcClient::new(jailed.api_socket.clone());
        if let Err(err) = client
            .put(
                "/snapshot/load",
                json!({
                    "snapshot_path": "/snapshot/vm.state",
                    "mem_backend": {
                        "backend_type": "File",
                        "backend_path": "/snapshot/vm.mem"
                    },
                    "track_dirty_pages": true,
                    "resume_vm": true,
                    "vsock_override": {
                        "uds_path": "/control.vsock"
                    }
                }),
            )
            .await
        {
            let _ = terminate_pid(jailed.pid).await;
            let _ = cleanup_jail(&self.config, &jailed).await;
            return Err(err);
        }
        Ok(RuntimeHandles {
            pid: Some(jailed.pid),
            api_socket: Some(jailed.api_socket),
            vsock_path: Some(jailed.vsock_path),
        })
    }

    async fn snapshot_and_stop(&self, record: &ShardRecord) -> Result<(), HostError> {
        if self.config.backend == BackendKind::Mock {
            return Ok(());
        }
        let runtime_paths = RuntimePaths::new(&self.config.runtime_dir, record);
        let jailed =
            JailedRuntime::for_record(&self.config, record, record.process_pid.unwrap_or(0))?;
        let api = record
            .api_socket
            .clone()
            .unwrap_or_else(|| jailed.api_socket.clone());
        prepare_jailer_writable_dir(
            &jailed.root.join("snapshot"),
            self.config.jailer_uid,
            self.config.jailer_gid,
        )
        .await?;
        let client = FcClient::new(api);
        client.patch("/vm", json!({"state": "Paused"})).await?;
        client
            .put(
                "/snapshot/create",
                json!({
                    "snapshot_type": "Full",
                    "snapshot_path": "/snapshot/vm.state",
                    "mem_file_path": "/snapshot/vm.mem"
                }),
            )
            .await?;
        self.stop_vm(record).await?;
        fs::create_dir_all(&runtime_paths.dir).await?;
        copy_file_readonly(&jailed.snapshot_state, &runtime_paths.snapshot_state).await?;
        copy_file_readonly(&jailed.snapshot_mem, &runtime_paths.snapshot_mem).await?;
        cleanup_jail(&self.config, &jailed).await?;
        Ok(())
    }

    async fn stop_vm(&self, record: &ShardRecord) -> Result<(), HostError> {
        if self.config.backend == BackendKind::Mock {
            return Ok(());
        }
        if let Some(pid) = record.process_pid {
            terminate_pid(pid).await?;
        }
        Ok(())
    }

    async fn cleanup_terminated_jail(&self, record: &ShardRecord) -> Result<(), HostError> {
        if self.config.backend == BackendKind::Mock {
            return Ok(());
        }
        let jailed = JailedRuntime::for_record(&self.config, record, 0)?;
        cleanup_jail(&self.config, &jailed).await
    }
}

impl ShardRecord {}

impl ShardRecord {
    fn new(
        key: ShardKey,
        runtime_epoch: u64,
        deployment_digest: String,
        user_id: String,
        root_deployment_id: String,
        policy: RuntimePolicy,
    ) -> Self {
        let now = now_ms();
        Self {
            key,
            runtime_epoch,
            deployment_digest,
            user_id,
            root_deployment_id,
            state: LifecycleState::Cold,
            policy,
            active_invocations: 0,
            last_active_unix_ms: now,
            process_pid: None,
            api_socket: None,
            vsock_path: None,
            last_error: None,
            request_count: 0,
            ingress_bytes: 0,
            egress_bytes: 0,
            memory_byte_ms: 0,
            last_meter_unix_ms: now,
        }
    }
}

fn validate_resource_id(name: &str, value: &str) -> Result<(), HostError> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(HostError::InvalidPolicy(format!(
            "{name} must contain 1..=128 ASCII alphanumeric, '-' or '_' characters"
        )));
    }
    Ok(())
}

fn validate_runtime_subject(name: &str, value: &str) -> Result<(), HostError> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(HostError::InvalidIdentity(format!(
            "{name} must be 1..=128 ASCII chars of [A-Za-z0-9._-]"
        )))
    }
}

fn check_epoch(record: &ShardRecord, requested: u64) -> Result<(), HostError> {
    if requested == record.runtime_epoch {
        Ok(())
    } else {
        Err(HostError::StaleEpoch {
            requested,
            current: record.runtime_epoch,
        })
    }
}

fn validate_execution_request(
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
) -> Result<(), HostError> {
    if execution_backend != ExecutionBackend::Firecracker {
        return Err(HostError::InvalidExecutionTarget(
            "this runtime-host accepts execution_backend=firecracker only".into(),
        ));
    }
    if !matches!(
        execution_class,
        ExecutionClass::Phoenix | ExecutionClass::DurableActor
    ) {
        return Err(HostError::InvalidExecutionTarget(
            "Firecracker runtime-host accepts only phoenix or durable_actor".into(),
        ));
    }
    Ok(())
}

fn validate_execution_target(
    execution_class: ExecutionClass,
    execution_backend: ExecutionBackend,
    tenant_isolation: &str,
) -> Result<(), HostError> {
    validate_execution_request(execution_class, execution_backend)?;
    if tenant_isolation != "single_tenant_microvm" {
        return Err(HostError::InvalidExecutionTarget(
            "Firecracker runtime-host requires single_tenant_microvm".into(),
        ));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), HostError> {
    let raw = value.strip_prefix("sha256:").unwrap_or(value);
    if raw.len() == 64
        && raw
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        Ok(())
    } else {
        Err(HostError::InvalidPolicy(
            "deployment_digest must be lowercase sha256".into(),
        ))
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

async fn require_file(path: &Path) -> Result<(), HostError> {
    let metadata = fs::symlink_metadata(path).await.map_err(|err| {
        HostError::Firecracker(format!("required file {}: {err}", path.display()))
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(HostError::Firecracker(format!(
            "{} must be a regular non-symlink file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(HostError::Firecracker(format!(
                "{} must not be group- or world-writable",
                path.display()
            )));
        }
    }
    Ok(())
}

#[derive(Debug)]
struct RuntimePaths {
    dir: PathBuf,
    snapshot_state: PathBuf,
    snapshot_mem: PathBuf,
}

impl RuntimePaths {
    fn new(root: &Path, record: &ShardRecord) -> Self {
        let safe_class = execution_class_name(record.key.execution_class);
        let safe_tenant = sanitize(&record.key.tenant_id);
        let safe_shard = sanitize(&record.key.shard_id);
        let dir = root
            .join(safe_class)
            .join(safe_tenant)
            .join(safe_shard)
            .join(record.runtime_epoch.to_string());
        Self {
            snapshot_state: dir.join("vm.state"),
            snapshot_mem: dir.join("vm.mem"),
            dir,
        }
    }
}

fn guest_boot_args(config: &HostConfig, record: &ShardRecord) -> String {
    format!(
        "{} bmscl.execution_class={} bmscl.execution_backend=firecracker bmscl.tenant_id={} bmscl.runtime_epoch={}",
        config.boot_args,
        execution_class_name(record.key.execution_class),
        record.key.tenant_id,
        record.runtime_epoch
    )
}

fn execution_class_name(execution_class: ExecutionClass) -> &'static str {
    match execution_class {
        ExecutionClass::Faas => "faas",
        ExecutionClass::Phoenix => "phoenix",
        ExecutionClass::DurableActor => "durable_actor",
    }
}

fn cgroup_path(config: &HostConfig, record: &ShardRecord) -> PathBuf {
    config
        .cgroup_root
        .join(execution_class_name(record.key.execution_class))
        .join(sanitize(&record.key.tenant_id))
        .join(sanitize(&record.key.shard_id))
        .join(record.runtime_epoch.to_string())
}

async fn prepare_cgroup(
    config: &HostConfig,
    record: &ShardRecord,
    pid: u32,
) -> Result<(), HostError> {
    let path = cgroup_path(config, record);
    fs::create_dir_all(&path)
        .await
        .map_err(|err| HostError::Cgroup(format!("create {}: {err}", path.display())))?;
    let memory_bytes = (record.policy.memory_mib as u64 + config.vmm_overhead_mib as u64)
        .saturating_mul(1024 * 1024);
    let cpu_quota = (record.policy.vcpu_count as u64).saturating_mul(100_000);
    write_cgroup(&path, "memory.max", &memory_bytes.to_string()).await?;
    write_cgroup(&path, "cpu.max", &format!("{cpu_quota} 100000")).await?;
    write_cgroup(&path, "pids.max", "256").await?;
    write_cgroup(&path, "cgroup.procs", &pid.to_string()).await?;
    Ok(())
}

async fn publish_runtime_identity(
    config: &HostConfig,
    record: &ShardRecord,
) -> Result<(), HostError> {
    let cgroup = cgroup_path(config, record);
    let output = Command::new(&config.identity_writer_bin)
        .arg("--cgroup-root")
        .arg(&config.cgroup_root)
        .arg("--cgroup-path")
        .arg(&cgroup)
        .arg("--identity-root")
        .arg(&config.identity_root)
        .arg("--user-id")
        .arg(&record.user_id)
        .arg("--tenant-id")
        .arg(&record.key.tenant_id)
        .arg("--deployment-id")
        .arg(&record.root_deployment_id)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .map_err(|error| {
            HostError::Identity(format!(
                "launch {}: {error}",
                config.identity_writer_bin.display()
            ))
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(HostError::Identity(format!(
            "identity writer failed with {}: {}",
            output.status,
            stderr.trim()
        )));
    }
    Ok(())
}

async fn write_cgroup(path: &Path, name: &str, value: &str) -> Result<(), HostError> {
    let file = path.join(name);
    fs::write(&file, value)
        .await
        .map_err(|err| HostError::Cgroup(format!("write {}: {err}", file.display())))
}

async fn read_cgroup_metering(
    config: &HostConfig,
    record: &ShardRecord,
) -> Result<(u64, u64), HostError> {
    let path = cgroup_path(config, record);
    let cpu_stat = fs::read_to_string(path.join("cpu.stat"))
        .await
        .map_err(|err| HostError::Cgroup(format!("read cpu.stat: {err}")))?;
    let usage_usec = cpu_stat
        .lines()
        .find_map(|line| {
            let mut parts = line.split_whitespace();
            match (parts.next(), parts.next()) {
                (Some("usage_usec"), Some(value)) => value.parse::<u64>().ok(),
                _ => None,
            }
        })
        .ok_or_else(|| HostError::Cgroup("cpu.stat missing usage_usec".into()))?;
    let memory_current = fs::read_to_string(path.join("memory.current"))
        .await
        .map_err(|err| HostError::Cgroup(format!("read memory.current: {err}")))?
        .trim()
        .parse::<u64>()
        .map_err(|err| HostError::Cgroup(format!("parse memory.current: {err}")))?;
    Ok((usage_usec.saturating_mul(1_000), memory_current))
}

fn sanitize(value: &str) -> String {
    value
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn snapshot_has_files(config: &HostConfig, record: &ShardRecord) -> bool {
    let paths = RuntimePaths::new(&config.runtime_dir, record);
    paths.snapshot_state.exists() && paths.snapshot_mem.exists()
}

#[derive(Debug)]
struct RuntimeHandles {
    pid: Option<u32>,
    api_socket: Option<PathBuf>,
    vsock_path: Option<PathBuf>,
}

impl RuntimeHandles {
    fn mock() -> Self {
        Self {
            pid: None,
            api_socket: None,
            vsock_path: None,
        }
    }
}

#[derive(Debug, Clone)]
struct JailedRuntime {
    pid: u32,
    id: String,
    instance_dir: PathBuf,
    root: PathBuf,
    api_socket: PathBuf,
    vsock_path: PathBuf,
    kernel: PathBuf,
    rootfs: PathBuf,
    snapshot_state: PathBuf,
    snapshot_mem: PathBuf,
    netns_name: String,
    netns_path: PathBuf,
}

impl JailedRuntime {
    fn for_record(config: &HostConfig, record: &ShardRecord, pid: u32) -> Result<Self, HostError> {
        let exec_name = config
            .firecracker_bin
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                HostError::Firecracker("firecracker executable must have a UTF-8 file name".into())
            })?;
        if !config.firecracker_bin.is_absolute() {
            return Err(HostError::Firecracker(
                "BMSCL_FIRECRACKER_BIN must be an absolute path when using the jailer".into(),
            ));
        }
        if !config.jailer_bin.is_absolute()
            || !config.jailer_chroot_base.is_absolute()
            || !config.ip_bin.is_absolute()
            || !config.netns_root.is_absolute()
        {
            return Err(HostError::Firecracker(
                "jailer, ip, chroot base, and netns root must use absolute paths".into(),
            ));
        }
        let id = jailer_id(record);
        let instance_dir = config.jailer_chroot_base.join(exec_name).join(&id);
        let root = instance_dir.join("root");
        let netns_name = id.clone();
        let netns_path = config.netns_root.join(&netns_name);
        Ok(Self {
            pid,
            id,
            api_socket: root.join("api.socket"),
            vsock_path: root.join("control.vsock"),
            kernel: root.join("vmlinux"),
            rootfs: root.join("rootfs.ext4"),
            snapshot_state: root.join("snapshot").join("vm.state"),
            snapshot_mem: root.join("snapshot").join("vm.mem"),
            netns_name,
            netns_path,
            instance_dir,
            root,
        })
    }
}

fn jailer_id(record: &ShardRecord) -> String {
    use sha2::{Digest, Sha256};
    let material = format!(
        "{}\0{}\0{}\0{}",
        execution_class_name(record.key.execution_class),
        record.key.tenant_id,
        record.key.shard_id,
        record.runtime_epoch
    );
    let digest = Sha256::digest(material.as_bytes());
    let short = digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("bmscl-{short}")
}

async fn spawn_firecracker(
    config: &HostConfig,
    record: &ShardRecord,
) -> Result<JailedRuntime, HostError> {
    require_file(&config.firecracker_bin).await?;
    require_file(&config.jailer_bin).await?;
    fs::create_dir_all(&config.jailer_chroot_base).await?;
    let mut jailed = JailedRuntime::for_record(config, record, 0)?;
    if jailed.instance_dir.exists() {
        fs::remove_dir_all(&jailed.instance_dir).await?;
    }
    prepare_network_namespace(config, &jailed).await?;
    let mut child = Command::new(&config.jailer_bin)
        .arg("--id")
        .arg(&jailed.id)
        .arg("--exec-file")
        .arg(&config.firecracker_bin)
        .arg("--uid")
        .arg(config.jailer_uid.to_string())
        .arg("--gid")
        .arg(config.jailer_gid.to_string())
        .arg("--chroot-base-dir")
        .arg(&config.jailer_chroot_base)
        .arg("--netns")
        .arg(&jailed.netns_path)
        .arg("--cgroup-version")
        .arg("2")
        .arg("--new-pid-ns")
        .arg("--")
        .arg("--api-sock")
        .arg("/api.socket")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|err| {
            let _ = std::process::Command::new(&config.ip_bin)
                .env("IP_NETNS_DIR", &config.netns_root)
                .args(["netns", "delete", &jailed.netns_name])
                .status();
            HostError::Firecracker(format!(
                "spawn jailer {}: {err}",
                config.jailer_bin.display()
            ))
        })?;
    let pid = child
        .id()
        .ok_or_else(|| HostError::Firecracker("jailer/firecracker process has no pid".into()))?;
    jailed.pid = pid;
    tokio::spawn(async move {
        let _ = child.wait().await;
    });
    Ok(jailed)
}

async fn stage_guest_boot_files(
    config: &HostConfig,
    jailed: &JailedRuntime,
) -> Result<(), HostError> {
    copy_file_readonly(&config.kernel_image, &jailed.kernel).await?;
    copy_file_readonly(&config.rootfs_image, &jailed.rootfs).await?;
    Ok(())
}

async fn stage_guest_restore_files(
    config: &HostConfig,
    runtime_paths: &RuntimePaths,
    jailed: &JailedRuntime,
) -> Result<(), HostError> {
    stage_guest_boot_files(config, jailed).await?;
    prepare_jailer_writable_dir(
        &jailed.root.join("snapshot"),
        config.jailer_uid,
        config.jailer_gid,
    )
    .await?;
    copy_file_readonly(&runtime_paths.snapshot_state, &jailed.snapshot_state).await?;
    copy_file_readonly(&runtime_paths.snapshot_mem, &jailed.snapshot_mem).await?;
    Ok(())
}

async fn prepare_jailer_writable_dir(path: &Path, uid: u32, gid: u32) -> Result<(), HostError> {
    use std::{
        ffi::CString,
        os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    };

    fs::create_dir_all(path).await?;
    fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    let raw = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        HostError::Firecracker(format!(
            "jailer writable path contains an interior NUL: {}",
            path.display()
        ))
    })?;
    let result = unsafe { libc::chown(raw.as_ptr(), uid, gid) };
    if result != 0 {
        return Err(HostError::Firecracker(format!(
            "chown {} to {uid}:{gid}: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

async fn copy_file_readonly(source: &Path, destination: &Path) -> Result<(), HostError> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).await?;
    }
    match fs::remove_file(destination).await {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    fs::copy(source, destination).await?;
    fs::set_permissions(destination, std::fs::Permissions::from_mode(0o444)).await?;
    Ok(())
}

async fn cleanup_jail(config: &HostConfig, jailed: &JailedRuntime) -> Result<(), HostError> {
    let jail_result = match fs::remove_dir_all(&jailed.instance_dir).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    };
    let netns_result = delete_network_namespace(config, jailed).await;
    jail_result.and(netns_result)
}

async fn prepare_network_namespace(
    config: &HostConfig,
    jailed: &JailedRuntime,
) -> Result<(), HostError> {
    let ip_bin = fs::canonicalize(&config.ip_bin).await.map_err(|err| {
        HostError::Firecracker(format!(
            "resolve ip binary {}: {err}",
            config.ip_bin.display()
        ))
    })?;
    require_file(&ip_bin).await?;
    fs::create_dir_all(&config.netns_root).await?;
    if jailed.netns_path.exists() {
        delete_network_namespace(config, jailed).await?;
    }
    let status = Command::new(&ip_bin)
        .env("IP_NETNS_DIR", &config.netns_root)
        .args(["netns", "add", &jailed.netns_name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .await
        .map_err(|err| {
            HostError::Firecracker(format!(
                "create network namespace {}: {err}",
                jailed.netns_name
            ))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(HostError::Firecracker(format!(
            "failed to create network namespace {}: {status}",
            jailed.netns_name
        )))
    }
}

async fn delete_network_namespace(
    config: &HostConfig,
    jailed: &JailedRuntime,
) -> Result<(), HostError> {
    if !jailed.netns_path.exists() {
        return Ok(());
    }
    let status = Command::new(&config.ip_bin)
        .env("IP_NETNS_DIR", &config.netns_root)
        .args(["netns", "delete", &jailed.netns_name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .status()
        .await
        .map_err(|err| {
            HostError::Firecracker(format!(
                "delete network namespace {}: {err}",
                jailed.netns_name
            ))
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(HostError::Firecracker(format!(
            "failed to delete network namespace {}: {status}",
            jailed.netns_name
        )))
    }
}

async fn terminate_pid(pid: u32) -> Result<(), HostError> {
    let status = Command::new("kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .await?;
    if status.success() {
        Ok(())
    } else {
        Err(HostError::Firecracker(format!(
            "failed to terminate firecracker pid {pid}: {status}"
        )))
    }
}

async fn wait_for_socket(path: &Path, timeout_ms: u64) -> Result<(), HostError> {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if path.exists() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HostError::Firecracker(format!(
                "timed out waiting for API socket {}",
                path.display()
            )));
        }
        sleep(Duration::from_millis(25)).await;
    }
}

#[derive(Debug, Clone)]
struct FcClient {
    socket: PathBuf,
}

impl FcClient {
    fn new(socket: PathBuf) -> Self {
        Self { socket }
    }

    async fn put(&self, path: &str, body: Value) -> Result<(), HostError> {
        self.request("PUT", path, body).await
    }

    async fn patch(&self, path: &str, body: Value) -> Result<(), HostError> {
        self.request("PATCH", path, body).await
    }

    async fn request(&self, method: &str, path: &str, body: Value) -> Result<(), HostError> {
        let body =
            serde_json::to_vec(&body).map_err(|err| HostError::Firecracker(err.to_string()))?;
        let mut stream = UnixStream::connect(&self.socket).await.map_err(|err| {
            HostError::Firecracker(format!("connect {}: {err}", self.socket.display()))
        })?;
        let head = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(head.as_bytes()).await?;
        stream.write_all(&body).await?;
        stream.shutdown().await?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await?;
        let text = String::from_utf8_lossy(&response);
        let status = text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| {
                HostError::Firecracker(format!("malformed Firecracker response: {text}"))
            })?;
        if (200..300).contains(&status) {
            Ok(())
        } else {
            Err(HostError::Firecracker(format!(
                "{method} {path} returned {status}: {text}"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> HostConfig {
        HostConfig {
            backend: BackendKind::Mock,
            firecracker_bin: "/usr/local/bin/firecracker".into(),
            jailer_bin: "/usr/local/bin/jailer".into(),
            jailer_chroot_base: "/tmp/bmscl-jailer-test".into(),
            jailer_uid: 65534,
            jailer_gid: 65534,
            ip_bin: "/run/current-system/sw/bin/ip".into(),
            netns_root: "/var/run/netns".into(),
            kernel_image: "kernel".into(),
            rootfs_image: "rootfs".into(),
            runtime_dir: "/tmp/bmscl-test".into(),
            cgroup_root: "/tmp/bmscl-cgroup-test".into(),
            identity_root: "/tmp/bmscl-identity-test".into(),
            identity_writer_bin: "/usr/local/bin/bmscl-runtime-identity-writer".into(),
            vmm_overhead_mib: 96,
            boot_args: "console=ttyS0".into(),
            api_socket_timeout_ms: 100,
        }
    }

    fn ensure(epoch: u64) -> EnsureShardRequest {
        EnsureShardRequest {
            user_id: "usr_test".into(),
            tenant_id: "t1".into(),
            shard_id: "0".into(),
            execution_class: ExecutionClass::Phoenix,
            execution_backend: ExecutionBackend::Firecracker,
            tenant_isolation: "single_tenant_microvm".into(),
            runtime_epoch: epoch,
            root_deployment_id: "dep_test".into(),
            deployment_digest: format!("sha256:{}", "a".repeat(64)),
            policy: RuntimePolicy::default(),
        }
    }

    fn epoch(epoch: u64) -> EpochRequest {
        EpochRequest {
            tenant_id: "t1".into(),
            shard_id: "0".into(),
            execution_class: ExecutionClass::Phoenix,
            execution_backend: ExecutionBackend::Firecracker,
            runtime_epoch: epoch,
        }
    }

    #[test]
    fn jailed_runtime_uses_dedicated_network_namespace() {
        let request = ensure(17);
        let record = ShardRecord::new(
            ShardKey {
                execution_class: request.execution_class,
                tenant_id: request.tenant_id,
                shard_id: request.shard_id,
            },
            request.runtime_epoch,
            request.deployment_digest,
            request.user_id,
            request.root_deployment_id,
            request.policy,
        );
        let jailed = JailedRuntime::for_record(&config(), &record, 0).unwrap();
        assert_eq!(jailed.netns_name, jailed.id);
        assert_eq!(
            jailed.netns_path,
            PathBuf::from("/var/run/netns").join(&jailed.id)
        );
    }

    #[test]
    fn mock_backend_requires_explicit_opt_in() {
        assert_eq!(select_backend("mock", false), BackendKind::Firecracker);
        assert_eq!(select_backend("mock", true), BackendKind::Mock);
        assert_eq!(select_backend("unexpected", true), BackendKind::Firecracker);
    }

    #[test]
    fn firecracker_host_rejects_standard_faas_and_bare_process_targets() {
        assert!(matches!(
            validate_execution_target(
                ExecutionClass::Faas,
                ExecutionBackend::Firecracker,
                "single_tenant_microvm"
            ),
            Err(HostError::InvalidExecutionTarget(_))
        ));
        assert!(matches!(
            validate_execution_target(
                ExecutionClass::Phoenix,
                ExecutionBackend::BareProcess,
                "single_tenant_microvm"
            ),
            Err(HostError::InvalidExecutionTarget(_))
        ));
    }

    #[test]
    fn firecracker_host_requires_single_tenant_microvm() {
        assert!(validate_execution_target(
            ExecutionClass::Phoenix,
            ExecutionBackend::Firecracker,
            "single_tenant_microvm"
        )
        .is_ok());
        assert!(validate_execution_target(
            ExecutionClass::DurableActor,
            ExecutionBackend::Firecracker,
            "single_tenant_microvm"
        )
        .is_ok());
        assert!(validate_execution_target(
            ExecutionClass::Phoenix,
            ExecutionBackend::Firecracker,
            "shared_host_restricted_process"
        )
        .is_err());
    }

    #[test]
    fn lifecycle_mutations_revalidate_backend() {
        assert!(
            validate_execution_request(ExecutionClass::Phoenix, ExecutionBackend::Firecracker)
                .is_ok()
        );
        assert!(validate_execution_request(
            ExecutionClass::DurableActor,
            ExecutionBackend::Firecracker
        )
        .is_ok());
        assert!(
            validate_execution_request(ExecutionClass::Phoenix, ExecutionBackend::BareProcess)
                .is_err()
        );
        assert!(
            validate_execution_request(ExecutionClass::Faas, ExecutionBackend::Firecracker)
                .is_err()
        );
    }

    #[test]
    fn guest_boot_args_bind_class_tenant_backend_and_epoch() {
        let request = ensure(9);
        let record = ShardRecord::new(
            ShardKey {
                execution_class: request.execution_class,
                tenant_id: request.tenant_id,
                shard_id: request.shard_id,
            },
            request.runtime_epoch,
            request.deployment_digest,
            request.user_id,
            request.root_deployment_id,
            request.policy,
        );
        let args = guest_boot_args(&config(), &record);
        assert!(args.contains("bmscl.execution_class=phoenix"));
        assert!(args.contains("bmscl.execution_backend=firecracker"));
        assert!(args.contains("bmscl.tenant_id=t1"));
        assert!(args.contains("bmscl.runtime_epoch=9"));
    }

    #[test]
    fn jailer_ids_are_tenant_epoch_scoped_and_path_safe() {
        let request = ensure(7);
        let record = ShardRecord::new(
            ShardKey {
                execution_class: request.execution_class,
                tenant_id: request.tenant_id,
                shard_id: request.shard_id,
            },
            request.runtime_epoch,
            request.deployment_digest,
            request.user_id,
            request.root_deployment_id,
            request.policy,
        );
        let id = jailer_id(&record);
        assert!(id.starts_with("bmscl-"));
        assert!(id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'));
        let jailed = JailedRuntime::for_record(&config(), &record, 123).unwrap();
        assert_eq!(jailed.api_socket, jailed.root.join("api.socket"));
        assert_eq!(jailed.vsock_path, jailed.root.join("control.vsock"));
        assert!(jailed.root.starts_with(&config().jailer_chroot_base));
    }

    #[test]
    fn runtime_resource_ids_are_path_safe_and_collision_free() {
        for value in ["tenant_1", "shard-01", "A9"] {
            assert!(validate_resource_id("id", value).is_ok());
        }
        for value in [
            "",
            "../tenant",
            "tenant/name",
            "tenant.name",
            &"a".repeat(129),
        ] {
            assert!(validate_resource_id("id", value).is_err());
        }
    }

    #[tokio::test]
    async fn ensure_and_start_are_idempotent() {
        let host = RuntimeHost::new(config());
        let status = host.ensure(ensure(1)).await.unwrap();
        assert_eq!(status.state, LifecycleState::Cold);
        assert_eq!(
            host.start(epoch(1)).await.unwrap().state,
            LifecycleState::Hot
        );
        assert_eq!(
            host.start(epoch(1)).await.unwrap().state,
            LifecycleState::Hot
        );
    }

    #[tokio::test]
    async fn stale_epoch_is_rejected() {
        let host = RuntimeHost::new(config());
        host.ensure(ensure(2)).await.unwrap();
        let err = host.start(epoch(1)).await.unwrap_err();
        assert!(matches!(err, HostError::StaleEpoch { .. }));
    }

    #[tokio::test]
    async fn hibernate_and_restore_preserve_epoch() {
        let host = RuntimeHost::new(config());
        host.ensure(ensure(3)).await.unwrap();
        host.start(epoch(3)).await.unwrap();
        host.mark_warm_idle(epoch(3)).await.unwrap();
        assert_eq!(
            host.hibernate(epoch(3)).await.unwrap().state,
            LifecycleState::Hibernated
        );
        let restored = host.start(epoch(3)).await.unwrap();
        assert_eq!(restored.runtime_epoch, 3);
        assert_eq!(restored.state, LifecycleState::Hot);
    }

    #[tokio::test]
    async fn cannot_replace_live_epoch() {
        let host = RuntimeHost::new(config());
        host.ensure(ensure(1)).await.unwrap();
        host.start(epoch(1)).await.unwrap();
        assert!(matches!(
            host.ensure(ensure(2)).await.unwrap_err(),
            HostError::EpochReplacementConflict
        ));
    }

    #[tokio::test]
    async fn touch_attributes_requests_and_network_bytes() {
        let host = RuntimeHost::new(config());
        host.ensure(ensure(1)).await.unwrap();
        host.start(epoch(1)).await.unwrap();
        host.touch(TouchRequest {
            tenant_id: "t1".into(),
            shard_id: "0".into(),
            execution_class: ExecutionClass::Phoenix,
            execution_backend: ExecutionBackend::Firecracker,
            runtime_epoch: 1,
            active_delta: 2,
            ingress_bytes: 100,
            egress_bytes: 250,
        })
        .await
        .unwrap();
        let sample = host
            .metering(ExecutionClass::Phoenix, "t1", "0")
            .await
            .unwrap();
        assert_eq!(sample.request_count, 2);
        assert_eq!(sample.ingress_bytes, 100);
        assert_eq!(sample.egress_bytes, 250);
    }
}
