pub mod module_contract;

pub use module_contract::{
    parse_entrypoint, CancellationModel, ConcurrencyModel, HostedCapability, InvocationMode,
    ModuleContractError, ModuleDescriptor, ModuleExecution, ModuleKind, CONTEXT_ABI_V1,
    MODULE_CONTRACT_V1, MODULE_SEMANTICS_V2,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use thiserror::Error;

pub const HOSTED_PROFILE_V1: &str = "bmscl-hosted-gleam-v1";
pub const HOSTED_PROFILE_V2: &str = "bmscl-hosted-gleam-v2-read-only";
pub const HOSTED_PROFILE_V3_HTTP: &str = "bmscl-hosted-gleam-v3-http-capability";
pub const DURABLE_ACTOR_PROFILE_V1: &str = "bmscl-hosted-gleam-durable-actor-v1";
pub const ERLANG_CRITICAL_SECTION_PROFILE_V1: &str = "bmscl-critical-section-erlang-v1";
pub const TENANT_RUNTIME_POLICY_V1: &str = "bmscl-tenant-runtime-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeBudget {
    pub max_wall_ms: u64,
    pub max_reductions: u64,
    pub max_heap_bytes: u64,
    pub max_processes: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityGrant {
    pub name: String,
    #[serde(default)]
    pub scope: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ArtifactManifest {
    pub format_version: u32,
    pub runtime: String,
    pub language: String,
    pub profile: String,
    pub source_sha256: String,
    pub build_sha256: String,
    pub entrypoint: String,
    pub capabilities: Vec<CapabilityGrant>,
    pub runtime_limits: RuntimeBudget,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ManifestError {
    #[error("unsupported manifest version")]
    Version,
    #[error("artifact language/runtime does not match the hosted profile")]
    Runtime,
    #[error("compiler profile is not admitted")]
    Profile,
    #[error("invalid sha256 digest")]
    Digest,
    #[error("invalid or duplicate capability grant")]
    Capability,
    #[error("artifact capability grants differ from module capability requests")]
    CapabilityParity,
    #[error("artifact entrypoint differs from admitted module entrypoint")]
    EntrypointParity,
    #[error("invalid runtime budget")]
    Budget,
    #[error(transparent)]
    ModuleContract(#[from] ModuleContractError),
}

impl ArtifactManifest {
    pub fn validate_shared_tier(&self) -> Result<(), ManifestError> {
        if self.format_version != 1 {
            return Err(ManifestError::Version);
        }
        if self.runtime != "beam" {
            return Err(ManifestError::Runtime);
        }
        match self.profile.as_str() {
            HOSTED_PROFILE_V1
            | HOSTED_PROFILE_V2
            | HOSTED_PROFILE_V3_HTTP
            | DURABLE_ACTOR_PROFILE_V1
                if self.language == "gleam" => {}
            ERLANG_CRITICAL_SECTION_PROFILE_V1 if self.language == "erlang" => {}
            HOSTED_PROFILE_V1
            | HOSTED_PROFILE_V2
            | HOSTED_PROFILE_V3_HTTP
            | DURABLE_ACTOR_PROFILE_V1
            | ERLANG_CRITICAL_SECTION_PROFILE_V1 => return Err(ManifestError::Runtime),
            _ => return Err(ManifestError::Profile),
        }
        if !is_sha256(&self.source_sha256) || !is_sha256(&self.build_sha256) {
            return Err(ManifestError::Digest);
        }

        let mut names = HashSet::new();
        if self.capabilities.iter().any(|grant| {
            hosted_capability_from_grant_name(&grant.name).is_none()
                || !names.insert(grant.name.as_str())
        }) {
            return Err(ManifestError::Capability);
        }

        let actual = self
            .capabilities
            .iter()
            .filter_map(|grant| hosted_capability_from_grant_name(&grant.name))
            .collect::<HashSet<_>>();
        let required = match self.profile.as_str() {
            HOSTED_PROFILE_V2 | DURABLE_ACTOR_PROFILE_V1 | ERLANG_CRITICAL_SECTION_PROFILE_V1 => {
                HashSet::from([HostedCapability::ClusterCall, HostedCapability::Log])
            }
            HOSTED_PROFILE_V3_HTTP => HashSet::from([
                HostedCapability::ClusterCall,
                HostedCapability::Http,
                HostedCapability::Log,
            ]),
            // Legacy v1 is dev-only compatibility. Keep its old capability
            // shape readable without widening any current production profile.
            HOSTED_PROFILE_V1 => actual.clone(),
            _ => unreachable!("profile was validated above"),
        };
        if actual != required {
            return Err(ManifestError::Capability);
        }

        // Hosted Gleam owns exactly one BEAM process per admitted invocation.
        // Trusted runtime processes (supervisors, pools, telemetry, routing) are
        // platform-owned and are not counted in this tenant limit.
        if self.runtime_limits.max_wall_ms == 0
            || self.runtime_limits.max_reductions == 0
            || self.runtime_limits.max_heap_bytes < 1024 * 1024
            || self.runtime_limits.max_processes != 1
        {
            return Err(ManifestError::Budget);
        }
        Ok(())
    }

    /// Validate both sides of the hosted capability boundary: the public module
    /// declares what it needs, and the build artifact records exactly what the
    /// runtime will grant. Neither side may silently widen the other.
    pub fn validate_shared_tier_for_module(
        &self,
        descriptor: &ModuleDescriptor,
    ) -> Result<(), ManifestError> {
        self.validate_shared_tier()?;
        descriptor.validate()?;
        if self.entrypoint != descriptor.entrypoint {
            return Err(ManifestError::EntrypointParity);
        }

        let requested = descriptor
            .capabilities
            .iter()
            .copied()
            .collect::<HashSet<_>>();
        let granted = self
            .capabilities
            .iter()
            .filter_map(|grant| hosted_capability_from_grant_name(&grant.name))
            .collect::<HashSet<_>>();
        if requested != granted {
            return Err(ManifestError::CapabilityParity);
        }
        Ok(())
    }
}

pub const fn hosted_capability_grant_name(capability: HostedCapability) -> &'static str {
    match capability {
        HostedCapability::ClusterCall => "ctx.cluster",
        HostedCapability::Http => "ctx.http",
        HostedCapability::Log => "ctx.log",
    }
}

pub fn hosted_capability_from_grant_name(value: &str) -> Option<HostedCapability> {
    match value {
        "ctx.cluster" => Some(HostedCapability::ClusterCall),
        "ctx.http" => Some(HostedCapability::Http),
        "ctx.log" => Some(HostedCapability::Log),
        _ => None,
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenantIsolation {
    /// Production default: one hardware-virtualized microVM per tenant shard.
    MicroVm,
    /// Development/testing only unless an explicit stronger policy allows it.
    LinuxContainer,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MicroVmBackend {
    Firecracker,
    CloudHypervisor,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TenantRuntimeState {
    Cold,
    Starting,
    Hot,
    WarmIdle,
    Hibernated,
    Draining,
    Terminated,
}

impl TenantRuntimeState {
    pub fn can_transition_to(self, next: Self) -> bool {
        use TenantRuntimeState::*;
        matches!(
            (self, next),
            (Cold, Starting)
                | (Starting, Hot)
                | (Starting, Terminated)
                | (Hot, WarmIdle)
                | (Hot, Draining)
                | (WarmIdle, Hot)
                | (WarmIdle, Hibernated)
                | (WarmIdle, Draining)
                | (Hibernated, Starting)
                | (Hibernated, Terminated)
                | (Draining, Terminated)
                | (Terminated, Cold)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenantRuntimePolicy {
    pub policy_version: String,
    pub isolation: TenantIsolation,
    #[serde(default = "default_microvm_backend")]
    pub microvm_backend: MicroVmBackend,
    pub vcpu_count: u16,
    pub min_memory_bytes: u64,
    pub max_memory_bytes: u64,
    pub warm_idle_ms: u64,
    pub hibernate_after_ms: u64,
    pub destroy_after_ms: u64,
    pub allow_snapshot_restore: bool,
}

fn default_microvm_backend() -> MicroVmBackend {
    MicroVmBackend::Firecracker
}

impl Default for TenantRuntimePolicy {
    fn default() -> Self {
        Self {
            policy_version: TENANT_RUNTIME_POLICY_V1.into(),
            isolation: TenantIsolation::MicroVm,
            microvm_backend: MicroVmBackend::Firecracker,
            vcpu_count: 1,
            min_memory_bytes: 128 * 1024 * 1024,
            max_memory_bytes: 1024 * 1024 * 1024,
            warm_idle_ms: 10_000,
            hibernate_after_ms: 60_000,
            destroy_after_ms: 15 * 60_000,
            allow_snapshot_restore: true,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TenantRuntimePolicyError {
    #[error("unsupported tenant runtime policy version")]
    Version,
    #[error("production tenant runtime must use a microVM")]
    Isolation,
    #[error("invalid vCPU allocation")]
    Cpu,
    #[error("invalid memory allocation")]
    Memory,
    #[error("invalid idle/hibernation/destruction lifecycle ordering")]
    Lifecycle,
}

impl TenantRuntimePolicy {
    pub fn validate_production(&self) -> Result<(), TenantRuntimePolicyError> {
        if self.policy_version != TENANT_RUNTIME_POLICY_V1 {
            return Err(TenantRuntimePolicyError::Version);
        }
        if self.isolation != TenantIsolation::MicroVm {
            return Err(TenantRuntimePolicyError::Isolation);
        }
        if self.vcpu_count == 0 {
            return Err(TenantRuntimePolicyError::Cpu);
        }
        if self.min_memory_bytes < 64 * 1024 * 1024 || self.max_memory_bytes < self.min_memory_bytes
        {
            return Err(TenantRuntimePolicyError::Memory);
        }
        if self.warm_idle_ms == 0
            || self.hibernate_after_ms <= self.warm_idle_ms
            || self.destroy_after_ms <= self.hibernate_after_ms
        {
            return Err(TenantRuntimePolicyError::Lifecycle);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct MeteringSample {
    /// Number of admitted root/child invocations completed in the sample.
    pub request_count: u64,
    /// CPU consumed by the tenant microVM during the sample.
    pub cpu_ns: u64,
    /// Integral of resident/charged memory over time, in byte-milliseconds.
    pub memory_byte_ms: u128,
    pub ingress_bytes: u64,
    pub egress_bytes: u64,
    pub durable_storage_byte_ms: u128,
}

impl MeteringSample {
    pub fn merge(&mut self, other: &Self) {
        self.request_count = self.request_count.saturating_add(other.request_count);
        self.cpu_ns = self.cpu_ns.saturating_add(other.cpu_ns);
        self.memory_byte_ms = self.memory_byte_ms.saturating_add(other.memory_byte_ms);
        self.ingress_bytes = self.ingress_bytes.saturating_add(other.ingress_bytes);
        self.egress_bytes = self.egress_bytes.saturating_add(other.egress_bytes);
        self.durable_storage_byte_ms = self
            .durable_storage_byte_ms
            .saturating_add(other.durable_storage_byte_ms);
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn valid_manifest() -> ArtifactManifest {
        ArtifactManifest {
            format_version: 1,
            runtime: "beam".into(),
            language: "gleam".into(),
            profile: HOSTED_PROFILE_V2.into(),
            source_sha256: "a".repeat(64),
            build_sha256: "b".repeat(64),
            entrypoint: "worker:handle/2".into(),
            capabilities: vec![
                CapabilityGrant {
                    name: "ctx.log".into(),
                    scope: None,
                },
                CapabilityGrant {
                    name: "ctx.cluster".into(),
                    scope: Some(json!({"actors":["catalog"]})),
                },
            ],
            runtime_limits: RuntimeBudget {
                max_wall_ms: 30_000,
                max_reductions: 50_000_000,
                max_heap_bytes: 64 * 1024 * 1024,
                max_processes: 1,
            },
        }
    }

    fn valid_descriptor() -> ModuleDescriptor {
        ModuleDescriptor {
            contract_version: MODULE_CONTRACT_V1.into(),
            context_abi: CONTEXT_ABI_V1.into(),
            semantics_version: Some(MODULE_SEMANTICS_V2.into()),
            kind: ModuleKind::Worker,
            name: "catalog_worker".into(),
            entrypoint: "worker:handle/2".into(),
            execution: ModuleExecution {
                invocation: InvocationMode::Event,
                concurrency: ConcurrencyModel::IsolatedInvocation,
                cancellation: CancellationModel::Cooperative,
            },
            capabilities: vec![HostedCapability::Log, HostedCapability::ClusterCall],
        }
    }

    #[test]
    fn validates_hosted_manifest_and_module_capability_parity() {
        assert_eq!(
            valid_manifest().validate_shared_tier_for_module(&valid_descriptor()),
            Ok(())
        );
    }

    #[test]
    fn rejects_artifact_entrypoint_that_differs_from_typed_module() {
        let mut manifest = valid_manifest();
        manifest.entrypoint = "other:handle/2".into();
        assert_eq!(
            manifest.validate_shared_tier_for_module(&valid_descriptor()),
            Err(ManifestError::EntrypointParity)
        );
    }

    #[test]
    fn admits_current_v3_http_profile_and_capability_name() {
        let mut manifest = valid_manifest();
        manifest.profile = HOSTED_PROFILE_V3_HTTP.into();
        manifest.capabilities.push(CapabilityGrant {
            name: "ctx.http".into(),
            scope: Some(json!({"origins":["https://api.example.com"]})),
        });
        let mut descriptor = valid_descriptor();
        descriptor.kind = ModuleKind::Http;
        descriptor.execution = ModuleExecution::default();
        descriptor.capabilities.push(HostedCapability::Http);
        assert_eq!(
            manifest.validate_shared_tier_for_module(&descriptor),
            Ok(())
        );
    }

    #[test]
    fn rejects_legacy_cluster_call_capability_alias() {
        let mut manifest = valid_manifest();
        manifest.capabilities[1].name = "ctx.cluster_call".into();
        assert_eq!(
            manifest.validate_shared_tier(),
            Err(ManifestError::Capability)
        );
    }

    #[test]
    fn v2_rejects_http_capability_widening() {
        let mut manifest = valid_manifest();
        manifest.capabilities.push(CapabilityGrant {
            name: "ctx.http".into(),
            scope: None,
        });
        assert_eq!(
            manifest.validate_shared_tier(),
            Err(ManifestError::Capability)
        );
    }

    #[test]
    fn rejects_unknown_hosted_capability_names() {
        let mut manifest = valid_manifest();
        manifest.capabilities.push(CapabilityGrant {
            name: "ctx.secrets".into(),
            scope: None,
        });
        assert_eq!(
            manifest.validate_shared_tier(),
            Err(ManifestError::Capability)
        );
    }

    #[test]
    fn rejects_capability_widening_or_omission() {
        let mut descriptor = valid_descriptor();
        descriptor.capabilities.pop();
        assert_eq!(
            valid_manifest().validate_shared_tier_for_module(&descriptor),
            Err(ManifestError::CapabilityParity)
        );
    }

    #[test]
    fn shared_tier_rejects_more_than_one_tenant_process() {
        let mut manifest = valid_manifest();
        manifest.runtime_limits.max_processes = 2;
        assert_eq!(manifest.validate_shared_tier(), Err(ManifestError::Budget));
    }

    #[test]
    fn production_runtime_defaults_to_microvm() {
        let policy = TenantRuntimePolicy::default();
        assert_eq!(policy.validate_production(), Ok(()));
        assert_eq!(policy.isolation, TenantIsolation::MicroVm);
        assert_eq!(policy.microvm_backend, MicroVmBackend::Firecracker);
    }

    #[test]
    fn lifecycle_is_explicit() {
        assert!(TenantRuntimeState::Cold.can_transition_to(TenantRuntimeState::Starting));
        assert!(TenantRuntimeState::Hot.can_transition_to(TenantRuntimeState::WarmIdle));
        assert!(TenantRuntimeState::WarmIdle.can_transition_to(TenantRuntimeState::Hibernated));
        assert!(!TenantRuntimeState::Hot.can_transition_to(TenantRuntimeState::Cold));
    }
}
