use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

/// Versioned semantic contract used by the compiler/runtime when admitting
/// user-exported modules.
pub const MODULE_CONTRACT_V1: &str = "bmscl-module-contract-v1";
pub const MODULE_SEMANTICS_V2: &str = "bmscl.module-semantics/v2";
pub const CONTEXT_ABI_V1: &str = "bmscl.context/v1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind {
    Lambda,
    Http,
    Rpc,
    Actor,
    Worker,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum InvocationMode {
    RequestResponse,
    Mailbox,
    Event,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ConcurrencyModel {
    /// One short-lived BEAM process owns one admitted invocation.
    IsolatedInvocation,
    /// One actor processes messages serially through its mailbox.
    SerializedActor,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CancellationModel {
    Deadline,
    Cooperative,
}

/// Hosted BeamScale deliberately exposes a very small capability vocabulary.
/// The tokens themselves remain opaque in the public SDK.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum HostedCapability {
    ClusterCall,
    Http,
    Log,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleExecution {
    pub invocation: InvocationMode,
    pub concurrency: ConcurrencyModel,
    pub cancellation: CancellationModel,
}

impl Default for ModuleExecution {
    fn default() -> Self {
        Self {
            invocation: InvocationMode::RequestResponse,
            concurrency: ConcurrencyModel::IsolatedInvocation,
            cancellation: CancellationModel::Deadline,
        }
    }
}

/// Language-neutral description of one user-exported module.
///
/// The public SDKs provide language-native types that make the handler shape a
/// compile-time contract. This descriptor is the runtime/compiler projection
/// used for admission and artifact manifests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub contract_version: String,
    pub context_abi: String,
    #[serde(default)]
    pub semantics_version: Option<String>,
    pub kind: ModuleKind,
    pub name: String,
    /// Runtime-qualified entrypoint, for example `worker:handle/2`.
    pub entrypoint: String,
    pub execution: ModuleExecution,
    #[serde(default)]
    pub capabilities: Vec<HostedCapability>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModuleContractError {
    #[error("unsupported module contract version")]
    Version,
    #[error("unsupported context ABI")]
    ContextAbi,
    #[error("unsupported module semantics version")]
    SemanticsVersion,
    #[error("module name must be a non-empty portable identifier")]
    Name,
    #[error("entrypoint must use <module>:<function>/<arity>")]
    Entrypoint,
    #[error("typed BeamScale module entrypoints must have arity 2: (input, Context)")]
    EntrypointArity,
    #[error("module execution semantics do not match its kind")]
    Execution,
    #[error("module capability list contains duplicates")]
    DuplicateCapability,
}

impl ModuleDescriptor {
    pub fn validate(&self) -> Result<(), ModuleContractError> {
        if self.contract_version != MODULE_CONTRACT_V1 {
            return Err(ModuleContractError::Version);
        }
        if self.context_abi != CONTEXT_ABI_V1 {
            return Err(ModuleContractError::ContextAbi);
        }
        if self
            .semantics_version
            .as_deref()
            .is_some_and(|version| version != MODULE_SEMANTICS_V2)
        {
            return Err(ModuleContractError::SemanticsVersion);
        }
        if !is_portable_ident(&self.name) {
            return Err(ModuleContractError::Name);
        }
        let (_, _, arity) =
            parse_entrypoint(&self.entrypoint).ok_or(ModuleContractError::Entrypoint)?;
        if arity != 2 {
            return Err(ModuleContractError::EntrypointArity);
        }

        if !execution_matches_kind(self.kind, self.execution) {
            return Err(ModuleContractError::Execution);
        }

        let mut unique = HashSet::with_capacity(self.capabilities.len());
        if self
            .capabilities
            .iter()
            .any(|capability| !unique.insert(*capability))
        {
            return Err(ModuleContractError::DuplicateCapability);
        }
        Ok(())
    }
}

fn execution_matches_kind(kind: ModuleKind, execution: ModuleExecution) -> bool {
    match kind {
        ModuleKind::Actor => {
            execution.invocation == InvocationMode::Mailbox
                && execution.concurrency == ConcurrencyModel::SerializedActor
                && execution.cancellation == CancellationModel::Cooperative
        }
        ModuleKind::Lambda | ModuleKind::Http | ModuleKind::Rpc => {
            execution.invocation == InvocationMode::RequestResponse
                && execution.concurrency == ConcurrencyModel::IsolatedInvocation
                && execution.cancellation == CancellationModel::Deadline
        }
        ModuleKind::Worker => {
            matches!(
                execution.invocation,
                InvocationMode::Mailbox | InvocationMode::Event
            )
        }
    }
}

/// Parse a Beam-style module/function/arity entrypoint without imposing
/// transport semantics. Signature/type conformance is enforced by the public
/// SDK at compile time.
pub fn parse_entrypoint(value: &str) -> Option<(&str, &str, u16)> {
    let (module, rest) = value.split_once(':')?;
    let (function, arity) = rest.rsplit_once('/')?;
    if !is_portable_path(module) || !is_portable_ident(function) {
        return None;
    }
    let arity = arity.parse::<u16>().ok()?;
    if arity == 0 {
        return None;
    }
    Some((module, function, arity))
}

fn is_portable_ident(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn is_portable_path(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b'/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_request_response_module_v2() {
        let descriptor = ModuleDescriptor {
            contract_version: MODULE_CONTRACT_V1.into(),
            context_abi: CONTEXT_ABI_V1.into(),
            semantics_version: Some(MODULE_SEMANTICS_V2.into()),
            kind: ModuleKind::Lambda,
            name: "hello_world".into(),
            entrypoint: "worker:handle/2".into(),
            execution: ModuleExecution::default(),
            capabilities: vec![HostedCapability::Log],
        };

        assert_eq!(descriptor.validate(), Ok(()));
        assert_eq!(
            parse_entrypoint(&descriptor.entrypoint),
            Some(("worker", "handle", 2))
        );
    }

    #[test]
    fn rejects_entrypoint_arity_that_cannot_match_public_context_abi() {
        let descriptor = ModuleDescriptor {
            contract_version: MODULE_CONTRACT_V1.into(),
            context_abi: CONTEXT_ABI_V1.into(),
            semantics_version: Some(MODULE_SEMANTICS_V2.into()),
            kind: ModuleKind::Lambda,
            name: "bad_arity".into(),
            entrypoint: "worker:handle/1".into(),
            execution: ModuleExecution::default(),
            capabilities: Vec::new(),
        };
        assert_eq!(
            descriptor.validate(),
            Err(ModuleContractError::EntrypointArity)
        );
    }

    #[test]
    fn actor_requires_mailbox_serialization() {
        let mut descriptor = ModuleDescriptor {
            contract_version: MODULE_CONTRACT_V1.into(),
            context_abi: CONTEXT_ABI_V1.into(),
            semantics_version: Some(MODULE_SEMANTICS_V2.into()),
            kind: ModuleKind::Actor,
            name: "counter".into(),
            entrypoint: "counter:handle/2".into(),
            execution: ModuleExecution::default(),
            capabilities: vec![HostedCapability::ClusterCall, HostedCapability::Log],
        };
        assert_eq!(descriptor.validate(), Err(ModuleContractError::Execution));

        descriptor.execution = ModuleExecution {
            invocation: InvocationMode::Mailbox,
            concurrency: ConcurrencyModel::SerializedActor,
            cancellation: CancellationModel::Cooperative,
        };
        assert_eq!(descriptor.validate(), Ok(()));
    }

    #[test]
    fn request_response_modules_require_deadline_cancellation() {
        let descriptor = ModuleDescriptor {
            contract_version: MODULE_CONTRACT_V1.into(),
            context_abi: CONTEXT_ABI_V1.into(),
            semantics_version: Some(MODULE_SEMANTICS_V2.into()),
            kind: ModuleKind::Http,
            name: "http_worker".into(),
            entrypoint: "worker:handle/2".into(),
            execution: ModuleExecution {
                invocation: InvocationMode::RequestResponse,
                concurrency: ConcurrencyModel::IsolatedInvocation,
                cancellation: CancellationModel::Cooperative,
            },
            capabilities: vec![HostedCapability::Http, HostedCapability::Log],
        };
        assert_eq!(descriptor.validate(), Err(ModuleContractError::Execution));
    }

    #[test]
    fn rejects_duplicate_capability_requests() {
        let descriptor = ModuleDescriptor {
            contract_version: MODULE_CONTRACT_V1.into(),
            context_abi: CONTEXT_ABI_V1.into(),
            semantics_version: Some(MODULE_SEMANTICS_V2.into()),
            kind: ModuleKind::Rpc,
            name: "lookup".into(),
            entrypoint: "rpc:lookup/2".into(),
            execution: ModuleExecution::default(),
            capabilities: vec![HostedCapability::Log, HostedCapability::Log],
        };
        assert_eq!(
            descriptor.validate(),
            Err(ModuleContractError::DuplicateCapability)
        );
    }

    #[test]
    fn omitted_semantics_version_does_not_bypass_kind_execution_rules() {
        let descriptor = ModuleDescriptor {
            contract_version: MODULE_CONTRACT_V1.into(),
            context_abi: CONTEXT_ABI_V1.into(),
            semantics_version: None,
            kind: ModuleKind::Actor,
            name: "actor_without_semantics_tag".into(),
            entrypoint: "actor:handle/2".into(),
            execution: ModuleExecution::default(),
            capabilities: Vec::new(),
        };
        assert_eq!(descriptor.validate(), Err(ModuleContractError::Execution));
    }

    #[test]
    fn descriptor_deserialization_requires_explicit_execution() {
        let json = r#"{
            "contract_version":"bmscl-module-contract-v1",
            "context_abi":"bmscl.context/v1",
            "kind":"lambda",
            "name":"hello",
            "entrypoint":"worker:handle/2",
            "capabilities":[]
        }"#;
        assert!(serde_json::from_str::<ModuleDescriptor>(json).is_err());
    }
}
