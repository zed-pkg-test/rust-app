use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

pub const MODULE_CONTRACT_V1: &str = "scintilla-module-contract-v1";
pub const MODULE_SEMANTICS_V2: &str = "scintilla.module-semantics/v2";
pub const CONTEXT_ABI_V1: &str = "scintilla.context/v1";

/// Small platform-owned invocation metadata shared by every user context.
///
/// Runtimes may construct a richer user context through middleware/DI, but
/// exported modules must always be able to recover this stable Scintilla base.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationContext {
    pub request_id: String,
    pub deadline_unix_ms: Option<u64>,
    pub attempt: u32,
}

pub trait ModuleContext: Send + Sync {
    fn invocation(&self) -> &InvocationContext;
}

impl ModuleContext for InvocationContext {
    fn invocation(&self) -> &InvocationContext {
        self
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ModuleKind {
    Lambda,
    Http,
    Rpc,
    Worker,
    Actor,
    Container,
}

impl ModuleKind {
    pub const fn interface(self) -> &'static str {
        match self {
            Self::Lambda => "scintilla.lambda.v1",
            Self::Http => "scintilla.http.v1",
            Self::Rpc => "scintilla.rpc.v1",
            Self::Worker => "scintilla.worker.v1",
            Self::Actor => "scintilla.actor.v1",
            Self::Container => "scintilla.container.v1",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum InvocationMode {
    RequestResponse,
    Stream,
    Event,
    LongLived,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ConcurrencyModel {
    Concurrent,
    Serial,
    KeyedSerial,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum CancellationModel {
    Deadline,
    Cooperative,
    ProcessTermination,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum IsolationRequirement {
    RuntimeDefault,
    Process,
    Container,
    MicroVm,
}

/// Provider-neutral authority requested by an exported module. Deployment
/// profiles decide whether and how each capability is granted on Scintilla,
/// AWS, GCP, or another compatible target.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Clock,
    Random,
    NetworkOutbound,
    NetworkListen,
    FilesystemRead,
    FilesystemWrite,
    ProcessSpawn,
    EnvRead,
    SecretsRead,
    DatabaseRead,
    DatabaseWrite,
    KeyValueRead,
    KeyValueWrite,
    QueuePublish,
    QueueConsume,
    ObjectStorageRead,
    ObjectStorageWrite,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionProfile {
    pub invocation: InvocationMode,
    pub concurrency: ConcurrencyModel,
    pub cancellation: CancellationModel,
    pub isolation: IsolationRequirement,
    /// Zero delegates timeout selection to the deployment target.
    pub default_timeout_ms: u64,
    /// `None` delegates the cap to the deployment target.
    pub max_concurrency: Option<u32>,
    pub idempotent: bool,
    pub retry_safe: bool,
}

impl Default for ExecutionProfile {
    fn default() -> Self {
        Self {
            invocation: InvocationMode::RequestResponse,
            concurrency: ConcurrencyModel::Concurrent,
            cancellation: CancellationModel::Deadline,
            isolation: IsolationRequirement::RuntimeDefault,
            default_timeout_ms: 0,
            max_concurrency: None,
            idempotent: false,
            retry_safe: false,
        }
    }
}

/// Language-neutral projection emitted into build/deploy metadata.
///
/// Language SDKs should expose native interfaces/traits whose implementations
/// project to this descriptor rather than treating JSON metadata as the source
/// of handler semantics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleDescriptor {
    pub contract_version: String,
    #[serde(default)]
    pub semantics_version: Option<String>,
    #[serde(default)]
    pub context_abi: Option<String>,
    pub kind: ModuleKind,
    pub name: String,
    pub entrypoint: String,
    pub interface: String,
    #[serde(default)]
    pub execution: ExecutionProfile,
    #[serde(default)]
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ModuleContractError {
    #[error("unsupported module contract version")]
    Version,
    #[error("unsupported module semantics version")]
    SemanticsVersion,
    #[error("unsupported module context ABI")]
    ContextAbi,
    #[error("module name must be a non-empty portable identifier")]
    Name,
    #[error("entrypoint must be non-empty and contain no whitespace")]
    Entrypoint,
    #[error("module interface does not match its semantic kind")]
    Interface,
    #[error("module execution profile is invalid")]
    Execution,
    #[error("module capability list contains duplicates")]
    DuplicateCapability,
}

impl ModuleDescriptor {
    pub fn validate(&self) -> Result<(), ModuleContractError> {
        if self.contract_version != MODULE_CONTRACT_V1 {
            return Err(ModuleContractError::Version);
        }
        if self
            .semantics_version
            .as_deref()
            .is_some_and(|version| version != MODULE_SEMANTICS_V2)
        {
            return Err(ModuleContractError::SemanticsVersion);
        }
        if self
            .context_abi
            .as_deref()
            .is_some_and(|version| version != CONTEXT_ABI_V1)
        {
            return Err(ModuleContractError::ContextAbi);
        }
        if !portable_ident(&self.name) {
            return Err(ModuleContractError::Name);
        }
        if self.entrypoint.is_empty() || self.entrypoint.chars().any(char::is_whitespace) {
            return Err(ModuleContractError::Entrypoint);
        }
        if self.interface != self.kind.interface() {
            return Err(ModuleContractError::Interface);
        }
        if self.execution.max_concurrency == Some(0) {
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

/// Base interface implemented by every Rust module exported to Scintilla.
/// Other language SDKs should project equivalent interfaces to the same
/// `ModuleDescriptor` shape.
pub trait ModuleExport {
    const KIND: ModuleKind;
    const NAME: &'static str;
    const INTERFACE: &'static str;
    const EXECUTION: ExecutionProfile = ExecutionProfile {
        invocation: InvocationMode::RequestResponse,
        concurrency: ConcurrencyModel::Concurrent,
        cancellation: CancellationModel::Deadline,
        isolation: IsolationRequirement::RuntimeDefault,
        default_timeout_ms: 0,
        max_concurrency: None,
        idempotent: false,
        retry_safe: false,
    };
    const CAPABILITIES: &'static [Capability] = &[];
}

/// Compile-time contract for Rust lambda entrypoints.
///
/// `async fn` is intentional here: callers implement the natural async handler
/// shape while provider adapters remain free to choose their executor/runtime.
#[allow(async_fn_in_trait)]
pub trait LambdaEntrypoint: ModuleExport + Send + Sync {
    type Input: Send;
    type Output: Send;
    type Error: Send;
    type Context: ModuleContext;

    async fn invoke(
        &self,
        context: &Self::Context,
        input: Self::Input,
    ) -> Result<Self::Output, Self::Error>;
}

/// Zero-cost assertions used by generated/scaffolded entrypoint modules.
pub const fn assert_module_export<T: ModuleExport>() {}
pub const fn assert_lambda_entrypoint<T: LambdaEntrypoint>() {}

pub fn descriptor_for<T: ModuleExport>(entrypoint: impl Into<String>) -> ModuleDescriptor {
    ModuleDescriptor {
        contract_version: MODULE_CONTRACT_V1.to_owned(),
        semantics_version: Some(MODULE_SEMANTICS_V2.to_owned()),
        context_abi: Some(CONTEXT_ABI_V1.to_owned()),
        kind: T::KIND,
        name: T::NAME.to_owned(),
        entrypoint: entrypoint.into(),
        interface: T::INTERFACE.to_owned(),
        execution: T::EXECUTION,
        capabilities: T::CAPABILITIES.to_vec(),
    }
}

fn portable_ident(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;

    #[derive(Debug)]
    struct AppContext {
        platform: InvocationContext,
        db_pool_name: String,
    }

    impl ModuleContext for AppContext {
        fn invocation(&self) -> &InvocationContext {
            &self.platform
        }
    }

    impl ModuleExport for Echo {
        const KIND: ModuleKind = ModuleKind::Lambda;
        const NAME: &'static str = "echo";
        const INTERFACE: &'static str = "scintilla.lambda.v1";
        const EXECUTION: ExecutionProfile = ExecutionProfile {
            invocation: InvocationMode::RequestResponse,
            concurrency: ConcurrencyModel::Concurrent,
            cancellation: CancellationModel::Deadline,
            isolation: IsolationRequirement::Process,
            default_timeout_ms: 30_000,
            max_concurrency: Some(64),
            idempotent: true,
            retry_safe: true,
        };
        const CAPABILITIES: &'static [Capability] =
            &[Capability::Clock, Capability::NetworkOutbound];
    }

    struct BadEcho;

    impl ModuleExport for BadEcho {
        const KIND: ModuleKind = ModuleKind::Lambda;
        const NAME: &'static str = "bad_echo";
        const INTERFACE: &'static str = "scintilla.rpc.v1";
    }

    impl LambdaEntrypoint for Echo {
        type Input = String;
        type Output = String;
        type Error = ();
        type Context = AppContext;

        async fn invoke(
            &self,
            _context: &Self::Context,
            input: Self::Input,
        ) -> Result<Self::Output, Self::Error> {
            Ok(input)
        }
    }

    #[test]
    fn rust_exports_project_execution_semantics() {
        assert_module_export::<Echo>();
        assert_lambda_entrypoint::<Echo>();
        let descriptor = descriptor_for::<Echo>("crate::lambda::Echo");
        assert_eq!(descriptor.validate(), Ok(()));
        assert_eq!(descriptor.kind, ModuleKind::Lambda);
        assert_eq!(descriptor.interface, ModuleKind::Lambda.interface());
        assert_eq!(
            descriptor.semantics_version.as_deref(),
            Some(MODULE_SEMANTICS_V2)
        );
        assert_eq!(descriptor.context_abi.as_deref(), Some(CONTEXT_ABI_V1));
        assert_eq!(
            descriptor.execution.isolation,
            IsolationRequirement::Process
        );
        assert_eq!(descriptor.capabilities.len(), 2);
    }

    #[test]
    fn user_context_can_extend_platform_context_without_framework_lock_in() {
        let context = AppContext {
            platform: InvocationContext {
                request_id: "req-1".into(),
                deadline_unix_ms: Some(42),
                attempt: 2,
            },
            db_pool_name: "primary".into(),
        };
        assert_eq!(context.invocation().request_id, "req-1");
        assert_eq!(context.invocation().deadline_unix_ms, Some(42));
        assert_eq!(context.db_pool_name, "primary");
    }

    #[test]
    fn rejects_unknown_context_abi_when_present() {
        let mut descriptor = descriptor_for::<Echo>("crate::lambda::Echo");
        descriptor.context_abi = Some("scintilla.context/v0".into());
        assert_eq!(descriptor.validate(), Err(ModuleContractError::ContextAbi));
    }

    #[test]
    fn declared_interface_drift_survives_projection_and_is_rejected() {
        let descriptor = descriptor_for::<BadEcho>("crate::lambda::BadEcho");
        assert_eq!(descriptor.interface, "scintilla.rpc.v1");
        assert_eq!(descriptor.validate(), Err(ModuleContractError::Interface));
    }

    #[test]
    fn rejects_kind_interface_drift() {
        let mut descriptor = descriptor_for::<Echo>("crate::lambda::Echo");
        descriptor.interface = "scintilla.rpc.v1".into();
        assert_eq!(descriptor.validate(), Err(ModuleContractError::Interface));
    }

    #[test]
    fn rejects_duplicate_capabilities() {
        let mut descriptor = descriptor_for::<Echo>("crate::lambda::Echo");
        descriptor.capabilities.push(Capability::Clock);
        assert_eq!(
            descriptor.validate(),
            Err(ModuleContractError::DuplicateCapability)
        );
    }

    #[test]
    fn legacy_descriptor_remains_valid_without_v2_semantics() {
        let descriptor = ModuleDescriptor {
            contract_version: MODULE_CONTRACT_V1.into(),
            semantics_version: None,
            context_abi: None,
            kind: ModuleKind::Container,
            name: "legacy".into(),
            entrypoint: "legacy::main".into(),
            interface: "scintilla.container.v1".into(),
            execution: ExecutionProfile::default(),
            capabilities: Vec::new(),
        };
        assert_eq!(descriptor.validate(), Ok(()));
    }
}
