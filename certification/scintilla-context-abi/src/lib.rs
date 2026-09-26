//! Canonical Scintilla persistence and user-module boundaries.
//!
//! This crate separates contracts, bounded reads, API-owned writes, and
//! operator-owned migration planning. It never runs schema changes at service
//! startup and never exports a raw SeaORM connection.

pub mod module_contract;

#[cfg(feature = "read")]
pub mod capabilities;
#[cfg(feature = "contracts")]
pub mod contracts;
#[cfg(feature = "migrator")]
pub mod dpm;

pub use module_contract::{
    assert_lambda_entrypoint, assert_module_export, descriptor_for, CancellationModel, Capability,
    ConcurrencyModel, ExecutionProfile, InvocationContext, InvocationMode, IsolationRequirement,
    LambdaEntrypoint, ModuleContext, ModuleContractError, ModuleDescriptor, ModuleExport,
    ModuleKind, CONTEXT_ABI_V1, MODULE_CONTRACT_V1, MODULE_SEMANTICS_V2,
};

#[cfg(feature = "write")]
pub use capabilities::WriteContext;
#[cfg(feature = "read")]
pub use capabilities::{
    AccessScope, ActorContext, CapabilityError, DatabaseFlavor, ReadContext, TenantContext,
};
