//! ORM-first derivative schema and validator tooling.
//!
//! Diesel and SeaORM are parsed independently into a normalized structural IR.
//! The two lanes must converge before derivative shapes are generated. The IR
//! and everything emitted from it are downstream evidence, never authored
//! contract authority.

pub mod admission;
pub mod descriptor;
pub mod diesel;
pub mod emit;
pub mod error;
pub mod ir;
pub mod parity;
pub mod policy;
pub mod seaorm;
pub mod shapes;

pub use admission::{
    REQUIRED_PUBLIC_RUNTIME_VALIDATOR_IDS, TJSV_ADMISSION_BINDING_SCHEMA, TJSV_CONTRACT_IR_SCHEMA,
    TJSV_PARITY_REPORT_SCHEMA, TJSV_PROJECTION_MANIFEST_SCHEMA,
    TJSV_PROJECTION_VERIFICATION_RECEIPT_SCHEMA, TjsvAdmissionBinding, TjsvOutputBinding,
};
pub use descriptor::{
    DescriptorField, DescriptorModel, DescriptorScalar, DescriptorSource, DescriptorType,
    ORM_DESCRIPTOR_SCHEMA, OrmDescriptor, OrmWitness, describe_table,
};
pub use error::{OrmError, Result};
pub use ir::{Column, OrmIr, OrmType, ScalarType, SourceKind, Table};
pub use parity::{Finding, ParityReport, compare};
pub use policy::{FieldVisibility, Policy, TablePolicy};
pub use shapes::{Shape, ShapeField, ShapeKind, derive_shape};
