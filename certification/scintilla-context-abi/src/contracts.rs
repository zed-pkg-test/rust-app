//! Compile-time access to the immutable persistence contract bundle.

pub const PERSISTENCE_SCHEMA_JSON: &str = include_str!("../contracts/database/schema.json");
pub const DESIRED_SQL: &str = include_str!("../contracts/database/desired.sql");
pub const COMPATIBILITY_JSON: &str = include_str!("../contracts/database/compatibility.json");
pub const SOURCE_PINS_JSON: &str = include_str!("../contracts/database/sources.json");
pub const GENERATED_PROVENANCE_JSON: &str = include_str!("../generated/provenance.json");
