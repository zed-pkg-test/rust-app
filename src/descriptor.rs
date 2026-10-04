use crate::error::{OrmError, Result};
use crate::ir::{OrmType, ScalarType, Table};
use crate::policy::{FieldVisibility, Policy};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const ORM_DESCRIPTOR_SCHEMA: &str = "ores.orm-descriptor/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub enum OrmWitness {
    #[serde(rename = "diesel")]
    Diesel,
    #[serde(rename = "seaorm")]
    SeaOrm,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DescriptorSource {
    pub repository: String,
    pub revision: String,
    #[serde(rename = "crate")]
    pub crate_name: String,
    pub toolchain: String,
    pub orm: Vec<OrmWitness>,
}

impl DescriptorSource {
    pub fn new(
        repository: impl Into<String>,
        revision: impl Into<String>,
        crate_name: impl Into<String>,
        toolchain: impl Into<String>,
        orm: Vec<OrmWitness>,
    ) -> Result<Self> {
        let repository = repository.into();
        let revision = revision.into();
        let crate_name = crate_name.into();
        let toolchain = toolchain.into();

        for (label, value) in [
            ("repository", repository.as_str()),
            ("crate", crate_name.as_str()),
            ("toolchain", toolchain.as_str()),
        ] {
            if value.trim().is_empty() {
                return Err(OrmError::Invalid(format!(
                    "ORM descriptor source {label} must not be empty"
                )));
            }
        }

        if revision.len() != 40 || !revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(OrmError::Invalid(
                "ORM descriptor source revision must be a 40-character hexadecimal Git revision"
                    .to_owned(),
            ));
        }
        if orm.is_empty() {
            return Err(OrmError::Invalid(
                "ORM descriptor must identify at least one ORM witness".to_owned(),
            ));
        }
        let unique_witnesses = orm
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        if unique_witnesses.len() != orm.len() {
            return Err(OrmError::Invalid(
                "ORM descriptor source contains duplicate ORM witnesses".to_owned(),
            ));
        }

        return Ok(Self {
            repository,
            revision: revision.to_ascii_lowercase(),
            crate_name,
            toolchain,
            orm,
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescriptorType {
    pub kind: DescriptorScalar,
    pub array: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum DescriptorScalar {
    Boolean,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    Decimal,
    String,
    Uuid,
    PlainDate,
    UtcDateTime,
    Bytes,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescriptorField {
    pub name: String,
    pub wire_name: String,
    pub database_name: String,
    pub previous_wire_names: Vec<String>,
    pub previous_database_names: Vec<String>,
    pub r#type: DescriptorType,
    pub nullable: bool,
    pub generated: bool,
    pub defaulted: bool,
    pub selectable: bool,
    pub insertable: bool,
    pub updatable: bool,
    pub visibility: FieldVisibility,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DescriptorModel {
    pub namespace: String,
    pub name: String,
    pub table: String,
    pub public_surface: bool,
    pub fields: Vec<DescriptorField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrmDescriptor {
    pub schema: String,
    pub source: DescriptorSource,
    pub model: DescriptorModel,
}

pub fn describe_table(
    table: &Table,
    policy: &Policy,
    namespace: impl Into<String>,
    source: DescriptorSource,
) -> Result<OrmDescriptor> {
    policy.validate_table(table)?;
    let table_policy = policy.table_policy(table);
    let fields = table
        .columns
        .iter()
        .map(|column| {
            let wire_name = table_policy
                .wire_names
                .get(&column.db_name)
                .cloned()
                .unwrap_or_else(|| column.db_name.clone());

            return descriptor_type(&column.ty).map(|r#type| DescriptorField {
                name: column.rust_name.clone(),
                wire_name,
                database_name: column.db_name.clone(),
                previous_wire_names: Vec::new(),
                previous_database_names: Vec::new(),
                r#type,
                nullable: column.nullable,
                generated: table_policy.generated.contains(&column.db_name),
                defaulted: table_policy.defaulted.contains(&column.db_name),
                selectable: true,
                insertable: !table_policy.generated.contains(&column.db_name),
                updatable: !table_policy.generated.contains(&column.db_name)
                    && !table_policy.immutable.contains(&column.db_name),
                visibility: table_policy.visibility(&column.db_name),
            });
        })
        .collect::<Result<Vec<_>>>()?;

    return Ok(OrmDescriptor {
        schema: ORM_DESCRIPTOR_SCHEMA.to_owned(),
        source,
        model: DescriptorModel {
            namespace: namespace.into(),
            name: table.db_name.clone(),
            table: table.qualified_name(),
            public_surface: table_policy.public_surface,
            fields,
        },
    });
}

fn descriptor_type(ty: &OrmType) -> Result<DescriptorType> {
    let (kind, array) = match ty {
        OrmType::Scalar(scalar) => (descriptor_scalar(scalar), false),
        OrmType::Array(inner) => {
            if matches!(inner.as_ref(), OrmType::Array(_)) {
                return Err(OrmError::Unsupported(
                    "nested ORM arrays are not representable in ores.orm-descriptor/v1".to_owned(),
                ));
            }
            let inner = descriptor_type(inner)?;
            (inner.kind, true)
        }
        OrmType::Named(name) => {
            return Err(OrmError::Unsupported(format!(
                "named ORM type {name} requires admitted contract mapping before descriptor emission"
            )));
        }
    };

    return Ok(DescriptorType { kind, array });
}

fn descriptor_scalar(scalar: &ScalarType) -> DescriptorScalar {
    return match scalar {
        ScalarType::Boolean => DescriptorScalar::Boolean,
        ScalarType::Int16 => DescriptorScalar::Int16,
        ScalarType::Int32 => DescriptorScalar::Int32,
        ScalarType::Int64 => DescriptorScalar::Int64,
        ScalarType::Float32 => DescriptorScalar::Float32,
        ScalarType::Float64 => DescriptorScalar::Float64,
        ScalarType::Decimal => DescriptorScalar::Decimal,
        ScalarType::String => DescriptorScalar::String,
        ScalarType::Uuid => DescriptorScalar::Uuid,
        ScalarType::Date => DescriptorScalar::PlainDate,
        ScalarType::DateTime => DescriptorScalar::UtcDateTime,
        ScalarType::Bytes => DescriptorScalar::Bytes,
        ScalarType::Json => DescriptorScalar::Json,
    };
}
