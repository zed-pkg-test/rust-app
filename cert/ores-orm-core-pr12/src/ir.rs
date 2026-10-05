use crate::error::{OrmError, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const ORM_IR_SCHEMA: &str = "ores.orm-core.ir/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Diesel,
    SeaOrm,
    Converged,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScalarType {
    Boolean,
    Int16,
    Int32,
    Int64,
    Float32,
    Float64,
    Decimal,
    String,
    Uuid,
    Date,
    DateTime,
    Bytes,
    Json,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum OrmType {
    Scalar(ScalarType),
    Array(Box<OrmType>),
    /// A DB/ORM named type whose semantic definition is not present in this
    /// structural lane. It may participate in ORM parity, but public validation
    /// emission must resolve it against admitted contract evidence first.
    Named(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Column {
    pub rust_name: String,
    pub db_name: String,
    pub ordinal: usize,
    pub ty: OrmType,
    pub nullable: bool,
    pub primary_key: bool,
    pub unique: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Table {
    pub schema_name: Option<String>,
    pub db_name: String,
    pub columns: Vec<Column>,
}

impl Table {
    #[must_use]
    pub fn qualified_name(&self) -> String {
        return self.schema_name.as_ref().map_or_else(
            || self.db_name.clone(),
            |schema| format!("{schema}.{}", self.db_name),
        );
    }

    #[must_use]
    pub fn column(&self, db_name: &str) -> Option<&Column> {
        return self.columns.iter().find(|column| column.db_name == db_name);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OrmIr {
    pub schema: String,
    pub source: SourceKind,
    pub tables: Vec<Table>,
}

impl OrmIr {
    #[must_use]
    pub fn new(source: SourceKind, mut tables: Vec<Table>) -> Self {
        tables.sort_by_key(Table::qualified_name);
        for table in &mut tables {
            table.columns.sort_by_key(|column| column.ordinal);
        }
        return Self {
            schema: ORM_IR_SCHEMA.to_owned(),
            source,
            tables,
        };
    }

    pub fn try_new(source: SourceKind, tables: Vec<Table>) -> Result<Self> {
        let ir = Self::new(source, tables);
        ir.validate()?;
        return Ok(ir);
    }

    pub fn validate(&self) -> Result<()> {
        if self.schema != ORM_IR_SCHEMA {
            return Err(OrmError::Invalid(format!(
                "unsupported ORM IR schema {}; expected {ORM_IR_SCHEMA}",
                self.schema
            )));
        }

        let mut qualified_table_names = BTreeSet::new();
        for table in &self.tables {
            if table.db_name.trim().is_empty() {
                return Err(OrmError::Invalid(
                    "ORM IR table database name must not be empty".to_owned(),
                ));
            }
            if table
                .schema_name
                .as_ref()
                .is_some_and(|schema| schema.trim().is_empty())
            {
                return Err(OrmError::Invalid(format!(
                    "ORM IR table {} has an empty schema name",
                    table.db_name
                )));
            }

            let qualified_name = table.qualified_name();
            if !qualified_table_names.insert(qualified_name.clone()) {
                return Err(OrmError::Invalid(format!(
                    "ORM IR contains duplicate table identity {qualified_name}"
                )));
            }

            let mut database_names = BTreeSet::new();
            let mut rust_names = BTreeSet::new();
            let mut ordinals = BTreeSet::new();
            for column in &table.columns {
                if column.db_name.trim().is_empty() {
                    return Err(OrmError::Invalid(format!(
                        "ORM IR table {qualified_name} contains an empty database column name"
                    )));
                }
                if column.rust_name.trim().is_empty() {
                    return Err(OrmError::Invalid(format!(
                        "ORM IR table {qualified_name} contains an empty Rust column name"
                    )));
                }
                if !database_names.insert(column.db_name.clone()) {
                    return Err(OrmError::Invalid(format!(
                        "ORM IR table {qualified_name} contains duplicate database column {}",
                        column.db_name
                    )));
                }
                if !rust_names.insert(column.rust_name.clone()) {
                    return Err(OrmError::Invalid(format!(
                        "ORM IR table {qualified_name} contains duplicate Rust column {}",
                        column.rust_name
                    )));
                }
                if !ordinals.insert(column.ordinal) {
                    return Err(OrmError::Invalid(format!(
                        "ORM IR table {qualified_name} contains duplicate ordinal {}",
                        column.ordinal
                    )));
                }

                validate_type(&column.ty, &format!("{qualified_name}.{}", column.db_name))?;
            }

            for (expected_ordinal, column) in table.columns.iter().enumerate() {
                if column.ordinal != expected_ordinal {
                    return Err(OrmError::Invalid(format!(
                        "ORM IR table {qualified_name} has non-contiguous ordinal {} for column {}; expected {expected_ordinal}",
                        column.ordinal, column.db_name
                    )));
                }
            }
        }

        return Ok(());
    }

    #[must_use]
    pub fn table(&self, qualified_name: &str) -> Option<&Table> {
        return self
            .tables
            .iter()
            .find(|table| table.qualified_name() == qualified_name);
    }
}

fn validate_type(ty: &OrmType, path: &str) -> Result<()> {
    match ty {
        OrmType::Scalar(_) => {}
        OrmType::Array(inner) => {
            validate_type(inner, path)?;
        }
        OrmType::Named(name) => {
            if name.trim().is_empty() {
                return Err(OrmError::Invalid(format!(
                    "ORM IR named type at {path} must not be empty"
                )));
            }
        }
    }

    return Ok(());
}
