use crate::error::{OrmError, Result};
use crate::ir::{OrmIr, Table};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FieldVisibility {
    Public,
    Private,
    Secret,
    Unclassified,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(default, deny_unknown_fields)]
pub struct TablePolicy {
    pub public_surface: bool,
    pub generated: BTreeSet<String>,
    pub defaulted: BTreeSet<String>,
    pub immutable: BTreeSet<String>,
    pub private: BTreeSet<String>,
    pub secret: BTreeSet<String>,
    pub public_read: BTreeSet<String>,
    pub public_create: BTreeSet<String>,
    pub public_update: BTreeSet<String>,
    pub wire_names: BTreeMap<String, String>,
}

impl TablePolicy {
    #[must_use]
    pub fn visibility(&self, column: &str) -> FieldVisibility {
        let is_public = self.public_read.contains(column)
            || self.public_create.contains(column)
            || self.public_update.contains(column);

        if is_public {
            return FieldVisibility::Public;
        }
        if self.secret.contains(column) {
            return FieldVisibility::Secret;
        }
        if self.private.contains(column) {
            return FieldVisibility::Private;
        }

        return FieldVisibility::Unclassified;
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    #[serde(default = "default_true")]
    pub require_diesel: bool,
    #[serde(default = "default_true")]
    pub require_seaorm: bool,
    #[serde(default)]
    pub table: BTreeMap<String, TablePolicy>,
}

const fn default_true() -> bool {
    return true;
}

impl Policy {
    pub fn from_toml(source: &str) -> Result<Self> {
        let policy: Self = toml::from_str(source)?;
        if policy.version != 1 {
            return Err(OrmError::Invalid(format!(
                "unsupported .ores-orm.toml version {}",
                policy.version
            )));
        }

        return Ok(policy);
    }

    #[must_use]
    pub fn table_policy(&self, table: &Table) -> TablePolicy {
        return self
            .table
            .get(&table.qualified_name())
            .or_else(|| self.table.get(&table.db_name))
            .cloned()
            .unwrap_or_default();
    }

    /// Validate the complete policy against one exact ORM IR. This is the
    /// release-facing check: it rejects typo/orphan table keys and ambiguous
    /// unqualified names instead of silently leaving those entries unused.
    pub fn validate_ir(&self, ir: &OrmIr) -> Result<()> {
        ir.validate()?;

        for table in &ir.tables {
            self.validate_table(table)?;
        }

        for configured_key in self.table.keys() {
            let matches = ir
                .tables
                .iter()
                .filter(|table| {
                    configured_key.as_str() == table.qualified_name()
                        || configured_key.as_str() == table.db_name
                })
                .collect::<Vec<_>>();

            match matches.as_slice() {
                [] => {
                    return Err(OrmError::Invalid(format!(
                        "policy table {configured_key:?} does not match any ORM IR table"
                    )));
                }
                [_] => {}
                [first, second, ..] => {
                    return Err(OrmError::Invalid(format!(
                        "policy table {configured_key:?} is ambiguous between {} and {}; use qualified table keys",
                        first.qualified_name(),
                        second.qualified_name()
                    )));
                }
            }
        }

        return Ok(());
    }

    pub fn validate_table(&self, table: &Table) -> Result<()> {
        let qualified_name = table.qualified_name();
        if qualified_name != table.db_name
            && self.table.contains_key(&qualified_name)
            && self.table.contains_key(&table.db_name)
        {
            return Err(OrmError::Invalid(format!(
                "policy configures table {} through both qualified key {qualified_name:?} and unqualified key {:?}; refusing precedence-based resolution",
                table.qualified_name(),
                table.db_name
            )));
        }

        let policy = self.table_policy(table);
        let actual: BTreeSet<_> = table
            .columns
            .iter()
            .map(|column| column.db_name.as_str())
            .collect();

        for (label, names) in [
            ("generated", &policy.generated),
            ("defaulted", &policy.defaulted),
            ("immutable", &policy.immutable),
            ("private", &policy.private),
            ("secret", &policy.secret),
            ("public_read", &policy.public_read),
            ("public_create", &policy.public_create),
            ("public_update", &policy.public_update),
        ] {
            for name in names {
                if !actual.contains(name.as_str()) {
                    return Err(OrmError::Invalid(format!(
                        "policy {label} references unknown column {}.{name}",
                        table.qualified_name()
                    )));
                }
            }
        }

        for name in policy.wire_names.keys() {
            if !actual.contains(name.as_str()) {
                return Err(OrmError::Invalid(format!(
                    "policy wire_names references unknown column {}.{name}",
                    table.qualified_name()
                )));
            }
        }

        let mut effective_wire_names = BTreeMap::new();
        for column in &table.columns {
            let wire_name = policy
                .wire_names
                .get(&column.db_name)
                .map_or(column.db_name.as_str(), String::as_str);
            if wire_name.trim().is_empty() {
                return Err(OrmError::Invalid(format!(
                    "policy wire_names maps {}.{} to an empty wire name",
                    table.qualified_name(),
                    column.db_name
                )));
            }
            if let Some(previous_column) =
                effective_wire_names.insert(wire_name.to_owned(), column.db_name.clone())
            {
                return Err(OrmError::Invalid(format!(
                    "policy wire name {wire_name:?} collides for columns {}.{previous_column} and {}.{}",
                    table.qualified_name(),
                    table.qualified_name(),
                    column.db_name
                )));
            }
        }

        let has_public_fields = !policy.public_read.is_empty()
            || !policy.public_create.is_empty()
            || !policy.public_update.is_empty();
        if has_public_fields && !policy.public_surface {
            return Err(OrmError::Invalid(format!(
                "table {} declares public fields but public_surface is false",
                table.qualified_name()
            )));
        }

        let public_fields: BTreeSet<_> = policy
            .public_read
            .iter()
            .chain(policy.public_create.iter())
            .chain(policy.public_update.iter())
            .cloned()
            .collect();

        for name in &public_fields {
            if policy.private.contains(name) || policy.secret.contains(name) {
                return Err(OrmError::Invalid(format!(
                    "column {}.{name} is both public and private/secret",
                    table.qualified_name()
                )));
            }
        }

        for name in &policy.private {
            if policy.secret.contains(name) {
                return Err(OrmError::Invalid(format!(
                    "column {}.{name} is both private and secret",
                    table.qualified_name()
                )));
            }
        }

        for name in &policy.public_create {
            if policy.generated.contains(name) {
                return Err(OrmError::Invalid(format!(
                    "column {}.{name} is both public_create and generated; refusing to silently drop it from create projections",
                    table.qualified_name()
                )));
            }
        }

        for name in &policy.public_update {
            if policy.generated.contains(name) || policy.immutable.contains(name) {
                return Err(OrmError::Invalid(format!(
                    "column {}.{name} is public_update but generated or immutable; refusing to silently drop it from update projections",
                    table.qualified_name()
                )));
            }
        }

        if policy.public_surface {
            for column in &table.columns {
                if policy.visibility(&column.db_name) == FieldVisibility::Unclassified {
                    return Err(OrmError::Invalid(format!(
                        "public table {} leaves column {} unclassified",
                        table.qualified_name(),
                        column.db_name
                    )));
                }
            }
        }

        return Ok(());
    }
}
