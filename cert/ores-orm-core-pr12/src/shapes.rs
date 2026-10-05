use crate::error::{OrmError, Result};
use crate::ir::{OrmType, Table};
use crate::policy::Policy;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ShapeKind {
    Row,
    Create,
    Update,
    Patch,
    PublicRead,
    PublicCreate,
    PublicUpdate,
    PublicPatch,
}

impl ShapeKind {
    #[must_use]
    pub const fn is_public(self) -> bool {
        return matches!(
            self,
            Self::PublicRead | Self::PublicCreate | Self::PublicUpdate | Self::PublicPatch
        );
    }

    #[must_use]
    pub const fn requires_non_empty_object(self) -> bool {
        return matches!(self, Self::Patch | Self::PublicPatch);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ShapeField {
    pub db_name: String,
    pub wire_name: String,
    pub ty: OrmType,
    pub nullable: bool,
    pub required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Shape {
    pub table: String,
    pub kind: ShapeKind,
    pub fields: Vec<ShapeField>,
}

impl Shape {
    pub fn validate(&self) -> Result<()> {
        if self.table.trim().is_empty() {
            return Err(OrmError::Invalid(
                "derived shape table identity must not be empty".to_owned(),
            ));
        }
        if self.fields.is_empty() {
            return Err(OrmError::Invalid(format!(
                "derived {:?} shape for {} contains no fields",
                self.kind, self.table
            )));
        }

        let mut database_names = BTreeSet::new();
        let mut wire_names = BTreeSet::new();
        for field in &self.fields {
            if field.db_name.trim().is_empty() || field.wire_name.trim().is_empty() {
                return Err(OrmError::Invalid(format!(
                    "derived {:?} shape for {} contains an empty database or wire field name",
                    self.kind, self.table
                )));
            }
            if !database_names.insert(field.db_name.clone()) {
                return Err(OrmError::Invalid(format!(
                    "derived {:?} shape for {} contains duplicate database field {}",
                    self.kind, self.table, field.db_name
                )));
            }
            if !wire_names.insert(field.wire_name.clone()) {
                return Err(OrmError::Invalid(format!(
                    "derived {:?} shape for {} contains duplicate wire field {}",
                    self.kind, self.table, field.wire_name
                )));
            }

            if matches!(self.kind, ShapeKind::Row | ShapeKind::PublicRead) && !field.required {
                return Err(OrmError::Invalid(format!(
                    "derived {:?} shape for {} cannot make row field {} optional",
                    self.kind, self.table, field.db_name
                )));
            }
            if matches!(self.kind, ShapeKind::Patch | ShapeKind::PublicPatch) && field.required {
                return Err(OrmError::Invalid(format!(
                    "derived {:?} shape for {} cannot require patch field {}",
                    self.kind, self.table, field.db_name
                )));
            }
        }

        return Ok(());
    }
}

pub fn derive_shape(table: &Table, policy: &Policy, kind: ShapeKind) -> Result<Shape> {
    policy.validate_table(table)?;
    let table_policy = policy.table_policy(table);

    if kind.is_public() && !table_policy.public_surface {
        return Err(OrmError::Invalid(format!(
            "cannot derive public shape for {} without public_surface = true",
            table.qualified_name()
        )));
    }

    let fields = table
        .columns
        .iter()
        .filter_map(|column| {
            let name = &column.db_name;
            let include = match kind {
                ShapeKind::Row => true,
                ShapeKind::Create => !table_policy.generated.contains(name),
                ShapeKind::Update | ShapeKind::Patch => {
                    !table_policy.generated.contains(name) && !table_policy.immutable.contains(name)
                }
                ShapeKind::PublicRead => table_policy.public_read.contains(name),
                ShapeKind::PublicCreate => {
                    table_policy.public_create.contains(name)
                        && !table_policy.generated.contains(name)
                }
                ShapeKind::PublicUpdate | ShapeKind::PublicPatch => {
                    table_policy.public_update.contains(name)
                        && !table_policy.generated.contains(name)
                        && !table_policy.immutable.contains(name)
                }
            };

            if !include {
                return None;
            }

            let required = match kind {
                ShapeKind::Row | ShapeKind::PublicRead => true,
                ShapeKind::Create | ShapeKind::PublicCreate => {
                    !column.nullable && !table_policy.defaulted.contains(name)
                }
                ShapeKind::Update | ShapeKind::PublicUpdate => true,
                ShapeKind::Patch | ShapeKind::PublicPatch => false,
            };
            let wire_name = table_policy
                .wire_names
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.clone());

            return Some(ShapeField {
                db_name: name.clone(),
                wire_name,
                ty: column.ty.clone(),
                nullable: column.nullable,
                required,
            });
        })
        .collect();

    let shape = Shape {
        table: table.qualified_name(),
        kind,
        fields,
    };
    shape.validate()?;
    return Ok(shape);
}
