use crate::error::{OrmError, Result};
use crate::ir::{Column, OrmIr, SourceKind, Table};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub code: String,
    pub path: String,
    pub left: Option<String>,
    pub right: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ParityReport {
    pub passed: bool,
    pub findings: Vec<Finding>,
}

impl ParityReport {
    pub fn require_passed(&self) -> Result<()> {
        if self.passed {
            return Ok(());
        }
        let summary = self
            .findings
            .iter()
            .map(|finding| format!("{} at {}", finding.code, finding.path))
            .collect::<Vec<_>>()
            .join("; ");
        return Err(OrmError::Parity(summary));
    }
}

type TableIdentity = (Option<String>, String);

#[must_use]
pub fn compare(left: &OrmIr, right: &OrmIr) -> ParityReport {
    let mut findings = Vec::new();
    if let Err(error) = left.validate() {
        findings.push(Finding {
            code: "invalid_left_ir".to_owned(),
            path: "$".to_owned(),
            left: Some(error.to_string()),
            right: None,
        });
    }
    if let Err(error) = right.validate() {
        findings.push(Finding {
            code: "invalid_right_ir".to_owned(),
            path: "$".to_owned(),
            left: None,
            right: Some(error.to_string()),
        });
    }
    if !findings.is_empty() {
        return ParityReport {
            passed: false,
            findings,
        };
    }

    let left_tables = index_tables(left);
    let right_tables = index_tables(right);
    let names: BTreeSet<_> = left_tables
        .keys()
        .chain(right_tables.keys())
        .cloned()
        .collect();

    for identity in names {
        match (left_tables.get(&identity), right_tables.get(&identity)) {
            (Some(left_table), Some(right_table)) => {
                compare_table(left_table, right_table, &mut findings);
            }
            (Some(left_table), None) => findings.push(Finding {
                code: "table_missing_right".to_owned(),
                path: left_table.qualified_name(),
                left: Some("present".to_owned()),
                right: None,
            }),
            (None, Some(right_table)) => findings.push(Finding {
                code: "table_missing_left".to_owned(),
                path: right_table.qualified_name(),
                left: None,
                right: Some("present".to_owned()),
            }),
            (None, None) => unreachable!("identity came from at least one map"),
        }
    }

    return ParityReport {
        passed: findings.is_empty(),
        findings,
    };
}

pub fn converge(left: &OrmIr, right: &OrmIr) -> Result<OrmIr> {
    let independent_lanes = matches!(
        (left.source, right.source),
        (SourceKind::Diesel, SourceKind::SeaOrm) | (SourceKind::SeaOrm, SourceKind::Diesel)
    );
    if !independent_lanes {
        return Err(OrmError::Invalid(format!(
            "ORM convergence requires one Diesel witness and one SeaORM witness; got {:?} and {:?}",
            left.source, right.source
        )));
    }

    let report = compare(left, right);
    report.require_passed()?;

    let right_tables = index_tables(right);
    let mut tables = Vec::with_capacity(left.tables.len());
    for left_table in &left.tables {
        let identity = table_identity(left_table);
        let right_table = right_tables.get(&identity).copied().ok_or_else(|| {
            OrmError::Parity(format!(
                "missing converged table {}",
                left_table.qualified_name()
            ))
        })?;
        tables.push(canonical_table(left_table, right_table)?);
    }

    return OrmIr::try_new(SourceKind::Converged, tables);
}

fn table_identity(table: &Table) -> TableIdentity {
    return (table.schema_name.clone(), table.db_name.clone());
}

fn index_tables(ir: &OrmIr) -> BTreeMap<TableIdentity, &Table> {
    return ir
        .tables
        .iter()
        .map(|table| (table_identity(table), table))
        .collect();
}

fn canonical_table(left: &Table, right: &Table) -> Result<Table> {
    let right_columns: BTreeMap<_, _> = right
        .columns
        .iter()
        .map(|column| (column.db_name.as_str(), column))
        .collect();
    let mut columns = Vec::with_capacity(left.columns.len());

    for left_column in &left.columns {
        let right_column = right_columns
            .get(left_column.db_name.as_str())
            .copied()
            .ok_or_else(|| {
                OrmError::Parity(format!(
                    "missing converged column {}.{}",
                    left.qualified_name(),
                    left_column.db_name
                ))
            })?;

        let rust_name = if left_column.rust_name == right_column.rust_name {
            left_column.rust_name.clone()
        } else {
            // Rust-side identifiers are source-specific syntax, not persistence
            // semantics. Use the exact database identity when the witnesses use
            // different aliases so convergence is independent of argument order.
            left_column.db_name.clone()
        };

        columns.push(Column {
            rust_name,
            db_name: left_column.db_name.clone(),
            ordinal: left_column.ordinal,
            ty: left_column.ty.clone(),
            nullable: left_column.nullable,
            primary_key: left_column.primary_key,
            // `unique` is not currently proven by both parser lanes (Diesel
            // print-schema does not carry it). Retain it only if both witnesses
            // independently prove it so source-specific metadata cannot leak
            // through whichever lane happened to be passed first.
            unique: left_column.unique && right_column.unique,
        });
    }

    return Ok(Table {
        schema_name: left.schema_name.clone(),
        db_name: left.db_name.clone(),
        columns,
    });
}

fn compare_table(left: &Table, right: &Table, findings: &mut Vec<Finding>) {
    let path = left.qualified_name();
    let left_columns: BTreeMap<_, _> = left
        .columns
        .iter()
        .map(|column| (column.db_name.clone(), column))
        .collect();
    let right_columns: BTreeMap<_, _> = right
        .columns
        .iter()
        .map(|column| (column.db_name.clone(), column))
        .collect();
    let names: BTreeSet<_> = left_columns
        .keys()
        .chain(right_columns.keys())
        .cloned()
        .collect();

    for name in names {
        let field_path = format!("{path}.{name}");
        match (left_columns.get(&name), right_columns.get(&name)) {
            (Some(left_column), Some(right_column)) => {
                if left_column.ordinal != right_column.ordinal {
                    findings.push(Finding {
                        code: "column_ordinal_mismatch".to_owned(),
                        path: field_path.clone(),
                        left: Some(left_column.ordinal.to_string()),
                        right: Some(right_column.ordinal.to_string()),
                    });
                }
                if left_column.ty != right_column.ty {
                    findings.push(Finding {
                        code: "column_type_mismatch".to_owned(),
                        path: field_path.clone(),
                        left: Some(format!("{:?}", left_column.ty)),
                        right: Some(format!("{:?}", right_column.ty)),
                    });
                }
                if left_column.nullable != right_column.nullable {
                    findings.push(Finding {
                        code: "column_nullability_mismatch".to_owned(),
                        path: field_path.clone(),
                        left: Some(left_column.nullable.to_string()),
                        right: Some(right_column.nullable.to_string()),
                    });
                }
                if left_column.primary_key != right_column.primary_key {
                    findings.push(Finding {
                        code: "column_primary_key_mismatch".to_owned(),
                        path: field_path,
                        left: Some(left_column.primary_key.to_string()),
                        right: Some(right_column.primary_key.to_string()),
                    });
                }
            }
            (Some(_), None) => findings.push(Finding {
                code: "column_missing_right".to_owned(),
                path: field_path,
                left: Some("present".to_owned()),
                right: None,
            }),
            (None, Some(_)) => findings.push(Finding {
                code: "column_missing_left".to_owned(),
                path: field_path,
                left: None,
                right: Some("present".to_owned()),
            }),
            (None, None) => unreachable!("name came from at least one map"),
        }
    }
}
