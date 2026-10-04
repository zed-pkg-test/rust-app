use crate::error::{OrmError, Result};
use crate::ir::{OrmType, ScalarType};
use crate::shapes::{Shape, ShapeField, ShapeKind};
use serde_json::{Map, Value, json};

pub const DRAFT_2020_12: &str = "https://json-schema.org/draft/2020-12/schema";

pub fn emit(shape: &Shape) -> Result<Value> {
    shape.validate()?;
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in &shape.fields {
        properties.insert(field.wire_name.clone(), field_schema(field)?);
        if field.required {
            required.push(Value::String(field.wire_name.clone()));
        }
    }

    let table_identity = hex::encode(shape.table.as_bytes());
    let mut schema = json!({
        "$schema": DRAFT_2020_12,
        "$id": format!("urn:ores:orm:table:{table_identity}:{}", shape_slug(shape.kind)),
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": required,
        "x-ores-orm-derivative": true,
        "x-ores-table": shape.table
    });

    if shape.kind.requires_non_empty_object() {
        schema["minProperties"] = json!(1);
    }

    return Ok(schema);
}

const fn shape_slug(kind: ShapeKind) -> &'static str {
    match kind {
        ShapeKind::Row => "row",
        ShapeKind::Create => "create",
        ShapeKind::Update => "update",
        ShapeKind::Patch => "patch",
        ShapeKind::PublicRead => "public_read",
        ShapeKind::PublicCreate => "public_create",
        ShapeKind::PublicUpdate => "public_update",
        ShapeKind::PublicPatch => "public_patch",
    }
}

fn field_schema(field: &ShapeField) -> Result<Value> {
    let base = type_schema(&field.ty)?;
    if !field.nullable {
        return Ok(base);
    }
    Ok(json!({"anyOf": [base, {"type": "null"}]}))
}

fn type_schema(ty: &OrmType) -> Result<Value> {
    match ty {
        OrmType::Scalar(scalar) => Ok(match scalar {
            ScalarType::Boolean => json!({"type": "boolean"}),
            ScalarType::Int16 => json!({
                "type": "integer",
                "format": "int16",
                "minimum": -32768,
                "maximum": 32767
            }),
            ScalarType::Int32 => json!({
                "type": "integer",
                "format": "int32",
                "minimum": -2147483648_i64,
                "maximum": 2147483647_i64
            }),
            ScalarType::Int64 => {
                return Err(OrmError::Unsupported(
                    "int64 requires an explicit JSON wire mapping".to_owned(),
                ));
            }
            ScalarType::Float32 => {
                return Err(OrmError::Unsupported(
                    "float32 requires an admitted cross-runtime wire/domain mapping before JSON Schema emission".to_owned(),
                ));
            }
            ScalarType::Float64 => json!({"type": "number"}),
            ScalarType::Decimal => {
                return Err(OrmError::Unsupported(
                    "decimal requires an explicit JSON wire mapping".to_owned(),
                ));
            }
            ScalarType::String => json!({"type": "string"}),
            ScalarType::Uuid => {
                return Err(OrmError::Unsupported(
                    "uuid requires an admitted canonical string/validator mapping before JSON Schema emission; format annotations alone are not a portable assertion guarantee".to_owned(),
                ));
            }
            ScalarType::Date => {
                return Err(OrmError::Unsupported(
                    "date requires an admitted semantic calendar-date mapping before JSON Schema emission; format annotations alone are not a portable assertion guarantee".to_owned(),
                ));
            }
            ScalarType::DateTime => {
                return Err(OrmError::Unsupported(
                    "date-time requires an explicit JSON wire mapping".to_owned(),
                ));
            }
            ScalarType::Bytes => {
                return Err(OrmError::Unsupported(
                    "bytes require an explicit JSON wire mapping".to_owned(),
                ));
            }
            ScalarType::Json => json!({}),
        }),
        OrmType::Array(inner) => Ok(json!({
            "type": "array",
            "items": type_schema(inner)?
        })),
        OrmType::Named(name) => Err(OrmError::Unsupported(format!(
            "named ORM type {name} must be resolved against contract evidence before JSON Schema emission"
        ))),
    }
}
