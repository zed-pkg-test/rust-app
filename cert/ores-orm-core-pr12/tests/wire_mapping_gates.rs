use ores_orm_core::emit::{dart, gleam, json_schema, rust, typescript};
use ores_orm_core::ir::{OrmType, ScalarType};
use ores_orm_core::shapes::{Shape, ShapeField, ShapeKind};

fn shape(scalar: ScalarType) -> Shape {
    Shape {
        table: "wire_mapping_gate".to_owned(),
        kind: ShapeKind::PublicRead,
        fields: vec![ShapeField {
            db_name: "value".to_owned(),
            wire_name: "value".to_owned(),
            ty: OrmType::Scalar(scalar),
            nullable: false,
            required: true,
        }],
    }
}

#[test]
fn ambiguous_cross_runtime_scalars_require_admitted_mappings() {
    for scalar in [
        ScalarType::Int64,
        ScalarType::Float32,
        ScalarType::Decimal,
        ScalarType::Uuid,
        ScalarType::Date,
        ScalarType::DateTime,
        ScalarType::Bytes,
    ] {
        let candidate = shape(scalar.clone());
        assert!(
            rust::emit(&candidate).is_err(),
            "Rust unexpectedly admitted {scalar:?}"
        );
        assert!(
            typescript::emit(&candidate).is_err(),
            "TypeScript unexpectedly admitted {scalar:?}"
        );
        assert!(
            dart::emit(&candidate).is_err(),
            "Dart unexpectedly admitted {scalar:?}"
        );
        assert!(
            gleam::emit(&candidate).is_err(),
            "Gleam unexpectedly admitted {scalar:?}"
        );
        assert!(
            json_schema::emit(&candidate).is_err(),
            "JSON Schema unexpectedly admitted {scalar:?}"
        );
    }
}

#[test]
fn portable_scalar_subset_remains_generatable() {
    for scalar in [
        ScalarType::Boolean,
        ScalarType::Int16,
        ScalarType::Int32,
        ScalarType::Float64,
        ScalarType::String,
        ScalarType::Json,
    ] {
        let candidate = shape(scalar.clone());
        rust::emit(&candidate).unwrap_or_else(|error| panic!("Rust rejected {scalar:?}: {error}"));
        typescript::emit(&candidate)
            .unwrap_or_else(|error| panic!("TypeScript rejected {scalar:?}: {error}"));
        dart::emit(&candidate).unwrap_or_else(|error| panic!("Dart rejected {scalar:?}: {error}"));
        gleam::emit(&candidate)
            .unwrap_or_else(|error| panic!("Gleam rejected {scalar:?}: {error}"));
        json_schema::emit(&candidate)
            .unwrap_or_else(|error| panic!("JSON Schema rejected {scalar:?}: {error}"));
    }
}
