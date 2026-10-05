use ores_orm_core::diesel;
use ores_orm_core::emit::bundle::GenerationEvidence;
use ores_orm_core::emit::{dart, gleam, json_schema, typescript};
use ores_orm_core::ir::{OrmType, ScalarType};
use ores_orm_core::parity;
use ores_orm_core::policy::Policy;
use ores_orm_core::seaorm;
use ores_orm_core::shapes::{Shape, ShapeField, ShapeKind, derive_shape};

const DIESEL: &str = include_str!("../fixtures/diesel/schema.rs");
const SEAORM: &str = include_str!("../fixtures/seaorm/users.rs");
const POLICY: &str = include_str!("../fixtures/ores-orm.toml");

fn converged() -> ores_orm_core::OrmIr {
    let diesel = diesel::parse_schema(DIESEL).expect("Diesel fixture should parse");
    let seaorm = seaorm::parse_source(SEAORM).expect("SeaORM fixture should parse");
    return parity::converge(&diesel, &seaorm).expect("ORM fixtures should converge");
}

#[test]
fn duplicate_effective_wire_names_fail_closed() {
    let ir = converged();
    let table = ir.table("users").expect("users table");
    let mut policy = Policy::from_toml(POLICY).expect("policy should parse");
    let table_policy = policy.table.get_mut("users").expect("users policy");
    table_policy
        .wire_names
        .insert("email".to_owned(), "identity".to_owned());
    table_policy
        .wire_names
        .insert("display_name".to_owned(), "identity".to_owned());

    let error = derive_shape(table, &policy, ShapeKind::PublicRead)
        .expect_err("wire-name collisions must be rejected before emission");
    assert!(error.to_string().contains("wire name"));
    assert!(error.to_string().contains("collides"));
}

#[test]
fn direct_shapes_with_duplicate_wire_names_fail_before_emission() {
    let shape = Shape {
        table: "example".to_owned(),
        kind: ShapeKind::Row,
        fields: vec![
            ShapeField {
                db_name: "first".to_owned(),
                wire_name: "same".to_owned(),
                ty: OrmType::Scalar(ScalarType::String),
                nullable: false,
                required: true,
            },
            ShapeField {
                db_name: "second".to_owned(),
                wire_name: "same".to_owned(),
                ty: OrmType::Scalar(ScalarType::String),
                nullable: false,
                required: true,
            },
        ],
    };

    let error = json_schema::emit(&shape).expect_err("duplicate wire names must fail closed");
    assert!(error.to_string().contains("duplicate wire field"));
}

#[test]
fn seaorm_time_offset_datetime_matches_diesel_timestamptz() {
    let diesel = diesel::parse_schema(
        "diesel::table! { events (id) { id -> Uuid, occurred_at -> Timestamptz, } }",
    )
    .expect("Diesel event schema");
    let seaorm = seaorm::parse_source(
        r#"
        use sea_orm::entity::prelude::*;
        use time::OffsetDateTime;
        #[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
        #[sea_orm(table_name = "events")]
        pub struct Model {
            #[sea_orm(primary_key, auto_increment = false)]
            pub id: Uuid,
            pub occurred_at: OffsetDateTime,
        }
        "#,
    )
    .expect("SeaORM time crate model");

    parity::converge(&diesel, &seaorm)
        .expect("time::OffsetDateTime must normalize to the same DateTime domain as Timestamptz");
}

#[test]
fn public_create_cannot_silently_drop_generated_fields() {
    let ir = converged();
    let table = ir.table("users").expect("users table");
    let mut policy = Policy::from_toml(POLICY).expect("policy should parse");
    let table_policy = policy.table.get_mut("users").expect("users policy");
    table_policy.public_create.insert("id".to_owned());

    let error = derive_shape(table, &policy, ShapeKind::PublicCreate)
        .expect_err("generated public-create fields must not disappear silently");
    assert!(error.to_string().contains("public_create"));
    assert!(error.to_string().contains("generated"));
}

#[test]
fn public_update_cannot_silently_drop_immutable_fields() {
    let ir = converged();
    let table = ir.table("users").expect("users table");
    let mut policy = Policy::from_toml(POLICY).expect("policy should parse");
    let table_policy = policy.table.get_mut("users").expect("users policy");
    table_policy.public_update.insert("created_at".to_owned());

    let error = derive_shape(table, &policy, ShapeKind::PublicUpdate)
        .expect_err("immutable public-update fields must not disappear silently");
    assert!(error.to_string().contains("public_update"));
    assert!(error.to_string().contains("immutable"));
}

#[test]
fn emitted_numeric_validators_do_not_widen_database_domains() {
    let shape = Shape {
        table: "numeric_bounds".to_owned(),
        kind: ShapeKind::Row,
        fields: vec![
            ShapeField {
                db_name: "small".to_owned(),
                wire_name: "small".to_owned(),
                ty: OrmType::Scalar(ScalarType::Int16),
                nullable: false,
                required: true,
            },
            ShapeField {
                db_name: "normal".to_owned(),
                wire_name: "normal".to_owned(),
                ty: OrmType::Scalar(ScalarType::Int32),
                nullable: false,
                required: true,
            },
            ShapeField {
                db_name: "ratio".to_owned(),
                wire_name: "ratio".to_owned(),
                ty: OrmType::Scalar(ScalarType::Float64),
                nullable: false,
                required: true,
            },
        ],
    };

    let ts = typescript::emit(&shape).expect("TypeScript");
    assert!(ts.contains("min(-32768).max(32767)"));
    assert!(ts.contains("min(-2147483648).max(2147483647)"));
    assert!(ts.contains("z.number().finite()"));

    let dart = dart::emit(&shape).expect("Dart");
    assert!(dart.contains(">= -32768"));
    assert!(dart.contains("<= 2147483647"));
    assert!(dart.contains(".isFinite"));

    let gleam = gleam::emit(&shape).expect("Gleam");
    assert!(gleam.contains("value >= -32_768 && value <= 32_767"));
    assert!(gleam.contains("value >= -2_147_483_648 && value <= 2_147_483_647"));
}

#[test]
fn provenance_rejects_duplicate_source_names() {
    let ir = converged();
    let error = GenerationEvidence::from_bytes(
        &ir,
        &[
            ("schema.rs", DIESEL.as_bytes()),
            ("schema.rs", SEAORM.as_bytes()),
        ],
        b"hardening-test",
        None,
    )
    .expect_err("duplicate provenance labels are ambiguous");
    assert!(error.to_string().contains("duplicate source name"));
}

#[test]
fn empty_contract_evidence_cannot_claim_evidence_bound_state() {
    let ir = converged();
    let error = GenerationEvidence::from_bytes(
        &ir,
        &[("schema.rs", DIESEL.as_bytes())],
        b"hardening-test",
        Some((b"", b"")),
    )
    .expect_err("empty contract evidence must not be digest-bound");
    assert!(
        error
            .to_string()
            .contains("non-empty Contract IR and receipt")
    );
}

#[test]
fn provenance_rejects_invalid_ir() {
    let mut ir = converged();
    ir.tables.push(ir.tables[0].clone());
    let error = GenerationEvidence::from_bytes(
        &ir,
        &[("schema.rs", DIESEL.as_bytes())],
        b"hardening-test",
        None,
    )
    .expect_err("invalid ORM IR must not receive provenance digests");
    assert!(error.to_string().contains("duplicate table identity"));
}
