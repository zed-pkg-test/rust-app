use ores_orm_core::diesel;
use ores_orm_core::emit::json_schema;
use ores_orm_core::parity;
use ores_orm_core::policy::Policy;
use ores_orm_core::seaorm;
use ores_orm_core::shapes::{ShapeKind, derive_shape};
use pretty_assertions::assert_eq;

const DIESEL: &str = include_str!("../fixtures/diesel/schema.rs");
const SEAORM: &str = include_str!("../fixtures/seaorm/users.rs");
const POLICY: &str = include_str!("../fixtures/ores-orm.toml");

#[test]
fn diesel_and_seaorm_converge_on_structural_shape() {
    let diesel = diesel::parse_schema(DIESEL).expect("Diesel fixture should parse");
    let seaorm = seaorm::parse_source(SEAORM).expect("SeaORM fixture should parse");
    let report = parity::compare(&diesel, &seaorm);
    assert_eq!(report.findings, vec![]);
    assert!(report.passed);

    let converged = parity::converge(&diesel, &seaorm).expect("ORM lanes should converge");
    assert_eq!(converged.tables.len(), 1);
    assert_eq!(converged.tables[0].db_name, "users");
}

#[test]
fn public_create_keeps_presence_and_nullability_separate() {
    let diesel = diesel::parse_schema(DIESEL).expect("Diesel fixture should parse");
    let policy = Policy::from_toml(POLICY).expect("policy should parse");
    let table = diesel.table("users").expect("users table");
    let shape = derive_shape(table, &policy, ShapeKind::PublicCreate).expect("derive shape");

    assert_eq!(shape.fields.len(), 2);
    let email = shape
        .fields
        .iter()
        .find(|field| field.db_name == "email")
        .expect("email");
    assert!(email.required);
    assert!(!email.nullable);

    let display_name = shape
        .fields
        .iter()
        .find(|field| field.db_name == "display_name")
        .expect("display_name");
    assert!(!display_name.required);
    assert!(display_name.nullable);

    let schema = json_schema::emit(&shape).expect("schema should emit");
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["required"], serde_json::json!(["email"]));
    assert_eq!(
        schema["properties"]["display_name"],
        serde_json::json!({"anyOf": [{"type": "string"}, {"type": "null"}]})
    );
}

#[test]
fn drift_fails_closed() {
    let diesel = diesel::parse_schema(DIESEL).expect("Diesel fixture should parse");
    let drifted = SEAORM.replace("pub email: String", "pub email: i64");
    let seaorm = seaorm::parse_source(&drifted).expect("SeaORM drift fixture should parse");
    let report = parity::compare(&diesel, &seaorm);
    assert!(!report.passed);
    assert!(report.findings.iter().any(|finding| {
        finding.code == "column_type_mismatch" && finding.path == "users.email"
    }));
}

#[test]
fn convergence_requires_independent_orm_witnesses() {
    let diesel = diesel::parse_schema(DIESEL).expect("Diesel fixture should parse");
    let error = parity::converge(&diesel, &diesel)
        .expect_err("two Diesel witnesses must not be admitted as convergence");
    assert!(
        error
            .to_string()
            .contains("one Diesel witness and one SeaORM witness")
    );
}

#[test]
fn seaorm_ignore_fields_are_not_treated_as_database_columns() {
    let ignored = SEAORM.replace(
        "    pub display_name: Option<String>,",
        "    #[sea_orm(ignore)]\n    pub display_name: Option<String>,",
    );
    let ir = seaorm::parse_source(&ignored).expect("ignored field should parse");
    let users = ir.table("users").expect("users table");
    assert!(users.column("display_name").is_none());
}

#[test]
fn seaorm_database_type_overrides_fail_closed() {
    let overridden = SEAORM.replace(
        "    pub email: String,",
        "    #[sea_orm(column_type = \"Text\")]\n    pub email: String,",
    );
    let error = seaorm::parse_source(&overridden)
        .expect_err("column_type changes database semantics and must not be ignored");
    assert!(error.to_string().contains("column_type"));
    assert!(error.to_string().contains("explicit mapping"));
}

#[test]
fn duplicate_database_column_names_fail_closed() {
    let duplicate = SEAORM.replace(
        "    pub display_name: Option<String>,",
        "    #[sea_orm(column_name = \"email\")]\n    pub display_name: Option<String>,",
    );
    let error = seaorm::parse_source(&duplicate)
        .expect_err("duplicate database identities must be rejected");
    assert!(
        error
            .to_string()
            .contains("duplicate database column email")
    );
}

#[test]
fn invalid_ir_cannot_hide_behind_parity_indexing() {
    let mut diesel = diesel::parse_schema(DIESEL).expect("Diesel fixture should parse");
    diesel.tables.push(diesel.tables[0].clone());
    let seaorm = seaorm::parse_source(SEAORM).expect("SeaORM fixture should parse");

    let report = parity::compare(&diesel, &seaorm);
    assert!(!report.passed);
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == "invalid_left_ir")
    );
}
