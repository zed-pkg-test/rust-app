use ores_orm_core::diesel;

const DIESEL: &str = include_str!("../fixtures/diesel/schema.rs");

#[test]
fn valid_diesel_primary_key_still_parses() {
    let ir = diesel::parse_schema(DIESEL).expect("valid Diesel fixture should parse");
    let users = ir.table("users").expect("users table");
    let id = users.column("id").expect("id column");
    assert!(id.primary_key);
}

#[test]
fn empty_diesel_primary_key_list_fails_closed() {
    let source = DIESEL.replace("users (id)", "users ()");
    let error = diesel::parse_schema(&source)
        .expect_err("an explicit empty primary-key list must be rejected");
    assert!(error.to_string().contains("empty primary-key list"));
}

#[test]
fn duplicate_diesel_primary_key_column_fails_closed() {
    let source = DIESEL.replace("users (id)", "users (id, id)");
    let error = diesel::parse_schema(&source)
        .expect_err("duplicate primary-key identifiers must be rejected");
    assert!(
        error
            .to_string()
            .contains("duplicate primary-key column id")
    );
}

#[test]
fn undeclared_diesel_primary_key_column_fails_closed() {
    let source = DIESEL.replace("users (id)", "users (missing_pk)");
    let error = diesel::parse_schema(&source)
        .expect_err("primary-key identifiers must reference declared columns");
    assert!(
        error
            .to_string()
            .contains("primary-key column missing_pk is not declared")
    );
}
