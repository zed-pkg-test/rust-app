use serde_json::Value;

#[test]
fn contract_bundle_is_parseable_and_complete() {
    let schema: Value =
        serde_json::from_str(scintilla_lib_core::contracts::PERSISTENCE_SCHEMA_JSON).unwrap();
    let sources: Value =
        serde_json::from_str(scintilla_lib_core::contracts::SOURCE_PINS_JSON).unwrap();
    let compatibility: Value =
        serde_json::from_str(scintilla_lib_core::contracts::COMPATIBILITY_JSON).unwrap();
    let provenance: Value =
        serde_json::from_str(scintilla_lib_core::contracts::GENERATED_PROVENANCE_JSON).unwrap();

    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert!(sources["sources"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert_eq!(compatibility["startupMigrations"], "forbidden");
    assert_eq!(provenance["format"], 1);
}

#[test]
fn desired_sql_matches_the_declared_table_inventory() {
    let schema: Value =
        serde_json::from_str(scintilla_lib_core::contracts::PERSISTENCE_SCHEMA_JSON).unwrap();
    let desired = scintilla_lib_core::contracts::DESIRED_SQL.to_ascii_lowercase();
    for table in schema["x-lib-core"]["tables"].as_array().unwrap() {
        let table = table.as_str().unwrap();
        assert!(
            desired.contains(&format!("create table if not exists {table}")),
            "desired SQL is missing {table}"
        );
    }
}
