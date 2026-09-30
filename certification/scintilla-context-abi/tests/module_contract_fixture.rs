use scintilla_lib_core::ModuleDescriptor;

#[test]
fn canonical_v2_fixture_matches_rust_admission() {
    let descriptor: ModuleDescriptor = serde_json::from_str(include_str!(
        "../contracts/fixtures/module-descriptor.v2.json"
    ))
    .expect("canonical module descriptor fixture must deserialize");

    descriptor
        .validate()
        .expect("canonical module descriptor fixture must pass Rust admission");
}
