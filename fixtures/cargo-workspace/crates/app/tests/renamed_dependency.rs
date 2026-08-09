#[test]
fn dev_dependency_alias_preserves_package_identity_and_features() {
    assert_eq!(
        zed_rust_lib::greet("workspace-test"),
        "HELLO WORKSPACE-TEST FROM ZED-PKG-TEST/RUST-LIB"
    );
}
