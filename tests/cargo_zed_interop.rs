#[test]
fn target_and_build_dependency_feature_sets_remain_separate() {
    assert_eq!(
        rust_lib::greet("integration"),
        "HELLO INTEGRATION FROM ZED-PKG-TEST/RUST-LIB"
    );
    assert_eq!(
        env!("ZED_BUILD_GREETING"),
        "hello build-script from zed-pkg-test/rust-lib"
    );
}

#[test]
fn zed_materialized_crate_keeps_its_cargo_dependency_graph() {
    assert_eq!(rust_lib::format_count(u64::MAX), "18446744073709551615");
    assert!(unicode_ident::is_xid_continue('δ'));
}
