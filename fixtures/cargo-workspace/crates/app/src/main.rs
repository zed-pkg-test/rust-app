fn main() {
    assert_eq!(
        workspace_support::greeting(),
        "HELLO WORKSPACE-SUPPORT FROM ZED-PKG-TEST/RUST-LIB"
    );
    assert_eq!(
        env!("ZED_WORKSPACE_BUILD_GREETING"),
        "hello workspace-build from zed-pkg-test/rust-lib"
    );
    assert_eq!(workspace_support::formatted_count(10_000_001), "10000001");
    assert!(unicode_ident::is_xid_start('λ'));

    println!("{}", workspace_support::greeting());
    println!("{}", env!("ZED_WORKSPACE_BUILD_GREETING"));
    println!("OK: Cargo workspace inheritance + Zed path package");
}
