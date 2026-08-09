fn main() {
    let runtime_greeting = rust_lib::greet("rust-app");
    assert_eq!(
        runtime_greeting, "HELLO RUST-APP FROM ZED-PKG-TEST/RUST-LIB",
        "target dependency did not receive the requested Cargo feature"
    );
    assert_eq!(
        env!("ZED_BUILD_GREETING"),
        "hello build-script from zed-pkg-test/rust-lib",
        "build dependency feature set leaked from the target graph"
    );
    assert_eq!(rust_lib::format_count(1_000_001), "1000001");
    assert!(unicode_ident::is_xid_start('Δ'));

    println!("{runtime_greeting}");
    println!("{}", env!("ZED_BUILD_GREETING"));
    println!("OK: Zed package + Cargo registry dependencies resolved together");
}
