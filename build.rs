fn main() {
    println!("cargo:rerun-if-changed=Cargo.toml");

    // Cargo resolver v2 must keep this host build dependency feature set
    // independent from the target dependency's `uppercase` feature.
    let greeting = rust_lib::greet("build-script");
    assert_eq!(
        greeting, "hello build-script from zed-pkg-test/rust-lib",
        "build dependency unexpectedly inherited target-only Cargo features"
    );
    println!("cargo:rustc-env=ZED_BUILD_GREETING={greeting}");
}
