fn main() {
    let greeting = zed_rust_lib::greet("workspace-build");
    assert_eq!(
        greeting, "hello workspace-build from zed-pkg-test/rust-lib",
        "resolver v2 leaked target/dev features into the host build graph"
    );
    println!("cargo:rustc-env=ZED_WORKSPACE_BUILD_GREETING={greeting}");
}
