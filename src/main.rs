fn main() {
    let msg = rust_lib::greet("rust-app");
    println!("{msg}");
    assert!(
        msg.contains("from zed-pkg-test/rust-lib"),
        "zed-sourced crate did not resolve"
    );
    println!("OK: zed-sourced crate resolved via cargo path dep");
}
