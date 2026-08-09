pub fn greeting() -> String {
    zed_rust_lib::greet("workspace-support")
}

pub fn formatted_count(value: u64) -> String {
    zed_rust_lib::format_count(value)
}

#[cfg(test)]
mod tests {
    use super::{formatted_count, greeting};

    #[test]
    fn target_specific_alias_receives_workspace_feature() {
        assert_eq!(
            greeting(),
            "HELLO WORKSPACE-SUPPORT FROM ZED-PKG-TEST/RUST-LIB"
        );
        assert_eq!(formatted_count(10_000_001), "10000001");
    }
}
