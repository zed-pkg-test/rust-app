//! Contract tests for the embedded macOS Seatbelt helper.

const HELPER: &str = include_str!("../scripts/macos/ores-proc-isolate.sh");

#[test]
fn local_development_networking_is_ip_scoped() {
    assert!(HELPER.contains(r#"(allow network-bind (local ip "*:*"))"#));
    assert!(HELPER.contains(r#"(allow network-inbound (local ip "*:*"))"#));
    assert!(HELPER.contains(r#"(allow network-outbound (remote ip "*:*"))"#));
    assert!(!HELPER.contains("(allow network-inbound)"));
    assert!(!HELPER.contains("(allow network-outbound)"));
}

#[test]
fn macos_helper_does_not_switch_or_create_users() {
    for forbidden in ["sudo ", "dscl ", "sysadminctl ", "setuid", "setgid"] {
        assert!(
            !HELPER.contains(forbidden),
            "macOS same-user sandbox helper must not contain {forbidden:?}"
        );
    }
}

#[test]
fn macos_helper_keeps_keychain_services_denied() {
    for forbidden in [
        "com.apple.SecurityServer",
        "com.apple.securityd",
        "/Library/Keychains",
        "/Library/Keychains/",
    ] {
        assert!(
            !HELPER.contains(forbidden),
            "same-user local sandbox must not opt into Keychain surface {forbidden:?}"
        );
    }
    assert!(HELPER.contains("com.apple.trustd"));
    assert!(HELPER.contains("com.apple.ocspd"));
}

#[test]
fn macos_helper_allows_only_system_tls_configuration() {
    assert!(HELPER.contains(r#"(subpath "/private/etc/ssl")"#));
    assert!(!HELPER.contains(r#"(subpath "/private/etc")"#));
    assert!(!HELPER.contains(r#"(subpath "/Users")"#));
}
