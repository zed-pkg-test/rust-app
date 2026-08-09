# Changelog

## 0.2.0

- compose a Zed-materialized Rust crate with direct and transitive crates.io dependencies;
- track the binary application's exact Cargo lock;
- certify Cargo resolver-v2 target/build feature separation;
- preserve Cargo and Zed lockfiles independently;
- add symlink, frozen-copy, fresh-container, offline, and Cargo-lock-drift canaries;
- run locked Cargo checks on Linux, macOS, and Windows.
