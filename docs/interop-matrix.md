# Cargo and Zed interoperability matrix

This fixture treats Zed and Cargo as composable package-management layers rather
than competing resolvers.

| Concern | Owner | Certified behavior |
| --- | --- | --- |
| package acquisition | Zed | exact `rust-lib` artifact is published to a disposable registry and materialized under `.vendor/.zed` |
| Zed dependency version | `.zpkg.toml` / `.zpkg.lock` | `zed-pkg-test/rust-lib ^1.0.1` resolves once and frozen copy mode reuses the exact lock |
| Cargo path package | `Cargo.toml` / `Cargo.lock` | Cargo resolves the Zed materialization as `rust-lib 1.0.1` with no registry source |
| transitive Cargo registry dependency | Cargo | `rust-lib` retains `itoa 1.0.18` from crates.io |
| direct Cargo registry dependency | Cargo | `rust-app` retains `unicode-ident 1.0.24` from crates.io |
| Cargo features | Cargo resolver v2 | target dependency receives `uppercase`; build dependency remains default-feature-only |
| binary reproducibility | Cargo | tracked `Cargo.lock` is unchanged by Zed install and supports `--locked --offline` |
| Zed reproducibility | Zed | `.zpkg.lock` is unchanged by Cargo run, test, metadata, and rejected Cargo-lock drift |
| development layout | Zed symlink mode | works while the Zed home/store is mounted and fails when that store is absent |
| portable layout | Zed copy mode | works in a fresh network-disabled Rust container with no Zed home or registry |
| host coverage | GitHub Actions | locked Cargo build, lint, test, run, metadata, and offline replay on Linux, macOS, and Windows |

## Deliberate non-goals

Zed does not rewrite Cargo manifests, publish crates to crates.io, or encode
crates.io dependencies in the Zed dependency table. Cargo does not resolve Zed
versions or modify `.zpkg.lock`. Integration occurs through a normal Cargo path
dependency at the deterministic Zed install location.

## Failure canaries

The suite must fail when:

- a Zed package is absent from the expected install path;
- the symlink store is not mounted;
- target-only Cargo features leak into the build-dependency graph;
- `Cargo.lock` would need to change under `--locked`;
- either lockfile changes while the other package manager runs;
- an exact source commit does not match the configured immutable reference; or
- a supposedly offline copied project attempts network access.
