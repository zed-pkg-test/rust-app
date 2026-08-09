# Cargo workspace and Zed package interoperability

The root `rust-app` fixture certifies one Cargo package consuming one
Zed-installed Rust crate. `fixtures/cargo-workspace` extends that boundary to a
virtual Cargo workspace without changing either package manager's ownership.

## Certified graph

```text
cargo-workspace-consumer (.zpkg.toml)
└── zed-pkg-test/rust-lib ^1.0.1              Zed resolution

Cargo virtual workspace (resolver = "2")
├── workspace-app
│   ├── workspace-support                     path/workspace dependency
│   ├── unicode-ident = 1.0.24               crates.io dependency
│   ├── zed-rust-lib -> rust-lib = 1.0.1     inherited build dependency
│   └── zed-rust-lib -> rust-lib = 1.0.1     inherited dev dependency
└── workspace-support
    └── zed-rust-lib -> rust-lib = 1.0.1      target-specific dependency
        └── itoa = 1.0.18                     transitive crates.io dependency
```

The `zed-rust-lib` key is an ordinary Cargo dependency rename. The package
identity remains `rust-lib`; Cargo metadata must retain `rename =
"zed-rust-lib"` for normal, build, and dev dependency kinds.

## Adapter boundary

Zed installs the exact `rust-lib` artifact beneath:

```text
.vendor/.zed/zed-pkg-test/rust-lib
```

The Rust adapter emits `.zed/cargo-paths.toml` with:

- a Cargo `paths` override; and
- a `[patch.crates-io]` entry for the installed crate's real Cargo package name.

The fixture's `.cargo/config.toml` is the checked-in, consumer-owned merge of
that generated fragment. The E2E suite parses both files and requires semantic
equality. This proves that Cargo can retain a normal version dependency and
resolve it to Zed-installed source without Zed rewriting `Cargo.toml`.

The generated fragment remains advisory because Cargo has no environment-only
path injection mechanism. Zed owns deterministic generation; the consumer owns
merging the fragment into Cargo configuration.

## Resolver and scope coverage

Cargo resolver v2 must keep these graphs separate:

- target-specific `workspace-support` dependency with feature `uppercase`;
- host build dependency with default features disabled; and
- test-only renamed dependency with feature `uppercase`.

The build script asserts that target/dev features do not leak into the host
build graph. Runtime and integration tests assert that the target and dev graphs
do receive the requested feature.

## Lock and portability guarantees

The suite requires:

- a tracked workspace `Cargo.lock` containing direct and transitive crates.io
  checksums;
- a generated `.zpkg.lock` containing only the Zed package resolution;
- neither package manager changing the other's lockfile;
- locked and locked/offline execution on Linux, macOS, and Windows;
- Zed symlink mode failing without its store, as designed;
- frozen copy mode working with no Zed home, registry, or network;
- Cargo requirement drift failing under `--locked`; and
- repository cleanup restoring the exact reviewed source state.

## Scope boundary

This fixture does not make Zed a Cargo registry, publish to crates.io, or teach
Cargo to resolve Zed package versions. It tests the intentional composition
point: immutable Zed acquisition plus ordinary Cargo workspace semantics.
