# rust-app

`rust-app` is a deterministic interoperability fixture for **zed-pkg**. It is not a production application. Its only purpose is to prove that a Rust/Cargo consumer can source one crate through Zed while Cargo retains ownership of ordinary Rust dependencies.

## Package graph

```text
rust-app
└── zed-pkg-test/rust-lib ^1.0.0   (Zed)
```

`.zpkg.toml` installs Zed-managed content beneath `.vendor/.zed`; `Cargo.toml` consumes the installed package as the path dependency `.vendor/.zed/zed-pkg-test/rust-lib`.

## Deterministic inputs and outputs

Tracked package metadata, source, Zed manifest/lock data, and the exact `rust-lib` resolution are the fixture inputs. For identical pinned inputs, a clean install must reconstruct the same dependency graph and the same application/test output without reaching outside the declared install root.

The consuming assertion should install the fixture using the selected mode, compile/test with Cargo, and execute the app-level assertion that calls the Zed-provided crate. CI is expected to prove that the path dependency exists because Zed installed it, not because an undeclared workspace or machine-local path happened to be present.

## Install-mode expectations

- **Local developer mode:** symlink semantics are allowed and preferred when the Zed local mode supports them.
- **Docker/OCI mode:** the installed dependency must be a self-contained copy. Container correctness must not rely on source-tree symlinks, host hardlinks, caches, or paths outside the image/install root.
- **Filesystem boundary:** after a copy-mode install, removing the source/cache must not invalidate the installed crate.
- **Integrity:** checksum/provenance mismatches must fail closed rather than silently substituting content.

The shared canary implementation for these semantics belongs to DEN-588/DEN-591; this fixture consumes that contract instead of introducing a competing one.

## Expected failures

A missing/incompatible `rust-lib`, invalid integrity metadata, an escaped filesystem boundary, or a Cargo path that was not materialized by Zed must produce an actionable failure. Cross-platform tests should assert stable failure classes/messages without timing-sensitive sleeps.

## Ownership and security

The canonical owner is the `zed-pkg-test` GitHub organization. Repository transfers or renames must preserve graph history and package identity until consumers are repointed. See `agents.md` for automation rules. Sensitive security reports inherit the organization security/contact policy and must not be posted publicly with credentials or secrets.
