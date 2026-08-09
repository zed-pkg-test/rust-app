# Agent policy

This repository is a deterministic zed-pkg interoperability fixture, not a production application.

Automated contributors must preserve the minimal Cargo/Zed graph and the explicit ownership boundary: Zed provides `zed-pkg-test/rust-lib`; Cargo owns compilation and any ordinary Rust dependencies. Do not add deployment infrastructure, production credentials, network-dependent fixtures, or unrelated framework dependencies.

Install behavior follows the shared conformance contract: local mode may use symlinks; Docker/OCI installs must be self-contained copies; checksum/provenance failures must fail closed; and tests must use deterministic assertions rather than sleep-based timing.

Before changing package identity, repository ownership, install paths, or lock data, verify downstream consumers and preserve commit/graph history. Re-homing is allowed only after consumers are repointed without loss of package identity.

Security and credential reports inherit the `zed-pkg-test` organization security/contact policy. Never commit secrets, tokens, private keys, production data, or credentials. Sensitive reports belong in the organization’s private reporting/contact path rather than public issues.
