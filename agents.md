# Agent policy

This repository is a deterministic zed-pkg interoperability fixture, not a production application.

Automated contributors must preserve the minimal Cargo/Zed graph and the explicit ownership boundary: Zed provides `zed-pkg-test/rust-lib`; Cargo owns compilation and any ordinary Rust dependencies. Do not add deployment infrastructure, production credentials, network-dependent fixtures, or unrelated framework dependencies.

Install behavior follows the shared conformance contract: local mode may use symlinks; Docker/OCI installs must be self-contained copies; checksum/provenance failures must fail closed; and tests must use deterministic assertions rather than sleep-based timing.

Before changing package identity, repository ownership, install paths, or lock data, verify downstream consumers and preserve commit/graph history. Re-homing is allowed only after consumers are repointed without loss of package identity.

Security and credential reports inherit the `zed-pkg-test` organization security/contact policy. Never commit secrets, tokens, private keys, production data, or credentials. Sensitive reports belong in the organization’s private reporting/contact path rather than public issues.

## Repository-local Git worktrees

- Create or use a Git worktree only when the human operator explicitly authorizes it for the current task. Concurrency or a dirty checkout is not permission by itself.
- Put every authorized worktree at `<repository-root>/tmp/worktrees/<name>`; from the repository root, use `./tmp/worktrees/<name>`. Never place worktrees beside repositories or organization directories.
- Keep `tmp`, `temp`, `tmp/worktrees`, and `temp/worktrees` ignored in the repository-root `.gitignore`. Do not commit files from those directories.
- Relocate or remove a worktree only when the operator explicitly requests it. Before removal, preserve and publish intended changes, verify its commit is represented on the target branch, and confirm there are no tracked, untracked, ignored-sensitive, or in-use files that must survive. Remove it with `git worktree remove <path>` without `--force`; never delete a worktree directory with `rm`.
