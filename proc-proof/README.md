# ores-proc-isolation-cli

`ores-proc-isolation-cli` launches explicitly configured processes inside a small, fail-closed macOS/Linux sandbox without requiring Docker or a long-running daemon.

The design deliberately separates **policy** from **OS mechanics**:

- Rust loads and validates `.ores-proc-isolation.yaml`, resolves process ↔ group membership, sanitizes the target environment, canonicalizes allowed host paths, and selects the backend.
- `.cli-flags.toml` is the sole public CLI contract and is audited/parsed by [`flags-2-env`](https://github.com/flags-2-env/flags-2-env).
- [`ORESoftware/ores-reactive-maps`](https://github.com/ORESoftware/ores-reactive-maps) resolves membership layers deterministically: default group → `groups.*.members` → explicit `processes.*.group`.
- Small reviewed Bash helpers perform the final OS-specific sandbox setup. They are embedded into the Rust binary with `include_str!`, so a packaged CLI and its reviewed sandbox scripts stay together.

## Security model

### Linux

The Linux backend uses `bubblewrap` plus `slirp4netns`:

- a user namespace is mandatory; if the kernel does not permit it, launch fails closed;
- separate mount, PID, IPC, UTS, and network namespaces are created;
- no host root, home directory, current working directory, `/tmp`, `/proc`, `/sys`, or `/run` mount is shared;
- target root filesystem is synthetic/ephemeral;
- only the target executable, minimal dynamic-loader/runtime directories, TLS certificate roots, and explicit `filesystem.read_only` paths are visible;
- capabilities are dropped and nested user namespaces are disabled;
- target environment is cleared and rebuilt from policy;
- external networking uses a separate network namespace with `slirp4netns --disable-host-loopback`;
- namespace loopback is disabled before target exec;
- IPv4 and IPv6 loopback, link-local, RFC1918/ULA, CGNAT, the slirp host gateway, and every global IP address assigned to the host are rejected before the target is released;
- there is **no** fallback to host networking if setup fails.

`mode: external` therefore means Internet egress only, not “any outbound network.” Both `deny_loopback` and `deny_private_networks` are strict invariants and cannot be disabled for an external group.

Runtime dependencies for external-network mode are intentionally small: `bwrap`, `slirp4netns`, `nsenter`, `ip`, `iptables`, and `ip6tables`.

### macOS

macOS has no Linux-style per-process network namespace, so the backend uses the kernel Seatbelt sandbox through `/usr/bin/sandbox-exec`:

- `(deny default)` baseline;
- only the target executable, macOS runtime/framework files, standard device handles, and explicit read-only paths are readable;
- host file writes are denied (except standard device handles such as `/dev/null` / terminal descriptors);
- target environment is cleared and rebuilt from policy;
- children inherit the same Seatbelt policy;
- `mode: none` is supported as the strict network profile;
- `mode: local` is an explicit local-development profile for tools such as `ores-compose`: it keeps the current macOS login user, permits declared read-write workspace paths, and allows host/loopback/private/external **IP** networking so local services can bind and communicate. Unix-domain sockets remain denied by the default Seatbelt policy. It does **not** claim network-namespace isolation.

The macOS backend never creates users, calls `sudo`, changes uid/gid, or requires one Unix account per service. Local development stays under the current macOS user; isolation comes from Seatbelt policy, explicit filesystem grants, resource limits, environment clearing, and process inheritance.

Apple marks `sandbox-exec` deprecated, so the CLI treats its presence as a checked host capability and fails closed if it disappears. More importantly, Seatbelt cannot express the same destination-level Internet-only rule as the Linux namespace/firewall backend. Because `mode: external` requires private/local destination denial, strict external mode is intentionally rejected on macOS rather than silently weakened.

## Configuration

The default policy filename is `.ores-proc-isolation.yaml`.

```yaml
version: 1

defaults:
  group: external-only

groups:
  external-only:
    members:
      - api-worker
    filesystem:
      read_only:
        - /opt/company/public-ca.pem
      read_write: []
    network:
      mode: external
      deny_loopback: true
      deny_private_networks: true
    limits:
      max_open_files: 128
      cpu_seconds: 300
    environment:
      RUST_LOG: info

processes:
  api-worker:
    # This may also be inferred from groups.external-only.members. If both are
    # present, they must agree.
    group: external-only
    command:
      - /opt/company/bin/api-worker
      - --serve-once
    environment:
      APP_MODE: sandboxed
```

Unknown YAML keys, missing groups, contradictory memberships, relative executables, host-root read allowlisting, dangerous dynamic-loader environment variables, and insecure external-network policies all fail validation.

For portable Linux/macOS policy, use a `mode: none` group. Use `mode: external` only where the Linux backend is available. Use `mode: local` only for explicitly trusted local-development workloads on macOS; it requires `deny_loopback: false` and `deny_private_networks: false` so the weaker network boundary is never accidental.

### Process/group mapping

Both directions are first-class:

- `groups.<group>.members` answers “which processes belong to this group?”
- `processes.<process>.group` answers “which group owns this process?”

A process may use either declaration style. If both are present they must resolve to the same group. If neither is present, `defaults.group` applies.

## Usage

```bash
# Validate config only.
ores-proc-isolation check

# Check local backend dependencies/capabilities.
ores-proc-isolation doctor

# Show resolved process/group/policy without exposing environment values.
ores-proc-isolation explain api-worker

# Preview the exact backend plan.
ores-proc-isolation run api-worker --dry-run -- --request-id abc123

# Launch in the sandbox.
ores-proc-isolation run api-worker -- --request-id abc123
```

Use another policy file with `--config` / `-c`:

```bash
ores-proc-isolation run api-worker -c ./prod.ores-proc-isolation.yaml
```

The target command itself must come from the policy and must use an absolute executable path. Arbitrary ad-hoc commands are intentionally not accepted by the initial CLI surface.

## Environment isolation

The target never inherits the caller's environment wholesale. The backend starts from an empty environment and adds only fixed sandbox values plus `groups.*.environment` and `processes.*.environment`.

The following loader/shell injection families are rejected at config validation time:

- `LD_*`
- `DYLD_*`
- `BASH_ENV`
- `ENV`
- `SHELLOPTS`

Dry-run/explain output reports only environment **keys**, never values. Environment values are passed to the embedded helper through a private mode-0600 temporary file rather than command-line arguments, avoiding disclosure through ordinary process listings.

## Development

```bash
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
bash -n scripts/linux/ores-proc-isolate.sh
bash -n scripts/macos/ores-proc-isolate.sh
```

CI runs on Linux and macOS. Linux smoke tests prove host-file denial, external Internet egress, host-loopback denial, and denial of the host's non-loopback interface address. macOS smoke tests prove no-network isolation and host-file denial, and explicitly prove that the unsupported strict-external policy fails closed. Test HTTP endpoints are served by a tiny Rust fixture rather than Python or another scripting runtime.


## ores-compose local macOS profile

For `ores-compose up` on a developer Mac, the intended boundary is one macOS login user with one Seatbelt sandbox per launched build/service/healthcheck process. Do not create per-service macOS accounts.

The compose adapter should generate a narrow policy per process:

- `network.mode: local` with loopback/private access explicitly acknowledged;
- the checkout/project root as the smallest practical `filesystem.read_write` grant;
- the service directory as `working_directory`;
- only the resolved executable plus required system runtime files outside that workspace;
- a cleared environment rebuilt from admitted compose/runtime values.

This protects the rest of the home directory and host filesystem from accidental or compromised local service code while preserving normal local inter-service networking. For stronger tenant-grade network isolation, use the Linux namespace backend rather than treating macOS local mode as equivalent.
