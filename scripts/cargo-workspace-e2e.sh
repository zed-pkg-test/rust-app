#!/usr/bin/env bash
set -euo pipefail

: "${ZED_INTERFACES_REF:?ZED_INTERFACES_REF is required}"
: "${ZED_CLI_REF:?ZED_CLI_REF is required}"
: "${RUST_LIB_REF:?RUST_LIB_REF is required}"

ROOT="${GITHUB_WORKSPACE:-$(pwd)}"
FIXTURE="$ROOT/fixtures/cargo-workspace"
TMP="${RUNNER_TEMP:-${TMPDIR:-/tmp}/zed-cargo-workspace}"
CONTEXT="$TMP/context"
REGISTRY="$TMP/registry"
ZED_HOME="$TMP/zed-home"
CARGO_HOME_DIR="$TMP/cargo-home"
LIB="$TMP/rust-lib"
IMAGE="zed-pkg-test/cargo-workspace:${GITHUB_SHA:-local}"

rm -rf "$CONTEXT" "$REGISTRY" "$ZED_HOME" "$CARGO_HOME_DIR" "$LIB"
mkdir -p "$CONTEXT" "$REGISTRY" "$ZED_HOME" "$CARGO_HOME_DIR"

clone_at() {
  local url="$1" ref="$2" destination="$3"
  git init -q "$destination"
  git -C "$destination" remote add origin "$url"
  git -C "$destination" fetch --depth 1 origin "$ref"
  git -C "$destination" checkout -q --detach FETCH_HEAD
  test "$(git -C "$destination" rev-parse HEAD)" = "$ref"
}

clone_at https://github.com/zed-pkg/zed-interfaces.git "$ZED_INTERFACES_REF" "$CONTEXT/zed-interfaces"
clone_at https://github.com/zed-pkg/zed-cli.git "$ZED_CLI_REF" "$CONTEXT/zed-cli"
docker build -q -f "$ROOT/.github/docker/Dockerfile" -t "$IMAGE" "$CONTEXT"

clone_at https://github.com/zed-pkg-test/rust-lib.git "$RUST_LIB_REF" "$LIB"
docker run --rm \
  -v "$LIB:/source:ro" \
  -v "$REGISTRY:/registry" \
  -v "$CARGO_HOME_DIR:/cargo-home" \
  -w /tmp "$IMAGE" sh -euc '
    cp -a /source /tmp/package
    chmod -R u+w /tmp/package
    cd /tmp/package
    CARGO_HOME=/cargo-home cargo test --quiet --all-features
    CARGO_HOME=/cargo-home zed publish --registry file:///registry --skip-vcs-checks
  '
test -z "$(git -C "$LIB" status --porcelain)"
test -n "$(find "$REGISTRY" -type f -print -quit)"

rm -rf "$FIXTURE/.vendor" "$FIXTURE/.zed" "$FIXTURE/.zpkg.lock" "$FIXTURE/target"
CARGO_HASH="$(git -C "$ROOT" hash-object fixtures/cargo-workspace/Cargo.lock)"

# Development layout: product-generated Cargo wiring must match the fragment the
# consumer deliberately merged into .cargo/config.toml.
docker run --rm \
  -v "$FIXTURE:/work" \
  -v "$REGISTRY:/registry:ro" \
  -v "$ZED_HOME:/zed-home" \
  -v "$CARGO_HOME_DIR:/cargo-home" \
  -w /work "$IMAGE" sh -euc '
    zed install --registry file:///registry --home /zed-home --install-mode symlink
    test -L .vendor/.zed/zed-pkg-test/rust-lib
    test -f .zpkg.lock
    test -f .zed/cargo-paths.toml
    test -f .zed/paths.json
    grep -Fq "zed-pkg-test/rust-lib" .zed/paths.json
    python3 - <<"PY"
import tomllib
from pathlib import Path
with Path(".zed/cargo-paths.toml").open("rb") as handle:
    generated = tomllib.load(handle)
with Path(".cargo/config.toml").open("rb") as handle:
    consumed = tomllib.load(handle)
assert generated["paths"] == consumed["paths"]
assert generated["patch"]["crates-io"] == consumed["patch"]["crates-io"]
PY
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo run --locked -q -p workspace-app
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo test --locked -q --workspace --all-targets
  '
test "$(git -C "$ROOT" hash-object fixtures/cargo-workspace/Cargo.lock)" = "$CARGO_HASH"
ZPKG_HASH="$(sha256sum "$FIXTURE/.zpkg.lock" | cut -d ' ' -f1)"

# The symlink must not appear portable when its Zed store is absent.
if docker run --rm --network none \
  -v "$FIXTURE:/work:ro" \
  -v "$CARGO_HOME_DIR:/cargo-home" \
  -w /work rust:1.97-bookworm sh -euc '
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo run --locked --offline -p workspace-app
  '
then
  echo "expected missing Zed store to break symlink mode" >&2
  exit 1
fi

# Frozen copy mode must preserve both locks and run with no Zed store, registry,
# or network after Cargo's registry cache is warm.
docker run --rm \
  -v "$FIXTURE:/work" \
  -v "$REGISTRY:/registry:ro" \
  -v "$ZED_HOME:/zed-home" \
  -v "$CARGO_HOME_DIR:/cargo-home" \
  -w /work "$IMAGE" sh -euc '
    zed install --frozen --registry file:///registry --home /zed-home --install-mode copy
    test ! -L .vendor/.zed/zed-pkg-test/rust-lib
    test -z "$(find .vendor/.zed -type l -print -quit)"
  '
test "$(git -C "$ROOT" hash-object fixtures/cargo-workspace/Cargo.lock)" = "$CARGO_HASH"
test "$(sha256sum "$FIXTURE/.zpkg.lock" | cut -d ' ' -f1)" = "$ZPKG_HASH"

docker run --rm --network none \
  -v "$FIXTURE:/work:ro" \
  -v "$CARGO_HOME_DIR:/cargo-home" \
  -w /work rust:1.97-bookworm sh -euc '
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo run --locked --offline -q -p workspace-app
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo test --locked --offline -q --workspace --all-targets
  '
test "$(git -C "$ROOT" hash-object fixtures/cargo-workspace/Cargo.lock)" = "$CARGO_HASH"
test "$(sha256sum "$FIXTURE/.zpkg.lock" | cut -d ' ' -f1)" = "$ZPKG_HASH"

rm -rf "$FIXTURE/.vendor" "$FIXTURE/.zed" "$FIXTURE/.zpkg.lock" "$FIXTURE/target"
test -z "$(git -C "$ROOT" status --porcelain --untracked-files=all)"
