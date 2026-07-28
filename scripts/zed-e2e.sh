#!/usr/bin/env bash
set -euo pipefail

: "${ZED_INTERFACES_REF:?ZED_INTERFACES_REF is required}"
: "${ZED_CLI_REF:?ZED_CLI_REF is required}"
: "${RUST_LIB_REF:?RUST_LIB_REF is required}"

WORKSPACE="${GITHUB_WORKSPACE:-$(pwd)}"
TEMP_ROOT="${RUNNER_TEMP:-${TMPDIR:-/tmp}/zed-pkg-test-rust}"
RUN_ID="${GITHUB_SHA:-local}"
CONTEXT="$TEMP_ROOT/zed-docker-context"
REGISTRY="$TEMP_ROOT/zed-registry"
HOME_DIR="$TEMP_ROOT/zed-home"
RUST_LIB="$TEMP_ROOT/rust-lib"
IMAGE="zed-pkg-test/rust-e2e:$RUN_ID"

rm -rf "$CONTEXT" "$REGISTRY" "$HOME_DIR" "$RUST_LIB"
mkdir -p "$CONTEXT" "$REGISTRY" "$HOME_DIR"

clone_at() {
  local repo="$1"
  local ref="$2"
  local destination="$3"
  git init -q "$destination"
  git -C "$destination" remote add origin "$repo"
  git -C "$destination" fetch --depth 1 origin "$ref"
  git -C "$destination" checkout -q --detach FETCH_HEAD
  test "$(git -C "$destination" rev-parse HEAD)" = "$ref"
}

cd "$WORKSPACE"

python3 - <<'PY'
import tomllib
from pathlib import Path

with Path("Cargo.toml").open("rb") as handle:
    cargo = tomllib.load(handle)
with Path(".zpkg.toml").open("rb") as handle:
    zed = tomllib.load(handle)
package = cargo["package"]
zed_package = zed["package"]
assert package["name"] == zed_package["name"]
assert package["version"] == zed_package["version"]
assert package["description"] == zed_package["description"]
assert package["license"] == zed_package["license"]
assert package["publish"] is False
assert zed_package["org"] == "zed-pkg-test"
assert cargo["dependencies"]["rust-lib"]["path"] == ".vendor/.zed/zed-pkg-test/rust-lib"
assert zed["dependencies"] == {"zed-pkg-test/rust-lib": "^1.0.0"}
PY

clone_at https://github.com/zed-pkg/zed-interfaces.git \
  "$ZED_INTERFACES_REF" "$CONTEXT/zed-interfaces"
clone_at https://github.com/zed-pkg/zed-cli.git \
  "$ZED_CLI_REF" "$CONTEXT/zed-cli"

docker build \
  --file "$WORKSPACE/.github/docker/Dockerfile" \
  --tag "$IMAGE" \
  "$CONTEXT"

clone_at https://github.com/zed-pkg-test/rust-lib.git \
  "$RUST_LIB_REF" "$RUST_LIB"
test -z "$(git -C "$RUST_LIB" status --porcelain)"

docker run --rm \
  --volume "$RUST_LIB:/source:ro" \
  --workdir /tmp \
  rust:bookworm \
  sh -euc '
    cp -a /source /tmp/package
    chmod -R u+w /tmp/package
    cd /tmp/package
    CARGO_TARGET_DIR=/tmp/target cargo test --quiet
    grep -Fq "zed-pkg-test/rust-lib" src/lib.rs
  '
test -z "$(git -C "$RUST_LIB" status --porcelain)"
test "$(git -C "$RUST_LIB" rev-parse HEAD)" = "$RUST_LIB_REF"

docker run --rm \
  --volume "$RUST_LIB:/source:ro" \
  --volume "$REGISTRY:/registry" \
  --workdir /tmp \
  "$IMAGE" \
  sh -euc '
    cp -a /source /tmp/package
    chmod -R u+w /tmp/package
    cd /tmp/package
    zed publish --registry file:///registry --skip-vcs-checks
  '
test -z "$(git -C "$RUST_LIB" status --porcelain)"
test "$(git -C "$RUST_LIB" rev-parse HEAD)" = "$RUST_LIB_REF"
if ! find "$REGISTRY" -type f -print -quit | grep -q .; then
  echo "zed publish produced no registry artifact" >&2
  exit 1
fi

rm -rf .vendor/.zed .zed target

docker run --rm \
  --volume "$WORKSPACE:/work" \
  --volume "$REGISTRY:/registry:ro" \
  --volume "$HOME_DIR:/zed-home" \
  --workdir /work \
  "$IMAGE" \
  sh -euc '
    zed install \
      --registry file:///registry \
      --home /zed-home \
      --install-mode symlink
    test -L .vendor/.zed/zed-pkg-test/rust-lib
    CARGO_TARGET_DIR=/tmp/target cargo run --quiet
  '

if docker run --rm \
  --volume "$WORKSPACE:/work:ro" \
  --workdir /work \
  rust:bookworm \
  sh -euc 'CARGO_TARGET_DIR=/tmp/target cargo run --quiet'
then
  echo "expected the unmounted store-backed symlink to fail" >&2
  exit 1
fi

docker run --rm \
  --volume "$WORKSPACE:/work" \
  --volume "$REGISTRY:/registry:ro" \
  --volume "$HOME_DIR:/zed-home" \
  --workdir /work \
  "$IMAGE" \
  sh -euc '
    zed install \
      --frozen \
      --registry file:///registry \
      --home /zed-home \
      --install-mode copy
    test ! -L .vendor/.zed/zed-pkg-test/rust-lib
    test -z "$(find .vendor/.zed -type l -print -quit)"
    CARGO_TARGET_DIR=/tmp/target cargo run --quiet
  '

docker run --rm \
  --volume "$WORKSPACE:/work:ro" \
  --workdir /work \
  rust:bookworm \
  sh -euc 'CARGO_TARGET_DIR=/tmp/target cargo run --quiet'
