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
CARGO_HOME_DIR="$TEMP_ROOT/cargo-home"
EVIDENCE="$TEMP_ROOT/evidence"
RUST_LIB="$TEMP_ROOT/rust-lib"
DRIFT="$TEMP_ROOT/cargo-lock-drift"
IMAGE="zed-pkg-test/rust-cargo-e2e:$RUN_ID"

rm -rf \
  "$CONTEXT" \
  "$REGISTRY" \
  "$HOME_DIR" \
  "$CARGO_HOME_DIR" \
  "$EVIDENCE" \
  "$RUST_LIB" \
  "$DRIFT"
mkdir -p "$CONTEXT" "$REGISTRY" "$HOME_DIR" "$CARGO_HOME_DIR" "$EVIDENCE"

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

assert_lock_unchanged() {
  local expected="$1"
  test "$(git -C "$WORKSPACE" hash-object Cargo.lock)" = "$expected"
}

cd "$WORKSPACE"

test -f Cargo.lock
test ! -e .zpkg.lock

# Cargo and Zed describe complementary ownership domains.
docker run --rm -i \
  --volume "$WORKSPACE:/work:ro" \
  --workdir /work \
  python:3.12-bookworm \
  python3 - <<'PY'
import tomllib
from pathlib import Path

with Path("Cargo.toml").open("rb") as handle:
    cargo = tomllib.load(handle)
with Path(".zpkg.toml").open("rb") as handle:
    zed = tomllib.load(handle)

package = cargo["package"]
zed_package = zed["package"]
assert package["name"] == zed_package["name"] == "rust-app"
assert package["version"] == zed_package["version"] == "0.2.0"
assert package["description"] == zed_package["description"]
assert package["license"] == zed_package["license"]
assert package["publish"] is False
assert package["resolver"] == "2"
assert package["rust-version"] == "1.88"
assert zed_package["org"] == "zed-pkg-test"

normal = cargo["dependencies"]["rust-lib"]
build = cargo["build-dependencies"]["rust-lib"]
assert normal["path"] == ".vendor/.zed/zed-pkg-test/rust-lib"
assert normal["features"] == ["uppercase"]
assert build["path"] == normal["path"]
assert build["default-features"] is False
assert cargo["dependencies"]["unicode-ident"] == "=1.0.24"
assert zed["dependencies"] == {"zed-pkg-test/rust-lib": "^1.0.1"}
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

# The Zed-distributed crate is independently valid under both Cargo feature sets.
docker run --rm \
  --volume "$RUST_LIB:/source:ro" \
  --volume "$CARGO_HOME_DIR:/cargo-home" \
  --workdir /tmp \
  rust:1.97-bookworm \
  sh -euc '
    cp -a /source /tmp/package
    chmod -R u+w /tmp/package
    cd /tmp/package
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo test --quiet
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo test --quiet --all-features
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo package --allow-dirty --quiet
    test ! -e .zpkg.lock
  '
test -z "$(git -C "$RUST_LIB" status --porcelain)"
test "$(git -C "$RUST_LIB" rev-parse HEAD)" = "$RUST_LIB_REF"

# Publish only to a disposable file registry.
docker run --rm \
  --volume "$RUST_LIB:/source:ro" \
  --volume "$REGISTRY:/registry" \
  --volume "$CARGO_HOME_DIR:/cargo-home" \
  --workdir /tmp \
  "$IMAGE" \
  sh -euc '
    cp -a /source /tmp/package
    chmod -R u+w /tmp/package
    cd /tmp/package
    CARGO_HOME=/cargo-home zed publish \
      --registry file:///registry \
      --skip-vcs-checks
  '
test -z "$(git -C "$RUST_LIB" status --porcelain)"
test "$(git -C "$RUST_LIB" rev-parse HEAD)" = "$RUST_LIB_REF"
if ! find "$REGISTRY" -type f -print -quit | grep -q .; then
  echo "zed publish produced no registry artifact" >&2
  exit 1
fi

rm -rf .vendor/.zed .zed .zpkg.lock target
CARGO_LOCK_HASH="$(git hash-object Cargo.lock)"

# Symlink mode proves the store-backed development layout and warms Cargo's
# crates.io cache. Neither tool may rewrite the other tool's lockfile.
docker run --rm \
  --volume "$WORKSPACE:/work" \
  --volume "$REGISTRY:/registry:ro" \
  --volume "$HOME_DIR:/zed-home" \
  --volume "$CARGO_HOME_DIR:/cargo-home" \
  --volume "$EVIDENCE:/evidence" \
  --workdir /work \
  "$IMAGE" \
  sh -euc '
    zed install \
      --registry file:///registry \
      --home /zed-home \
      --install-mode symlink
    test -L .vendor/.zed/zed-pkg-test/rust-lib
    test -f .zpkg.lock
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo run --locked --quiet
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo test --locked --all-targets --quiet
    CARGO_HOME=/cargo-home cargo metadata --locked --format-version 1 > /evidence/metadata.json
  '
assert_lock_unchanged "$CARGO_LOCK_HASH"
test -f .zpkg.lock
ZPKG_LOCK_HASH="$(sha256sum .zpkg.lock | cut -d ' ' -f1)"

python3 - "$EVIDENCE/metadata.json" <<'PY'
import json
import sys
from pathlib import Path

metadata = json.loads(Path(sys.argv[1]).read_text())
packages = {package["name"]: package for package in metadata["packages"]}
assert packages["rust-app"]["version"] == "0.2.0"
assert packages["rust-lib"]["version"] == "1.0.1"
assert packages["rust-lib"]["source"] is None
assert packages["itoa"]["version"] == "1.0.18"
assert packages["unicode-ident"]["version"] == "1.0.24"
assert packages["itoa"]["source"].startswith("registry+")
assert packages["unicode-ident"]["source"].startswith("registry+")

resolve = metadata["resolve"]
root = next(node for node in resolve["nodes"] if node["id"] == resolve["root"])
# Cargo metadata uses crate aliases in resolve.nodes[].deps[].name, not package
# spellings. Hyphenated package names therefore appear with underscores here.
dep_names = {dependency["name"] for dependency in root["deps"]}
assert dep_names == {"rust_lib", "unicode_ident"}
PY
assert_lock_unchanged "$CARGO_LOCK_HASH"
test "$(sha256sum .zpkg.lock | cut -d ' ' -f1)" = "$ZPKG_LOCK_HASH"

# A store-backed symlink is intentionally not portable without the Zed home.
if docker run --rm --network none \
  --volume "$WORKSPACE:/work:ro" \
  --volume "$CARGO_HOME_DIR:/cargo-home" \
  --workdir /work \
  rust:1.97-bookworm \
  sh -euc 'CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo run --locked --offline --quiet'
then
  echo "expected the unmounted store-backed symlink to fail" >&2
  exit 1
fi
assert_lock_unchanged "$CARGO_LOCK_HASH"
test "$(sha256sum .zpkg.lock | cut -d ' ' -f1)" = "$ZPKG_LOCK_HASH"

# Frozen copy mode replaces the symlink with portable source while preserving
# both lockfiles byte-for-byte.
docker run --rm \
  --volume "$WORKSPACE:/work" \
  --volume "$REGISTRY:/registry:ro" \
  --volume "$HOME_DIR:/zed-home" \
  --volume "$CARGO_HOME_DIR:/cargo-home" \
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
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo run --locked --quiet
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo test --locked --all-targets --quiet
  '
assert_lock_unchanged "$CARGO_LOCK_HASH"
test "$(sha256sum .zpkg.lock | cut -d ' ' -f1)" = "$ZPKG_LOCK_HASH"

# The copied package and warmed Cargo cache work in a fresh, network-disabled
# Rust container with no Zed store or registry mounted.
docker run --rm --network none \
  --volume "$WORKSPACE:/work:ro" \
  --volume "$CARGO_HOME_DIR:/cargo-home" \
  --workdir /work \
  rust:1.97-bookworm \
  sh -euc '
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo run --locked --offline --quiet
    CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo test --locked --offline --all-targets --quiet
  '
assert_lock_unchanged "$CARGO_LOCK_HASH"
test "$(sha256sum .zpkg.lock | cut -d ' ' -f1)" = "$ZPKG_LOCK_HASH"

# Cargo requirement drift is rejected by --locked and cannot mutate the Zed
# lock. This uses an isolated copy so the reviewed source remains unchanged.
mkdir -p "$DRIFT"
git archive HEAD | tar -x -C "$DRIFT"
cp -a .vendor "$DRIFT/.vendor"
cp .zpkg.lock "$DRIFT/.zpkg.lock"
sed -i 's/unicode-ident = "=1.0.24"/unicode-ident = "=1.0.23"/' "$DRIFT/Cargo.toml"
DRIFT_ZPKG_HASH="$(sha256sum "$DRIFT/.zpkg.lock" | cut -d ' ' -f1)"
if docker run --rm --network none \
  --volume "$DRIFT:/work" \
  --volume "$CARGO_HOME_DIR:/cargo-home" \
  --workdir /work \
  rust:1.97-bookworm \
  sh -euc 'CARGO_HOME=/cargo-home CARGO_TARGET_DIR=/tmp/target cargo check --locked --offline'
then
  echo "expected Cargo.lock drift to fail under --locked" >&2
  exit 1
fi
test "$(sha256sum "$DRIFT/.zpkg.lock" | cut -d ' ' -f1)" = "$DRIFT_ZPKG_HASH"

assert_lock_unchanged "$CARGO_LOCK_HASH"
test "$(sha256sum .zpkg.lock | cut -d ' ' -f1)" = "$ZPKG_LOCK_HASH"
test -z "$(git status --porcelain --untracked-files=all)"
