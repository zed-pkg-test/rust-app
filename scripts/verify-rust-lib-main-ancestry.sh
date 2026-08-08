#!/usr/bin/env bash
set -euo pipefail

: "${RUST_LIB_REF:?RUST_LIB_REF is required}"

RUST_LIB_REPOSITORY="${RUST_LIB_REPOSITORY:-https://github.com/zed-pkg-test/rust-lib.git}"
EVIDENCE_PATH="${1:-}"

if [[ ! "$RUST_LIB_REF" =~ ^[0-9a-f]{40}$ ]]; then
  echo "RUST_LIB_REF must be a lowercase 40-character Git commit" >&2
  exit 2
fi

TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rust-lib-main-ancestry.XXXXXXXX")"
trap 'rm -rf "$TEMP_ROOT"' EXIT HUP INT TERM
CHECKOUT="$TEMP_ROOT/repository"

git init -q "$CHECKOUT"
git -C "$CHECKOUT" remote add origin "$RUST_LIB_REPOSITORY"
git -C "$CHECKOUT" fetch --quiet --no-tags --prune \
  origin refs/heads/main:refs/remotes/origin/main

MAIN_TIP="$(git -C "$CHECKOUT" rev-parse refs/remotes/origin/main)"
if ! git -C "$CHECKOUT" cat-file -e "$RUST_LIB_REF^{commit}" 2>/dev/null; then
  echo "certified rust-lib ref is not reachable from fetched main history" >&2
  exit 1
fi
if ! git -C "$CHECKOUT" merge-base --is-ancestor "$RUST_LIB_REF" "$MAIN_TIP"; then
  echo "certified rust-lib ref is not an ancestor of rust-lib/main" >&2
  exit 1
fi

if [[ -n "$EVIDENCE_PATH" ]]; then
  mkdir -p "$(dirname "$EVIDENCE_PATH")"
  python3 - "$EVIDENCE_PATH" "$RUST_LIB_REF" "$MAIN_TIP" "$RUST_LIB_REPOSITORY" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "schema": "zed-pkg-test/rust-lib-main-ancestry/v1",
    "repository": sys.argv[4],
    "certified_ref": sys.argv[2],
    "observed_main_tip": sys.argv[3],
    "certified_ref_is_main_ancestor": True,
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
fi

printf 'certified rust-lib ref %s is in main ancestry at %s\n' \
  "$RUST_LIB_REF" "$MAIN_TIP"
