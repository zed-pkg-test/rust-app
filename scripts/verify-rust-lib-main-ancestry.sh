#!/usr/bin/env bash
set -euo pipefail

: "${RUST_LIB_REF:?RUST_LIB_REF is required}"
: "${RUST_LIB_REVIEWED_MERGE_REF:?RUST_LIB_REVIEWED_MERGE_REF is required}"

RUST_LIB_REPOSITORY="${RUST_LIB_REPOSITORY:-https://github.com/zed-pkg-test/rust-lib.git}"
EVIDENCE_PATH="${1:-}"

for name in RUST_LIB_REF RUST_LIB_REVIEWED_MERGE_REF; do
  value="${!name}"
  if [[ ! "$value" =~ ^[0-9a-f]{40}$ ]]; then
    echo "$name must be a lowercase 40-character Git commit" >&2
    exit 2
  fi
done

TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rust-lib-main-ancestry.XXXXXXXX")"
trap 'rm -rf "$TEMP_ROOT"' EXIT HUP INT TERM
CHECKOUT="$TEMP_ROOT/repository"

git init -q "$CHECKOUT"
git -C "$CHECKOUT" remote add origin "$RUST_LIB_REPOSITORY"
git -C "$CHECKOUT" fetch --quiet --no-tags --prune \
  origin refs/heads/main:refs/remotes/origin/main

# Fetch the certified ref explicitly as well. On hosts that permit fetching a
# reachable object by SHA this lets the ancestry check distinguish a fetchable
# side-branch commit from one that actually passed through reviewed main.
git -C "$CHECKOUT" fetch --quiet --no-tags origin "$RUST_LIB_REF" || true

MAIN_TIP="$(git -C "$CHECKOUT" rev-parse refs/remotes/origin/main)"
for ref in "$RUST_LIB_REF" "$RUST_LIB_REVIEWED_MERGE_REF"; do
  if ! git -C "$CHECKOUT" cat-file -e "$ref^{commit}" 2>/dev/null; then
    echo "required rust-lib commit is not present in fetched history" >&2
    exit 1
  fi
done

read -r -a merge_line <<<"$(git -C "$CHECKOUT" rev-list --parents -n 1 "$RUST_LIB_REVIEWED_MERGE_REF")"
if (( ${#merge_line[@]} < 3 )); then
  echo "reviewed rust-lib integration ref is not a merge commit" >&2
  exit 1
fi
if ! git -C "$CHECKOUT" merge-base --is-ancestor \
  "$RUST_LIB_REF" "$RUST_LIB_REVIEWED_MERGE_REF"
then
  echo "certified rust-lib ref is not an ancestor of the reviewed merge" >&2
  exit 1
fi
if ! git -C "$CHECKOUT" merge-base --is-ancestor \
  "$RUST_LIB_REVIEWED_MERGE_REF" "$MAIN_TIP"
then
  echo "reviewed rust-lib merge is not an ancestor of rust-lib/main" >&2
  exit 1
fi

if [[ -n "$EVIDENCE_PATH" ]]; then
  mkdir -p "$(dirname "$EVIDENCE_PATH")"
  python3 - \
    "$EVIDENCE_PATH" \
    "$RUST_LIB_REF" \
    "$RUST_LIB_REVIEWED_MERGE_REF" \
    "$MAIN_TIP" \
    "$RUST_LIB_REPOSITORY" <<'PY'
import json
import sys
from pathlib import Path

path = Path(sys.argv[1])
payload = {
    "schema": "zed-pkg-test/rust-lib-main-ancestry/v2",
    "repository": sys.argv[5],
    "certified_ref": sys.argv[2],
    "reviewed_merge_ref": sys.argv[3],
    "observed_main_tip": sys.argv[4],
    "certified_ref_is_reviewed_merge_ancestor": True,
    "reviewed_merge_is_main_ancestor": True,
}
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
fi

printf 'certified rust-lib ref %s reached main through reviewed merge %s; observed tip %s\n' \
  "$RUST_LIB_REF" "$RUST_LIB_REVIEWED_MERGE_REF" "$MAIN_TIP"
