#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/rust-lib-main-ancestry-test.XXXXXXXX")"
trap 'rm -rf "$TEMP_ROOT"' EXIT HUP INT TERM
ORIGIN="$TEMP_ROOT/origin.git"
WORK="$TEMP_ROOT/work"
EVIDENCE="$TEMP_ROOT/evidence.json"

git init -q --bare "$ORIGIN"
git init -q -b main "$WORK"
git -C "$WORK" config user.name "Cargo Zed Interop Test"
git -C "$WORK" config user.email "cargo-zed-interop@example.invalid"
printf 'one\n' > "$WORK/value.txt"
git -C "$WORK" add value.txt
git -C "$WORK" commit -q -m one
CERTIFIED_REF="$(git -C "$WORK" rev-parse HEAD)"
printf 'two\n' >> "$WORK/value.txt"
git -C "$WORK" commit -qam two
git -C "$WORK" remote add origin "$ORIGIN"
git -C "$WORK" push -q -u origin main

RUST_LIB_REPOSITORY="$ORIGIN" \
RUST_LIB_REF="$CERTIFIED_REF" \
  "$ROOT/scripts/verify-rust-lib-main-ancestry.sh" "$EVIDENCE"

python3 - "$EVIDENCE" "$CERTIFIED_REF" <<'PY'
import json
import sys
from pathlib import Path

payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
assert payload["schema"] == "zed-pkg-test/rust-lib-main-ancestry/v1"
assert payload["certified_ref"] == sys.argv[2]
assert payload["certified_ref_is_main_ancestor"] is True
assert len(payload["observed_main_tip"]) == 40
PY

git -C "$WORK" switch -q -c unmerged "$CERTIFIED_REF"
printf 'side\n' > "$WORK/side.txt"
git -C "$WORK" add side.txt
git -C "$WORK" commit -q -m side
UNMERGED_REF="$(git -C "$WORK" rev-parse HEAD)"
git -C "$WORK" push -q origin unmerged

if RUST_LIB_REPOSITORY="$ORIGIN" RUST_LIB_REF="$UNMERGED_REF" \
  "$ROOT/scripts/verify-rust-lib-main-ancestry.sh" >/dev/null 2>&1
then
  echo "expected an unmerged rust-lib ref to fail ancestry validation" >&2
  exit 1
fi

if RUST_LIB_REPOSITORY="$ORIGIN" RUST_LIB_REF="not-a-commit" \
  "$ROOT/scripts/verify-rust-lib-main-ancestry.sh" >/dev/null 2>&1
then
  echo "expected an invalid rust-lib ref to fail validation" >&2
  exit 1
fi
