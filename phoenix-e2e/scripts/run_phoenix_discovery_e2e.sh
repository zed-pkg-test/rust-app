#!/usr/bin/env bash
set -euo pipefail

: "${BMSCL_CLI_DIR:?set BMSCL_CLI_DIR}"
: "${BMSCL_COMPILER_DIR:?set BMSCL_COMPILER_DIR}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FIXTURE="$ROOT/fixtures/phoenix-discovery"
OUT="$ROOT/evidence/run/phoenix-discovery"
FIXTURE_OUT="$FIXTURE/.bmscl-e2e-out"

rm -rf "$OUT" "$FIXTURE_OUT"
mkdir -p "$OUT" "$FIXTURE_OUT"

pushd "$BMSCL_CLI_DIR" >/dev/null
cargo test --all-targets
cargo build
CLI="$BMSCL_CLI_DIR/target/debug/bmscl"
popd >/dev/null

pushd "$BMSCL_COMPILER_DIR" >/dev/null
cargo test --all-targets
cargo build
COMPILER="$BMSCL_COMPILER_DIR/target/debug/bmscl-compiler"
popd >/dev/null

pushd "$FIXTURE" >/dev/null
mix deps.get
mix compile

"$CLI" phoenix-plan . \
  --router BmsclPhoenixFixtureWeb.Router \
  --endpoint BmsclPhoenixFixtureWeb.Endpoint \
  --socket-path /manual-socket \
  --output ".bmscl-e2e-out/plan-a.json"

"$CLI" phoenix-plan . \
  --router BmsclPhoenixFixtureWeb.Router \
  --endpoint BmsclPhoenixFixtureWeb.Endpoint \
  --socket-path /manual-socket \
  --output ".bmscl-e2e-out/plan-b.json"

MIX_ENV=prod mix release --overwrite
popd >/dev/null

cmp "$FIXTURE_OUT/plan-a.json" "$FIXTURE_OUT/plan-b.json"
cp "$FIXTURE_OUT/plan-a.json" "$OUT/plan-a.json"

python3 - "$OUT/plan-a.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
plan = json.loads(path.read_text())

assert plan["schema_version"] == "bmscl.phoenix.discovery.v2"
assert plan["build_granularity"] == "application_generation"
assert plan["isolation_class"] == "firecracker"
assert plan["router"] == "BmsclPhoenixFixtureWeb.Router"
assert plan["endpoint"] == "BmsclPhoenixFixtureWeb.Endpoint"

routes = {(r["method"], r["path"], r["execution_class"], r["protocol"]) for r in plan["routes"]}
assert ("GET", "/health", "request", "http") in routes
assert ("GET", "/dashboard", "request", "http") in routes
assert ("GET", "/live-dashboard", "request", "http") in routes
assert ("POST", "/api/users", "request", "http") in routes

connections = {(r["path"], r["execution_class"], r["protocol"]) for r in plan["connections"]}
assert ("/socket", "connection", "websocket") in connections
assert ("/live", "connection", "websocket") in connections
assert ("/manual-socket", "connection", "websocket") in connections

paths = [r["path"] for r in plan["connections"]]
assert paths == sorted(set(paths)), paths

print("PASS: Phoenix route/socket discovery v2 is deterministic and Firecracker-classed")
PY

SOURCE_SHA="$(python3 - "$FIXTURE" <<'PY'
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
excluded = {"_build", "deps", ".bmscl-e2e-out"}
h = hashlib.sha256()
files = [
    p for p in root.rglob("*")
    if p.is_file() and not any(part in excluded for part in p.relative_to(root).parts)
]
for path in sorted(files):
    rel = path.relative_to(root).as_posix().encode()
    data = path.read_bytes()
    h.update(len(rel).to_bytes(4, "big"))
    h.update(rel)
    h.update(len(data).to_bytes(8, "big"))
    h.update(data)
print(h.hexdigest())
PY
)"

KEY="$OUT/test-signing-key.hex"
printf '%064d\n' 1 > "$KEY"

"$COMPILER" phoenix-package \
  --release-dir "$FIXTURE/_build/prod/rel/bmscl_phoenix_fixture" \
  --out-dir "$OUT/artifact" \
  --app bmscl_phoenix_fixture \
  --version 0.1.0 \
  --router BmsclPhoenixFixtureWeb.Router \
  --endpoint BmsclPhoenixFixtureWeb.Endpoint \
  --route-plan "$OUT/plan-a.json" \
  --source-sha256 "$SOURCE_SHA" \
  --builder-image-digest "sha256:$(printf 'a%.0s' {1..64})" \
  --signing-key "$KEY" \
  --key-id phoenix-e2e

PUBLIC_KEY="$("$COMPILER" public-key --signing-key "$KEY")"
"$COMPILER" verify "$OUT/artifact" \
  --public-key "$PUBLIC_KEY" \
  --key-id phoenix-e2e

python3 - "$OUT/artifact/manifest.json" "$OUT/artifact/route-plan.json" <<'PY'
import hashlib
import json
import pathlib
import sys

manifest = json.loads(pathlib.Path(sys.argv[1]).read_text())
route_bytes = pathlib.Path(sys.argv[2]).read_bytes()

assert manifest["profile"] == "bmscl-phoenix-elixir-v1"
assert manifest["execution_class"] == "phoenix"
assert manifest["isolation_class"] == "firecracker"
assert manifest["artifact_root"] == "release"
assert manifest["route_plan_sha256"] == hashlib.sha256(route_bytes).hexdigest()
PY

cp "$OUT/artifact/route-plan.json" "$OUT/route-plan.backup.json"
python3 - "$OUT/artifact/route-plan.json" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
doc = json.loads(path.read_text())
doc["router"] = "Tampered.Router"
path.write_text(json.dumps(doc, indent=2) + "\n")
PY

if "$COMPILER" verify "$OUT/artifact" \
  --public-key "$PUBLIC_KEY" \
  --key-id phoenix-e2e; then
  echo "FAIL: tampered Phoenix route plan was accepted" >&2
  exit 1
fi

cp "$OUT/route-plan.backup.json" "$OUT/artifact/route-plan.json"
"$COMPILER" verify "$OUT/artifact" \
  --public-key "$PUBLIC_KEY" \
  --key-id phoenix-e2e >/dev/null

sha256sum "$OUT/plan-a.json"
sha256sum "$OUT/artifact/phoenix-release.tar.gz"
rm -f "$KEY"
rm -rf "$FIXTURE_OUT"
printf 'PASS: Phoenix discovery, release packaging, signing, verification and tamper rejection\n'
