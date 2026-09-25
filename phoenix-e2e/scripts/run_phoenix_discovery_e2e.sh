#!/usr/bin/env bash
set -euo pipefail

: "${BMSCL_CLI_DIR:?set BMSCL_CLI_DIR}"

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

pushd "$FIXTURE" >/dev/null
mix deps.get
mix compile

"$CLI" phoenix-plan .   --router BmsclPhoenixFixtureWeb.Router   --endpoint BmsclPhoenixFixtureWeb.Endpoint   --socket-path /manual-socket   --output ".bmscl-e2e-out/plan-a.json"

"$CLI" phoenix-plan .   --router BmsclPhoenixFixtureWeb.Router   --endpoint BmsclPhoenixFixtureWeb.Endpoint   --socket-path /manual-socket   --output ".bmscl-e2e-out/plan-b.json"
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

sha256sum "$OUT/plan-a.json"
rm -rf "$FIXTURE_OUT"
