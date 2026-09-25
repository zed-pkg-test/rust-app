#!/usr/bin/env python3
import ipaddress
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
path = ROOT / (sys.argv[1] if len(sys.argv) > 1 else "deploy/topology.prod.json")

def fail(message: str) -> None:
    raise SystemExit(f"deployment-topology: {message}")

data = json.loads(path.read_text())

if data.get("schemaVersion") != "beamscale.deploy-topology.v1":
    fail("unsupported schemaVersion")
if data.get("platform") != "beamscale":
    fail("platform must be beamscale")
if data.get("environment") != "prod":
    fail("production topology must declare environment=prod")

k8s = data.get("kubernetes", {})
clusters = k8s.get("clusters", [])
if k8s.get("enabled"):
    if len(clusters) != 2:
        fail("production Kubernetes requires exactly two independent regional clusters")
    ids = [c.get("id") for c in clusters]
    regions = [c.get("region") for c in clusters]
    if len(set(ids)) != 2 or any(not x for x in ids):
        fail("Kubernetes cluster ids must be non-empty and unique")
    if len(set(regions)) != 2 or any(not x for x in regions):
        fail("Kubernetes clusters must be in two distinct regions")
    for c in clusters:
        if int(c.get("controlPlaneNodes", 0)) < 3:
            fail(f"{c.get('id')}: controlPlaneNodes must be >= 3")
    cidrs = []
    for c in clusters:
        for key in ("podCidr", "serviceCidr"):
            try:
                cidrs.append((c["id"], key, ipaddress.ip_network(c[key], strict=False)))
            except Exception as exc:
                fail(f"{c.get('id')}: invalid {key}: {exc}")
    for i, left in enumerate(cidrs):
        for right in cidrs[i + 1:]:
            if left[2].overlaps(right[2]):
                fail(f"CIDR overlap: {left[0]}.{left[1]} overlaps {right[0]}.{right[1]}")

bare = data.get("bareProcess", {})
if bare.get("enabled"):
    count = int(bare.get("hostCount", 0))
    if not 3 <= count <= 9:
        fail("bare-process production fleet must contain 3-9 hosts")
    regions = bare.get("regions", [])
    if len(set(regions)) < 2:
        fail("bare-process production fleet must span at least two regions")
    if bare.get("hostConfiguration") != "nixos":
        fail("bare-process hostConfiguration must be nixos")
    if bare.get("deployer") != "colmena":
        fail("bare-process deployer must be colmena")
    if bare.get("sandbox") != "ores-proc-isolation-cli":
        fail("bare-process sandbox must be ores-proc-isolation-cli")
    policy = ROOT / bare.get("policy", "")
    if not policy.is_file():
        fail(f"declared isolation policy does not exist: {policy.relative_to(ROOT)}")

firecracker = data.get("firecracker", {})
if firecracker.get("enabled"):
    count = int(firecracker.get("hostCount", 0))
    if not 2 <= count <= 64:
        fail("Firecracker production pool must contain 2-64 hosts")
    regions = firecracker.get("regions", [])
    if len(set(regions)) < 2:
        fail("Firecracker production pool must span at least two regions")
    if firecracker.get("hostConfiguration") != "nixos":
        fail("Firecracker hostConfiguration must be nixos")
    if firecracker.get("deployer") != "colmena":
        fail("Firecracker deployer must be colmena")
    if firecracker.get("hypervisor") != "firecracker":
        fail("Firecracker pool hypervisor must be firecracker")
    if firecracker.get("jailerRequired") is not True:
        fail("Firecracker jailerRequired must be true")
    if firecracker.get("signedControlPlaneRequired") is not True:
        fail("Firecracker signedControlPlaneRequired must be true")
    if firecracker.get("controlContractVersion") != "bmscl.runtime-control.v1":
        fail("Firecracker controlContractVersion must be bmscl.runtime-control.v1")
    if firecracker.get("nonceReplayProtection") is not True:
        fail("Firecracker nonceReplayProtection must be true")
    if not str(firecracker.get("jailerChrootBase", "")).startswith("/"):
        fail("Firecracker jailerChrootBase must be absolute")
    if int(firecracker.get("jailerUid", -1)) <= 0 or int(firecracker.get("jailerGid", -1)) <= 0:
        fail("Firecracker jailer UID/GID must be non-root positive integers")
    if firecracker.get("kvmRequired") is not True:
        fail("Firecracker kvmRequired must be true")
    if firecracker.get("tenantIsolation") != "single_tenant_microvm":
        fail("Firecracker tenantIsolation must be single_tenant_microvm")
    if set(firecracker.get("executionClasses", [])) != {"phoenix", "durable_actor"}:
        fail("Firecracker executionClasses must be exactly phoenix + durable_actor")
    if firecracker.get("guestTransport") != "vsock":
        fail("Firecracker guestTransport must be vsock")
    if firecracker.get("rootFilesystem") != "read_only":
        fail("Firecracker rootFilesystem must be read_only")
    if int(firecracker.get("writableTmpfsMiB", 0)) <= 0:
        fail("Firecracker writableTmpfsMiB must be positive")
    if firecracker.get("osProcessSpawnDefault") != "deny":
        fail("Firecracker OS process spawning must default deny")
    if firecracker.get("nativeCodeDefault") != "deny":
        fail("Firecracker native code must default deny")
    contract = ROOT / firecracker.get("contract", "")
    if not contract.is_file():
        fail(f"declared Firecracker contract does not exist: {contract.relative_to(ROOT)}")
    contract_data = json.loads(contract.read_text())
    if contract_data.get("schemaVersion") != "beamscale.firecracker-runtime.v1":
        fail("unsupported Firecracker runtime contract schema")
    if set(contract_data.get("acceptedExecutionClasses", [])) != {"phoenix", "durable_actor"}:
        fail("Firecracker contract must accept exactly phoenix + durable_actor")
    if contract_data.get("requiredBackend") != "firecracker":
        fail("Firecracker contract requiredBackend must be firecracker")
    if contract_data.get("tenantIsolation") != "single_tenant_microvm":
        fail("Firecracker contract must require single-tenant microVM isolation")
    host_isolation = contract_data.get("hostIsolation", {})
    if host_isolation.get("launcher") != "jailer" or host_isolation.get("jailerRequired") is not True:
        fail("Firecracker contract must require the jailer launcher")
    auth = contract_data.get("controlAuthentication", {})
    if auth.get("required") is not True or auth.get("scheme") != "hmac-sha256":
        fail("Firecracker contract must require HMAC-SHA256 control authentication")
    if auth.get("contractVersion") != "bmscl.runtime-control.v1":
        fail("Firecracker contract control auth version is invalid")
    if auth.get("exactRequestSha256") is not True or auth.get("nonceReplay") != "reject_once_consumed":
        fail("Firecracker control auth must bind exact request bytes and reject nonce replay")
    guest = contract_data.get("guest", {})
    if guest.get("transport") != "vsock":
        fail("Firecracker guest contract must use vsock")
    if guest.get("rootFilesystem") != "read_only":
        fail("Firecracker guest root filesystem must be read-only")
    if guest.get("osProcessSpawn") != "denied_by_default":
        fail("Firecracker guest OS process spawn must be denied by default")
    if guest.get("nativeCode") != "denied_by_default":
        fail("Firecracker guest native code must be denied by default")

if not k8s.get("enabled") and not bare.get("enabled") and not firecracker.get("enabled"):
    fail("at least one production deployment backend must be enabled")

if firecracker.get("enabled") and bare.get("enabled"):
    if firecracker.get("poolId") in (None, "", "bare-process"):
        fail("Firecracker poolId must identify a dedicated pool")

print(f"validated {path.relative_to(ROOT)}")
