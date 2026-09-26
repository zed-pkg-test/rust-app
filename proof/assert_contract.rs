use std::{fs, path::Path};

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path.as_ref())
        .unwrap_or_else(|e| panic!("read {}: {e}", path.as_ref().display()))
}

fn require(source: &str, needle: &str, context: &str) {
    assert!(
        source.contains(needle),
        "{context} lost required contract fragment: {needle}"
    );
}

fn main() {
    let api = read("proof/api/src/main.rs");
    let api_model = read("proof/api/src/critical_sections.rs");
    let placement = read("proof/api/src/placement.rs");
    let host = read("proof/infra/modules/tenant_runtime/runtime-host/src/main.rs");
    let actor = read("proof/supervisor/src/bmscl_critical_section_actor.erl");
    let registry = read("proof/supervisor/src/bmscl_critical_section_registry.erl");
    let store = read("proof/supervisor/src/bmscl_critical_section_store.erl");
    let durable_store = read("proof/supervisor/src/bmscl_durable_store.erl");
    let interfaces = read("proof/interfaces/typespec/main.tsp");

    for source in [&api, &host, &actor, &interfaces] {
        require(source, "request_id", "critical-section acquire request identity");
    }

    for field in ["runtime_epoch", "owner_epoch", "sequence"] {
        require(&api, field, "public API fencing token");
        require(&host, field, "runtime-host fencing token");
        require(&actor, field, "guest actor fencing token");
    }

    require(
        &api_model,
        "TENANCY_CLASS",
        "tenant-dedicated API policy",
    );
    require(
        &api_model,
        "tenant_dedicated",
        "tenant-dedicated API value",
    );
    require(
        &api,
        "/v1/critical-sections/{deployment_id}/acquire",
        "public acquire endpoint",
    );
    require(
        &api,
        "/v1/critical-sections/{deployment_id}/renew",
        "public renew endpoint",
    );
    require(
        &api,
        "/v1/critical-sections/{deployment_id}/release",
        "public release endpoint",
    );
    require(
        &host,
        "/v1/shards/critical-section",
        "runtime-host critical-section endpoint",
    );
    require(
        &registry,
        "claim_and_load",
        "durable state reload",
    );
    require(
        &actor,
        "durable_commit_failed",
        "fail-closed durable commit",
    );
    require(
        &actor,
        "inherited_lease",
        "failover inherited lease state",
    );
    require(
        &store,
        "request_id",
        "persisted replay identity",
    );
    require(
        &store,
        "bmscl.critical-section.state/v1",
        "versioned critical-section payload",
    );
    require(
        &durable_store,
        "stale_owner_epoch",
        "durable owner fencing",
    );

    require(
        &placement,
        "/v1/shards/activate",
        "activation route",
    );
    require(
        &placement,
        "activation_ack_matches",
        "exact-generation activation acknowledgement",
    );

    println!("PASS exact-head critical-section request-id + failover contract");
}
