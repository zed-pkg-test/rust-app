use axum::{
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::env;
use tokio::net::TcpListener;

const HOSTED_GLEAM_PROFILE: &str = "bmscl-hosted-gleam-v1";

#[derive(Debug, Deserialize)]
struct RpcRequest {
    jsonrpc: String,
    id: Value,
    method: String,
    #[serde(default)]
    params: Value,
}

#[derive(Debug, Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    id: Value,
    result: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolCall {
    name: String,
    #[serde(default)]
    arguments: Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostedWorkerManifest {
    language: String,
    profile: String,
    execution_class: String,
    isolation_class: String,
    max_processes: u32,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/mcp", post(handle_rpc));
    let bind = env::var("BMSCL_BIND").unwrap_or_else(|_| "127.0.0.1:8280".into());
    let listener = TcpListener::bind(&bind).await.expect("bind MCP");
    axum::serve(listener, app).await.expect("serve MCP");
}

async fn handle_rpc(Json(req): Json<RpcRequest>) -> Json<RpcResponse> {
    let result = dispatch(&req);
    Json(RpcResponse {
        jsonrpc: "2.0",
        id: req.id,
        result,
    })
}

fn dispatch(req: &RpcRequest) -> Value {
    if req.jsonrpc != "2.0" {
        return json!({"error": "unsupported jsonrpc version"});
    }

    match req.method.as_str() {
        "tools/list" => json!({
            "tools": [{
                "name": "worker.validate_manifest",
                "description": "Validate a hosted Gleam worker manifest without side effects"
            }]
        }),
        "tools/call" => match serde_json::from_value::<ToolCall>(req.params.clone()) {
            Ok(call) => call_tool(call),
            Err(error) => json!({"error": "invalid tools/call parameters", "detail": error.to_string()}),
        },
        "ping" => json!({"ok": true}),
        _ => json!({"error":"method not implemented"}),
    }
}

fn call_tool(call: ToolCall) -> Value {
    match call.name.as_str() {
        "worker.validate_manifest" => match validate_hosted_worker_manifest(&call.arguments) {
            Ok(()) => json!({"ok": true, "profile": HOSTED_GLEAM_PROFILE}),
            Err(error) => json!({"ok": false, "error": error}),
        },
        _ => json!({"error": "unknown or unavailable tool"}),
    }
}

fn validate_hosted_worker_manifest(value: &Value) -> Result<(), &'static str> {
    let manifest: HostedWorkerManifest =
        serde_json::from_value(value.clone()).map_err(|_| "invalid manifest shape")?;

    if manifest.language != "gleam"
        || manifest.profile != HOSTED_GLEAM_PROFILE
        || manifest.execution_class != "request"
        || manifest.isolation_class != "bare_process"
        || manifest.max_processes != 1
    {
        return Err("manifest does not satisfy hosted Gleam execution contract");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, params: Value) -> RpcRequest {
        RpcRequest {
            jsonrpc: "2.0".into(),
            id: json!(1),
            method: method.into(),
            params,
        }
    }

    fn valid_manifest() -> Value {
        json!({
            "language": "gleam",
            "profile": "bmscl-hosted-gleam-v1",
            "execution_class": "request",
            "isolation_class": "bare_process",
            "max_processes": 1
        })
    }

    #[test]
    fn advertised_tools_are_actually_callable() {
        let listed = dispatch(&request("tools/list", Value::Null));
        let tools = listed["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], "worker.validate_manifest");

        let result = dispatch(&request(
            "tools/call",
            json!({"name":"worker.validate_manifest","arguments":valid_manifest()}),
        ));
        assert_eq!(result["ok"], true);
    }

    #[test]
    fn does_not_advertise_unimplemented_tenant_tools() {
        let listed = dispatch(&request("tools/list", Value::Null));
        let text = listed.to_string();
        assert!(!text.contains("deployment.inspect"));
        assert!(!text.contains("invocation.inspect"));
    }

    #[test]
    fn unknown_tool_fails_closed() {
        let result = dispatch(&request(
            "tools/call",
            json!({"name":"deployment.inspect","arguments":{}}),
        ));
        assert_eq!(result["error"], "unknown or unavailable tool");
    }

    #[test]
    fn hosted_manifest_rejects_runtime_escalation() {
        let mut manifest = valid_manifest();
        manifest["isolation_class"] = json!("firecracker");
        let result = dispatch(&request(
            "tools/call",
            json!({"name":"worker.validate_manifest","arguments":manifest}),
        ));
        assert_eq!(result["ok"], false);
    }

    #[test]
    fn hosted_manifest_rejects_extra_processes() {
        let mut manifest = valid_manifest();
        manifest["max_processes"] = json!(2);
        let result = dispatch(&request(
            "tools/call",
            json!({"name":"worker.validate_manifest","arguments":manifest}),
        ));
        assert_eq!(result["ok"], false);
    }

    #[test]
    fn malformed_tool_call_fails_closed() {
        let result = dispatch(&request("tools/call", json!({"arguments":{}})));
        assert_eq!(result["error"], "invalid tools/call parameters");
    }
}
