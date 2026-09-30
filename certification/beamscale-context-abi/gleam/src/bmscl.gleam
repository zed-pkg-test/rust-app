pub const context_abi_version = "bmscl.context/v1"

pub const module_contract_version = "bmscl-module-contract-v1"

pub const module_semantics_version = "bmscl.module-semantics/v2"

pub type Request {
  Request(
    method: String,
    url: String,
    headers: List(#(String, String)),
    body: BitArray,
  )
}

pub type Response {
  Response(status: Int, headers: List(#(String, String)), body: BitArray)
}

pub opaque type ClusterCapability {
  ClusterCapability(token: BitArray)
}

pub opaque type LogCapability {
  LogCapability(token: BitArray)
}

/// Hosted v2 intentionally exposes no filesystem, process, arbitrary network,
/// KV, database, queue, env, or secret capability. Tenant code receives only
/// signed same-cluster and observability capabilities through Context.
pub type Context {
  Context(cluster: ClusterCapability, log: LogCapability, deadline_unix_ms: Int)
}

/// Canonical HTTP/lambda entrypoint shape for user code.
///
/// Giving an exported function this type (or passing it to `lambda`) makes the
/// compiler enforce the BeamScale request/context/response boundary.
pub type LambdaEntrypoint =
  fn(Request, Context) -> Response

/// Stable semantic kinds understood by the compiler and runtime.
pub type ModuleKind {
  Lambda
  Http
  Rpc
  Actor
  Worker
}

/// Declarative capability requirements. These are requests consumed by build
/// admission; opaque signed capability tokens remain the actual authority.
pub type HostedCapability {
  ClusterCall
  HttpClient
  Log
}

pub type InvocationMode {
  RequestResponse
  Mailbox
  Event
}

pub type ConcurrencyModel {
  IsolatedInvocation
  SerializedActor
}

pub type CancellationModel {
  Deadline
  Cooperative
}

pub type ModulePolicy {
  ModulePolicy(
    invocation: InvocationMode,
    concurrency: ConcurrencyModel,
    cancellation: CancellationModel,
  )
}

/// A typed user module export. The constructor is opaque so callers cannot
/// manufacture a module without providing a handler of the declared type.
pub opaque type Module(input, output) {
  Module(
    kind: ModuleKind,
    policy: ModulePolicy,
    capabilities: List(HostedCapability),
    entrypoint: fn(input, Context) -> output,
  )
}

pub fn default_policy(kind: ModuleKind) -> ModulePolicy {
  case kind {
    Actor ->
      ModulePolicy(
        invocation: Mailbox,
        concurrency: SerializedActor,
        cancellation: Cooperative,
      )
    Worker ->
      ModulePolicy(
        invocation: Event,
        concurrency: IsolatedInvocation,
        cancellation: Cooperative,
      )
    Lambda | Http | Rpc ->
      ModulePolicy(
        invocation: RequestResponse,
        concurrency: IsolatedInvocation,
        cancellation: Deadline,
      )
  }
}

/// Backward-compatible constructor using the canonical policy for `kind` and
/// no declared capability requirements.
pub fn module(
  kind: ModuleKind,
  entrypoint: fn(input, Context) -> output,
) -> Module(input, output) {
  Module(
    kind: kind,
    policy: default_policy(kind),
    capabilities: [],
    entrypoint: entrypoint,
  )
}

/// Explicit constructor used when an export needs cluster-call/log capability
/// declarations or a non-default worker policy admitted by the build profile.
pub fn module_with_policy(
  kind: ModuleKind,
  policy: ModulePolicy,
  capabilities: List(HostedCapability),
  entrypoint: fn(input, Context) -> output,
) -> Module(input, output) {
  Module(
    kind: kind,
    policy: policy,
    capabilities: capabilities,
    entrypoint: entrypoint,
  )
}

/// Wrap the standard BeamScale HTTP/lambda handler contract.
pub fn lambda(entrypoint: LambdaEntrypoint) -> Module(Request, Response) {
  module(Lambda, entrypoint)
}

/// `http` is an explicit alias for applications that distinguish an HTTP
/// module from another lambda in their source tree.
pub fn http(entrypoint: LambdaEntrypoint) -> Module(Request, Response) {
  module(Http, entrypoint)
}

/// Wrap an RPC dispatcher while preserving its input/output types.
pub fn rpc(entrypoint: fn(input, Context) -> output) -> Module(input, output) {
  module(Rpc, entrypoint)
}

/// Actor exports are mailbox-driven and serialized by construction.
pub fn actor(
  entrypoint: fn(input, Context) -> output,
) -> Module(input, output) {
  module(Actor, entrypoint)
}

/// Worker exports default to event invocation with isolated BEAM processes.
pub fn worker(
  entrypoint: fn(input, Context) -> output,
) -> Module(input, output) {
  module(Worker, entrypoint)
}

pub fn module_kind(module_export: Module(input, output)) -> ModuleKind {
  let Module(kind, _, _, _) = module_export
  kind
}

pub fn module_policy(module_export: Module(input, output)) -> ModulePolicy {
  let Module(_, policy, _, _) = module_export
  policy
}

pub fn module_capabilities(
  module_export: Module(input, output),
) -> List(HostedCapability) {
  let Module(_, _, capabilities, _) = module_export
  capabilities
}

/// Runtime/scaffold adapters use this helper rather than reaching through the
/// opaque module representation.
pub fn invoke_module(
  module_export: Module(input, output),
  input: input,
  context: Context,
) -> output {
  let Module(_, _, _, entrypoint) = module_export
  entrypoint(input, context)
}

pub fn text(status: Int, body: String) -> Response {
  Response(
    status: status,
    headers: [
      #("content-type", "text/plain; charset=utf-8"),
    ],
    body: <<body:utf8>>,
  )
}
