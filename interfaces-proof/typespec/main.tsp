import "@typespec/http";
import "./security.tsp";

using TypeSpec.Http;

namespace BeamScale;

scalar Sha256 extends string;
scalar CapabilityName extends string;
scalar DeploymentId extends string;
scalar WorkerVersionId extends string;
scalar TenantId extends string;
scalar ShardId extends string;
scalar RuntimeEpoch extends int64;
scalar DeploymentRevision extends int64;

enum ModuleKind {
  lambda,
  http,
  rpc,
  actor,
  worker,
}

enum InvocationMode {
  request_response,
  mailbox,
  event,
}

enum ConcurrencyModel {
  isolated_invocation,
  serialized_actor,
}

enum CancellationModel {
  deadline,
  cooperative,
}

enum HostedCapability {
  cluster_call,
  log,
}

model RequestResponseExecution {
  invocation: "request_response";
  concurrency: "isolated_invocation";
  cancellation: CancellationModel;
}

model ActorExecution {
  invocation: "mailbox";
  concurrency: "serialized_actor";
  cancellation: "cooperative";
}

model WorkerExecution {
  invocation: "mailbox" | "event";
  concurrency: ConcurrencyModel;
  cancellation: CancellationModel;
}

model ModuleDescriptorBase {
  contract_version: "bmscl-module-contract-v1";
  context_abi: "bmscl.context/v1";
  semantics_version?: "bmscl.module-semantics/v2";
  name: string;
  entrypoint: string;
  capabilities: HostedCapability[];
}

model LambdaModuleDescriptor extends ModuleDescriptorBase {
  kind: "lambda";
  execution: RequestResponseExecution;
}

model HttpModuleDescriptor extends ModuleDescriptorBase {
  kind: "http";
  execution: RequestResponseExecution;
}

model RpcModuleDescriptor extends ModuleDescriptorBase {
  kind: "rpc";
  execution: RequestResponseExecution;
}

model ActorModuleDescriptor extends ModuleDescriptorBase {
  kind: "actor";
  execution: ActorExecution;
}

model WorkerModuleDescriptor extends ModuleDescriptorBase {
  kind: "worker";
  execution: WorkerExecution;
}

union ModuleDescriptor {
  lambda: LambdaModuleDescriptor,
  http: HttpModuleDescriptor,
  rpc: RpcModuleDescriptor,
  actor: ActorModuleDescriptor,
  worker: WorkerModuleDescriptor,
}

model RuntimeBudget {
  max_wall_ms: int64;
  max_reductions: int64;
  max_heap_bytes: int64;
  max_processes: 1;
  max_mailbox_bytes?: int64;
  max_output_bytes?: int64;
  max_outbound_requests?: int32;
}

model CapabilityGrant {
  name: CapabilityName;
  scope?: unknown;
}

model ArtifactManifest {
  format_version: int32;
  runtime: "beam";
  language: "gleam";
  profile: string;
  source_sha256: Sha256;
  build_sha256: Sha256;
  entrypoint: string;
  capabilities: CapabilityGrant[];
  runtime_limits: RuntimeBudget;
}

enum TenantIsolation {
  micro_vm,
  linux_container,
}

enum MicroVmBackend {
  firecracker,
  cloud_hypervisor,
}

enum TenantRuntimeState {
  cold,
  starting,
  hot,
  warm_idle,
  hibernated,
  draining,
  terminated,
}

model TenantRuntimeIdentity {
  tenant_id: TenantId;
  shard_id: ShardId;
  runtime_epoch: RuntimeEpoch;
}

model TenantRuntimePolicy {
  policy_version: "bmscl-tenant-runtime-v1";
  isolation: TenantIsolation;
  microvm_backend: MicroVmBackend;
  vcpu_count: int32;
  min_memory_bytes: int64;
  max_memory_bytes: int64;
  warm_idle_ms: int64;
  hibernate_after_ms: int64;
  destroy_after_ms: int64;
  allow_snapshot_restore: boolean;
}

model TenantRuntimeStatus {
  identity: TenantRuntimeIdentity;
  state: TenantRuntimeState;
  deployment_id?: DeploymentId;
  worker_version_id?: WorkerVersionId;
  worker_version_digest?: Sha256;
  host_id?: string;
}

model MeteringSample {
  identity: TenantRuntimeIdentity;
  request_count: int64;
  cpu_ns: int64;
  memory_byte_ms: int64;
  ingress_bytes: int64;
  egress_bytes: int64;
  durable_storage_byte_ms: int64;
}

model InvocationRequest {
  invocation_id: string;
  root_invocation_id?: string;
  parent_invocation_id?: string;
  call_depth?: int32;
  deployment_id: DeploymentId;
  worker_version_id: WorkerVersionId;
  method: string;
  url: string;
  headers: Record<string>;
  body_base64?: string;
  deadline_unix_ms: int64;
}

model InvocationResponse {
  status: int32;
  headers: Record<string>;
  body_base64?: string;
  cpu_reductions: int64;
  wall_ms: int64;
  peak_heap_bytes?: int64;
  termination_reason?: string;
}

// Deployment desired state is intentionally typed by lifecycle ownership.
// lambda units are P3 worker generations. middleware units are P2/daddy inputs.
enum DeploymentUnitKind {
  lambda,
  middleware,
}

model DeploymentUnitIdentity {
  kind: DeploymentUnitKind;
  name: string;
}

model DeploymentUnitCandidate extends DeploymentUnitIdentity {
  build_sha256: Sha256;
  source_sha256: Sha256;
}

model DeploymentUnitTombstone extends DeploymentUnitIdentity {}

// Wire-compatibility input for the pre-typed v1 deployment clients.
// Implementations canonicalize these entries to kind=lambda.
model LegacyLambdaCandidate {
  name: string;
  build_sha256: Sha256;
  source_sha256: Sha256;
}

model DeploymentDesiredStateChange {
  project: string;
  environment: string;
  git_commit?: string;
  force?: boolean;
  units?: DeploymentUnitCandidate[];
  tombstones?: DeploymentUnitTombstone[];
  lambdas?: LegacyLambdaCandidate[];
}

model DeploymentPlanRequest extends DeploymentDesiredStateChange {}

model DeploymentApplyRequest extends DeploymentDesiredStateChange {
  expected_revision: DeploymentRevision;
}

enum DeploymentPlanReason {
  forced,
  not_deployed,
  build_changed,
  artifact_missing,
  up_to_date,
  deleted,
  already_deleted,
}

model PlannedDeploymentUnit extends DeploymentUnitIdentity {
  tombstone: boolean;
  build_sha256?: Sha256;
  source_sha256?: Sha256;
  current_build_sha256?: Sha256;
  artifact_present: boolean;
  reason: DeploymentPlanReason;
}

model DeploymentPlanResponse {
  project: string;
  environment: string;
  revision: DeploymentRevision;
  changed: PlannedDeploymentUnit[];
  unchanged: PlannedDeploymentUnit[];
}

model DeploymentApplyResponse {
  project: string;
  environment: string;
  previous_revision: DeploymentRevision;
  revision: DeploymentRevision;
  applied: PlannedDeploymentUnit[];
  unchanged: PlannedDeploymentUnit[];
}

model DeploymentTarget extends DeploymentUnitIdentity {
  build_sha256: Sha256;
  source_sha256: Sha256;
  git_commit?: string;
  updated_unix_seconds: int64;
  activation_state: string;
}

model DeploymentTombstoneRecord extends DeploymentUnitIdentity {
  git_commit?: string;
  updated_unix_seconds: int64;
  activation_state: string;
}

model DeploymentTargetState {
  format_version: int32;
  project: string;
  environment: string;
  revision: DeploymentRevision;
  lambdas: Record<DeploymentTarget>;
  middleware: Record<DeploymentTarget>;
  tombstones: Record<DeploymentTombstoneRecord>;
}

enum DurableObjectLanguage {
  erlang,
  gleam,
}

model CriticalSectionDeploymentRequest {
  deployment_id?: DeploymentId;
  tenant_id: TenantId;
  `namespace`: string;
  language: DurableObjectLanguage;
  build_sha256: Sha256;
  tenancy_class?: "tenant_dedicated";
}

@minValue(1)
@maxValue(9007199254740991)
scalar CriticalSectionSequence extends safeint;

model CriticalSectionToken {
  runtime_epoch: RuntimeEpoch;
  owner_epoch: int64;
  sequence: CriticalSectionSequence;
}

@minLength(1)
@maxLength(256)
scalar CriticalSectionRequestId extends string;

model CriticalSectionAcquireRequest {
  key: string;
  holder: string;
  request_id: CriticalSectionRequestId;
  lease_ms: int64;
}

model CriticalSectionRenewRequest {
  key: string;
  holder: string;
  lease_ms: int64;
  token: CriticalSectionToken;
}

model CriticalSectionReleaseRequest {
  key: string;
  holder: string;
  token: CriticalSectionToken;
}

model CriticalSectionGrant {
  `op`: "critical_section_result";
  operation: "acquire" | "renew";
  ok: true;
  token: CriticalSectionToken;
  expires_at_ms: int64;
}

model CriticalSectionReleased {
  `op`: "critical_section_result";
  operation: "release";
  ok: true;
}

model CriticalSectionRefused {
  `op`: "critical_section_result";
  operation: "acquire" | "renew" | "release";
  ok: false;
  error_code: string;
  remaining_ms?: int64;
}

union CriticalSectionResult {
  grant: CriticalSectionGrant,
  released: CriticalSectionReleased,
  refused: CriticalSectionRefused,
}

model CriticalSectionDeployment {
  deployment_id: DeploymentId;
  user_id: string;
  tenant_id: TenantId;
  `namespace`: string;
  runtime: "beam";
  language: DurableObjectLanguage;
  profile: "bmscl-critical-section-v1";
  build_sha256: Sha256;
  tenancy_class: "tenant_dedicated";
  execution_class: "durable_actor";
  isolation_class: "firecracker";
  shard_id: ShardId;
  runtime_host: string;
  runtime_epoch: RuntimeEpoch;
  runtime_state: string;
}

@service(#{ title: "BeamScale API" })
namespace Api {
  @route("/v1/critical-sections/deployments")
  interface CriticalSectionDeployments {
    @post deploy(@body request: CriticalSectionDeploymentRequest): CriticalSectionDeployment;
  }

  @route("/v1/critical-sections/{deployment_id}/acquire")
  interface CriticalSectionAcquire {
    @post acquire(
      @path deployment_id: DeploymentId,
      @body request: CriticalSectionAcquireRequest,
    ): CriticalSectionResult;
  }

  @route("/v1/critical-sections/{deployment_id}/renew")
  interface CriticalSectionRenew {
    @post renew(
      @path deployment_id: DeploymentId,
      @body request: CriticalSectionRenewRequest,
    ): CriticalSectionResult;
  }

  @route("/v1/critical-sections/{deployment_id}/release")
  interface CriticalSectionRelease {
    @post release(
      @path deployment_id: DeploymentId,
      @body request: CriticalSectionReleaseRequest,
    ): CriticalSectionResult;
  }

  @route("/v1/invocations/{deployment_id}")
  interface Invocations {
    @post invoke(@path deployment_id: string, @body request: InvocationRequest): InvocationResponse;
  }
}

namespace AdminApi {
  @route("/v1/admin/deployment-plans")
  interface DeploymentPlans {
    @post plan(@body request: DeploymentPlanRequest): DeploymentPlanResponse;
  }

  @route("/v1/admin/deployment-targets/{project}/{environment}")
  interface DeploymentTargetStateRead {
    @get get(
      @path project: string,
      @path environment: string,
    ): DeploymentTargetState;
  }

  @route("/v1/admin/deployment-targets/apply")
  interface DeploymentTargets {
    @post apply(@body request: DeploymentApplyRequest): DeploymentApplyResponse;
  }
}
