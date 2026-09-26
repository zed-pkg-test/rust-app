import "@typespec/http";

using TypeSpec.Http;

namespace BeamScale;

scalar UserId extends string;
scalar RuntimeId extends string;
scalar IncidentId extends string;

model HostRuntimeIdentity {
  runtime_id: RuntimeId;
  user_id: UserId;
  tenant_id: TenantId;
  deployment_id: DeploymentId;
  invocation_id?: string | null;
}

model HostPeerCredentials {
  pid: int32;
  uid: int64;
  gid: int64;
}

model HostAttribution {
  peer: HostPeerCredentials;
  cgroup_path: string;
  identity: HostRuntimeIdentity;
}

model HostTripwireReport {
  command: string;
  argc: int32;
}

enum HostSecuritySensor {
  command_wrapper: "command-wrapper",
  kernel_exec: "kernel-exec",
  canary_file: "canary-file",
  firecracker_guest: "firecracker-guest",
}

enum HostSecurityIncidentStage {
  detected,
  contained,
}

model HostNamespaceEvidence {
  mnt?: string;
  pid?: string;
  user?: string;
  net?: string;
  cgroup?: string;
  ipc?: string;
  uts?: string;
}

model HostSecurityIncident {
  incident_id: IncidentId;
  detected_at: string;
  sensor: HostSecuritySensor;
  stage: HostSecurityIncidentStage;
  report: HostTripwireReport;
  attribution: HostAttribution;
  namespaces: HostNamespaceEvidence;
  frozen: boolean;
}

model HostSecurityIncidentReceipt {
  incident_id: IncidentId;
  body_sha256: string;
  host_id: string;
  received_unix_seconds: int64;
  user_id: UserId;
  tenant_id: TenantId;
  deployment_id: DeploymentId;
  runtime_id: RuntimeId;
  security_state: "blocked";
  notification_state: "alert_pending";
  duplicate: boolean;
}

namespace AdminApi {
  @route("/v1/admin/security/host-incidents")
  interface HostSecurityIncidents {
    @post ingest(
      @header("x-bmscl-host-id") host_id: string,
      @header("x-bmscl-timestamp") timestamp: string,
      @header("x-bmscl-nonce") nonce: string,
      @header("x-bmscl-body-sha256") body_sha256: string,
      @header("x-bmscl-signature") signature: string,
      @body incident: HostSecurityIncident,
    ): HostSecurityIncidentReceipt;
  }
}
