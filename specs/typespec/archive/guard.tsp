import "@typespec/http";
import "../common/scalars.tsp";

using TypeSpec.Http;

namespace ShallowCopy;

/** Preservation Guard lifecycle states */
enum GuardState {
  requested,
  impact_analysis,
  dry_run_ready,
  explicit_confirmation,
  quarantine_delay,
  committed,
  cancelled,
  restored,
}

/** Evaluated impact report for requested guarded operation */
model ImpactReport {
  affected_objects: int32;
  affected_bytes: int64;
  is_reversible: boolean;
  has_verified_backup: boolean;
  backup_checkpoint_timestamp?: int64;
  warnings: string[];
}

model GuardAnalyzeRequest {
  objectIds: string[];
}

model GuardAnalyzeResponse {
  sessionId: string;
  confirmationToken: string;
  confirmationExpiresAtUnixMs: int64;
  impact: ImpactReport;
}

model GuardActionRequest {
  sessionId: string;
  confirmationToken: string;
  typedConfirmation: string;
  allowUnverifiedBackupOverride: boolean;
}

model GuardActionResponse {
  sessionId: string;
  state: GuardState;
  stepUpConfirmed: boolean;
  quarantineDeadlineUnixMs?: int64;
}

@route("/v1/archive/guard")
@tag("Archive")
interface GuardApi {
  /** Analyze impact of a guarded destructive operation */
  @post
  @route("/analyze")
  analyze(@body body: GuardAnalyzeRequest): GuardAnalyzeResponse | ErrorResponse;

  /** Confirm and transition a guarded destructive operation to quarantine */
  @post
  @route("/action")
  action(@body body: GuardActionRequest): GuardActionResponse | ErrorResponse;
}
