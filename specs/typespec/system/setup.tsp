import "@typespec/http";
import "../common/scalars.tsp";

using TypeSpec.Http;

namespace ShallowCopy;

/** First-run core setup state and configuration readiness */
model SystemSetupStatus {
  /** True if the core archive storage directory and manifest exist and are initialized */
  archiveInitialized: boolean;
  /** True if administrative credentials / session have been provisioned */
  adminProvisioned: boolean;
  /** True if recovery key / backup target is configured */
  recoveryConfigured: boolean;
  /** True if the first-run setup has completed */
  isComplete: boolean;
  /** Safe canonicalized archive path if initialized */
  archivePath?: string;
  /** Safe canonicalized backup target directory path if configured */
  backupPath?: string;
}

/** Request body to complete first-run core setup */
model SystemSetupRequest {
  /** Optional custom local archive directory path */
  archivePath?: string;
  /** Optional local directory backup target */
  backupPath?: string;
  /** Acknowledgment confirming recovery material has been recorded and verified */
  recoveryConfirmed: boolean;
}

/** Result of first-run core setup execution (never returns secrets or raw recovery keys) */
model SystemSetupResponse {
  /** True if setup succeeded */
  success: boolean;
  /** Updated setup status */
  status: SystemSetupStatus;
  /** Informational description of configuration state */
  message: string;
}

@route("/v1/system/setup")
@tag("System")
interface SystemSetupApi {
  /** Get current first-run setup state and configuration readiness */
  @get
  getStatus(): SystemSetupStatus | ErrorResponse;

  /** Execute first-run core setup configuration (replays will be rejected) */
  @post
  configure(@body body: SystemSetupRequest): SystemSetupResponse | ErrorResponse;
}
