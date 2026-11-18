import "@typespec/http";

using TypeSpec.Http;

namespace ShallowCopy;

/** Authenticated system readiness and operational status */
model SystemReadinessResponse {
  archiveReady: boolean;
  objectCount: int64;
  pendingJobs: int64;
  failedJobs: int64;
  filesystemIngestAvailable: boolean;
  /** Safe canonicalized archive path if initialized */
  archivePath?: string;
  /** Safe canonicalized backup target directory path if configured */
  backupPath?: string;
}

@route("/v1/system/readiness")
@tag("System")
interface SystemReadinessApi {
  /** Get authenticated system readiness and operational metrics */
  @get
  op getReadiness(): SystemReadinessResponse;
}
