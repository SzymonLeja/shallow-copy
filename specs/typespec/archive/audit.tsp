import "@typespec/http";
import "../common/scalars.tsp";

using TypeSpec.Http;

namespace ShallowCopy;

/** Catalog append-only audit event */
model AuditEvent {
  id: string;
  event_type: string;
  actor: string;
  object_id?: string;
  details_json?: string;
  created_unix_ms: int64;
}

@route("/v1/archive/audit")
@tag("Archive")
interface ArchiveAuditApi {
  /** List append-only audit events */
  @get
  list(@query limit?: int32): AuditEvent[] | ErrorResponse;
}
