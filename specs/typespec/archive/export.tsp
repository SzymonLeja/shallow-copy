import "@typespec/http";
import "../common/scalars.tsp";

using TypeSpec.Http;

namespace ShallowCopy;

model ExportRequest {
  destination: string;
  objectId?: Sha256Digest;
  format?: "oiaf" | "jsonl";
}

model ExportResult {
  objects: int32;
  blobs: int32;
  bytes: int64;
  destination: string;
}

@route("/v1/archive/export")
@tag("Archive")
interface ExportApi {
  /** Export archive or single object */
  @post
  run(@body body: ExportRequest): Job | ErrorResponse;
}
