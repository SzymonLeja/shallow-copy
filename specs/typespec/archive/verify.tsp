import "@typespec/http";
import "../common/scalars.tsp";

using TypeSpec.Http;

namespace ShallowCopy;

model VerificationReport {
  objects: int32;
  blobs: int32;
  bytes: int64;
  fixityOnly: boolean;
  startedAt: utcDateTime;
  completedAt: utcDateTime;
}

@route("/v1/archive/verify")
@tag("Archive")
interface VerifyApi {
  /** Trigger a verification run; returns Job */
  @post
  run(@body body: { full?: boolean }): Job | ErrorResponse;
}
