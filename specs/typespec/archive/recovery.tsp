import "@typespec/http";
import "../common/scalars.tsp";

using TypeSpec.Http;

namespace ShallowCopy;

/** Recovery drill execution response */
model RecoveryDrillResponse {
  success: boolean;
  objects_tested: int32;
}

@route("/v1/archive/recovery")
@tag("Archive")
interface RecoveryApi {
  /** Run an offline/standalone recovery verification drill */
  @post
  @route("/drill")
  drill(): RecoveryDrillResponse | ErrorResponse;
}
