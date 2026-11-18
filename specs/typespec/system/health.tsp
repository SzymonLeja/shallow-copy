import "@typespec/http";

using TypeSpec.Http;

namespace ShallowCopy;

@route("/health")
@tag("Health")
interface HealthApi {
  /** Service health check endpoint */
  @get
  get(): string;
}
