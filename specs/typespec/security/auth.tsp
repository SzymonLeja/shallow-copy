import "@typespec/http";
import "../common/scalars.tsp";

using TypeSpec.Http;

namespace ShallowCopy;

/** Available permission scopes */
enum Scope {
  `archive.read`,
  `archive.write`,
  `archive.destructive`,
  `recovery.manage`,
  `connector.manage`,
  `knowledge.read`,
  `persona.use`,
  `secrets.read`,
}

model SessionToken {
  token: string;
  deviceId: string;
  scopes: Scope[];
  expiresAt: utcDateTime;
}

model LoginRequest {
  password: string;
}

@route("/v1/auth")
@tag("Auth")
interface AuthApi {
  @post
  @route("/session")
  login(@body body: LoginRequest): SessionToken | ErrorResponse;

  @delete
  @route("/session")
  logout(): void | ErrorResponse;
}
