using TypeSpec.Http;

namespace ShallowCopy;

/** ULID string identifier */
scalar Ulid extends string;

/** SHA-256 hex digest (64 lowercase hex chars) */
scalar Sha256Digest extends string;

/** Archive domain */
enum ArchiveDomain {
  public,
  private,
  restricted,
  legacy,
  secrets,
}

/** Standard error response */
model ErrorResponse {
  code: string;
  message: string;
  requestId: string;
  details?: Record<unknown>;
}
