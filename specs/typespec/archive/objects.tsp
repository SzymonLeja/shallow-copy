import "@typespec/http";
import "@typespec/rest";
import "../common/scalars.tsp";

using TypeSpec.Http;
using TypeSpec.Rest;

namespace ShallowCopy;

/** Evidence envelope for one source occurrence */
model SourceObject {
  objectId: Sha256Digest;
  domain: ArchiveDomain;
  blobDigest: Sha256Digest;
  blobSize: int64;
  blobAlgorithm: string;
  connectorId: string;
  sourceInstance: string;
  externalId: string;
  revision: string;
  sourceLocator: string;
  observedTimeUnixMs: int64;
  ingestedTimeUnixMs: int64;
  eventTimeUnixMs?: int64;
}

/** Cursor-paginated list response */
model ObjectListResponse {
  items: SourceObject[];
  nextCursor?: string;
  total?: int64;
}

@route("/v1/archive/objects")
@tag("Archive")
interface ArchiveObjectsApi {
  /** List objects with cursor pagination */
  @get
  list(
    @query cursor?: string,
    @query limit?: int32,
    @query domain?: ArchiveDomain,
  ): ObjectListResponse | ErrorResponse;

  /** Get provenance envelope for one object */
  @get
  @route("/{objectId}")
  get(@path objectId: Sha256Digest): SourceObject | ErrorResponse;
}
