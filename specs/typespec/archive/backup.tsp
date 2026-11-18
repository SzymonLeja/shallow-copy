import "@typespec/http";
import "../common/scalars.tsp";

using TypeSpec.Http;

namespace ShallowCopy;

/** OIAF Backup Manifest snapshot */
model BackupManifest {
  oiaf_version: string;
  timestamp_unix_ms: int64;
  total_objects: int32;
  total_blob_bytes: int64;
  root_manifest_hash: Sha256Digest;
  envelopes: Record<string>;
}

/** Backup manifest verification response */
model BackupManifestVerifyResponse {
  valid: boolean;
}

@route("/v1/archive/backup-manifest")
@tag("Archive")
interface BackupManifestApi {
  /** Generate a backup manifest snapshot */
  @post
  @route("/generate")
  generate(): BackupManifest | ErrorResponse;

  /** Verify a backup manifest snapshot against live archive */
  @post
  @route("/verify")
  verify(@body manifest: BackupManifest): BackupManifestVerifyResponse | ErrorResponse;
}
