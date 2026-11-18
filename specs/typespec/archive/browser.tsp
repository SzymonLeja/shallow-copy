import "@typespec/http";
import "../common/scalars.tsp";

using TypeSpec.Http;

namespace ShallowCopy;

/** Request parameters for browser history ingestion (source database is server-configured). */
model BrowserHistoryIngestRequest {
  /** Optional logical source instance identifier override */
  sourceInstance?: string;
}

/** Result summary of browser history ingestion */
model BrowserHistoryIngestResponse {
  /** Effective source instance identifier */
  sourceInstance: string;
  /** Total visit records discovered in configured history database */
  totalVisits: int64;
  /** Number of newly imported objects */
  importedCount: int64;
  /** Number of duplicate visits skipped due to existing fingerprint */
  skippedCount: int64;
  /** List of object IDs corresponding to ingested visits */
  objectIds: Sha256Digest[];
}

/** Page transition type for browser visits */
enum PageTransitionType {
  link,
  typed,
  auto_bookmark,
  auto_subframe,
  manual_subframe,
  generated,
  auto_toplevel,
  form_submit,
  reload,
  keyword,
  keyword_generated,
  other,
}

/** Enriched browser visit entry stored in OIAF archive */
model BrowserVisitRecord {
  /** Unique visit identifier */
  visitId: int64;
  /** Visited URL */
  url: string;
  /** Page title if recorded by browser */
  title?: string;
  /** Cumulative visit count for this URL */
  visitCount?: int64;
  /** Raw Chromium microsecond timestamp */
  visitTimeRaw: int64;
  /** Converted Unix millisecond epoch timestamp */
  eventTimeUnixMs?: int64;
  /** Raw numeric transition code from Chromium database */
  transitionRaw?: int64;
  /** Normalized transition type */
  transitionType?: PageTransitionType;
}

/** Browser bookmark entry with folder hierarchy */
model BrowserBookmarkRecord {
  /** Bookmark identifier from Chromium Bookmarks JSON */
  bookmarkId: string;
  /** Bookmark title */
  title: string;
  /** Bookmark URL */
  url: string;
  /** Folder path hierarchy elements from root to parent */
  folderPath: string[];
  /** Formatted slash-separated folder path */
  folder: string;
  /** Raw date added string from Chromium Bookmarks JSON */
  dateAddedRaw?: string;
  /** Converted Unix millisecond epoch timestamp */
  dateAddedUnixMs?: int64;
}

@route("/v1/archive/ingest/browser-history")
@tag("Archive")
interface BrowserHistoryIngestApi {
  /** Ingest browser history visits from server-configured Chromium history database */
  @post
  ingest(
    @body body?: BrowserHistoryIngestRequest,
  ): BrowserHistoryIngestResponse | ErrorResponse;
}
