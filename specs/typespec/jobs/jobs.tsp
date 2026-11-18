import "@typespec/http";
import "../common/scalars.tsp";

using TypeSpec.Http;

namespace ShallowCopy;

enum JobStatus {
  pending,
  running,
  completed,
  failed,
  cancelled,
}

model Job {
  jobId: Ulid;
  kind: string;
  status: JobStatus;
  progressPct?: int32;
  createdAt: utcDateTime;
  updatedAt: utcDateTime;
  error?: string;
}

@route("/v1/jobs")
@tag("Jobs")
interface JobsApi {
  @get
  list(@query status?: JobStatus): { items: Job[] } | ErrorResponse;

  @get
  @route("/{jobId}")
  get(@path jobId: Ulid): Job | ErrorResponse;
}
