import "@typespec/http";
import "@typespec/rest";
import "@typespec/openapi3";

import "./common/scalars.tsp";
import "./archive/objects.tsp";
import "./archive/verify.tsp";
import "./archive/export.tsp";
import "./archive/backup.tsp";
import "./archive/audit.tsp";
import "./archive/browser.tsp";
import "./archive/guard.tsp";
import "./archive/recovery.tsp";
import "./security/auth.tsp";
import "./jobs/jobs.tsp";
import "./system/health.tsp";
import "./system/readiness.tsp";
import "./system/setup.tsp";

@service({
  title: "Shallow Copy API",
})
namespace ShallowCopy;
