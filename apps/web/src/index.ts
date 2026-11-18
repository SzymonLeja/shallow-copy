const app = document.getElementById("app") as HTMLElement;

let authToken: string | null = null;
let deviceId: string | null = null;

// Sign‑in form
function renderSignIn(): void {
  app.innerHTML = `
    <h2>Sign In</h2>
    <form id="signInForm">
      <label>Device ID: <input type="text" name="deviceId" required /></label>
      <label>Passphrase: <input type="password" name="passphrase" /></label>
      <button type="submit">Sign In</button>
    </form>
    <div id="error" style="color:red"></div>
  `;
  const form = document.getElementById("signInForm") as HTMLFormElement;
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(form);
    const dId = formData.get("deviceId") as string;
    const pass = formData.get("passphrase") as string;
    deviceId = dId;
    try {
      const res = await fetch("/v1/auth/session", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-device-id": dId,
        },
        body: JSON.stringify({
          deviceId: dId,
          ...(pass ? { passphrase: pass } : {}),
        }),
      });
      if (!res.ok) {
        throw new Error("Invalid credentials or device ID");
      }
      const data = (await res.json()) as { token: string };
      authToken = data.token;
      renderDashboard();
    } catch (err) {
      const errorDiv = document.getElementById("error") as HTMLElement;
      if (errorDiv) {
        errorDiv.textContent = err instanceof Error ? err.message : String(err);
      }
    }
  });
}

interface SystemReadinessResponse {
  archiveReady: boolean;
  objectCount: number;
  pendingJobs: number;
  failedJobs: number;
  filesystemIngestAvailable: boolean;
}

interface FilesystemIngestResponse {
  object_id: string;
  ingest_fingerprint: string;
  created: boolean;
}

async function fetchMetrics(): Promise<SystemReadinessResponse> {
  if (!deviceId) throw new Error("Device ID missing");
  const res = await fetch("/v1/system/readiness", {
    headers: {
      ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
      "x-device-id": deviceId,
    },
  });
  if (!res.ok) throw new Error("Failed to fetch metrics");
  return res.json() as Promise<SystemReadinessResponse>;
}

function renderDashboard(): void {
  app.innerHTML = `<h2>System Readiness</h2><div id="metrics">Loading...</div>`;
  fetchMetrics()
    .then((m) => {
      const metricsHtml = `
        <p>Archive Ready: ${m.archiveReady}</p>
        <p>Object Count: ${m.objectCount}</p>
        <p>Pending Jobs: ${m.pendingJobs}</p>
        <p>Failed Jobs: ${m.failedJobs}</p>
        <p>Filesystem Ingest Available: ${m.filesystemIngestAvailable}</p>
        <div id="ingest-form"></div>
      `;
      const metricsDiv = document.getElementById("metrics") as HTMLElement;
      if (metricsDiv) metricsDiv.innerHTML = metricsHtml;
      renderIngestForm();
    })
    .catch((err) => {
      const metricsDiv = document.getElementById("metrics") as HTMLElement;
      if (metricsDiv) {
        metricsDiv.textContent = err instanceof Error ? err.message : String(err);
      }
    });
}

function renderIngestForm(): void {
  const formContainer = document.getElementById("ingest-form") as HTMLElement;
  if (!formContainer) return;
  formContainer.innerHTML = `
    <h3>Filesystem Ingest</h3>
    <form id="ingestForm">
      <label>Path: <input type="text" name="path" required /></label>
      <button type="submit">Ingest</button>
    </form>
    <div id="ingest-result" style="margin-top:0.5rem;"></div>
  `;
  const ingestForm = document.getElementById("ingestForm") as HTMLFormElement;
  ingestForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const formData = new FormData(ingestForm);
    const path = formData.get("path") as string;
    const resultDiv = document.getElementById("ingest-result") as HTMLElement;
    try {
      if (!deviceId || !authToken) throw new Error("Not authenticated");
      const res = await fetch("/v1/archive/ingest/filesystem", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${authToken}`,
          "x-device-id": deviceId,
        },
        body: JSON.stringify({ path }),
      });
      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`Ingest failed: ${res.status} ${errText}`);
      }
      const ingestRes = (await res.json()) as FilesystemIngestResponse;
      resultDiv.textContent = `Created: ${ingestRes.created}, Object ID: ${ingestRes.object_id}`;
      // refresh metrics
      fetchMetrics().then((m) => {
        const metricsDiv = document.getElementById("metrics") as HTMLElement;
        if (metricsDiv) {
          const metricsHtml = `
            <p>Archive Ready: ${m.archiveReady}</p>
            <p>Object Count: ${m.objectCount}</p>
            <p>Pending Jobs: ${m.pendingJobs}</p>
            <p>Failed Jobs: ${m.failedJobs}</p>
            <p>Filesystem Ingest Available: ${m.filesystemIngestAvailable}</p>
            <div id="ingest-form"></div>
          `;
          metricsDiv.innerHTML = metricsHtml;
          renderIngestForm();
        }
      });
    } catch (err) {
      resultDiv.textContent = err instanceof Error ? err.message : String(err);
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  if (authToken) {
    renderDashboard();
  } else {
    renderSignIn();
  }
});
