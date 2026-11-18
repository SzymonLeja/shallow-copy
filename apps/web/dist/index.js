"use strict";
const app = document.getElementById("app");
let authToken = null;
let deviceId = null;
// Sign‑in form
function renderSignIn() {
    app.innerHTML = `
    <h2>Sign In</h2>
    <form id="signInForm">
      <label>Device ID: <input type="text" name="deviceId" required /></label>
      <label>Passphrase: <input type="password" name="passphrase" /></label>
      <button type="submit">Sign In</button>
    </form>
    <div id="error" style="color:red"></div>
  `;
    const form = document.getElementById("signInForm");
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        const formData = new FormData(form);
        const dId = formData.get("deviceId");
        const pass = formData.get("passphrase");
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
            const data = (await res.json());
            authToken = data.token;
            renderDashboard();
        }
        catch (err) {
            const errorDiv = document.getElementById("error");
            if (errorDiv) {
                errorDiv.textContent = err instanceof Error ? err.message : String(err);
            }
        }
    });
}
async function fetchMetrics() {
    if (!deviceId)
        throw new Error("Device ID missing");
    const res = await fetch("/v1/system/readiness", {
        headers: {
            ...(authToken ? { Authorization: `Bearer ${authToken}` } : {}),
            "x-device-id": deviceId,
        },
    });
    if (!res.ok)
        throw new Error("Failed to fetch metrics");
    return res.json();
}
function renderDashboard() {
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
        const metricsDiv = document.getElementById("metrics");
        if (metricsDiv)
            metricsDiv.innerHTML = metricsHtml;
        renderIngestForm();
    })
        .catch((err) => {
        const metricsDiv = document.getElementById("metrics");
        if (metricsDiv) {
            metricsDiv.textContent = err instanceof Error ? err.message : String(err);
        }
    });
}
function renderIngestForm() {
    const formContainer = document.getElementById("ingest-form");
    if (!formContainer)
        return;
    formContainer.innerHTML = `
    <h3>Filesystem Ingest</h3>
    <form id="ingestForm">
      <label>Path: <input type="text" name="path" required /></label>
      <button type="submit">Ingest</button>
    </form>
    <div id="ingest-result" style="margin-top:0.5rem;"></div>
  `;
    const ingestForm = document.getElementById("ingestForm");
    ingestForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const formData = new FormData(ingestForm);
        const path = formData.get("path");
        const resultDiv = document.getElementById("ingest-result");
        try {
            if (!deviceId || !authToken)
                throw new Error("Not authenticated");
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
            const ingestRes = (await res.json());
            resultDiv.textContent = `Created: ${ingestRes.created}, Object ID: ${ingestRes.object_id}`;
            // refresh metrics
            fetchMetrics().then((m) => {
                const metricsDiv = document.getElementById("metrics");
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
        }
        catch (err) {
            resultDiv.textContent = err instanceof Error ? err.message : String(err);
        }
    });
}
document.addEventListener("DOMContentLoaded", () => {
    if (authToken) {
        renderDashboard();
    }
    else {
        renderSignIn();
    }
});
