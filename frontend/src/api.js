/**
 * api.js — All backend calls for the CloudSentry dashboard.
 *
 * All paths are relative ("/events", not an absolute URL): in dev
 * (`npm run dev`), Vite's proxy (see vite.config.js) forwards these to
 * scripts/local-api-server.py on :3001; after `npm run build`, that same
 * server serves the built app directly, so requests are already same-origin.
 */

async function getJson(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) {
    let detail = "";
    try {
      const body = await res.json();
      detail = body.error || body.detail || "";
    } catch { /* ignore */ }
    throw new Error(detail || `HTTP ${res.status} for ${path}`);
  }
  return res.json();
}

export async function fetchEvents() {
  const data = await getJson("/events");
  return data.events || [];
}

export async function fetchStats() {
  return getJson("/stats");
}

export async function fetchCompliance() {
  return getJson("/compliance");
}

export async function fetchPolicies() {
  return getJson("/policies");
}

export async function togglePolicy(policyId, enabled, extra = {}) {
  return getJson(`/policies/${policyId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ enabled, ...extra }),
  });
}

export async function syncPolicies(source) {
  const url = source === "all" ? "/policies/sync" : `/policies/sync/${source}`;
  return getJson(url, { method: "POST", headers: { "Content-Type": "application/json" } });
}

export async function createGithubIssues(limit = 5) {
  return getJson("/create-issues", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ limit }),
  });
}

/** Layers 1-5 + orchestrator, run over `limit` events.
 * Each event runs a real SBERT embedding + graph BFS + (if flagged
 * anomalous) a live LLM reasoning call, so this is slower than the other
 * endpoints — expect a few seconds per anomalous event.
 *
 * source="live": the most recent real CSPM events. Their resource names
 * don't match any node in the demo blast-radius graph, so Layer 3 honestly
 * reports LOW for all of them.
 * source="demo": crafted incidents using the actual IAM principals in the
 * demo graph (see blast_radius_seed.json), so Layer 3 produces real,
 * varied output — this is what shows the full pipeline working end-to-end. */
export async function fetchAiInsights(limit = 10, source = "live") {
  return getJson(`/ai/insights?limit=${limit}&source=${source}`);
}

/** Runs the full pipeline against exactly ONE event — used by Policy Diff
 * so it always analyzes the specific real incident the user clicked, never
 * a substituted demo scenario. For a real IAM Audit finding, the backend
 * attaches a policy_fix_context fetched live from LocalStack IAM. */
export async function analyzeEvent(event) {
  return getJson("/ai/analyze-event", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(event),
  });
}

/** Applies a sandbox-verified Layer 4 draft back to the real identity it was
 * drafted for (LocalStack IAM only — never real AWS). `deployTarget` comes
 * from a prior analyzeEvent() result's event.policy_fix_context.deploy_target. */
export async function deployPolicyFix(deployTarget, policyJson) {
  return getJson("/policies/deploy-fix", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ deploy_target: deployTarget, policy_json: policyJson }),
  });
}

/** Read-only snapshot for the Settings page: which LLM/reasoner is active,
 * the calibrated thresholds, whether GitHub/Discord are configured (booleans
 * only, never the actual secret), and policy-review counts. */
export async function fetchSystemInfo() {
  return getJson("/system-info");
}

/** POST /simulate — trigger one targeted attack against the running
 * LocalStack backend on demand (see scripts/local-api-server.py). */
export async function runSimulatedAttack(type, { target, account, region } = {}) {
  return getJson("/simulate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ type, target, account, region }),
  });
}
