import { useEffect, useState } from "react";
import { fetchSystemInfo, runSimulatedAttack } from "../../api.js";
import DecryptedText from "../DecryptedText.jsx";
import {
  getLiveAnalysisLimit, setLiveAnalysisLimit,
  LIVE_ANALYSIS_LIMIT_DEFAULT, LIVE_ANALYSIS_LIMIT_MAX,
} from "../../utils.js";

const ATTACK_TYPE_LABELS = {
  s3_public: "S3 — Public Access",
  s3_encrypt: "S3 — Encryption Removed",
  iam: "IAM — Overpermissive Policy",
  sg: "Security Group — Open SSH",
  dynamodb: "DynamoDB — Unencrypted Table",
};

function StatusDot({ ok, unknown }) {
  const color = unknown ? "var(--text-muted)" : ok ? "#22c55e" : "#f43f5e";
  return <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: "50%", background: color, marginRight: "0.5rem" }} />;
}

function Card({ title, children }) {
  return (
    <div className="glass-card" style={{ padding: "1.5rem" }}>
      <h4 style={{ color: "var(--text-primary)", marginBottom: "1rem" }}>{title}</h4>
      {children}
    </div>
  );
}

export default function SettingsView({ onNavigate, onRefresh }) {
  const [info, setInfo] = useState(null);
  const [infoError, setInfoError] = useState(null);
  const [limit, setLimit] = useState(getLiveAnalysisLimit());

  const [attackType, setAttackType] = useState("s3_public");
  const [simStatus, setSimStatus] = useState("idle"); // idle | running | done | error
  const [simResult, setSimResult] = useState(null);
  const [simError, setSimError] = useState(null);

  const loadInfo = () => {
    fetchSystemInfo()
      .then((data) => { setInfo(data); setInfoError(null); })
      .catch((err) => setInfoError(err.message));
  };

  useEffect(() => { loadInfo(); }, []);

  function handleLimitChange(raw) {
    const n = parseInt(raw, 10);
    const clamped = Number.isFinite(n) ? Math.max(1, Math.min(n, LIVE_ANALYSIS_LIMIT_MAX)) : LIVE_ANALYSIS_LIMIT_DEFAULT;
    setLimit(clamped);
    setLiveAnalysisLimit(clamped);
  }

  async function handleRunSimulation() {
    setSimStatus("running");
    setSimError(null);
    try {
      const result = await runSimulatedAttack(attackType);
      setSimResult(result);
      setSimStatus("done");
      onRefresh?.();
      loadInfo();
    } catch (err) {
      setSimError(err.message);
      setSimStatus("error");
    }
  }

  return (
    <div className="view-section active">
      <section className="settings-container glass-card reveal-element delay-1" style={{ padding: "2.5rem", marginTop: "2rem" }}>
        <h3 className="section-title"><DecryptedText text="SYSTEM CONFIGURATION" animateOn="view" sequential revealDirection="start" speed={28} encryptedClassName="dtx-scramble" /></h3>
        <p style={{ color: "var(--text-secondary)", marginBottom: "2rem" }}>
          Live status of the AI pipeline and integrations, an operational control, and a way to
          trigger a targeted attack against this running instance — all read from the real backend,
          not placeholder copy.
        </p>

        {infoError && (
          <div className="empty-state" style={{ borderColor: "var(--danger)", marginBottom: "1.5rem" }}>
            <p>Couldn't load system status: {infoError}</p>
          </div>
        )}

        <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem", maxWidth: "720px" }}>

          <Card title="AI Pipeline Status">
            {!info ? (
              <p style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>Loading…</p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem", fontSize: "0.88rem", color: "var(--text-secondary)" }}>
                <div><StatusDot ok={info.ai_engine_available} />5-layer AI engine: {info.ai_engine_available ? "Available" : `Unavailable (${info.ai_engine_error || "unknown"})`}</div>
                {info.ai_engine_available && (
                  <>
                    <div><StatusDot ok /> Active reasoner: <b>{info.reasoner}</b> • LLM client: <b>{info.llm_client}</b></div>
                    <div><StatusDot ok /> Anomaly threshold (Layer 1): <b>{info.anomaly_threshold?.toFixed(4)}</b></div>
                    <div>
                      <StatusDot ok={info.attack_classifier_calibrated} />
                      ATT&CK threshold (Layer 2): <b>{info.attack_classifier_threshold?.toFixed(4)}</b>{" "}
                      {info.attack_classifier_calibrated ? "(calibrated from labeled pairs)" : "(fallback — calibration data unavailable)"}
                    </div>
                  </>
                )}
              </div>
            )}
          </Card>

          <Card title="Live Events Analysis Limit">
            <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginBottom: "1rem" }}>
              How many of the most recent real events "AI Reasoning → Analyze Live Events" runs
              through the full pipeline. Each anomalous one can trigger a live LLM call, so a higher
              limit takes longer and is more likely to hit provider rate limits — the backend caps
              this at {LIVE_ANALYSIS_LIMIT_MAX} regardless of what's set here.
            </p>
            <div style={{ display: "flex", alignItems: "center", gap: "0.8rem" }}>
              <input
                type="range" min={1} max={LIVE_ANALYSIS_LIMIT_MAX} value={limit}
                onChange={(e) => handleLimitChange(e.target.value)}
                style={{ flex: 1 }}
              />
              <input
                type="number" min={1} max={LIVE_ANALYSIS_LIMIT_MAX} value={limit}
                onChange={(e) => handleLimitChange(e.target.value)}
                style={{ width: "4.5rem", padding: "0.4rem", background: "rgba(0,0,0,0.2)", border: "1px solid var(--border-highlight)", color: "var(--text-primary)", borderRadius: "4px" }}
              />
            </div>
            <p style={{ color: "var(--text-muted)", fontSize: "0.78rem", marginTop: "0.6rem" }}>
              Saved to this browser only — takes effect next time you click "Analyze Live Events".
            </p>
          </Card>

          <Card title="Attack Simulator">
            <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginBottom: "1rem" }}>
              Trigger one targeted attack against the running LocalStack backend on demand, instead
              of only replaying <code>scripts/simulate-attacks.py</code>'s fixed sequence — useful for
              watching detection happen live rather than seeing pre-seeded results.
            </p>
            {info && !info.simulate_available && (
              <p style={{ color: "var(--danger)", fontSize: "0.85rem" }}>Simulator not available on this server.</p>
            )}
            <div style={{ display: "flex", gap: "0.6rem", flexWrap: "wrap", alignItems: "center" }}>
              <select
                value={attackType}
                onChange={(e) => setAttackType(e.target.value)}
                disabled={simStatus === "running"}
                style={{ padding: "0.6rem", background: "rgba(0,0,0,0.2)", border: "1px solid var(--border-highlight)", color: "var(--text-primary)", borderRadius: "4px" }}
              >
                {(info?.simulate_attack_types || Object.keys(ATTACK_TYPE_LABELS)).map((t) => (
                  <option key={t} value={t}>{ATTACK_TYPE_LABELS[t] || t}</option>
                ))}
              </select>
              <button className="sync-btn sync-btn--primary" disabled={simStatus === "running"} onClick={handleRunSimulation}>
                <span className="sync-btn__icon">{simStatus === "running" ? "⟳" : "▶"}</span>
                {simStatus === "running" ? "Running..." : "Run Attack Simulation"}
              </button>
            </div>

            {simStatus === "error" && (
              <p style={{ color: "var(--danger)", fontSize: "0.85rem", marginTop: "0.8rem" }}>{simError}</p>
            )}
            {simStatus === "done" && simResult && (
              <div className="glass-card" style={{ padding: "0.9rem", marginTop: "1rem", background: "rgba(34,197,94,0.06)", border: "1px solid rgba(34,197,94,0.25)" }}>
                <p style={{ fontSize: "0.85rem", color: "var(--text-primary)", marginBottom: "0.4rem" }}>
                  Attack simulated and seeded into live events — check <a onClick={() => onNavigate?.("dashboard")} style={{ cursor: "pointer", textDecoration: "underline" }}>Security Posture</a> or run "Analyze Live Events" on the AI Reasoning page to see it flow through detection.
                </p>
                <pre style={{ fontSize: "0.75rem", color: "var(--text-muted)", whiteSpace: "pre-wrap", margin: 0 }}>
                  {JSON.stringify(simResult, null, 2)}
                </pre>
              </div>
            )}
          </Card>

          <Card title="Policy Review Queue">
            {!info ? (
              <p style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>Loading…</p>
            ) : (
              <p style={{ color: "var(--text-secondary)", fontSize: "0.88rem" }}>
                <b>{info.policies_enabled}</b> of <b>{info.policies_total}</b> policies active
                {info.policies_pending_review > 0 && (
                  <> — <b>{info.policies_pending_review}</b> awaiting human review (auto-generated from a novel finding type, disabled by design until approved).</>
                )}
                {" "}
                <a onClick={() => onNavigate?.("policies")} style={{ cursor: "pointer", textDecoration: "underline" }}>Review in Policy Engine →</a>
              </p>
            )}
          </Card>

          <Card title="Integrations">
            {!info ? (
              <p style={{ color: "var(--text-muted)", fontSize: "0.9rem" }}>Loading…</p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "0.7rem", fontSize: "0.88rem", color: "var(--text-secondary)" }}>
                <div>
                  <StatusDot ok={info.discord_configured} />
                  Discord webhook: {info.discord_configured ? "Configured (DISCORD_WEBHOOK_URL set)" : "Not configured — set DISCORD_WEBHOOK_URL before deploy-lambdas.py to enable"}
                </div>
                <div>
                  <StatusDot ok={info.github_configured} />
                  GitHub Issues ({info.github_repo}): {info.github_configured ? "Configured (GITHUB_TOKEN set)" : "Not configured — set GITHUB_TOKEN to enable /create-issues"}
                </div>
              </div>
            )}
          </Card>

        </div>
      </section>
    </div>
  );
}
