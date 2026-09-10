import { useCallback, useState } from "react";
import { fetchAiInsights } from "../../api.js";
import DecryptedText from "../DecryptedText.jsx";
import {
  formatTimestamp, severityClass, vulnTypeClass,
  SEVERITY_COLORS, PRIORITY_TIER_COLORS, DECISION_LABELS,
  getLiveAnalysisLimit,
} from "../../utils.js";

function ScoreBar({ value, threshold }) {
  const pct = Math.round(Math.min(1, Math.max(0, value)) * 100);
  return (
    <div className="progress-track" title={`${value.toFixed(4)} (threshold ${threshold})`}>
      <div
        className="progress-fill"
        style={{ width: `${pct}%`, background: value >= threshold ? "#f43f5e" : "#00e5ff" }}
      ></div>
    </div>
  );
}

function ResultCard({ result, threshold, onSelectIncident }) {
  const { event, is_anomalous, anomaly_score, deviating_features, classification, blast_radius, priority, decision, rationale, policy_draft } = result;
  const decisionInfo = DECISION_LABELS[decision] || { label: decision, cls: "badge--compliant" };

  return (
    <div className="glass-card policy-card" style={{ "--card-glow": SEVERITY_COLORS[event.severity]?.glow || "rgba(255,255,255,0.1)" }}>
      <div className="policy-card__header">
        <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", flexWrap: "wrap" }}>
          <span className={`vuln-type ${vulnTypeClass(event.vulnerability_type)}`}>{event.vulnerability_type}</span>
          <span className={`severity ${severityClass(event.severity)}`}>{event.severity}</span>
        </div>
        <span className={`badge ${decisionInfo.cls}`}>{decisionInfo.label}</span>
      </div>

      <h4 className="policy-card__title">{event.bucket_name}</h4>
      <p className="policy-card__desc" style={{ marginBottom: "0.6rem" }}>
        {event.region} • {formatTimestamp(event.timestamp)}
      </p>

      <div style={{ marginBottom: "0.9rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: "0.3rem" }}>
          <span>Layer 1 — Anomaly Score</span>
          <span>{anomaly_score.toFixed(4)} {is_anomalous ? "(anomalous)" : "(below threshold)"}</span>
        </div>
        <ScoreBar value={anomaly_score} threshold={threshold} />
      </div>

      {!is_anomalous ? (
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
          Below the anomaly threshold — Layers 2-5 and the orchestrator were skipped for this event, matching the pipeline's short-circuit design.
        </p>
      ) : (
        <>
          {deviating_features.length > 0 && (
            <div className="policy-card__compliance" style={{ marginBottom: "0.7rem" }}>
              {deviating_features.map((f) => <span className="compliance-tag" key={f}>{f}</span>)}
            </div>
          )}

          <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.6rem", marginBottom: "0.8rem" }}>
            <div className="glass-card" style={{ padding: "0.7rem" }}>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: "0.25rem" }}>Layer 2 — ATT&CK</div>
              {classification && classification.technique_id !== "UNKNOWN" ? (
                <div style={{ fontSize: "0.85rem" }}>
                  <strong>{classification.technique_id}</strong> {classification.technique_name}
                  <div style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>
                    {classification.tactic} • conf {classification.confidence.toFixed(2)}
                  </div>
                </div>
              ) : (
                <div style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                  UNKNOWN {classification ? `(conf ${classification.confidence.toFixed(2)})` : ""}
                </div>
              )}
            </div>

            <div className="glass-card" style={{ padding: "0.7rem" }}>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: "0.25rem" }}>Layer 3 — Blast Radius</div>
              {blast_radius && (
                <div style={{ fontSize: "0.85rem" }}>
                  <span
                    className="policy-severity"
                    style={{ background: SEVERITY_COLORS[blast_radius.severity]?.bg, color: SEVERITY_COLORS[blast_radius.severity]?.text }}
                  >
                    {blast_radius.severity}
                  </span>
                  <div style={{ color: "var(--text-muted)", fontSize: "0.75rem", marginTop: "0.25rem" }}>
                    {blast_radius.critical_resources_reached.length} critical resource(s) • depth {blast_radius.max_depth}
                  </div>
                </div>
              )}
            </div>
          </div>

          {priority && (
            <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "0.8rem" }}>
              <span
                className="policy-severity"
                style={{ background: PRIORITY_TIER_COLORS[priority.tier]?.bg, color: PRIORITY_TIER_COLORS[priority.tier]?.text, fontWeight: 700 }}
              >
                {priority.tier}
              </span>
              <span style={{ fontSize: "0.85rem", color: "var(--text-secondary)" }}>
                Layer 5 — Priority Score: {priority.score}/100
              </span>
            </div>
          )}

          <div className="glass-card" style={{ padding: "0.9rem", background: "rgba(0, 229, 255, 0.04)", border: "1px solid rgba(0, 229, 255, 0.15)" }}>
            <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: "0.35rem", textTransform: "uppercase", letterSpacing: "0.05em" }}>
              Orchestrator Rationale
            </div>
            <p style={{ fontSize: "0.88rem", color: "var(--text-primary)", lineHeight: 1.5 }}>{rationale}</p>
          </div>

          {policy_draft ? (
            <div className="glass-card" style={{ padding: "0.9rem", marginTop: "0.7rem" }}>
              <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: "0.35rem", textTransform: "uppercase" }}>
                Layer 4 — Policy Draft ({policy_draft.test_passed ? "sandbox test passed" : "sandbox test failed"})
              </div>
              <p style={{ fontSize: "0.85rem" }}>{policy_draft.description}</p>
              <button
                className="btn-glass btn-glow"
                style={{ marginTop: "0.7rem" }}
                onClick={() => onSelectIncident?.(event)}
              >
                Review Policy Diff →
              </button>
            </div>
          ) : (
            // No draft doesn't mean nothing to show — the orchestrator still
            // made a real decision (escalate/gather-context/monitor) with a
            // real reason. Route to the same Policy Diff page, which shows
            // that reason honestly instead of the button just vanishing
            // with no way to see why.
            <button
              className="btn-glass"
              style={{ marginTop: "0.7rem" }}
              onClick={() => onSelectIncident?.(event)}
            >
              Review Decision Details →
            </button>
          )}
        </>
      )}
    </div>
  );
}

export default function AIInsightsView({ onSelectIncident }) {
  const [status, setStatus] = useState("idle"); // idle | loading | done | error
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [source, setSource] = useState("demo");

  const runAnalysis = useCallback(async (src) => {
    setStatus("loading");
    setSource(src);
    setError(null);
    try {
      const result = await fetchAiInsights(src === "demo" ? 4 : getLiveAnalysisLimit(), src);
      setData(result);
      setStatus("done");
    } catch (err) {
      setError(err.message);
      setStatus("error");
    }
  }, []);

  const anomalousCount = data?.results?.filter((r) => r.is_anomalous).length ?? 0;

  return (
    <div className="view-section active">
      <section className="policies-header glass-card reveal-element delay-1" style={{ padding: "2.5rem", marginBottom: "2rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
          <div>
            <h3 className="section-title" style={{ marginBottom: "0.5rem" }}><DecryptedText text="AI THREAT INTELLIGENCE" animateOn="view" sequential revealDirection="start" speed={26} encryptedClassName="dtx-scramble" /></h3>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.92rem" }}>
              5-layer ML pipeline + agentic LLM orchestrator — anomaly detection, ATT&CK classification, blast radius, priority scoring, and reasoning
            </p>
          </div>
          <div style={{ display: "flex", gap: "0.6rem" }}>
            <button className="sync-btn sync-btn--primary" disabled={status === "loading"} onClick={() => runAnalysis("demo")}>
              <span className="sync-btn__icon">{status === "loading" && source === "demo" ? "⟳" : "▶"}</span>
              {status === "loading" && source === "demo" ? "Analyzing..." : "Simulate Attack Scenarios"}
            </button>
            <button className="sync-btn" disabled={status === "loading"} onClick={() => runAnalysis("live")}>
              <span className="sync-btn__icon">{status === "loading" && source === "live" ? "⟳" : "▶"}</span>
              {status === "loading" && source === "live" ? "Analyzing..." : "Analyze Live Events"}
            </button>
          </div>
        </div>

        {status === "done" && data && (
          <p style={{ marginTop: "1rem", color: "var(--text-muted)", fontSize: "0.85rem" }}>
            {source === "demo" ? (
              <>Crafted incidents using the demo blast-radius graph's real IAM principals — not live telemetry. </>
            ) : (
              <>{data.results.length} most recent real CSPM events (adjustable in System Settings) — their resource names don't match the demo graph, so blast radius will show LOW. </>
            )}
            {anomalousCount}/{data.results.length} flagged anomalous • Reasoner: <code>{data.reasoner}</code> • LLM: <code>{data.llm_client}</code>
          </p>
        )}
      </section>

      {status === "idle" && (
        <div className="empty-state">
          <div className="empty-state__icon"></div>
          <p>Choose a mode above to run the full AI pipeline.</p>
          <p className="empty-state__sub">
            "Simulate Attack Scenarios" uses crafted incidents tied to the demo graph's IAM roles, so blast radius and (for one scenario) an auto-fix draft actually fire. "Analyze Live Events" runs Layers 1-5 over real CSPM telemetry, but blast radius stays LOW since those events carry no matching identity.
          </p>
        </div>
      )}

      {status === "loading" && (
        <div className="empty-state">
          <div className="empty-state__icon"></div>
          <p>Running Layers 1-5 and the orchestrator...</p>
          <p className="empty-state__sub">This can take 10-60 seconds depending on how many events cross the anomaly threshold and need an LLM call.</p>
        </div>
      )}

      {status === "error" && (
        <div className="empty-state">
          <div className="empty-state__icon"></div>
          <p>AI engine unavailable.</p>
          <p className="empty-state__sub">{error}</p>
        </div>
      )}

      {status === "done" && data && (
        <div className="policy-cards-grid">
          {data.results.map((r) => (
            <ResultCard key={r.event.event_id} result={r} threshold={0.46} onSelectIncident={onSelectIncident} />
          ))}
        </div>
      )}
    </div>
  );
}
