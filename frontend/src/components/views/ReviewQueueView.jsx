import { useCallback, useEffect, useState } from "react";
import { fetchAiInsights } from "../../api.js";
import { formatTimestamp, severityClass, vulnTypeClass, getLiveAnalysisLimit, DECISION_LABELS } from "../../utils.js";
import DecryptedText from "../DecryptedText.jsx";

const QUEUE_DECISIONS = new Set(["escalate_to_human", "gather_more_context"]);

export default function ReviewQueueView({ onSelectIncident }) {
  const [status, setStatus] = useState("idle"); // idle | loading | ready | error
  const [items, setItems] = useState([]);
  const [scanned, setScanned] = useState(0);
  const [error, setError] = useState(null);

  const load = useCallback(async () => {
    setStatus("loading");
    setError(null);
    try {
      const data = await fetchAiInsights(getLiveAnalysisLimit(), "live");
      setScanned(data.results.length);
      setItems(data.results.filter((r) => QUEUE_DECISIONS.has(r.decision)));
      setStatus("ready");
    } catch (err) {
      setError(err.message);
      setStatus("error");
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  return (
    <div className="view-section active">
      <section className="policies-header glass-card reveal-element delay-1" style={{ padding: "2.5rem", marginBottom: "2rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
          <div>
            <h3 className="section-title" style={{ marginBottom: "0.5rem" }}><DecryptedText text="NEEDS REVIEW" animateOn="view" sequential revealDirection="start" speed={28} encryptedClassName="dtx-scramble" /></h3>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.92rem" }}>
              Every incident the orchestrator currently has sitting in "Escalated to Human" or
              "Gathering Context" — the LLM proposed nothing, so a person has to look. This is the
              actionable inbox those badges didn't have anywhere else in the app.
            </p>
          </div>
          <button className="sync-btn sync-btn--primary" disabled={status === "loading"} onClick={load}>
            <span className="sync-btn__icon">{status === "loading" ? "⟳" : "↻"}</span>
            {status === "loading" ? "Scanning..." : "Re-check Live Events"}
          </button>
        </div>
        {status === "ready" && (
          <p style={{ marginTop: "1rem", color: "var(--text-muted)", fontSize: "0.85rem" }}>
            {items.length} of {scanned} recently-scanned live events need review.
          </p>
        )}
      </section>

      {status === "loading" && (
        <div className="empty-state"><p>Running Layers 1-5 against recent live events...</p></div>
      )}
      {status === "error" && (
        <div className="empty-state" style={{ borderColor: "var(--danger)" }}><p>{error}</p></div>
      )}
      {status === "ready" && items.length === 0 && (
        <div className="empty-state">
          <div className="empty-state__icon"></div>
          <p>Nothing waiting on you right now.</p>
          <p className="empty-state__sub">Every recently-scanned live event was either auto-fixed, monitor-only, or below the anomaly threshold.</p>
        </div>
      )}

      {status === "ready" && items.length > 0 && (
        <div className="policy-cards-grid">
          {items.map((r) => {
            const decisionInfo = DECISION_LABELS[r.decision] || { label: r.decision, cls: "badge--compliant" };
            return (
              <div className="glass-card policy-card" key={r.event.event_id}>
                <div className="policy-card__header">
                  <div style={{ display: "flex", gap: "0.5rem", alignItems: "center", flexWrap: "wrap" }}>
                    <span className={`vuln-type ${vulnTypeClass(r.event.vulnerability_type)}`}>{r.event.vulnerability_type}</span>
                    <span className={`severity ${severityClass(r.event.severity)}`}>{r.event.severity}</span>
                  </div>
                  <span className={`badge ${decisionInfo.cls}`}>{decisionInfo.label}</span>
                </div>
                <h4 className="policy-card__title">{r.event.bucket_name}</h4>
                <p className="policy-card__desc" style={{ marginBottom: "0.6rem" }}>
                  {r.event.region} • {formatTimestamp(r.event.timestamp)}
                </p>
                <div className="glass-card" style={{ padding: "0.9rem", background: "rgba(0, 229, 255, 0.04)", border: "1px solid rgba(0, 229, 255, 0.15)" }}>
                  <div style={{ fontSize: "0.72rem", color: "var(--text-muted)", marginBottom: "0.35rem", textTransform: "uppercase" }}>Why it's here</div>
                  <p style={{ fontSize: "0.85rem" }}>{r.rationale}</p>
                </div>
                <button className="btn-glass btn-glow" style={{ marginTop: "0.7rem" }} onClick={() => onSelectIncident?.(r.event)}>
                  Review Decision Details →
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
