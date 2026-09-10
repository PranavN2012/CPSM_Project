import { useState } from "react";
import { createGithubIssues } from "../../api.js";
import { formatTimestamp, statusInfo, severityClass, vulnTypeClass } from "../../utils.js";
import DecryptedText from "../DecryptedText.jsx";

const FILTERS = [
  { key: "all", label: "All" },
  { key: "REMEDIATED", label: "Secured" },
  { key: "COMPLIANT", label: "Verified" },
  { key: "FAILED", label: "Alerts" },
  { key: "IAM_OVERPERMISSIVE", label: "IAM" },
];

function matchesFilter(event, filter) {
  if (filter === "all") return true;
  if (filter === "FAILED") return ["REMEDIATION_FAILED", "ENCRYPTION_FAILED"].includes(event.status);
  if (filter === "REMEDIATED") return event.status === "REMEDIATED" || event.status === "ENCRYPTION_REMEDIATED";
  return event.status === filter;
}

export default function EventsView({ events }) {
  const [filter, setFilter] = useState("all");
  const [issuesState, setIssuesState] = useState({ label: "Dispatch Issues", variant: "", disabled: false });

  const filtered = events.filter((e) => matchesFilter(e, filter));

  async function handleCreateIssues() {
    setIssuesState({ label: "Creating...", variant: "", disabled: true });
    try {
      const data = await createGithubIssues(5);
      if (data.created > 0) {
        setIssuesState({ label: `✓ ${data.created} Issues Created`, variant: "btn-github--success", disabled: true });
        const firstUrl = data.issues?.find((i) => i.url)?.url;
        if (firstUrl) window.open(firstUrl, "_blank");
      } else if (data.failed > 0) {
        setIssuesState({ label: "Network Error — Try Mobile Hotspot", variant: "btn-github--error", disabled: true });
      } else {
        setIssuesState({ label: "No actionable events", variant: "", disabled: true });
      }
    } catch (err) {
      setIssuesState({ label: "Failed: " + err.message, variant: "btn-github--error", disabled: true });
    }
    setTimeout(() => setIssuesState({ label: "Dispatch Issues", variant: "", disabled: false }), 5000);
  }

  return (
    <div className="view-section active">
      <section className="table-section reveal-element delay-1">
        <div className="table-header">
          <h3 className="section-title"><DecryptedText text="SYSTEM EVENT LOG" animateOn="view" sequential revealDirection="start" speed={28} encryptedClassName="dtx-scramble" /></h3>
          <div className="table-header__controls">
            <button
              className={`btn-glass btn-glow ${issuesState.variant}`}
              title="Dispatch to GitHub"
              disabled={issuesState.disabled}
              onClick={handleCreateIssues}
            >
              <span>{issuesState.label}</span>
              <div className="btn-glow-effect"></div>
            </button>
            <div className="filter-group">
              {FILTERS.map((f) => (
                <button
                  key={f.key}
                  className={`filter-btn${filter === f.key ? " filter-btn--active" : ""}`}
                  onClick={() => setFilter(f.key)}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="empty-state">
            <div className="empty-state__icon"></div>
            <p>System Initialized. Awaiting telemetry.</p>
            <p className="empty-state__sub">Execute simulation protocols to display metrics.</p>
          </div>
        ) : (
          <div className="glass-card table-wrapper">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Resource Identifier</th>
                  <th>Detection Type</th>
                  <th>Zone</th>
                  <th>Level</th>
                  <th>State</th>
                  <th>AI Summary</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((e, i) => {
                  const status = statusInfo(e.status);
                  const summary = e.nlp_summary || "";
                  return (
                    <tr key={e.event_id || i} style={{ animationDelay: `${i * 0.03}s` }}>
                      <td className="cell-timestamp">{formatTimestamp(e.timestamp)}</td>
                      <td className="cell-resource">{e.bucket_name}</td>
                      <td><span className={`vuln-type ${vulnTypeClass(e.vulnerability_type)}`}>{e.vulnerability_type || "S3 Public Access"}</span></td>
                      <td className="cell-mono">{e.region}</td>
                      <td><span className={`severity ${severityClass(e.severity)}`}>{(e.severity || "MEDIUM").toUpperCase()}</span></td>
                      <td><span className={`badge ${status.cls}`}>{status.label}</span></td>
                      <td className="cell-nlp" title={summary}>
                        {summary.substring(0, 120)}{summary.length > 120 ? "…" : summary ? "" : "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}
