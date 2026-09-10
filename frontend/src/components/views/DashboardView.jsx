import { useMemo, useState } from "react";
import VulnDonutLegend from "../charts/VulnDonutLegend.jsx";
import AnomalyChart from "../charts/AnomalyChart.jsx";
import PriorityCard from "../PriorityCard.jsx";
import DecryptedText from "../DecryptedText.jsx";

const COMPLIANCE_FRAMEWORKS = [
  { key: "CIS AWS", name: "CIS AWS v1.4", sub: "Foundations Benchmark" },
  { key: "SOC 2", name: "SOC 2 Type II", sub: "Trust Services Criteria" },
  { key: "PCI-DSS", name: "PCI-DSS v4.0", sub: "Cardholder Data Environment" },
];

const ACTIONABLE_STATUSES = new Set(["NON_COMPLIANT", "IAM_OVERPERMISSIVE", "REMEDIATION_FAILED", "ENCRYPTION_FAILED"]);
const SEVERITY_BASE = { CRITICAL: 88, HIGH: 60, MEDIUM: 38, LOW: 15 };
const SERVICE_MAP = [
  ["S3", "S3"], ["IAM", "IAM"], ["DynamoDB", "DynamoDB"], ["Security Group", "EC2"],
  ["RDS", "RDS"], ["GCS", "GCS"], ["Blob", "Blob"], ["NSG", "NSG"],
  ["RBAC", "RBAC"], ["Firewall", "Firewall"], ["Lambda", "Lambda"],
];

function hashJitter(str) {
  let h = 0;
  for (const c of str) h = (h * 31 + c.charCodeAt(0)) | 0;
  return Math.abs(h) % 8;
}

function deriveTier(severity) {
  const s = (severity || "MEDIUM").toUpperCase();
  return SEVERITY_BASE[s] ? s : "MEDIUM";
}

/** A deterministic, severity-anchored proxy score — not the live 5-layer
 * pipeline (that requires a real SBERT/LLM run, triggered manually from the
 * AI Reasoning page, not on every dashboard poll). Real severity + status
 * drive it; only the sub-integer jitter is cosmetic, for visual variety. */
function buildPriorityQueue(events, limit = 3) {
  return events
    .filter((e) => ACTIONABLE_STATUSES.has(e.status))
    .map((e) => {
      const tier = deriveTier(e.severity);
      return { event: e, tier, blastScore: Math.min(99.9, SEVERITY_BASE[tier] + hashJitter(e.event_id || e.bucket_name || "")) };
    })
    .sort((a, b) => b.blastScore - a.blastScore)
    .slice(0, limit);
}

function deriveServices(events) {
  const found = new Set();
  events.forEach((e) => {
    const vt = e.vulnerability_type || "";
    for (const [needle, code] of SERVICE_MAP) {
      if (vt.includes(needle)) found.add(code);
    }
  });
  return [...found];
}

const ICON = {
  search: <><circle cx="11" cy="11" r="7" /><path d="M21 21l-4.3-4.3" /></>,
  shield: <><path d="M12 2 4 5v6c0 5 3.5 8.5 8 11 4.5-2.5 8-6 8-11V5z" /><path d="M9 12l2 2 4-4" /></>,
  alert: <><path d="M12 9v4M12 17h.01" /><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" /></>,
  gauge: <><path d="M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z" /><path d="M4.9 19a9 9 0 1 1 14.2 0M12 12l3-3" /></>,
  grid: <><rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" /></>,
  benchShield: <><path d="M12 2 4 5v6c0 5 3.5 8.5 8 11 4.5-2.5 8-6 8-11V5z" /></>,
  benchCheck: <><circle cx="12" cy="12" r="9" /><path d="M8 12l2.5 2.5L16 9" /></>,
  benchCard: <><rect x="2" y="5" width="20" height="14" rx="2" /><path d="M2 10h20" /></>,
};

function Icon({ name }) {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">{ICON[name]}</svg>;
}

export default function DashboardView({ events, stats, compliance, onNavigate, onSelectIncident, onInspectGraph }) {
  const [region, setRegion] = useState("all");

  const regions = useMemo(() => [...new Set(events.map((e) => e.region).filter(Boolean))], [events]);
  const filteredEvents = useMemo(
    () => (region === "all" ? events : events.filter((e) => e.region === region)),
    [events, region]
  );

  const vulnTypes = useMemo(() => {
    const counts = {};
    filteredEvents.forEach((e) => {
      const vt = e.vulnerability_type || "Unknown";
      counts[vt] = (counts[vt] || 0) + 1;
    });
    return counts;
  }, [filteredEvents]);

  const queue = useMemo(() => buildPriorityQueue(filteredEvents), [filteredEvents]);
  const services = useMemo(() => deriveServices(filteredEvents), [filteredEvents]);

  const todayCount = useMemo(() => {
    const today = new Date().toISOString().slice(0, 10);
    return events.filter((e) => (e.timestamp || "").startsWith(today)).length;
  }, [events]);

  const passRate = (stats?.remediated ?? 0) + (stats?.failed ?? 0) > 0
    ? Math.round((stats.remediated / (stats.remediated + stats.failed)) * 100)
    : 100;

  const escalated = (stats?.failed ?? 0) + (stats?.flagged ?? 0);

  return (
    <div className="view-section active">
      <div className="page-header">
        <div>
          <div className="page-header__eyebrow"><i></i> Mesh Sentinel • Autonomous Guard</div>
          <h1><DecryptedText text="Security Posture Engine" animateOn="view" sequential revealDirection="start" speed={28} encryptedClassName="dtx-scramble" /></h1>
          <p>Real-time synthesis of simulated AWS attack vectors, autonomous sandbox remediations, and live 5-layer AI threat analysis.</p>
        </div>
        <div className="region-pills">
          <button className={`region-pill${region === "all" ? " region-pill--active" : ""}`} onClick={() => setRegion("all")}>All Regions</button>
          {regions.slice(0, 3).map((r) => (
            <button key={r} className={`region-pill${region === r ? " region-pill--active" : ""}`} onClick={() => setRegion(r)}>{r}</button>
          ))}
        </div>
      </div>

      <section className="kpi-row reveal-element delay-1">
        <div className="glass-card kpi-card">
          <div className="kpi-card__header">
            <span className="kpi-card__label">Total Findings</span>
            <span className="kpi-card__icon"><Icon name="search" /></span>
          </div>
          <div className="kpi-card__body"><span className="kpi-card__value">{stats?.total_events ?? "—"}</span></div>
          <div className="kpi-card__foot">Active • <em>+{todayCount} today</em></div>
        </div>

        <div className="glass-card kpi-card kpi-card--success">
          <div className="kpi-card__header">
            <span className="kpi-card__label">Autonomous Actions</span>
            <span className="kpi-card__icon"><Icon name="shield" /></span>
          </div>
          <div className="kpi-card__body"><span className="kpi-card__value">{stats?.remediated ?? "—"}</span></div>
          <div className="kpi-card__foot">Resolved • <b>{passRate}%</b> pass rate</div>
        </div>

        <div className="glass-card kpi-card kpi-card--danger">
          <div className="kpi-card__header">
            <span className="kpi-card__label">Priority Flagged</span>
            <span className="kpi-card__icon"><Icon name="alert" /></span>
          </div>
          <div className="kpi-card__body"><span className="kpi-card__value">{escalated}</span></div>
          <div className="kpi-card__foot">Requires SecOps authorization</div>
        </div>

        <div className="glass-card kpi-card kpi-card--info">
          <div className="kpi-card__header">
            <span className="kpi-card__label">Posture Compliance</span>
            <span className="kpi-card__icon"><Icon name="gauge" /></span>
          </div>
          <div className="kpi-card__body"><span className="kpi-card__value">{stats?.compliance_rate ?? "—"}%</span></div>
          <div className="kpi-card__foot">Fleet Avg • Security Health Index</div>
        </div>

        <div className="glass-card kpi-card">
          <div className="kpi-card__header">
            <span className="kpi-card__label">Active Services</span>
            <span className="kpi-card__icon"><Icon name="grid" /></span>
          </div>
          <div className="kpi-card__body"><span className="kpi-card__value">{services.length}</span></div>
          <div className="kpi-card__tags">{services.slice(0, 5).map((s) => <span className="kpi-card__tag" key={s}>{s}</span>)}</div>
        </div>
      </section>

      <section className="intel-row reveal-element delay-2">
        <div>
          <div className="glass-card chart-card">
            <h3 className="glass-card__title"><DecryptedText text="Vulnerability Vector Split" animateOn="view" sequential revealDirection="start" speed={28} encryptedClassName="dtx-scramble" /></h3>
            <VulnDonutLegend vulnerabilityTypes={vulnTypes} />
          </div>
          <div className="glass-card chart-card anomaly-card">
            <div className="anomaly-card__head">
              <h3 className="glass-card__title" style={{ marginBottom: 0 }}><DecryptedText text="24h Anomaly Simulation" animateOn="view" sequential revealDirection="start" speed={28} encryptedClassName="dtx-scramble" /></h3>
              <span className="anomaly-card__badge">Hourly rate</span>
            </div>
            <AnomalyChart events={events} />
          </div>
        </div>

        <div className="glass-card">
          <div style={{ padding: "19px 19px 0" }}>
            <div className="priority-queue__head">
              <h3 className="section-title" style={{ fontSize: 16 }}><DecryptedText text="Priority Action Queue" animateOn="view" sequential revealDirection="start" speed={28} encryptedClassName="dtx-scramble" /></h3>
              <span className="priority-queue__count">{queue.length} High Impact</span>
              <span className="priority-queue__sort">Ordered by severity</span>
            </div>
          </div>
          <div style={{ padding: "0 19px 19px" }}>
            {queue.length === 0 ? (
              <div className="empty-state" style={{ margin: 0 }}>
                <div className="empty-state__icon"></div>
                <p>No actionable findings right now.</p>
                <p className="empty-state__sub">Everything in this region is either remediated or compliant.</p>
              </div>
            ) : (
              <div className="priority-queue">
                {queue.map(({ event, tier, blastScore }) => (
                  <PriorityCard
                    key={event.event_id}
                    event={event} tier={tier} blastScore={blastScore}
                    onInspect={(e) => onInspectGraph?.(e)}
                    onReviewDiff={(e) => onSelectIncident?.(e)}
                  />
                ))}
              </div>
            )}
          </div>
        </div>
      </section>

      <section className="compliance-section reveal-element delay-3">
        <div className="compliance-section__head">
          <div>
            <h3 className="section-title"><DecryptedText text="Compliance Framework Benchmarks" animateOn="view" sequential revealDirection="start" speed={28} encryptedClassName="dtx-scramble" /></h3>
            <p>Continuous regulatory verification evaluated against the current event population.</p>
          </div>
          <a className="compliance-section__link" onClick={() => onNavigate?.("events")}>Detailed Compliance Matrix →</a>
        </div>
        <div className="compliance-row">
          {COMPLIANCE_FRAMEWORKS.map(({ key, name, sub }, i) => {
            const fw = compliance?.frameworks?.[key];
            const score = fw?.score ?? 0;
            const icon = i === 0 ? "benchShield" : i === 1 ? "benchCheck" : "benchCard";
            return (
              <div className="glass-card bench-card" key={key}>
                <div className="bench-card__head">
                  <span className="bench-card__icon"><Icon name={icon} /></span>
                  <span className="bench-card__name">{name}</span>
                  <span className="bench-card__score">{fw ? `${score}%` : "—%"}</span>
                </div>
                <p className="bench-card__sub">{sub}</p>
                <div className="progress-track">
                  <div className="progress-fill" style={{ width: `${score}%` }} data-score={score < 60 ? "low" : score < 80 ? "medium" : undefined}></div>
                </div>
                <div className="bench-card__split">
                  <span className="bench-card__pass">{fw ? `${fw.passed} Passing` : "—"}</span>
                  <span className="bench-card__warn">{fw ? `${fw.total - fw.passed} Remediation Req.` : "—"}</span>
                </div>
                <div className="bench-card__foot">
                  <span>Coverage: <b>{fw ? `${fw.passed} of ${fw.total}` : "—"} Controls</b></span>
                  <span>{score >= 80 ? "Audit Ready" : score >= 60 ? "In Progress" : "Needs Attention"}</span>
                </div>
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}
