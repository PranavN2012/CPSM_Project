import { formatTimestamp } from "../utils.js";

const TIER_LABEL = { CRITICAL: "Critical Escalation", HIGH: "High Severity", MEDIUM: "Medium", LOW: "Low" };

const STATUS_STRIP = {
  REMEDIATION_FAILED: { main: "Remediation attempt failed", sub: "Manual intervention required", tag: "RETRY" },
  ENCRYPTION_FAILED: { main: "Encryption enforcement failed", sub: "Manual intervention required", tag: "RETRY" },
  IAM_OVERPERMISSIVE: { main: "Flagged by IAM policy audit", sub: "No auto-remediation for IAM changes", tag: "IAM" },
  NON_COMPLIANT: { main: "Detected via posture scan", sub: "Awaiting remediation decision", tag: "SCAN" },
};

export default function PriorityCard({ event, tier, blastScore, onInspect, onReviewDiff }) {
  const tierClass = tier.toLowerCase();
  const strip = STATUS_STRIP[event.status] || { main: "Awaiting triage", sub: "No automated action taken yet", tag: "NEW" };

  return (
    <div className={`glass-card priority-card priority-card--${tierClass}`}>
      <div className="priority-card__head">
        <span className="priority-card__sev">{TIER_LABEL[tier].toUpperCase()}</span>
        <span className="priority-card__id">{event.event_id ? event.event_id.slice(0, 8).toUpperCase() : "—"}</span>
        <span className="priority-card__score">BLAST SCORE <b>{blastScore.toFixed(1)}</b>/100</span>
      </div>

      <div className="priority-card__resource">{event.bucket_name}</div>
      <p className="priority-card__desc">
        {event.nlp_summary ? event.nlp_summary.split(".")[0] + "." : `${event.vulnerability_type} detected in ${event.region}.`}
      </p>

      <div className="priority-card__strip">
        <span className="priority-card__strip-main">
          {strip.main}
          <span className="priority-card__strip-sub">{strip.sub}</span>
        </span>
        <span className="priority-card__strip-tag">{strip.tag}</span>
      </div>

      <div className="priority-card__foot">
        <span className="priority-card__meta">{formatTimestamp(event.timestamp)} • {event.region}</span>
        <div className="priority-card__actions">
          <button className="btn-glass" onClick={() => onInspect?.(event)}>Inspect Graph Path</button>
          <button className="btn-glass btn-glow" onClick={() => onReviewDiff?.(event)}>
            Review Policy Diff
          </button>
        </div>
      </div>
    </div>
  );
}
