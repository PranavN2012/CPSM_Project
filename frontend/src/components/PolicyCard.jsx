import { PROVIDER_COLORS, SEVERITY_COLORS } from "../utils.js";

export default function PolicyCard({ policy, index, onToggle }) {
  const sev = SEVERITY_COLORS[policy.severity] || SEVERITY_COLORS.MEDIUM;
  const prov = PROVIDER_COLORS[policy.provider] || PROVIDER_COLORS.aws;
  const isEnabled = policy.enabled !== false;
  const isReview = policy.needs_review || policy.auto_generated;
  const feedSource = policy.feed_source || "";

  return (
    <div
      className={`policy-card glass-card ${isReview ? "policy-card--review" : ""}${isEnabled ? "" : " policy-card--off"}`}
      style={{ animationDelay: `${index * 0.06}s`, "--card-glow": sev.glow }}
    >
      <div className="policy-card__header">
        <div style={{ display: "flex", gap: "0.4rem", alignItems: "center" }}>
          <div className="policy-card__provider" style={{ background: prov.bg, borderColor: prov.border, color: prov.text }}>
            {prov.icon} {policy.provider.toUpperCase()}
          </div>
          {feedSource && <span className={`feed-source-tag feed-source-tag--${feedSource}`}>{feedSource.toUpperCase()}</span>}
          {isReview && <span className="review-badge">⚠ Pending Review</span>}
        </div>
        <label className="toggle-switch">
          <input
            type="checkbox"
            checked={isEnabled}
            onChange={(e) => onToggle(policy, e.target.checked)}
          />
          <span className="toggle-slider"></span>
        </label>
      </div>
      <h4 className="policy-card__title">{policy.name}</h4>
      <p className="policy-card__desc">{policy.description || ""}</p>
      <div className="policy-card__meta">
        <span className="policy-severity" style={{ background: sev.bg, color: sev.text }}>{policy.severity}</span>
        <span className="policy-service">{policy.service || ""}</span>
        <span className="policy-remediate">{policy.auto_remediate ? "⚡ Auto-fix" : "⚑ Flag only"}</span>
      </div>
      <div className="policy-card__compliance">
        {(policy.compliance || []).length > 0
          ? policy.compliance.map((c, i) => (
              <span className="compliance-tag" key={i}>{c.framework} {c.control}</span>
            ))
          : <span className="compliance-tag">No mappings</span>}
      </div>
      <div className="policy-card__id"><code>{policy.id}</code></div>
    </div>
  );
}
