// Per-viewer setting (not shared, not synced to the backend): how many
// live events "Analyze Live Events" pulls through the 5-layer pipeline.
// The backend (/ai/insights) independently clamps this to 25 regardless of
// what's stored here — see scripts/local-api-server.py's _handle_ai_insights.
const LIVE_ANALYSIS_LIMIT_KEY = "cspm.liveAnalysisLimit";
export const LIVE_ANALYSIS_LIMIT_DEFAULT = 10;
export const LIVE_ANALYSIS_LIMIT_MAX = 25;

export function getLiveAnalysisLimit() {
  try {
    const raw = window.localStorage.getItem(LIVE_ANALYSIS_LIMIT_KEY);
    const n = parseInt(raw, 10);
    if (Number.isFinite(n) && n > 0) return Math.min(n, LIVE_ANALYSIS_LIMIT_MAX);
  } catch { /* private-mode or blocked storage — fall through to default */ }
  return LIVE_ANALYSIS_LIMIT_DEFAULT;
}

export function setLiveAnalysisLimit(n) {
  try {
    window.localStorage.setItem(LIVE_ANALYSIS_LIMIT_KEY, String(Math.max(1, Math.min(n, LIVE_ANALYSIS_LIMIT_MAX))));
  } catch { /* nothing to persist to — the in-memory default still applies */ }
}

export function formatTimestamp(iso) {
  try {
    return new Date(iso).toLocaleString("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return iso;
  }
}

const STATUS_MAP = {
  REMEDIATED: { cls: "badge--remediated", label: "Secured" },
  ENCRYPTION_REMEDIATED: { cls: "badge--remediated", label: "Encrypted" },
  COMPLIANT: { cls: "badge--compliant", label: "Verified" },
  REMEDIATION_FAILED: { cls: "badge--failed", label: "Alert" },
  ENCRYPTION_FAILED: { cls: "badge--failed", label: "Enc. Alert" },
  IAM_OVERPERMISSIVE: { cls: "badge--flagged", label: "Flagged" },
};

export function statusInfo(status) {
  return STATUS_MAP[status] || { cls: "badge--compliant", label: status };
}

export function severityClass(severity) {
  return `severity--${(severity || "MEDIUM").toLowerCase()}`;
}

export function vulnTypeClass(type) {
  const t = type || "S3 Public Access";
  if (t.includes("Public")) return "vuln-type--s3-access";
  if (t.includes("Encrypt")) return "vuln-type--s3-encrypt";
  return "vuln-type--iam";
}

export const PROVIDER_COLORS = {
  aws: { bg: "rgba(255, 153, 0, 0.15)", border: "rgba(255, 153, 0, 0.4)", text: "#FF9900", icon: "☁" },
  azure: { bg: "rgba(0, 120, 212, 0.15)", border: "rgba(0, 120, 212, 0.4)", text: "#0078D4", icon: "☁" },
  gcp: { bg: "rgba(234, 67, 53, 0.15)", border: "rgba(234, 67, 53, 0.4)", text: "#EA4335", icon: "☁" },
};

export const SEVERITY_COLORS = {
  CRITICAL: { bg: "rgba(244, 63, 94, 0.15)", text: "#f43f5e", glow: "rgba(244, 63, 94, 0.3)" },
  HIGH: { bg: "rgba(245, 158, 11, 0.15)", text: "#f59e0b", glow: "rgba(245, 158, 11, 0.3)" },
  MEDIUM: { bg: "rgba(0, 229, 255, 0.15)", text: "#00e5ff", glow: "rgba(0, 229, 255, 0.3)" },
  LOW: { bg: "rgba(16, 185, 129, 0.15)", text: "#10b981", glow: "rgba(16, 185, 129, 0.3)" },
};

export const PRIORITY_TIER_COLORS = {
  P1: SEVERITY_COLORS.CRITICAL,
  P2: SEVERITY_COLORS.HIGH,
  P3: SEVERITY_COLORS.MEDIUM,
  P4: SEVERITY_COLORS.LOW,
};

export const DECISION_LABELS = {
  attempt_auto_fix: { label: "Auto-Fix Attempted", cls: "badge--remediated" },
  escalate_to_human: { label: "Escalated to Human", cls: "badge--failed" },
  gather_more_context: { label: "Gathering Context", cls: "badge--flagged" },
  monitor_only: { label: "Monitor Only", cls: "badge--compliant" },
};
