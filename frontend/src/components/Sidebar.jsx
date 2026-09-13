import TrueFocus from "./TrueFocus.jsx";

const ICONS = {
  posture: <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" />,
  brain: <><path d="M9 3a3 3 0 0 0-3 3v.2A3 3 0 0 0 4 9v1a3 3 0 0 0 1 2.24V15a3 3 0 0 0 3 3h1" /><path d="M15 3a3 3 0 0 1 3 3v.2A3 3 0 0 1 20 9v1a3 3 0 0 1-1 2.24V15a3 3 0 0 1-3 3h-1" /><path d="M9 3v16M15 3v16" /></>,
  graph: <><circle cx="5" cy="6" r="2" /><circle cx="19" cy="6" r="2" /><circle cx="12" cy="18" r="2" /><path d="M6.7 7.3 11 16M17.3 7.3 13 16M7 6h10" /></>,
  diff: <><path d="M9 4h6a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2z" /><path d="M9 9h6M9 13h4" /></>,
  policy: <><path d="M4 19V5a2 2 0 0 1 2-2h9l5 5v11a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2z" /><path d="M15 3v5h5" /></>,
  clock: <><circle cx="12" cy="12" r="9" /><path d="M12 7v5l3 3" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" /></>,
  inbox: <><path d="M22 12h-6l-2 3h-4l-2-3H2" /><path d="M5.45 5.11 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.45-6.89A2 2 0 0 0 16.76 4H7.24a2 2 0 0 0-1.79 1.11z" /></>,
};

const NAV_ITEMS = [
  { page: "dashboard", label: "Security Posture", title: "Security Posture", icon: "posture" },
  { page: "ai-insights", label: "AI Reasoning (5-Layer)", title: "AI Threat Intelligence (Layers 1-5 + Orchestrator)", icon: "brain" },
  { page: "review-queue", label: "Needs Review", title: "Incidents currently escalated or gathering context, waiting on a human", icon: "inbox" },
  { page: "attack-path", label: "Attack Path & Blast Radius", title: "Attack Path Visualization", icon: "graph" },
  { page: "policy-diff", label: "Policy Diff & Approval", title: "Review and approve an AI-drafted policy fix", icon: "diff" },
  { page: "events", label: "System & Audit Trace", title: "Events", icon: "clock" },
  { page: "policies", label: "Policy Engine", title: "Policy-as-Code manager (toggle & sync)", icon: "policy" },
  { page: "settings", label: "System Settings", title: "Settings", icon: "settings" },
];

function NavIcon({ name }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
      {ICONS[name]}
    </svg>
  );
}

export default function Sidebar({ activePage, onNavigate }) {
  return (
    <aside className="sidebar" id="sidebar">
      <div className="sidebar__brand">
        <svg className="sidebar__logo sidebar__logo--pop" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor"
          strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <path d="M12 2L3 7v5c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V7l-9-5z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
        <span className="sidebar__title">
          <TrueFocus
            sentence="Cloud Sentry"
            manualMode={false}
            blurAmount={1.6}
            borderColor="var(--primary, #4f46e5)"
            glowColor="rgba(79, 70, 229, 0.55)"
            animationDuration={0.5}
            pauseBetweenAnimations={1.2}
            className="sidebar__brand-focus"
          />
          <small>AEGIS SEC-OPS</small>
        </span>
      </div>

      <div className="sidebar__engine-badge">
        <i></i> CORE ENGINE <b>v4.9.2</b>
      </div>

      <nav className="sidebar__nav">
        <span className="sidebar__section-label">Operations</span>
        {NAV_ITEMS.map((item, i) => (
          <a
            key={item.page}
            className={`sidebar__link${activePage === item.page ? " sidebar__link--active" : ""}`}
            title={item.title}
            onClick={() => onNavigate(item.page)}
            style={{ animationDelay: `${0.05 + i * 0.045}s` }}
          >
            <span className="sidebar__link-fill" aria-hidden="true" />
            <span className="sidebar__link-icon"><NavIcon name={item.icon} /></span>
            <span className="sidebar__link-label-stack">
              <span className="sidebar__link-label">{item.label}</span>
              <span className="sidebar__link-label sidebar__link-label--hover" aria-hidden="true">{item.label}</span>
            </span>
          </a>
        ))}
      </nav>

      <div className="sidebar__footer">
        <span className="sidebar__telemetry-label">Telemetry Ingest</span>
        <span className="sidebar__telemetry-bar"><i></i></span>
        <span className="sidebar__version">AEGIS Posture Mesh <b>v3.0</b></span>
      </div>
    </aside>
  );
}
