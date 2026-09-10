import { useEffect, useState } from "react";
import Sidebar from "./components/Sidebar.jsx";
import Topbar from "./components/Topbar.jsx";
import DashboardView from "./components/views/DashboardView.jsx";
import AIInsightsView from "./components/views/AIInsightsView.jsx";
import EventsView from "./components/views/EventsView.jsx";
import PoliciesView from "./components/views/PoliciesView.jsx";
import PolicyDiffView from "./components/views/PolicyDiffView.jsx";
import SettingsView from "./components/views/SettingsView.jsx";
import AttackPathView from "./components/views/AttackPathView.jsx";
import ReviewQueueView from "./components/views/ReviewQueueView.jsx";
import ShapeGrid from "./components/ShapeGrid.jsx";
import { useDashboardData } from "./hooks/useDashboardData.js";
import { useTheme } from "./hooks/useTheme.js";
import { applyChartTheme } from "./components/charts/chartSetup.js";
import { formatTimestamp } from "./utils.js";

export default function App() {
  const [page, setPage] = useState("dashboard");
  const [selectedIncident, setSelectedIncident] = useState(null);
  const { events, stats, compliance, connected, refresh } = useDashboardData();
  const { isLight, toggleTheme } = useTheme();

  useEffect(() => {
    applyChartTheme(isLight);
  }, [isLight]);

  function navigate(target) {
    // Sidebar navigation is generic (no specific incident in mind) — clear
    // any incident left over from a previous "Review Policy Diff"/"Inspect
    // Graph Path" click so Attack Path/Policy Diff don't silently reuse a
    // stale one when reached this way instead of from a specific incident.
    setSelectedIncident(null);
    setPage(target);
  }

  function openPolicyDiff(incident) {
    setSelectedIncident(incident);
    setPage("policy-diff");
  }

  function openAttackPath(incident) {
    setSelectedIncident(incident);
    setPage("attack-path");
  }

  return (
    <>
      <div className="app-bg-grid" aria-hidden="true">
        <ShapeGrid
          direction="diagonal"
          speed={0.5}
          shape="hexagon"
          squareSize={23}
          borderColor={isLight ? "rgba(122,128,144,0.13)" : "rgba(160,168,188,0.09)"}
          hoverFillColor={isLight ? "rgba(122,128,144,0.10)" : "rgba(160,168,188,0.12)"}
          hoverTrailAmount={4}
        />
      </div>

      <Sidebar activePage={page} onNavigate={navigate} />

      <main className="main">
        <Topbar connected={connected} isLight={isLight} onToggleTheme={toggleTheme} onRefresh={refresh} />

        {page === "dashboard" && (
          <DashboardView events={events} stats={stats} compliance={compliance} onNavigate={navigate} onSelectIncident={openPolicyDiff} onInspectGraph={openAttackPath} />
        )}
        {page === "ai-insights" && <AIInsightsView onSelectIncident={openPolicyDiff} />}
        {page === "review-queue" && <ReviewQueueView onSelectIncident={openPolicyDiff} />}
        {page === "events" && <EventsView events={events} />}
        {page === "policies" && <PoliciesView />}
        {page === "policy-diff" && <PolicyDiffView incident={selectedIncident} onBack={() => navigate("dashboard")} onRefresh={refresh} />}
        {page === "settings" && <SettingsView onNavigate={navigate} onRefresh={refresh} />}
        {page === "attack-path" && <AttackPathView incident={selectedIncident} onBack={() => navigate("dashboard")} />}

        <footer className="footer reveal-element delay-5">
          <span className="footer__brand">CLOUDSENTRY CSPM v3.0 • Cloud-Agnostic Policy Engine • Auto-sync</span>
          {stats?.last_event && stats.last_event !== "N/A" && (
            <span className="footer__time">Last: {formatTimestamp(stats.last_event)}</span>
          )}
        </footer>
      </main>
    </>
  );
}
