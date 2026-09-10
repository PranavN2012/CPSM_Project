import { useCallback, useEffect, useState } from "react";
import { fetchPolicies, togglePolicy, syncPolicies } from "../../api.js";
import { PROVIDER_COLORS } from "../../utils.js";
import PolicyCard from "../PolicyCard.jsx";
import Toast from "../Toast.jsx";
import DecryptedText from "../DecryptedText.jsx";

export default function PoliciesView() {
  const [policies, setPolicies] = useState([]);
  const [totalCount, setTotalCount] = useState(0);
  const [enabledCount, setEnabledCount] = useState(0);
  const [providerFilter, setProviderFilter] = useState("all");
  const [syncing, setSyncing] = useState(false);
  const [syncStatus, setSyncStatus] = useState(null);
  const [toast, setToast] = useState(null);

  const loadPolicies = useCallback(async () => {
    try {
      const data = await fetchPolicies();
      setPolicies(data.policies || []);
      setTotalCount(data.total || 0);
      setEnabledCount(data.enabled || 0);
    } catch (err) {
      console.error("Failed to fetch policies:", err);
    }
  }, []);

  useEffect(() => {
    loadPolicies();
  }, [loadPolicies]);

  function showToast(message, type = "success") {
    setToast({ message, type });
    setTimeout(() => setToast(null), 4000);
  }

  async function handleToggle(policy, enabled) {
    try {
      const updateBody = {};
      if (enabled && (policy.needs_review || policy.auto_generated)) {
        updateBody.needs_review = false;
        updateBody.auto_generated = false;
      }
      await togglePolicy(policy.id, enabled, updateBody);

      setPolicies((prev) =>
        prev.map((p) => (p.id === policy.id ? { ...p, enabled, ...updateBody } : p))
      );
      setEnabledCount((prev) => (enabled ? prev + 1 : Math.max(0, prev - 1)));

      if (updateBody.needs_review === false) {
        showToast(`✅ Policy "${policy.id}" approved and enabled`, "success");
      }
    } catch (err) {
      console.error("Failed to toggle policy:", err);
    }
  }

  async function handleSync(source) {
    setSyncing(true);
    setSyncStatus({ text: "⟳ Syncing...", variant: "syncing" });
    try {
      const data = await syncPolicies(source);
      let added;
      if (source === "all") {
        added = data.total_added || 0;
        const skipped = data.total_skipped || 0;
        showToast(`Sync complete: ${added} new policies added, ${skipped} skipped`, added > 0 ? "success" : "info");
      } else {
        added = data.added || 0;
        showToast(`${source.toUpperCase()}: ${added} new policies added`, added > 0 ? "success" : "info");
      }
      setSyncStatus({ text: added > 0 ? `✓ +${added} new` : "✓ Up to date", variant: "done" });
      setTimeout(() => setSyncStatus(null), 3000);
      await loadPolicies();
    } catch (err) {
      console.error("Sync failed:", err);
      showToast("Sync failed: " + err.message, "error");
      setSyncStatus({ text: "✗ Failed", variant: "error" });
    } finally {
      setSyncing(false);
    }
  }

  const providers = [...new Set(policies.map((p) => p.provider))];
  const reviewCount = policies.filter((p) => p.needs_review || p.auto_generated).length;
  const filtered = providerFilter === "all" ? policies : policies.filter((p) => p.provider === providerFilter);

  return (
    <div className="view-section active">
      <section className="policies-header glass-card reveal-element delay-1" style={{ padding: "2.5rem", marginBottom: "2rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
          <div>
            <h3 className="section-title" style={{ marginBottom: "0.5rem" }}><DecryptedText text="POLICY ENGINE" animateOn="view" sequential revealDirection="start" speed={28} encryptedClassName="dtx-scramble" /></h3>
            <p style={{ color: "var(--text-secondary)", fontSize: "0.92rem" }}>
              Cloud-Agnostic Security Policies — Self-Learning Policy-as-Code
            </p>
          </div>
          <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
            <div className="policy-stat-pill">
              <span className="policy-stat-num">{totalCount}</span>
              <span className="policy-stat-label">Total</span>
            </div>
            <div className="policy-stat-pill policy-stat-pill--active">
              <span className="policy-stat-num">{enabledCount}</span>
              <span className="policy-stat-label">Active</span>
            </div>
            {reviewCount > 0 && (
              <div className="policy-stat-pill policy-stat-pill--review" title="Auto-generated policies start disabled and stay that way until a human approves them — the same 'proposes, never disposes' rule the AI reasoning pipeline follows for policy fixes.">
                <span className="policy-stat-num">{reviewCount}</span>
                <span className="policy-stat-label">Review</span>
              </div>
            )}
          </div>
        </div>

        {reviewCount > 0 && (
          <p style={{ marginTop: "1rem", color: "var(--text-muted)", fontSize: "0.85rem" }}>
            {reviewCount} {reviewCount === 1 ? "policy is" : "policies are"} disabled on purpose —
            they were auto-generated from a novel finding type (not one of the built-in checks) and
            require a human to review and enable them before they take effect. Toggle one on below
            once you've verified it.
          </p>
        )}

        <div className="sync-toolbar" style={{ marginTop: "1.5rem", display: "flex", gap: "0.6rem", flexWrap: "wrap", alignItems: "center" }}>
          <button className="sync-btn sync-btn--primary" disabled={syncing} onClick={() => handleSync("all")}>
            <span className="sync-btn__icon">↻</span> Sync All Sources
          </button>
          <button className="sync-btn" disabled={syncing} onClick={() => handleSync("github")}>
            <span className="sync-btn__icon">⚙</span> GitHub
          </button>
          <button className="sync-btn" disabled={syncing} onClick={() => handleSync("cis")}>
            <span className="sync-btn__icon">☑</span> CIS Benchmarks
          </button>
          <button className="sync-btn" disabled={syncing} onClick={() => handleSync("prowler")}>
            <span className="sync-btn__icon">🔍</span> Prowler
          </button>
          {syncStatus && <span className={`sync-status sync-status--${syncStatus.variant}`}>{syncStatus.text}</span>}
        </div>

        <div className="provider-badges" style={{ marginTop: "1.2rem" }}>
          <button
            className={`provider-badge${providerFilter === "all" ? " provider-badge--active" : ""}`}
            onClick={() => setProviderFilter("all")}
          >
            All Providers
          </button>
          {providers.map((prov) => {
            const colors = PROVIDER_COLORS[prov] || PROVIDER_COLORS.aws;
            const count = policies.filter((p) => p.provider === prov).length;
            return (
              <button
                key={prov}
                className={`provider-badge${providerFilter === prov ? " provider-badge--active" : ""}`}
                style={{ "--badge-color": colors.text, "--badge-bg": colors.bg, "--badge-border": colors.border }}
                onClick={() => setProviderFilter(prov)}
              >
                {colors.icon} {prov.toUpperCase()} <span className="provider-badge__count">{count}</span>
              </button>
            );
          })}
        </div>
      </section>

      <Toast toast={toast} />

      <div className="policy-cards-grid">
        {filtered.map((p, i) => (
          <PolicyCard key={p.id} policy={p} index={i} onToggle={handleToggle} />
        ))}
      </div>
    </div>
  );
}
