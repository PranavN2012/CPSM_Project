/**
 * CSPM Dashboard v2.0 — Power BI-Style Application Logic
 *
 * Features:
 *   - Chart.js donut, bar, and timeline charts
 *   - Real-time data from LocalStack or mock fallback
 *   - Auto-detects local API server
 *   - Vulnerability type and severity visualizations
 */

(function () {
    "use strict";

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------
    const CONFIGURED_API_URL = "";
    const LOCAL_API_URL = "http://localhost:3000";

    let API_BASE_URL = CONFIGURED_API_URL;
    let useMockData = false;
    const REFRESH_INTERVAL_MS = 30_000;
    let currentFilter = "all";
    let allEvents = [];

    // Chart instances
    let vulnTypeChart = null;
    let severityChart = null;
    let timelineChart = null;

    async function resolveApiUrl() {
        if (CONFIGURED_API_URL) return CONFIGURED_API_URL;
        if (location.hostname === "localhost" && location.port === "3000") {
            console.log("[CSPM] Local server — same-origin API.");
            return "";
        }
        try {
            const res = await fetch(`${LOCAL_API_URL}/stats`, { signal: AbortSignal.timeout(5000) });
            if (res.ok) return LOCAL_API_URL;
        } catch { }
        console.log("[CSPM] No API — using mock data.");
        return "";
    }

    // -----------------------------------------------------------------------
    // DOM References
    // -----------------------------------------------------------------------
    const dom = {
        totalEvents: document.getElementById("totalEvents"),
        remediatedCount: document.getElementById("remediatedCount"),
        failedCount: document.getElementById("failedCount"),
        complianceRate: document.getElementById("complianceRate"),
        activeRegions: document.getElementById("activeRegions"),
        lastEventTime: document.getElementById("lastEventTime"),
        eventsBody: document.getElementById("eventsBody"),
        emptyState: document.getElementById("emptyState"),
        tableWrapper: document.querySelector(".table-wrapper"),
        statusDot: document.getElementById("statusDot"),
        statusText: document.getElementById("statusText"),
        refreshBtn: document.getElementById("refreshBtn"),
        filterGroup: document.getElementById("filterGroup"),
    };

    // -----------------------------------------------------------------------
    // Mock Data
    // -----------------------------------------------------------------------
    function generateMockData() {
        const buckets = [
            "prod-data-lake-raw", "staging-logs-2026", "dev-user-uploads",
            "analytics-exports", "ml-training-datasets", "backup-vault",
            "cdn-static-assets", "customer-reports-q1",
        ];
        const iamResources = ["Role:AdminRole", "User:dev-intern", "Role:LambdaFullAccess"];
        const regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"];
        const configs = [
            { status: "REMEDIATED", type: "S3 Public Access", severity: "CRITICAL", event: "PutBucketPublicAccessBlock" },
            { status: "REMEDIATED", type: "S3 Public Access", severity: "CRITICAL", event: "CreateBucket" },
            { status: "ENCRYPTION_REMEDIATED", type: "S3 Encryption", severity: "HIGH", event: "PutBucketEncryption" },
            { status: "COMPLIANT", type: "S3 Encryption", severity: "LOW", event: "GetBucketEncryption" },
            { status: "REMEDIATION_FAILED", type: "S3 Public Access", severity: "CRITICAL", event: "PutBucketPublicAccessBlock" },
            { status: "IAM_OVERPERMISSIVE", type: "IAM Audit", severity: "CRITICAL", event: "IAMAuditScan" },
            { status: "IAM_OVERPERMISSIVE", type: "IAM Audit", severity: "HIGH", event: "IAMAuditScan" },
            { status: "ENCRYPTION_REMEDIATED", type: "S3 Encryption", severity: "HIGH", event: "PutBucketEncryption" },
            { status: "REMEDIATED", type: "S3 Public Access", severity: "CRITICAL", event: "CreateBucket" },
            { status: "COMPLIANT", type: "S3 Public Access", severity: "LOW", event: "PutBucketPublicAccessBlock" },
        ];
        const events = [];
        const now = Date.now();
        for (let i = 0; i < configs.length; i++) {
            const c = configs[i];
            const isIAM = c.type === "IAM Audit";
            events.push({
                event_id: crypto.randomUUID ? crypto.randomUUID() : `mock-${i}`,
                timestamp: new Date(now - i * 3_600_000 * (1 + Math.random() * 3)).toISOString(),
                bucket_name: isIAM ? iamResources[i % iamResources.length] : buckets[i % buckets.length],
                account_id: "123456789012",
                region: regions[i % regions.length],
                status: c.status,
                event_name: c.event,
                vulnerability_type: c.type,
                severity: c.severity,
            });
        }
        return events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    }

    function computeMockStats(events) {
        const remediated = events.filter(e => ["REMEDIATED", "ENCRYPTION_REMEDIATED"].includes(e.status)).length;
        const compliant = events.filter(e => e.status === "COMPLIANT").length;
        const failed = events.filter(e => ["REMEDIATION_FAILED", "ENCRYPTION_FAILED"].includes(e.status)).length;
        const flagged = events.filter(e => e.status === "IAM_OVERPERMISSIVE").length;
        const actionable = remediated + failed + flagged;
        const vuln_types = {};
        const severities = {};
        events.forEach(e => {
            const vt = e.vulnerability_type || "S3 Public Access";
            vuln_types[vt] = (vuln_types[vt] || 0) + 1;
            const sev = e.severity || "MEDIUM";
            severities[sev] = (severities[sev] || 0) + 1;
        });
        return {
            total_events: events.length,
            remediated, compliant, failed, flagged,
            unique_buckets: new Set(events.map(e => e.bucket_name)).size,
            active_regions: [...new Set(events.map(e => e.region))],
            last_event: events[0]?.timestamp || "N/A",
            compliance_rate: actionable ? +(remediated / actionable * 100).toFixed(1) : 100,
            vulnerability_types: vuln_types,
            severities,
        };
    }

    // -----------------------------------------------------------------------
    // API Calls
    // -----------------------------------------------------------------------
    async function fetchEvents() {
        if (useMockData) return generateMockData();
        try {
            const res = await fetch(`${API_BASE_URL}/events`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            const data = await res.json();
            return data.events || [];
        } catch (err) {
            console.error("Failed to fetch events:", err);
            setStatus(false);
            return [];
        }
    }

    async function fetchStats(events) {
        if (useMockData) return computeMockStats(events);
        try {
            const res = await fetch(`${API_BASE_URL}/stats`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return await res.json();
        } catch (err) {
            console.error("Failed to fetch stats:", err);
            setStatus(false);
            return null;
        }
    }

    // -----------------------------------------------------------------------
    // Charts (Chart.js)
    // -----------------------------------------------------------------------
    const COLORS = {
        blue: "#0078d4", green: "#107c10", red: "#d13438",
        amber: "#ffaa44", purple: "#8764b8", teal: "#038387",
    };

    function renderCharts(stats) {
        if (!stats) return;

        // Vulnerability Type Donut
        const vtLabels = Object.keys(stats.vulnerability_types || {});
        const vtData = Object.values(stats.vulnerability_types || {});
        const vtColors = vtLabels.map(l =>
            l.includes("Public") ? COLORS.blue :
                l.includes("Encrypt") ? COLORS.purple : COLORS.amber
        );

        if (vulnTypeChart) vulnTypeChart.destroy();
        vulnTypeChart = new Chart(document.getElementById("vulnTypeChart"), {
            type: "doughnut",
            data: {
                labels: vtLabels,
                datasets: [{ data: vtData, backgroundColor: vtColors, borderWidth: 0 }],
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: {
                    legend: { position: "bottom", labels: { padding: 12, usePointStyle: true, font: { size: 11 } } },
                },
                cutout: "65%",
            },
        });

        // Severity Bar Chart
        const sevOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
        const sevData = sevOrder.map(s => (stats.severities || {})[s] || 0);
        const sevColors = [COLORS.red, "#d83b01", COLORS.amber, COLORS.green];

        if (severityChart) severityChart.destroy();
        severityChart = new Chart(document.getElementById("severityChart"), {
            type: "bar",
            data: {
                labels: sevOrder,
                datasets: [{ data: sevData, backgroundColor: sevColors, borderRadius: 4, barPercentage: 0.6 }],
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, ticks: { stepSize: 1, font: { size: 11 } }, grid: { color: "#edebe9" } },
                    x: { ticks: { font: { size: 11 } }, grid: { display: false } },
                },
            },
        });

        // Timeline Chart (events per day)
        const dayMap = {};
        allEvents.forEach(e => {
            const day = e.timestamp?.substring(0, 10) || "unknown";
            dayMap[day] = (dayMap[day] || 0) + 1;
        });
        const days = Object.keys(dayMap).sort();
        const dayCounts = days.map(d => dayMap[d]);

        if (timelineChart) timelineChart.destroy();
        timelineChart = new Chart(document.getElementById("timelineChart"), {
            type: "line",
            data: {
                labels: days.map(d => d.substring(5)),
                datasets: [{
                    data: dayCounts, borderColor: COLORS.blue, backgroundColor: "rgba(0,120,212,0.08)",
                    fill: true, tension: 0.3, pointRadius: 4, pointBackgroundColor: COLORS.blue,
                }],
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    y: { beginAtZero: true, ticks: { stepSize: 1, font: { size: 11 } }, grid: { color: "#edebe9" } },
                    x: { ticks: { font: { size: 11 } }, grid: { display: false } },
                },
            },
        });
    }

    // -----------------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------------
    function animateValue(el, target) {
        const num = parseFloat(target) || 0;
        const isPercent = String(target).includes("%") || el.id === "complianceRate";
        const duration = 500;
        const start = parseFloat(el.textContent) || 0;
        const diff = num - start;
        if (diff === 0) { el.textContent = isPercent ? num + "%" : num; return; }
        const startTime = performance.now();
        function tick(now) {
            const progress = Math.min((now - startTime) / duration, 1);
            const ease = 1 - Math.pow(1 - progress, 3);
            const val = Math.round((start + diff * ease) * 10) / 10;
            el.textContent = isPercent ? val + "%" : Math.round(val);
            if (progress < 1) requestAnimationFrame(tick);
            else el.textContent = isPercent ? num + "%" : Math.round(num);
        }
        requestAnimationFrame(tick);
    }

    function renderStats(stats) {
        if (!stats) return;
        animateValue(dom.totalEvents, stats.total_events);
        animateValue(dom.remediatedCount, stats.remediated);
        animateValue(dom.failedCount, (stats.failed || 0) + (stats.flagged || 0));
        animateValue(dom.complianceRate, stats.compliance_rate);
        animateValue(dom.activeRegions, Array.isArray(stats.active_regions) ? stats.active_regions.length : stats.active_regions);
        if (stats.last_event && stats.last_event !== "N/A") {
            dom.lastEventTime.textContent = "Last: " + formatTimestamp(stats.last_event);
        }
    }

    function renderEvents(events) {
        const filtered = currentFilter === "all" ? events :
            currentFilter === "FAILED" ? events.filter(e => ["REMEDIATION_FAILED", "ENCRYPTION_FAILED"].includes(e.status)) :
                events.filter(e => e.status === currentFilter || (currentFilter === "REMEDIATED" && e.status === "ENCRYPTION_REMEDIATED"));

        if (filtered.length === 0) {
            dom.emptyState.style.display = "flex";
            dom.tableWrapper.style.display = "none";
            return;
        }
        dom.emptyState.style.display = "none";
        dom.tableWrapper.style.display = "block";

        dom.eventsBody.innerHTML = filtered.map((e, i) => `
            <tr style="animation-delay:${i * 0.03}s">
                <td class="cell-timestamp">${formatTimestamp(e.timestamp)}</td>
                <td class="cell-resource">${escapeHtml(e.bucket_name)}</td>
                <td>${vulnTypePill(e.vulnerability_type)}</td>
                <td class="cell-mono">${escapeHtml(e.region)}</td>
                <td>${severityBadge(e.severity)}</td>
                <td>${statusBadge(e.status)}</td>
            </tr>
        `).join("");
    }

    function statusBadge(status) {
        const map = {
            REMEDIATED: { cls: "badge--remediated", icon: "✓", label: "Remediated" },
            ENCRYPTION_REMEDIATED: { cls: "badge--remediated", icon: "✓", label: "Encrypted" },
            COMPLIANT: { cls: "badge--compliant", icon: "●", label: "Compliant" },
            REMEDIATION_FAILED: { cls: "badge--failed", icon: "✕", label: "Failed" },
            ENCRYPTION_FAILED: { cls: "badge--failed", icon: "✕", label: "Enc. Failed" },
            IAM_OVERPERMISSIVE: { cls: "badge--flagged", icon: "⚠", label: "Flagged" },
        };
        const info = map[status] || { cls: "badge--compliant", icon: "?", label: status };
        return `<span class="badge ${info.cls}">${info.icon} ${info.label}</span>`;
    }

    function severityBadge(severity) {
        const s = (severity || "MEDIUM").toUpperCase();
        const map = { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🟢" };
        const cls = `severity--${s.toLowerCase()}`;
        return `<span class="severity ${cls}">${map[s] || "⚪"} ${s}</span>`;
    }

    function vulnTypePill(type) {
        const t = type || "S3 Public Access";
        const cls = t.includes("Public") ? "vuln-type--s3-access" :
            t.includes("Encrypt") ? "vuln-type--s3-encrypt" : "vuln-type--iam";
        const icons = { "S3 Public Access": "🛡️", "S3 Encryption": "🔐", "IAM Audit": "👤" };
        return `<span class="vuln-type ${cls}">${icons[t] || "🔍"} ${t}</span>`;
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------
    function formatTimestamp(iso) {
        try {
            return new Date(iso).toLocaleString("en-US", {
                month: "short", day: "numeric", hour: "2-digit",
                minute: "2-digit", second: "2-digit", hour12: false,
            });
        } catch { return iso; }
    }

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str || "";
        return div.innerHTML;
    }

    function setStatus(connected) {
        dom.statusDot.classList.toggle("status-dot--error", !connected);
        dom.statusText.textContent = connected ? "Live • Auto-refresh" : "API Unreachable";
    }

    // -----------------------------------------------------------------------
    // Main Loop
    // -----------------------------------------------------------------------
    // (refresh function is defined below with compliance integration)

    // -----------------------------------------------------------------------
    dom.refreshBtn.addEventListener("click", () => {
        dom.refreshBtn.style.transform = "rotate(360deg)";
        refresh();
        setTimeout(() => { dom.refreshBtn.style.transform = ""; }, 500);
    });

    dom.filterGroup.addEventListener("click", (e) => {
        const btn = e.target.closest(".filter-btn");
        if (!btn) return;
        dom.filterGroup.querySelectorAll(".filter-btn").forEach(b => b.classList.remove("filter-btn--active"));
        btn.classList.add("filter-btn--active");
        currentFilter = btn.dataset.filter;
        renderEvents(allEvents);
    });

    // GitHub Issues button
    const githubBtn = document.getElementById("createIssuesBtn");
    if (githubBtn) {
        githubBtn.addEventListener("click", async () => {
            githubBtn.disabled = true;
            githubBtn.querySelector("span").textContent = "Creating...";
            githubBtn.classList.remove("btn-github--success", "btn-github--error");
            try {
                const res = await fetch("/create-issues", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ limit: 5 }),
                });
                const data = await res.json();
                if (data.created > 0) {
                    githubBtn.classList.add("btn-github--success");
                    githubBtn.querySelector("span").textContent = `✓ ${data.created} Issues Created`;
                    // Open first issue in new tab
                    const firstUrl = data.issues?.find(i => i.url)?.url;
                    if (firstUrl) window.open(firstUrl, "_blank");
                } else if (data.failed > 0) {
                    githubBtn.classList.add("btn-github--error");
                    githubBtn.querySelector("span").textContent = "Network Error — Try Mobile Hotspot";
                } else {
                    githubBtn.querySelector("span").textContent = "No actionable events";
                }
            } catch (err) {
                githubBtn.classList.add("btn-github--error");
                githubBtn.querySelector("span").textContent = "Failed: " + err.message;
            }
            setTimeout(() => {
                githubBtn.disabled = false;
                githubBtn.querySelector("span").textContent = "Create GitHub Issues";
                githubBtn.classList.remove("btn-github--success", "btn-github--error");
            }, 5000);
        });
    }

    // -----------------------------------------------------------------------
    // Compliance Frameworks
    // -----------------------------------------------------------------------
    async function fetchCompliance() {
        if (useMockData) {
            return {
                overall_score: 72.5,
                frameworks: {
                    "CIS AWS": { total: 6, passed: 4, score: 66.7 },
                    "SOC 2": { total: 5, passed: 4, score: 80.0 },
                    "PCI-DSS": { total: 6, passed: 4, score: 66.7 },
                },
            };
        }
        try {
            const res = await fetch(`${API_BASE_URL}/compliance`);
            if (!res.ok) throw new Error(`HTTP ${res.status}`);
            return await res.json();
        } catch {
            return null;
        }
    }

    function renderCompliance(data) {
        if (!data || !data.frameworks) return;

        const mapping = {
            "CIS AWS": { score: "scoreCIS", bar: "barCIS", detail: "detailCIS" },
            "SOC 2": { score: "scoreSOC2", bar: "barSOC2", detail: "detailSOC2" },
            "PCI-DSS": { score: "scorePCI", bar: "barPCI", detail: "detailPCI" },
        };

        for (const [fw, ids] of Object.entries(mapping)) {
            const stats = data.frameworks[fw];
            if (!stats) continue;

            const scoreEl = document.getElementById(ids.score);
            const barEl = document.getElementById(ids.bar);
            const detailEl = document.getElementById(ids.detail);

            if (scoreEl) scoreEl.textContent = stats.score + "%";
            if (barEl) {
                barEl.style.width = stats.score + "%";
                if (stats.score < 60) barEl.setAttribute("data-score", "low");
                else if (stats.score < 80) barEl.setAttribute("data-score", "medium");
                else barEl.removeAttribute("data-score");
            }
            if (detailEl) detailEl.textContent = `${stats.passed}/${stats.total} controls passed`;
        }
    }

    // -----------------------------------------------------------------------
    // Report Download
    // -----------------------------------------------------------------------
    const reportBtn = document.getElementById("downloadReportBtn");
    if (reportBtn) {
        reportBtn.addEventListener("click", () => {
            reportBtn.disabled = true;
            reportBtn.querySelector("span").textContent = "Generating...";
            window.open("/report", "_blank");
            setTimeout(() => {
                reportBtn.disabled = false;
                reportBtn.querySelector("span").textContent = "Report";
            }, 3000);
        });
    }

    // -----------------------------------------------------------------------
    // Initialization
    // -----------------------------------------------------------------------
    async function refresh() {
        try {
            const events = await fetchEvents();
            allEvents = events;
            const stats = await fetchStats(events);
            renderEvents(events);
            renderStats(stats);
            renderCharts(stats);
            setStatus(true);

            // Fetch compliance asynchronously
            const compliance = await fetchCompliance();
            renderCompliance(compliance);
        } catch (err) {
            console.error("Refresh error:", err);
            setStatus(false);
        }
    }

    async function init() {
        API_BASE_URL = await resolveApiUrl();
        await refresh();
        setInterval(refresh, REFRESH_INTERVAL_MS);
    }

    init();
})();
