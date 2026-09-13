import { Doughnut } from "react-chartjs-2";
import { COLORS } from "./chartSetup.js";

const PALETTE = [COLORS.blue, COLORS.info || COLORS.cyan, COLORS.emerald, COLORS.rose, COLORS.amber, "#8891c9"];

export default function VulnDonutLegend({ vulnerabilityTypes }) {
  const sorted = Object.entries(vulnerabilityTypes || {}).sort((a, b) => b[1] - a[1]);
  // Total must reflect every finding, not just the displayed rows — fold
  // anything past the top 5 into an "Other" slice instead of silently
  // dropping it from both the chart and the count in the middle.
  const total = sorted.reduce((sum, [, v]) => sum + v, 0) || 1;
  const shown = sorted.slice(0, 5);
  const otherCount = sorted.slice(5).reduce((sum, [, v]) => sum + v, 0);
  const entries = otherCount > 0 ? [...shown, ["Other", otherCount]] : shown;
  const labels = entries.map(([k]) => k);
  const data = entries.map(([, v]) => v);
  const colors = entries.map((_, i) => PALETTE[i % PALETTE.length]);

  return (
    <div className="donut-card__body">
      <div className="donut-card__chart">
        <Doughnut
          data={{ labels, datasets: [{ data, backgroundColor: colors, borderWidth: 1, borderColor: "#fff" }] }}
          options={{ responsive: true, maintainAspectRatio: false, cutout: "72%", plugins: { legend: { display: false } } }}
        />
        <div className="donut-card__chart-label">
          <b>{total}</b>
          <span>FINDINGS</span>
        </div>
      </div>
      <div className="donut-legend">
        {entries.map(([label, value], i) => (
          <div className="donut-legend__row" key={label}>
            <span className="donut-legend__dot" style={{ background: colors[i] }}></span>
            <span className="donut-legend__label">{label}</span>
            <span className="donut-legend__value">{Math.round((value / total) * 100)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}
