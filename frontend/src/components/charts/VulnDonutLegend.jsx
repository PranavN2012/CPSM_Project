import { Doughnut } from "react-chartjs-2";
import { COLORS } from "./chartSetup.js";

const PALETTE = [COLORS.blue, COLORS.info || COLORS.cyan, COLORS.emerald, COLORS.rose, COLORS.amber, "#8891c9"];

export default function VulnDonutLegend({ vulnerabilityTypes }) {
  const entries = Object.entries(vulnerabilityTypes || {}).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const total = entries.reduce((sum, [, v]) => sum + v, 0) || 1;
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
