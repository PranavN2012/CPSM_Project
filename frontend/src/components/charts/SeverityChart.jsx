import { Bar } from "react-chartjs-2";
import { COLORS } from "./chartSetup.js";

const SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const SEV_COLORS = [COLORS.rose, COLORS.amber, COLORS.cyan, COLORS.emerald];

export default function SeverityChart({ stats }) {
  const data = SEV_ORDER.map((s) => (stats?.severities || {})[s] || 0);

  return (
    <Bar
      data={{ labels: SEV_ORDER, datasets: [{ data, backgroundColor: SEV_COLORS, borderRadius: 4, barPercentage: 0.6 }] }}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          y: { beginAtZero: true, ticks: { stepSize: 1, font: { size: 11 } }, grid: { color: "#edebe9" } },
          x: { ticks: { font: { size: 11 } }, grid: { display: false } },
        },
      }}
    />
  );
}
