import { Doughnut } from "react-chartjs-2";
import { COLORS } from "./chartSetup.js";

export default function VulnTypeChart({ stats }) {
  const types = stats?.vulnerability_types || {};
  const labels = Object.keys(types);
  const data = Object.values(types);
  const colors = labels.map((l) =>
    l.includes("Public") ? COLORS.blue : l.includes("Encrypt") ? COLORS.purple : COLORS.amber
  );

  return (
    <Doughnut
      data={{ labels, datasets: [{ data, backgroundColor: colors, borderWidth: 1, borderColor: "rgba(255,255,255,0.05)" }] }}
      options={{
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { padding: 12, usePointStyle: true, font: { size: 10, family: "'Montserrat', sans-serif" } } },
        },
        cutout: "75%",
      }}
    />
  );
}
