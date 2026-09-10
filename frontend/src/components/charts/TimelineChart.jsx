import { Line } from "react-chartjs-2";
import { COLORS } from "./chartSetup.js";

export default function TimelineChart({ events }) {
  const dayMap = {};
  events.forEach((e) => {
    const day = e.timestamp?.substring(0, 10) || "unknown";
    dayMap[day] = (dayMap[day] || 0) + 1;
  });
  const days = Object.keys(dayMap).sort();
  const counts = days.map((d) => dayMap[d]);

  return (
    <Line
      data={{
        labels: days.map((d) => d.substring(5)),
        datasets: [{
          data: counts, borderColor: COLORS.cyan, backgroundColor: "rgba(0,229,255,0.05)",
          fill: true, tension: 0.4, pointRadius: 4, pointBackgroundColor: COLORS.cyan, borderWidth: 2,
        }],
      }}
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
