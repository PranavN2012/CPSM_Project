import { Line } from "react-chartjs-2";
import { COLORS } from "./chartSetup.js";

/** Buckets real event timestamps into hourly counts over the last 24h —
 * a genuine (if coarse) anomaly-rate proxy computed from live event data,
 * not fabricated. */
function bucketByHour(events) {
  const now = new Date();
  const buckets = new Array(24).fill(0);
  const labels = [];
  for (let i = 23; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 3600_000);
    labels.push(String(d.getHours()).padStart(2, "0"));
  }
  events.forEach((e) => {
    const ts = e.timestamp ? new Date(e.timestamp) : null;
    if (!ts || isNaN(ts)) return;
    const hoursAgo = Math.floor((now - ts) / 3600_000);
    if (hoursAgo >= 0 && hoursAgo < 24) buckets[23 - hoursAgo]++;
  });
  return { labels, buckets };
}

export default function AnomalyChart({ events }) {
  const { labels, buckets } = bucketByHour(events);
  const max = Math.max(...buckets, 1);
  const peakIdx = buckets.indexOf(max);
  const avg = (buckets.reduce((a, b) => a + b, 0) / 24).toFixed(1);

  return (
    <>
      <div className="anomaly-card__chart">
        <Line
          data={{
            labels,
            datasets: [{
              data: buckets, borderColor: COLORS.amber, backgroundColor: "rgba(202,138,4,0.08)",
              fill: true, tension: 0.35, pointRadius: buckets.map((_, i) => (i === peakIdx && max > 0 ? 4 : 0)),
              pointBackgroundColor: COLORS.rose, borderWidth: 2,
            }],
          }}
          options={{
            responsive: true, maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
              y: { beginAtZero: true, ticks: { stepSize: 1, font: { size: 9 } }, grid: { color: "#edebe9" } },
              x: { ticks: { font: { size: 9 }, maxTicksLimit: 7 }, grid: { display: false } },
            },
          }}
        />
      </div>
      <div className="anomaly-card__foot">
        <span>
          {max > 0 ? (
            <><i></i>Peak at {labels[peakIdx]}:00 — <b>{max} events/hr</b></>
          ) : (
            <>No events in the last 24h</>
          )}
        </span>
        <span>Avg: <b>{avg} ev/hr</b></span>
      </div>
    </>
  );
}
