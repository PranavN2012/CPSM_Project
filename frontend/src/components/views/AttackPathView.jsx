import { useCallback, useEffect, useMemo, useState } from "react";
import { fetchAiInsights, analyzeEvent } from "../../api.js";
import { SEVERITY_COLORS } from "../../utils.js";
import DecryptedText from "../DecryptedText.jsx";

const COL_WIDTH = 210;
const ROW_HEIGHT = 84;
const MARGIN_X = 90;
const MARGIN_Y = 50;

/** Turns a Layer 3 BlastRadiusResult (entry_point + paths: {resource -> [node ids]})
 * into an SVG layout: one column per BFS depth, nodes vertically spaced within
 * their column, edges reconstructed from each resource's own shortest path. This
 * is the actual graph traversal the orchestrator computed for this incident —
 * different entry points produce genuinely different shapes, not a re-skin of
 * the same fixed animation. */
function layoutBlastRadius(blastRadius) {
  const { entry_point, paths, critical_resources_reached = [] } = blastRadius;
  const criticalSet = new Set(critical_resources_reached);

  const depthOf = new Map([[entry_point, 0]]);
  const edgeSet = new Map(); // "from>to" -> {from, to}
  Object.entries(paths).forEach(([resource, path]) => {
    depthOf.set(resource, path.length - 1);
    for (let i = 0; i < path.length - 1; i++) {
      const key = `${path[i]}>${path[i + 1]}`;
      if (!edgeSet.has(key)) edgeSet.set(key, { from: path[i], to: path[i + 1] });
    }
  });

  const byDepth = new Map();
  depthOf.forEach((depth, id) => {
    if (!byDepth.has(depth)) byDepth.set(depth, []);
    byDepth.get(depth).push(id);
  });

  const maxDepth = Math.max(...byDepth.keys());
  const maxRows = Math.max(...[...byDepth.values()].map((v) => v.length));
  const nodePos = new Map();
  byDepth.forEach((ids, depth) => {
    ids.sort();
    const colHeight = ids.length * ROW_HEIGHT;
    const totalHeight = Math.max(colHeight, maxRows * ROW_HEIGHT);
    const yOffset = (totalHeight - colHeight) / 2;
    ids.forEach((id, i) => {
      nodePos.set(id, {
        x: MARGIN_X + depth * COL_WIDTH,
        y: MARGIN_Y + yOffset + i * ROW_HEIGHT + ROW_HEIGHT / 2,
        depth,
        isEntry: id === entry_point,
        isCritical: criticalSet.has(id),
      });
    });
  });

  const width = MARGIN_X * 2 + maxDepth * COL_WIDTH;
  const height = MARGIN_Y * 2 + maxRows * ROW_HEIGHT;

  const edges = [...edgeSet.values()].map((e) => ({
    ...e,
    from_pos: nodePos.get(e.from),
    to_pos: nodePos.get(e.to),
  }));

  return { nodePos, edges, width, height, maxDepth };
}

function GraphSVG({ layout, revealDepth }) {
  const { nodePos, edges, width, height } = layout;
  return (
    <svg viewBox={`0 0 ${width} ${height}`} width="100%" style={{ maxHeight: 480 }}>
      {edges.map((e, i) => {
        const shown = e.to_pos.depth <= revealDepth;
        return (
          <line
            key={i}
            x1={e.from_pos.x} y1={e.from_pos.y} x2={e.to_pos.x} y2={e.to_pos.y}
            stroke={e.to_pos.isCritical ? SEVERITY_COLORS.CRITICAL.text : "rgba(0,229,255,0.4)"}
            strokeWidth={2}
            style={{ opacity: shown ? 0.9 : 0, transition: "opacity 0.5s ease" }}
          />
        );
      })}
      {[...nodePos.entries()].map(([id, pos]) => {
        const shown = pos.depth <= revealDepth;
        const color = pos.isEntry ? "#f43f5e" : pos.isCritical ? SEVERITY_COLORS.CRITICAL.text : SEVERITY_COLORS.MEDIUM.text;
        return (
          <g key={id} style={{ opacity: shown ? 1 : 0, transition: "opacity 0.5s ease, transform 0.5s ease" }}>
            <circle cx={pos.x} cy={pos.y} r={pos.isEntry ? 12 : 9} fill={color} fillOpacity={0.25} stroke={color} strokeWidth={2} />
            <text x={pos.x} y={pos.y + 26} textAnchor="middle" fontSize="11" fill="var(--text-secondary)">
              {id.length > 20 ? id.slice(0, 18) + "…" : id}
            </text>
            {pos.isEntry && (
              <text x={pos.x} y={pos.y - 20} textAnchor="middle" fontSize="10" fill={color} fontWeight="700">ENTRY POINT</text>
            )}
          </g>
        );
      })}
    </svg>
  );
}

/** Why a real incident has no blast-radius graph to show — always a
 * specific, honest reason, never a substitution of different data. */
function noGraphReason(target) {
  if (!target.is_anomalous) {
    return {
      title: "This incident wasn't flagged anomalous",
      body: `Layer 1's anomaly score was ${target.anomaly_score.toFixed(4)}, below the calibrated threshold (0.46) — the orchestrator correctly short-circuited before Layer 3 (blast radius) ever ran.`,
    };
  }
  return {
    title: "No blast-radius result for this incident",
    body: "Layer 3 didn't produce a result this run — try re-running the analysis.",
  };
}

function StatsRow({ blastRadius }) {
  return (
    <div style={{ display: "flex", gap: "1.5rem", flexWrap: "wrap", fontSize: "0.85rem", color: "var(--text-muted)", marginBottom: "0.8rem" }}>
      <span>Entry: <b style={{ color: "var(--text-primary)" }}>{blastRadius.entry_point}</b></span>
      <span>Reachable: <b style={{ color: "var(--text-primary)" }}>{blastRadius.reachable_resources.length}</b></span>
      <span>Critical: <b style={{ color: SEVERITY_COLORS.CRITICAL.text }}>{blastRadius.critical_resources_reached.length}</b></span>
      <span>Max depth: <b style={{ color: "var(--text-primary)" }}>{blastRadius.max_depth}</b></span>
      <span>Severity: <b style={{ color: SEVERITY_COLORS[blastRadius.severity]?.text }}>{blastRadius.severity}</b></span>
    </div>
  );
}

export default function AttackPathView({ incident, onBack }) {
  const isRealIncident = incident && !String(incident.event_id || "").startsWith("demo-");

  const [status, setStatus] = useState("idle"); // idle | loading | ready | no_graph | error
  const [singleResult, setSingleResult] = useState(null);
  const [noGraph, setNoGraph] = useState(null);
  const [scenarios, setScenarios] = useState(null);
  const [selected, setSelected] = useState(0);
  const [revealDepth, setRevealDepth] = useState(-1);
  const [error, setError] = useState(null);

  const playFor = useCallback((blastRadius) => {
    setRevealDepth(-1);
    const l = layoutBlastRadius(blastRadius);
    for (let d = 0; d <= l.maxDepth; d++) setTimeout(() => setRevealDepth(d), 300 + d * 550);
  }, []);

  const loadReal = useCallback(async () => {
    setStatus("loading");
    setError(null);
    setNoGraph(null);
    try {
      const data = await analyzeEvent(incident);
      const target = data.result;
      if (!target.blast_radius) {
        setNoGraph(noGraphReason(target));
        setStatus("no_graph");
        return;
      }
      setSingleResult(target);
      setStatus("ready");
      setTimeout(() => playFor(target.blast_radius), 50);
    } catch (err) {
      setError(err.message);
      setStatus("error");
    }
  }, [incident, playFor]);

  const loadReference = useCallback(async () => {
    setStatus("loading");
    setError(null);
    try {
      const data = await fetchAiInsights(4, "demo");
      const withBlast = data.results.filter((r) => r.blast_radius);
      if (withBlast.length === 0) throw new Error("No scenario produced a blast-radius result this run.");
      setScenarios(withBlast);
      setSelected(0);
      setStatus("ready");
      setTimeout(() => playFor(withBlast[0].blast_radius), 50);
    } catch (err) {
      setError(err.message);
      setStatus("error");
    }
  }, [playFor]);

  useEffect(() => {
    if (isRealIncident) loadReal();
    // Reference mode stays idle until the user explicitly requests it —
    // real incidents load automatically since that's what was clicked.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [incident]);

  function selectScenario(i) {
    setSelected(i);
    setTimeout(() => playFor(scenarios[i].blast_radius), 50);
  }

  const current = isRealIncident ? singleResult : scenarios?.[selected];
  const layout = useMemo(() => (current?.blast_radius ? layoutBlastRadius(current.blast_radius) : null), [current]);

  return (
    <div className="view-section active">
      <section className="attack-path-container glass-card reveal-element delay-1">
        {onBack && (
          <button className="btn-glass" onClick={onBack} style={{ marginBottom: "1rem" }}>← Back</button>
        )}
        <h3 className="section-title"><DecryptedText text="ATTACK PATH & BLAST RADIUS" animateOn="view" sequential revealDirection="start" speed={26} encryptedClassName="dtx-scramble" /></h3>
        <p className="attack-path-desc">
          {isRealIncident
            ? `A real Layer 3 BFS traversal for the exact incident you selected (${incident.vulnerability_type} on ${incident.bucket_name}) — not a substitution. If its resource name doesn't match a known identity in the graph, that's shown honestly below (a sparse or LOW-severity result), not swapped for different data.`
            : "A real Layer 3 BFS traversal, animated — not a fixed illustration. No specific incident was selected, so this is a reference walkthrough using the 4 crafted scenarios, which have genuinely different entry points and reachable-resource sets."}
        </p>

        {status === "idle" && !isRealIncident && (
          <div className="empty-state" style={{ margin: "2rem 0" }}>
            <p>Run the pipeline against the 4 reference scenarios to load their real blast-radius graphs.</p>
            <button className="btn-glass btn-glow" style={{ marginTop: 12 }} onClick={loadReference}>▶ Load Reference Walkthrough</button>
          </div>
        )}

        {status === "loading" && (
          <div className="empty-state" style={{ margin: "2rem 0" }}>
            <p>Running Layers 1-3 {isRealIncident ? "against this incident" : "against the reference scenarios"}…</p>
          </div>
        )}

        {status === "error" && (
          <div className="empty-state" style={{ margin: "2rem 0", borderColor: "var(--danger)" }}>
            <p>{error}</p>
            <button className="btn-glass" style={{ marginTop: 12 }} onClick={isRealIncident ? loadReal : loadReference}>Retry</button>
          </div>
        )}

        {status === "no_graph" && noGraph && (
          <div className="empty-state" style={{ margin: "2rem 0", borderColor: "var(--border-highlight)" }}>
            <p>{noGraph.title}</p>
            <p className="empty-state__sub">{noGraph.body}</p>
            <button className="btn-glass" style={{ marginTop: 12 }} onClick={loadReal}>Re-run</button>
          </div>
        )}

        {status === "ready" && current && (
          <>
            {!isRealIncident && (
              <div style={{ display: "flex", gap: "0.6rem", flexWrap: "wrap", margin: "1rem 0" }}>
                {scenarios.map((s, i) => (
                  <button
                    key={s.event.event_id}
                    className={`region-pill${selected === i ? " region-pill--active" : ""}`}
                    onClick={() => selectScenario(i)}
                  >
                    {s.event.bucket_name} · {s.blast_radius.severity}
                  </button>
                ))}
              </div>
            )}
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "0.6rem" }}>
              <StatsRow blastRadius={current.blast_radius} />
              <button className="btn-glass" onClick={() => playFor(current.blast_radius)}>↻ Replay Animation</button>
            </div>

            <div className="glass-card" style={{ padding: "1rem", overflowX: "auto" }}>
              {layout && <GraphSVG layout={layout} revealDepth={revealDepth} />}
            </div>
          </>
        )}
      </section>
    </div>
  );
}
