import { useEffect, useMemo, useState } from "react";
import { fetchAiInsights, analyzeEvent, deployPolicyFix } from "../../api.js";
import { computeLineDiff, toPrettyLines } from "../../utils/lineDiff.js";
import DecryptedText from "../DecryptedText.jsx";

function useCountdown(seconds) {
  const [remaining, setRemaining] = useState(seconds);
  useEffect(() => {
    const id = setInterval(() => setRemaining((r) => (r > 0 ? r - 1 : 0)), 1000);
    return () => clearInterval(id);
  }, []);
  const m = Math.floor(remaining / 60), s = remaining % 60;
  return `${m}m ${String(s).padStart(2, "0")}s`;
}

// Per-scenario threat narrative — the title and "Identified Threat Vector"
// card used to be hardcoded to demo-2's S3 story, which was wrong copy for
// the other 3 scenarios now that all of them carry policy_fix_context.
// Keyed by vulnerability_type (the natural axis), with a generic fallback
// for any scenario type not yet covered here.
const THREAT_NARRATIVES = {
  "S3 Public Access": {
    title: "Restrict Public Access & IAM Privilege Escalation on",
    vectorName: "Arbitrary Policy Overwrite",
    vectorBody: (ctx) => `Public principal allowed wildcard ${ctx.offending_action}, exposing bucket reconfiguration to non-authenticated actors.`,
  },
  "IAM Audit": {
    title: "Restrict Unscoped Role Assumption via",
    vectorName: "Unrestricted Privilege Escalation Path",
    vectorBody: () => "A low-privilege identity can assume an admin-tagged role with no scoping — a single unrestricted AssumeRole grant turns a minor identity into a major one.",
  },
  "DynamoDB Unencrypted": {
    title: "Restrict Table Configuration Changes on",
    vectorName: "Overly Broad Table Administration",
    vectorBody: (ctx) => `A service role holds unscoped access to ${ctx.offending_action}, letting it alter or disable protections on a table containing session tokens.`,
  },
  "S3 Encryption": {
    title: "Restrict Encryption Configuration Changes on",
    vectorName: "Encryption Downgrade Risk",
    vectorBody: (ctx) => `An identity can call ${ctx.offending_action} on a production bucket, allowing encryption protections to be weakened or removed.`,
  },
};

function threatNarrativeFor(event, ctx) {
  return THREAT_NARRATIVES[event.vulnerability_type] || {
    title: "Restrict an Overly Broad Grant on",
    vectorName: "Unscoped Permission Grant",
    vectorBody: () => `${ctx.offending_action} was allowed on ${ctx.offending_resource} with no scoping.`,
  };
}

function DiffColumn({ side, lines, statements }) {
  return (
    <div className={`glass-card pd-diff__col pd-diff__col--${side}`}>
      <div className="pd-diff__col-head">
        <span className={`pd-diff__col-tag`}>{side === "old" ? "VULNERABLE" : "SANDBOX-TESTED"}</span>
        <b>{side === "old" ? "Current Active Policy" : "Proposed Remediation Policy"}</b>
        <span className="pd-diff__col-rev">{side === "old" ? "LIVE IN PROD" : "STAGED"}</span>
      </div>
      <pre className="pd-diff__code">
        {lines.map((l, i) => (
          <div className={`pd-diff__line${l.type !== "same" ? ` pd-diff__line--${l.type}` : ""}`} key={i}>
            <span className="pd-diff__ln">{i + 1}</span>
            <span>{l.text}</span>
          </div>
        ))}
      </pre>
    </div>
  );
}

/** Why an anomalous real incident still produced no policy draft — always
 * an honest, specific reason, never a substitution of different data. */
function noDraftReason(target) {
  if (!target.is_anomalous) {
    return {
      title: "This incident wasn't flagged anomalous",
      body: `Layer 1's anomaly score for this event was ${target.anomaly_score.toFixed(4)}, below the calibrated threshold (0.46) — so the orchestrator correctly short-circuited before Layers 2-5 ever ran, matching the pipeline's designed behavior. This isn't a missing feature: most routine findings shouldn't reach an LLM call at all.`,
    };
  }
  if (!target.event.policy_fix_context) {
    return {
      title: "This finding type has no IAM policy to diff",
      body: `${target.event.vulnerability_type} findings are remediated by flipping a resource configuration flag directly (see lambda/remediation/lambda_function.py) — there's no IAM policy document behind them for Layer 4 to draft against. Only IAM Audit findings (an overpermissive user/role policy) produce a real policy to diff. Check Security Posture for this finding's actual remediation status.`,
    };
  }
  return {
    title: "The orchestrator chose not to auto-fix this one",
    body: target.rationale || "The reasoner escalated or requested more context instead of drafting a fix — real LLM judgment based on this incident's blast radius and priority, not an error.",
  };
}

export default function PolicyDiffView({ incident, onBack, onRefresh }) {
  const [status, setStatus] = useState("idle"); // idle | loading | done | no_draft | error
  const [result, setResult] = useState(null);
  const [noDraft, setNoDraft] = useState(null);
  const [error, setError] = useState(null);
  const [deployStatus, setDeployStatus] = useState("idle"); // idle | deploying | done | error
  const [deployInfo, setDeployInfo] = useState(null);
  const [deployError, setDeployError] = useState(null);
  const sla = useCountdown(8 * 60 + 38);

  // A real incident (from the Dashboard/Events table) is analyzed directly —
  // it always gets its OWN result, never a different scenario's. Only when
  // there's no specific incident to review (navigated here directly) does
  // this fall back to a labeled reference walkthrough using one of the 4
  // crafted scenarios, which is kept specifically so an IAM policy draft
  // can always be demonstrated on demand even with no live anomalous IAM
  // finding on hand right now.
  const isRealIncident = incident && !String(incident.event_id || "").startsWith("demo-");

  const runAnalysis = async () => {
    setStatus("loading");
    setError(null);
    setNoDraft(null);
    setDeployStatus("idle");
    setDeployInfo(null);
    setDeployError(null);
    try {
      let target, reasoner, llm_client;
      if (isRealIncident) {
        const data = await analyzeEvent(incident);
        target = data.result;
        reasoner = data.reasoner;
        llm_client = data.llm_client;
      } else {
        const data = await fetchAiInsights(4, "demo");
        const targetEventId = incident?.event_id || "demo-2";
        target = data.results.find((r) => r.event.event_id === targetEventId) || data.results[0];
        reasoner = data.reasoner;
        llm_client = data.llm_client;
      }

      if (!target.policy_draft) {
        setNoDraft(noDraftReason(target));
        setStatus("no_draft");
        return;
      }
      setResult({ ...target, reasoner, llm_client });
      setStatus("done");
    } catch (err) {
      setError(err.message);
      setStatus("error");
    }
  };

  const handleDeploy = async () => {
    const target = result?.event?.policy_fix_context?.deploy_target;
    const policyJson = result?.policy_draft?.policy_json;
    if (!target || !policyJson) return;
    const confirmed = window.confirm(
      `Apply this policy to ${target.kind} "${target.name}" (policy "${target.policy_name}") on the LocalStack sandbox?\n\nThis does not touch real AWS. It overwrites the identity's current inline policy in your local LocalStack container.`
    );
    if (!confirmed) return;

    setDeployStatus("deploying");
    setDeployError(null);
    try {
      const data = await deployPolicyFix(target, policyJson);
      setDeployInfo(data);
      setDeployStatus("done");
      onRefresh?.();
    } catch (err) {
      setDeployError(err.message);
      setDeployStatus("error");
    }
  };

  const diff = useMemo(() => {
    if (!result?.policy_draft) return null;
    const oldPolicy = result.event.policy_fix_context?.current_policy || {};
    const newPolicy = result.policy_draft.policy_json;
    return computeLineDiff(toPrettyLines(oldPolicy), toPrettyLines(newPolicy));
  }, [result]);

  if (status !== "done") {
    return (
      <div className="view-section active">
        <div className="page-header">
          <div>
            <div className="page-header__eyebrow"><i></i> Policy Diff & Approval</div>
            <h1><DecryptedText text="Review an AI-Drafted Fix" animateOn="view" sequential revealDirection="start" speed={28} encryptedClassName="dtx-scramble" /></h1>
            <p>
              {incident
                ? `Selected incident: ${incident.vulnerability_type} on ${incident.bucket_name}. `
                : ""}
              {isRealIncident
                ? "This runs the real pipeline against exactly this incident — a real anomaly score, a real ATT&CK classification, and (for IAM Audit findings) a real policy fetched live from LocalStack and a real LLM-drafted fix. No substitution: if this incident can't produce a draft, that's shown honestly below instead."
                : "No specific incident selected — this runs a reference walkthrough against one of the 4 crafted scenarios so a full policy draft can be shown on demand, clearly labeled as such below."}
            </p>
          </div>
        </div>

        {status === "error" && (
          <div className="empty-state" style={{ borderColor: "var(--danger)" }}>
            <p>{error}</p>
          </div>
        )}

        {status === "no_draft" && noDraft && (
          <div className="empty-state pd-empty" style={{ borderColor: "var(--border-highlight)" }}>
            <div className="empty-state__icon"></div>
            <p>{noDraft.title}</p>
            <p className="empty-state__sub">{noDraft.body}</p>
            <button className="btn-glass" onClick={runAnalysis} style={{ marginTop: 14 }}>Re-run</button>
          </div>
        )}

        {(status === "idle" || status === "loading") && (
          <div className="empty-state pd-empty">
            <div className="empty-state__icon"></div>
            <p>{status === "loading" ? "Running Layers 1-5 and the orchestrator's propose-test-revise loop..." : "No policy draft loaded yet."}</p>
            <p className="empty-state__sub">
              {status === "loading"
                ? "This includes a real SBERT embedding, a blast-radius graph traversal, and (for IAM Audit findings) up to 3 live Groq/Gemini calls — usually 5-20 seconds."
                : isRealIncident
                  ? "Click below to run the pipeline against this exact incident and render its real output."
                  : "Click below to run the reference walkthrough and render its real output."}
            </p>
            <button className="btn-glass btn-glow" disabled={status === "loading"} onClick={runAnalysis} style={{ marginTop: 14 }}>
              {status === "loading" ? "Analyzing..." : isRealIncident ? "Run Analysis" : "Run Reference Walkthrough"}
            </button>
          </div>
        )}
      </div>
    );
  }

  const { event, classification, blast_radius, priority, policy_draft } = result;
  const ctx = event.policy_fix_context;
  const narrative = threatNarrativeFor(event, ctx);
  const deployTarget = ctx.deploy_target;
  const canDeploy = Boolean(deployTarget) && policy_draft.test_passed;

  return (
    <div className="view-section active">
      <div className="pd-header">
        <span>STEP 5 OF 7 • Human Verification • P1 Vector Mitigation</span>
        <span className="pd-header__sla">APPROVAL SLA TARGET: {sla} REMAINING</span>
      </div>
      <div className="pd-ticket">🛡 PATCH TICKET • {event.event_id.toUpperCase()}</div>
      <h1 className="pd-title">
        {narrative.title}
        <code>{ctx.offending_resource}</code>
      </h1>

      <div className="pd-status">
        <span className="pd-status__left">
          <b>✓</b> Validated by {result.llm_client || "the LLM client"} • Attempt {policy_draft.attempt_number} of 3
        </span>
        <span className="pd-status__verdict">
          {policy_draft.test_passed ? "SANDBOX TEST PASSED" : "SANDBOX TEST FAILED"}
        </span>
      </div>

      <div className="pd-grid2">
        <div className="glass-card pd-card">
          <div className="pd-card__label">⚠ Identified Threat Vector</div>
          <h4 className="pd-card__title">{narrative.vectorName}</h4>
          <p className="pd-card__body">{narrative.vectorBody(ctx)}</p>
          <div className="pd-card__foot">
            <span>Blast radius: <b>{blast_radius?.severity}</b></span>
            <span>Critical resources reached: <b>{blast_radius?.critical_resources_reached?.length ?? 0}</b></span>
          </div>
        </div>
        <div className="glass-card pd-card">
          <div className="pd-card__label">🧭 Autonomous Policy Synthesizer Rationale <span className="pd-conf">{classification && classification.technique_id !== "UNKNOWN" ? `conf ${(classification.confidence * 100).toFixed(1)}%` : ""}</span></div>
          <p className="pd-card__body"><q>{policy_draft.rationale}</q></p>
          <div className="pd-card__foot">
            <span>Priority: <b>{priority?.tier}</b> ({priority?.score}/100)</span>
          </div>
        </div>
      </div>

      <div className="pd-grid2">
        <div className="glass-card pd-card">
          <div className="pd-card__label">⚙ Synthesis Engine</div>
          <h4 className="pd-card__title">{result.llm_client}</h4>
          <p className="pd-card__body">{policy_draft.description}</p>
          <div className="pd-card__tags"><span>Reasoner: {result.reasoner}</span><span>Errors: {policy_draft.errors?.length ?? 0}</span></div>
        </div>
        <div className="glass-card pd-card">
          <div className="pd-card__label">🛡 Blast-Radius Verification</div>
          <div className="pd-card__stat">{blast_radius?.severity}</div>
          <div className="pd-card__stat-label">Layer 3 graph traversal result</div>
          <p className="pd-card__body" style={{ marginTop: 10 }}>
            Reachable resources: {blast_radius?.reachable_resources?.length ?? 0}, max depth {blast_radius?.max_depth ?? 0}.
            {blast_radius?.critical_resources_reached?.length > 0 && (
              <> Critical: {blast_radius.critical_resources_reached.join(", ")}.</>
            )}
          </p>
        </div>
      </div>

      {diff && (
        <div className="pd-diff">
          <div className="pd-diff__head">
            <h3 className="section-title" style={{ fontSize: 16 }}><DecryptedText text="IAM Policy Diff (real Layer 4 output)" animateOn="view" sequential revealDirection="start" speed={22} encryptedClassName="dtx-scramble" /></h3>
            <div className="pd-diff__badges">
              <span><b>{diff.left.filter((l) => l.type === "rm").length}</b> removed</span>
              <span><em>{diff.right.filter((l) => l.type === "add").length}</em> added</span>
            </div>
          </div>
          <div className="pd-diff__grid">
            <DiffColumn side="old" lines={diff.left} />
            <DiffColumn side="new" lines={diff.right} />
          </div>
        </div>
      )}

      <div className="glass-card pd-rollback">
        <div className="pd-rollback__text">
          <b>Must-still-allow check:</b>{" "}
          {ctx.must_still_allow?.length
            ? <>{ctx.must_still_allow.map(([a, r]) => `${a} on ${r}`).join(", ")} — verified {policy_draft.test_passed ? "preserved" : "NOT preserved"} by PolicyEvaluator.</>
            : "No specific access was required to be preserved for this incident — verified the offending grant was actually removed by PolicyEvaluator."}
        </div>
        <div className="pd-rollback__signer">
          {deployTarget
            ? "Deploying applies this exact policy to the LocalStack sandbox identity below — never real AWS."
            : "This is a reference walkthrough (not a real LocalStack identity) — nothing here can be deployed."}
        </div>
      </div>

      {deployStatus === "done" && deployInfo && (
        <div className="glass-card" style={{ padding: "1rem", marginBottom: "1rem", background: "rgba(34,197,94,0.06)", border: "1px solid rgba(34,197,94,0.25)" }}>
          <p style={{ fontSize: "0.88rem", color: "var(--text-primary)", margin: 0 }}>
            ✅ Deployed to <b>{deployInfo.identity}</b> (policy "{deployInfo.policy_name}") on LocalStack.
            {deployInfo.rescanned && (
              <> Re-scanned immediately — <b>{deployInfo.remaining_findings_for_identity?.length ?? 0}</b> IAM Audit finding(s) remain for this identity.</>
            )}
            {deployInfo.prior_findings_marked_compliant > 0 && (
              <> Confirmed clean — <b>{deployInfo.prior_findings_marked_compliant}</b> prior flagged event(s) for this identity marked COMPLIANT, so the compliance score reflects the fix.</>
            )}
          </p>
        </div>
      )}
      {deployStatus === "error" && (
        <div className="glass-card" style={{ padding: "1rem", marginBottom: "1rem", background: "rgba(244,63,94,0.06)", border: "1px solid rgba(244,63,94,0.25)" }}>
          <p style={{ fontSize: "0.88rem", color: "var(--danger)", margin: 0 }}>Deploy failed: {deployError}</p>
        </div>
      )}

      <div className="glass-card pd-actions">
        <div className="pd-actions__left">
          <button className="btn-glass" onClick={onBack}>← Back</button>
          <button className="btn-glass" onClick={runAnalysis}>Re-run Analysis</button>
        </div>
        <div>
          <button
            className="btn-glass btn-glow"
            disabled={!canDeploy || deployStatus === "deploying"}
            title={canDeploy ? undefined : "Deploying requires a sandbox-tested draft against a real LocalStack identity — not available for this incident."}
            onClick={handleDeploy}
          >
            {deployStatus === "deploying" ? "Deploying..." : deployStatus === "done" ? "🚀 Deployed — Re-run to Verify" : "🚀 Deploy Fix to LocalStack"}
          </button>
          <p className="pd-actions__note">
            {deployTarget ? "Applies to this LocalStack sandbox only — never real AWS." : "Nothing here touches real AWS."}
          </p>
        </div>
      </div>
    </div>
  );
}
