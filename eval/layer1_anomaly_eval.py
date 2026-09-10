"""
Layer 1 Evaluation — Anomaly Detection
========================================
Labeled dataset of "normal" vs "anomalous" cloud security events, scored
through a single AnomalyDetector session (so the windowed/session features —
account frequency, region frequency, cross-region flag — actually get a
chance to fire, matching how the detector is used in production: a
persistent detector accumulating a sliding window, not one-shot scoring).

Reports precision/recall/F1 at the orchestrator's calibrated operating
threshold (ANOMALY_THRESHOLD = 0.46, see ml/orchestrator.py's own comment
on how that number was derived) plus ROC-AUC, which is threshold-independent
and answers "does the score itself rank anomalous above normal, regardless
of where the cutoff sits."
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lambda", "shared"))

from ml.anomaly_detector import AnomalyDetector
from sklearn.metrics import precision_recall_fscore_support, roc_auc_score, confusion_matrix

ANOMALY_THRESHOLD = 0.46  # ml/orchestrator.py's calibrated operating point

# ---------------------------------------------------------------------------
# Labeled dataset — (event, label, category)
# label: 0 = normal, 1 = anomalous
# ---------------------------------------------------------------------------

NORMAL_EVENTS = [
    # -- ordinary S3 GetObject / compliant access, business hours --
    ({"timestamp": "2026-06-15T10:15:00Z", "vulnerability_type": "S3 Public Access",
      "severity": "LOW", "bucket_name": "team-shared-docs", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT"}, "ordinary_s3_access"),
    ({"timestamp": "2026-06-15T14:30:00Z", "vulnerability_type": "S3 Encryption",
      "severity": "LOW", "bucket_name": "weekly-reports", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT"}, "ordinary_s3_access"),
    ({"timestamp": "2026-06-16T11:00:00Z", "vulnerability_type": "S3 Public Access",
      "severity": "LOW", "bucket_name": "internal-wiki-assets", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT"}, "ordinary_s3_access"),

    # -- normal Lambda invocation --
    ({"timestamp": "2026-06-15T09:45:00Z", "vulnerability_type": "Lambda Invocation",
      "severity": "LOW", "bucket_name": "fn-nightly-cleanup", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT"}, "normal_lambda"),
    ({"timestamp": "2026-06-15T15:20:00Z", "vulnerability_type": "Lambda Invocation",
      "severity": "LOW", "bucket_name": "fn-image-resize", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT"}, "normal_lambda"),
    ({"timestamp": "2026-06-16T13:10:00Z", "vulnerability_type": "Lambda Invocation",
      "severity": "LOW", "bucket_name": "fn-log-shipper", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT"}, "normal_lambda"),

    # -- routine IAM operations --
    ({"timestamp": "2026-06-15T10:00:00Z", "vulnerability_type": "IAM Audit",
      "severity": "LOW", "bucket_name": "User:jsmith", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT", "principal": "jsmith"}, "routine_iam"),
    ({"timestamp": "2026-06-15T16:00:00Z", "vulnerability_type": "IAM Audit",
      "severity": "LOW", "bucket_name": "Role:analyst-readonly", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT"}, "routine_iam"),
    ({"timestamp": "2026-06-16T09:30:00Z", "vulnerability_type": "IAM Audit",
      "severity": "LOW", "bucket_name": "Role:ci-readonly", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT"}, "routine_iam"),

    # -- normal CloudTrail / infra events --
    ({"timestamp": "2026-06-15T11:30:00Z", "vulnerability_type": "DynamoDB Unencrypted",
      "severity": "LOW", "bucket_name": "app-sessions-table", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT"}, "normal_cloudtrail"),
    ({"timestamp": "2026-06-15T13:45:00Z", "vulnerability_type": "Security Group Open SSH",
      "severity": "LOW", "bucket_name": "sg-internal-app", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT"}, "normal_cloudtrail"),
    ({"timestamp": "2026-06-16T10:20:00Z", "vulnerability_type": "S3 Encryption",
      "severity": "LOW", "bucket_name": "dev-scratch-bucket", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT"}, "normal_cloudtrail"),

    # -- HARD cases: business-hours, but the resource name contains a
    # prod-keyword and severity is MEDIUM — a legitimate compliance check on
    # a production bucket during the day. Should still read as normal (no
    # off-hours, no elevated frequency, no CRITICAL/IAM signal), but is a
    # much closer call than the clean cases above, which is the point. --
    ({"timestamp": "2026-06-15T11:00:00Z", "vulnerability_type": "S3 Encryption",
      "severity": "MEDIUM", "bucket_name": "prod-analytics-exports", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT"}, "hard_normal_prod_daytime"),
    ({"timestamp": "2026-06-16T14:00:00Z", "vulnerability_type": "DynamoDB Unencrypted",
      "severity": "MEDIUM", "bucket_name": "prod-metrics-table", "account_id": "123456789012",
      "region": "us-east-1", "status": "COMPLIANT"}, "hard_normal_prod_daytime"),
]

ANOMALOUS_EVENTS = [
    # -- unusual privilege escalation --
    ({"timestamp": "2026-06-12T03:14:00Z", "vulnerability_type": "IAM Audit",
      "severity": "CRITICAL", "bucket_name": "wildcard-admin-policy-prod", "account_id": "999999999999",
      "region": "ap-southeast-1", "status": "IAM_OVERPERMISSIVE", "principal": "dev-intern-role"}, "priv_escalation"),
    ({"timestamp": "2026-06-12T02:47:00Z", "vulnerability_type": "IAM Audit",
      "severity": "CRITICAL", "bucket_name": "root-admin-credential-escalation", "account_id": "999999999999",
      "region": "ap-southeast-1", "status": "IAM_OVERPERMISSIVE"}, "priv_escalation"),
    ({"timestamp": "2026-06-13T04:02:00Z", "vulnerability_type": "IAM Audit",
      "severity": "CRITICAL", "bucket_name": "master-key-admin-secret", "account_id": "999999999999",
      "region": "ap-southeast-1", "status": "IAM_OVERPERMISSIVE"}, "priv_escalation"),

    # -- unexpected IAM changes --
    ({"timestamp": "2026-06-13T01:30:00Z", "vulnerability_type": "IAM Audit",
      "severity": "CRITICAL", "bucket_name": "Role:admin-payment-credential", "account_id": "999999999999",
      "region": "eu-west-1", "status": "IAM_OVERPERMISSIVE"}, "unexpected_iam_change"),
    ({"timestamp": "2026-06-13T02:10:00Z", "vulnerability_type": "IAM Audit",
      "severity": "CRITICAL", "bucket_name": "Role:root-secret-vault-admin", "account_id": "999999999999",
      "region": "eu-west-1", "status": "IAM_OVERPERMISSIVE"}, "unexpected_iam_change"),
    ({"timestamp": "2026-06-13T03:50:00Z", "vulnerability_type": "IAM Audit",
      "severity": "CRITICAL", "bucket_name": "Role:master-admin-override", "account_id": "999999999999",
      "region": "eu-west-1", "status": "IAM_OVERPERMISSIVE"}, "unexpected_iam_change"),

    # -- unusual S3 access (prod, off-hours, CRITICAL) --
    ({"timestamp": "2026-06-12T02:47:00Z", "vulnerability_type": "S3 Public Access",
      "severity": "CRITICAL", "bucket_name": "prod-customer-payment-data-lake", "account_id": "123456789012",
      "region": "eu-west-1", "status": "IAM_OVERPERMISSIVE", "principal": "ci-deploy-role"}, "unusual_s3_access"),
    ({"timestamp": "2026-06-12T02:51:00Z", "vulnerability_type": "S3 Public Access",
      "severity": "CRITICAL", "bucket_name": "prod-customer-secret-credential-lake", "account_id": "123456789012",
      "region": "eu-west-1", "status": "IAM_OVERPERMISSIVE"}, "unusual_s3_access"),
    ({"timestamp": "2026-06-12T02:55:00Z", "vulnerability_type": "S3 Public Access",
      "severity": "CRITICAL", "bucket_name": "prod-payment-admin-backup-vault", "account_id": "123456789012",
      "region": "eu-west-1", "status": "IAM_OVERPERMISSIVE"}, "unusual_s3_access"),

    # -- impossible / unusual sequences: rapid cross-region burst from one account --
    ({"timestamp": "2026-06-14T04:00:00Z", "vulnerability_type": "S3 Public Access",
      "severity": "HIGH", "bucket_name": "prod-burst-1", "account_id": "555555555555",
      "region": "us-east-1", "status": "IAM_OVERPERMISSIVE"}, "impossible_sequence"),
    ({"timestamp": "2026-06-14T04:00:30Z", "vulnerability_type": "IAM Audit",
      "severity": "HIGH", "bucket_name": "prod-burst-2", "account_id": "555555555555",
      "region": "eu-west-1", "status": "IAM_OVERPERMISSIVE"}, "impossible_sequence"),
    ({"timestamp": "2026-06-14T04:01:00Z", "vulnerability_type": "Security Group Open SSH",
      "severity": "HIGH", "bucket_name": "prod-burst-3", "account_id": "555555555555",
      "region": "ap-southeast-1", "status": "IAM_OVERPERMISSIVE"}, "impossible_sequence"),
    ({"timestamp": "2026-06-14T04:01:30Z", "vulnerability_type": "DynamoDB Unencrypted",
      "severity": "HIGH", "bucket_name": "prod-burst-4", "account_id": "555555555555",
      "region": "ap-northeast-1", "status": "IAM_OVERPERMISSIVE"}, "impossible_sequence"),

    # -- unusual principals / resources --
    ({"timestamp": "2026-06-12T01:30:00Z", "vulnerability_type": "S3 Encryption",
      "severity": "MEDIUM", "bucket_name": "analyst-user-ml-training-datasets-admin-credential-export",
      "account_id": "123456789012", "region": "us-west-2", "status": "IAM_OVERPERMISSIVE",
      "principal": "analyst-user"}, "unusual_principal"),
    ({"timestamp": "2026-06-12T04:02:00Z", "vulnerability_type": "DynamoDB Unencrypted",
      "severity": "HIGH", "bucket_name": "backup-service-role-session-tokens-secret-credential-table",
      "account_id": "123456789012", "region": "us-east-1", "status": "IAM_OVERPERMISSIVE",
      "principal": "backup-service-role"}, "unusual_principal"),

    # -- HARD cases: off-hours timing but a weak signal otherwise (LOW
    # severity, no prod keyword, no frequency burst) — a legitimately
    # scheduled off-hours job on a dev resource. Labeled anomalous here only
    # because it's still an off-hours IAM_OVERPERMISSIVE finding (a genuine,
    # if minor, misconfiguration), not because every off-hours event should
    # be flagged — these are the cases most likely to be missed, which is
    # exactly why they belong in the eval rather than being left out. --
    ({"timestamp": "2026-06-14T05:30:00Z", "vulnerability_type": "IAM Audit",
      "severity": "LOW", "bucket_name": "Role:dev-sandbox-scheduled-job", "account_id": "123456789012",
      "region": "us-east-1", "status": "IAM_OVERPERMISSIVE"}, "hard_anomalous_weak_signal"),
]


def main():
    detector = AnomalyDetector().fit()

    labeled = [(e, 0, cat) for e, cat in NORMAL_EVENTS] + [(e, 1, cat) for e, cat in ANOMALOUS_EVENTS]

    y_true, y_score, categories = [], [], []
    for event, label, category in labeled:
        score = detector.score(event)
        y_true.append(label)
        y_score.append(score)
        categories.append(category)

    y_pred = [1 if s >= ANOMALY_THRESHOLD else 0 for s in y_score]

    precision, recall, f1, _ = precision_recall_fscore_support(y_true, y_pred, average="binary", zero_division=0)
    try:
        auc = roc_auc_score(y_true, y_score)
    except ValueError:
        auc = float("nan")
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])

    print("=" * 70)
    print("LAYER 1 — Anomaly Detection Evaluation")
    print("=" * 70)
    print(f"Dataset: {len(NORMAL_EVENTS)} normal, {len(ANOMALOUS_EVENTS)} anomalous"
          f" ({len(labeled)} total), scored in one streaming session")
    print(f"Operating threshold: {ANOMALY_THRESHOLD} (ml/orchestrator.py's calibrated cutoff)")
    print()
    print(f"Precision: {precision:.3f}")
    print(f"Recall:    {recall:.3f}")
    print(f"F1:        {f1:.3f}")
    print(f"ROC-AUC:   {auc:.3f}  (threshold-independent ranking quality)")
    print()
    print("Confusion matrix [rows=actual, cols=predicted], labels=[normal, anomalous]:")
    print(cm)
    print()
    print(f"{'category':<22} {'label':<10} {'score':>8}  event")
    for (event, label, category), score in zip(labeled, y_score):
        pred = "ANOMALOUS" if score >= ANOMALY_THRESHOLD else "normal"
        mark = "OK" if (score >= ANOMALY_THRESHOLD) == bool(label) else "MISCLASSIFIED"
        print(f"{category:<22} {'anomalous' if label else 'normal':<10} {score:>8.4f}  -> {pred:<10} [{mark}]  {event['bucket_name']}")

    result = {
        "layer": 1, "name": "Anomaly Detection",
        "n_normal": len(NORMAL_EVENTS), "n_anomalous": len(ANOMALOUS_EVENTS),
        "threshold": ANOMALY_THRESHOLD,
        "precision": precision, "recall": recall, "f1": f1, "roc_auc": auc,
        "confusion_matrix": cm.tolist(),
    }
    return result


if __name__ == "__main__":
    result = main()
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results_layer1.json")
    with open(out_path, "w") as f:
        json.dump(result, f, indent=2)
    print(f"\nSaved -> {out_path}")
