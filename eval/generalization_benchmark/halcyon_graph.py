"""
halcyon_graph.py — Independent infrastructure graph for the Universal Security
Generalization Benchmark.
=================================================================================
Per the benchmark brief's "no reuse of existing demos/fixtures" and "use an
independent reachability oracle or manually verified graph" rules: this is a
completely separate, fictional environment ("Halcyon Corp") built specifically
for this benchmark. None of these node IDs, principal names, or resource names
appear anywhere else in the project (not in blast_radius_seed.json, not in any
eval/ or tests/ fixture, not in DEMO_ATTACK_SCENARIOS).

Deliberately includes:
  - A multi-hop escalation chain (halcyon-onboarding-role -> deploy pipeline ->
    2 critical-tagged resources) mirroring the real risk pattern the existing
    seed graph demonstrates, but with entirely new names/context.
  - A "narrow but high-impact" resource (halcyon-deploy-artifacts, tagged
    admin — a supply-chain risk: whoever can write to build artifacts can
    inject code into every deploy, even though the action itself sounds minor).
  - A resource that is genuinely sensitive in real-world terms (stores API
    keys/credentials) but NOT tagged with any of blast_radius.py's own
    CRITICAL_TAGS vocabulary (production/pii/payment/admin) — a deliberate
    probe of a real, disclosed system limitation: severity here is judged
    purely by those 4 tag words, not general semantic sensitivity.
"""

from ml.blast_radius import InfraGraph

HALCYON_NODES = [
    ("halcyon-onboarding-role", "IAMRole", []),
    ("halcyon-billing-service-role", "IAMRole", ["production"]),
    ("halcyon-support-agent-user", "IAMUser", []),
    ("halcyon-deploy-pipeline-role", "IAMRole", ["admin"]),
    ("halcyon-partner-sync-role", "IAMRole", []),
    ("halcyon-ml-training-role", "IAMRole", []),
    ("halcyon-legacy-reporting-role", "IAMRole", []),
    # Reaches ONLY the secrets vault — isolates the "system under-rates a
    # genuinely sensitive resource because it lacks the magic tag words"
    # trap from halcyon-billing-service-role (which also reaches a
    # magic-tagged resource and would mask the effect).
    ("halcyon-audit-bot-role", "IAMRole", []),
    ("halcyon-checkout-fn-exec-role", "IAMRole", []),
    ("halcyon-scheduled-cleanup-fn-role", "IAMRole", []),
    ("halcyon-report-export-fn-role", "IAMRole", []),  # deliberately no edges — its only real permission is properly source-IP-restricted (see scenarios.py GB-19)

    ("halcyon-customer-pii-store", "S3Bucket", ["production", "pii"]),
    ("halcyon-billing-records", "DynamoDBTable", ["production", "payment", "pii"]),
    ("halcyon-internal-wiki-assets", "S3Bucket", []),
    ("halcyon-dev-scratch-bucket", "S3Bucket", []),
    ("halcyon-partner-export-queue", "S3Bucket", ["production"]),
    # Deliberately NOT tagged "production/pii/payment/admin" despite holding
    # real secrets — see module docstring. Ground truth treats this as
    # genuinely sensitive; the system's own CRITICAL_TAGS check will not.
    ("halcyon-secrets-vault", "DynamoDBTable", ["secret", "credential"]),
    ("halcyon-deploy-artifacts", "S3Bucket", ["admin"]),
    ("halcyon-marketing-assets", "S3Bucket", []),
    ("halcyon-audit-log-archive", "DynamoDBTable", ["production"]),
    ("halcyon-tmp-cache-table", "DynamoDBTable", []),
]

HALCYON_EDGES = [
    ("halcyon-onboarding-role", "halcyon-internal-wiki-assets", "can_read"),
    ("halcyon-onboarding-role", "halcyon-deploy-pipeline-role", "can_assume"),
    ("halcyon-deploy-pipeline-role", "halcyon-deploy-artifacts", "can_administer"),
    ("halcyon-deploy-pipeline-role", "halcyon-billing-records", "can_write"),
    ("halcyon-billing-service-role", "halcyon-billing-records", "can_read"),
    ("halcyon-billing-service-role", "halcyon-secrets-vault", "can_read"),
    ("halcyon-support-agent-user", "halcyon-customer-pii-store", "can_read"),
    ("halcyon-partner-sync-role", "halcyon-partner-export-queue", "can_write"),
    ("halcyon-ml-training-role", "halcyon-customer-pii-store", "can_read"),
    ("halcyon-ml-training-role", "halcyon-dev-scratch-bucket", "can_write"),
    ("halcyon-legacy-reporting-role", "halcyon-audit-log-archive", "can_read"),
    ("halcyon-legacy-reporting-role", "halcyon-partner-sync-role", "can_assume"),
    ("halcyon-audit-bot-role", "halcyon-secrets-vault", "can_read"),
    ("halcyon-checkout-fn-exec-role", "halcyon-billing-records", "can_write"),
    ("halcyon-scheduled-cleanup-fn-role", "halcyon-tmp-cache-table", "can_write"),
]


def build_halcyon_graph() -> InfraGraph:
    graph = InfraGraph()
    for node_id, node_type, tags in HALCYON_NODES:
        graph.add_node(node_id, node_type, tags)
    for source, target, edge_type in HALCYON_EDGES:
        graph.add_edge(source, target, edge_type)
    return graph
