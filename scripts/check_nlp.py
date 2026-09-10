"""Quick check: do events in DynamoDB have nlp_summary populated?"""
import boto3

ddb = boto3.resource(
    "dynamodb",
    endpoint_url="http://localhost:4566",
    region_name="us-east-1",
    aws_access_key_id="test",
    aws_secret_access_key="test",
)
table = ddb.Table("cspm-remediation-events")
resp = table.scan()
items = resp.get("Items", [])

# Paginate
while "LastEvaluatedKey" in resp:
    resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
    items.extend(resp.get("Items", []))

items.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

print(f"Total events in DynamoDB: {len(items)}\n")
print(f"{'Status':<25} {'Resource':<30} {'NLP Summary?':<20} {'Timestamp'}")
print("-" * 110)

for e in items[:20]:
    summary = e.get("nlp_summary", "")
    has_nlp = f"YES ({len(summary)} chars)" if summary else "** MISSING **"
    print(f"{e.get('status','?'):<25} {e.get('bucket_name','?'):<30} {has_nlp:<20} {e.get('timestamp','?')[:19]}")

# Show one full NLP summary as example
print("\n" + "=" * 80)
with_nlp = [e for e in items if e.get("nlp_summary")]
without_nlp = [e for e in items if not e.get("nlp_summary")]
print(f"\nEvents WITH nlp_summary:    {len(with_nlp)}")
print(f"Events WITHOUT nlp_summary: {len(without_nlp)}")

if with_nlp:
    print(f"\n--- Example NLP summary (most recent) ---")
    print(with_nlp[0]["nlp_summary"][:500])

if without_nlp:
    print(f"\n--- Events missing NLP summary ---")
    for e in without_nlp[:5]:
        print(f"  event_id={e.get('event_id','?')[:8]}... status={e.get('status')} resource={e.get('bucket_name','?')} vuln_type={e.get('vulnerability_type','?')}")
