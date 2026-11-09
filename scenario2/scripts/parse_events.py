"""Parse collected CloudTrail logs into one clean table (CSV). Raw files are never changed.
Works for both scenarios (IAM and S3+EC2); extra columns identify the bucket / VM involved."""
import gzip
import json
import sys
from pathlib import Path

import pandas as pd


def first(d, key, field):
    """First element of CloudTrail's {key: {"items": [ {field: ...} ]}} structure."""
    items = ((d or {}).get(key) or {}).get("items") or []
    return items[0].get(field) if items and isinstance(items[0], dict) else None


def run_tag(rp):
    """RunInstances: value of the Name tag given at launch (we use the bucket name)."""
    for spec in ((rp.get("tagSpecificationSet") or {}).get("items") or []):
        for t in spec.get("tags") or []:
            if t.get("key") == "Name":
                return t.get("value")
    return None


coll = sys.argv[1]
raw = Path("data/raw") / coll
rows = []
for p in sorted(raw.rglob("*.json.gz")):
    if "CloudTrail-Digest" in p.parts:
        continue
    with gzip.open(p, "rt", encoding="utf-8") as fh:
        for r in json.load(fh).get("Records", []):
            rp = r.get("requestParameters") or {}
            resp = r.get("responseElements") or {}
            ui = r.get("userIdentity") or {}
            rows.append({
                "event_id": r.get("eventID"),
                "event_time": r.get("eventTime"),
                "event_source": r.get("eventSource"),
                "event_name": r.get("eventName"),
                "aws_region": r.get("awsRegion"),
                "identity_type": ui.get("type"),
                "principal": ui.get("arn") or ui.get("principalId"),
                "source_ip": r.get("sourceIPAddress"),
                "target_user": rp.get("userName"),
                "target_bucket": rp.get("bucketName"),
                "instance_id": (first(rp, "instancesSet", "instanceId")
                                or first(rp, "resourcesSet", "resourceId")
                                or first(resp, "instancesSet", "instanceId")),
                "run_tag": run_tag(rp),
                "error_code": r.get("errorCode"),
                "read_only": r.get("readOnly"),
                "log_file": p.name,
            })

df = pd.DataFrame(rows)
total = len(df)
df = df.drop_duplicates("event_id").sort_values("event_time").reset_index(drop=True)
out_dir = Path("data/processed")
out_dir.mkdir(parents=True, exist_ok=True)
out = out_dir / f"{coll}_events.csv"
df.to_csv(out, index=False)

print("records read:", total, "| unique events:", len(df), "| log files:", df["log_file"].nunique())
print("saved to", out)
print()
print("Top event names:")
print(df["event_name"].value_counts().head(16).to_string())
print()
print("Top event sources:")
print(df["event_source"].value_counts().head(8).to_string())
