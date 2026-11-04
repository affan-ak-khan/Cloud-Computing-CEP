"""Parse collected CloudTrail logs into one clean table (CSV). Raw files are never changed."""
import gzip
import json
import sys
from pathlib import Path

import pandas as pd

coll = sys.argv[1]
raw = Path("data/raw") / coll
rows = []
for p in sorted(raw.rglob("*.json.gz")):
    if "CloudTrail-Digest" in p.parts:
        continue
    with gzip.open(p, "rt", encoding="utf-8") as fh:
        for r in json.load(fh).get("Records", []):
            rp = r.get("requestParameters") or {}
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
print(df["event_name"].value_counts().head(12).to_string())
print()
print("Top event sources:")
print(df["event_source"].value_counts().head(8).to_string())
