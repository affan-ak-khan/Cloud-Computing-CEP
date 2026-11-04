"""Check which ground-truth steps appear in downloaded CloudTrail logs."""
import gzip
import json
import sys
from datetime import datetime, timedelta
from pathlib import Path


def parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


coll, raw_dir = sys.argv[1], sys.argv[2]
gt = json.loads(Path(f"data/ground_truth/{coll}.json").read_text(encoding="utf-8"))

records = []
for p in Path(raw_dir).rglob("*.json.gz"):
    if "CloudTrail-Digest" in p.parts:
        continue
    with gzip.open(p, "rt", encoding="utf-8") as fh:
        for r in json.load(fh).get("Records", []):
            records.append((r, p.name))
print(len(records), "records loaded")

found = 0
for s in gt["steps"]:
    t0 = parse(s["start_utc"]) - timedelta(seconds=5)
    t1 = parse(s["end_utc"]) + timedelta(seconds=90)
    hit = None
    for r, fname in records:
        if r.get("eventName") != s["event_name"] or r.get("eventSource") != s["event_source"]:
            continue
        if not (t0 <= parse(r["eventTime"]) <= t1):
            continue
        name = (r.get("requestParameters") or {}).get("userName")
        if name and name != s["target_alias"]:
            continue
        hit = (r, fname)
        break
    if hit:
        found += 1
        print("FOUND  ", s["step"], s["event_name"], hit[0]["eventTime"], hit[1])
    else:
        print("MISSING", s["step"], s["event_name"])
print(found, "of", len(gt["steps"]), "steps found")
