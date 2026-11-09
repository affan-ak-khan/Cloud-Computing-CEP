r"""Scenario 2: check which ground-truth steps (S3 + EC2) appear in downloaded CloudTrail logs.
Usage: python scripts\check_events_s2.py COLLECTION_ID RAW_DIR [--all]
Default output is a short per-event summary; --all also prints one line per step."""
import gzip
import json
import sys
from collections import OrderedDict
from datetime import datetime, timedelta
from pathlib import Path


def parse(ts):
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


def first(d, key, field):
    items = ((d or {}).get(key) or {}).get("items") or []
    return items[0].get(field) if items and isinstance(items[0], dict) else None


def instance_of(r):
    rp, resp = r.get("requestParameters") or {}, r.get("responseElements") or {}
    return (first(rp, "instancesSet", "instanceId") or first(rp, "resourcesSet", "resourceId")
            or first(resp, "instancesSet", "instanceId"))


args = [a for a in sys.argv[1:] if not a.startswith("--")]
show_all = "--all" in sys.argv
coll, raw_dir = args[0], args[1]
gt = json.loads(Path(f"data/ground_truth/{coll}.json").read_text(encoding="utf-8"))

records = []
for p in Path(raw_dir).rglob("*.json.gz"):
    if "CloudTrail-Digest" in p.parts:
        continue
    with gzip.open(p, "rt", encoding="utf-8") as fh:
        for r in json.load(fh).get("Records", []):
            records.append((r, p.name))
print(len(records), "records loaded")

# instance id of each run, taken from the ground truth (RunInstances step)
inst_of_run = {}
for s in gt["steps"]:
    if s.get("instance_id"):
        inst_of_run[s["target_alias"]] = s["instance_id"]

found = 0
per_event = OrderedDict()
for s in gt["steps"]:
    t0 = parse(s["start_utc"]) - timedelta(seconds=5)
    t1 = parse(s["end_utc"]) + timedelta(seconds=90)
    want_inst = inst_of_run.get(s["target_alias"]) if s["event_source"] == "ec2.amazonaws.com" else None
    hit = None
    for r, fname in records:
        if r.get("eventName") != s["event_name"] or r.get("eventSource") != s["event_source"]:
            continue
        if not (t0 <= parse(r["eventTime"]) <= t1):
            continue
        bucket = (r.get("requestParameters") or {}).get("bucketName")
        if bucket and bucket != s["target_alias"]:
            continue
        if want_inst and instance_of(r) != want_inst:
            continue
        hit = (r, fname)
        break
    ok = hit is not None
    found += ok
    f, n = per_event.get(s["event_name"], (0, 0))
    per_event[s["event_name"]] = (f + ok, n + 1)
    if show_all:
        print("FOUND  " if ok else "MISSING", s["run_id"], s["step"], s["event_name"],
              hit[0]["eventTime"] if ok else "")

print()
print(f"{'event':30s} found / total")
for name, (f, n) in per_event.items():
    print(f"{name:30s} {f:5d} / {n}")
print()
print(found, "of", len(gt["steps"]), "steps found")
