"""Rule-based reconstruction of the Scenario 2 (S3 + EC2) sequences from a CloudTrail event table,
plus evaluation against the ground truth."""
import json
import sys
from pathlib import Path

import pandas as pd

S3 = "s3.amazonaws.com"
EC2 = "ec2.amazonaws.com"
PREFIX = "cfr-s2-"
STAGES = ["CreateBucket", "PutBucketVersioning", "PutBucketEncryption", "PutBucketPublicAccessBlock",
          "PutBucketPolicy", "GetBucketPolicy", "RunInstances", "DescribeInstances", "CreateTags",
          "TerminateInstances", "DeleteBucketPolicy", "DeleteBucket"]
S3_STAGES = {"CreateBucket", "PutBucketVersioning", "PutBucketEncryption", "PutBucketPublicAccessBlock",
             "PutBucketPolicy", "GetBucketPolicy", "DeleteBucketPolicy", "DeleteBucket"}
VM_STAGES = {"DescribeInstances", "CreateTags", "TerminateInstances"}


def reconstruct(df):
    """Rules (no ground truth used):
    1. Keep successful S3 and EC2 events.
    2. S3 stage events are grouped per bucket; only buckets with the lab prefix cfr-s2- are runs.
    3. RunInstances carries the bucket name in its Name tag and returns the instance id:
       this links the VM to its bucket (the anchor of the VM chain).
    4. DescribeInstances / CreateTags / TerminateInstances name the instance id and join that run.
    Returns {bucket: {stage: event_time_as_Timestamp}}."""
    ok = df[df["event_source"].isin([S3, EC2]) & df["error_code"].isna()].copy()
    ok["t"] = pd.to_datetime(ok["event_time"], utc=True)
    ok = ok.sort_values("t")

    runs, inst = {}, {}
    for r in ok.itertuples():
        if r.event_source == S3 and r.event_name in S3_STAGES:
            if isinstance(r.target_bucket, str) and r.target_bucket.startswith(PREFIX):
                runs.setdefault(r.target_bucket, {}).setdefault(r.event_name, r.t)
        elif r.event_source == EC2 and r.event_name == "RunInstances":
            if isinstance(r.run_tag, str) and r.run_tag.startswith(PREFIX) and isinstance(r.instance_id, str):
                inst[r.instance_id] = r.run_tag
                runs.setdefault(r.run_tag, {}).setdefault("RunInstances", r.t)
    for r in ok.itertuples():
        if r.event_source == EC2 and r.event_name in VM_STAGES and r.instance_id in inst:
            runs[inst[r.instance_id]].setdefault(r.event_name, r.t)
    return runs


def evaluate(runs, gt):
    by_run = {}
    for s in gt["steps"]:
        by_run.setdefault(s["target_alias"], []).append(s)

    claimed = sum(len(v) for v in runs.values())
    correct = 0
    rows = []
    stage_hits = {s: 0 for s in STAGES}
    for bucket, steps in by_run.items():
        got = runs.get(bucket, {})
        found, times = [], []
        for s in sorted(steps, key=lambda x: x["step"]):
            t = got.get(s["event_name"])
            t0 = pd.Timestamp(s["start_utc"]) - pd.Timedelta(seconds=5)
            t1 = pd.Timestamp(s["end_utc"]) + pd.Timedelta(seconds=90)
            if t is not None and t0 <= t <= t1:
                found.append(s["event_name"])
                times.append(t)
                stage_hits[s["event_name"]] += 1
                correct += 1
        in_order = all(times[i] <= times[i + 1] for i in range(len(times) - 1))
        rows.append({
            "run_id": steps[0]["run_id"],
            "target_bucket": bucket,
            "steps_found": len(found),
            "missing": " ".join(s for s in STAGES if s not in found),
            "complete": len(found) == len(STAGES),
            "in_order": in_order,
        })

    n_steps = len(gt["steps"])
    n_runs = len(by_run)
    recall = correct / n_steps if n_steps else 0.0
    precision = correct / claimed if claimed else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    per_run = pd.DataFrame(rows)
    metrics = {
        "steps_total": n_steps,
        "steps_recovered": correct,
        "steps_claimed": claimed,
        "recall_step_coverage": round(recall, 4),
        "precision": round(precision, 4),
        "f1": round(f1, 4),
        "runs_total": n_runs,
        "runs_fully_reconstructed": int(per_run["complete"].sum()),
        "run_coverage": round(per_run["complete"].mean(), 4) if n_runs else 0.0,
        "ordering_accuracy": round(per_run["in_order"].mean(), 4) if n_runs else 0.0,
        "stage_recall": {s: round(stage_hits[s] / n_runs, 4) for s in STAGES},
    }
    return metrics, per_run


def main():
    coll = sys.argv[1]
    df = pd.read_csv(f"data/processed/{coll}_events.csv")
    gt = json.loads(Path(f"data/ground_truth/{coll}.json").read_text(encoding="utf-8"))
    metrics, per_run = evaluate(reconstruct(df), gt)
    out = Path("data/results")
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{coll}_L0_baseline.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    per_run.to_csv(out / f"{coll}_L0_baseline_runs.csv", index=False)
    for k, v in metrics.items():
        print(f"{k}: {v}")


if __name__ == "__main__":
    main()
