"""Rule-based reconstruction of the IAM test sequences from a CloudTrail event table,
plus evaluation against the ground truth. Used for the L0 baseline and later loss experiments."""
import json
import sys
from pathlib import Path

import pandas as pd

IAM = "iam.amazonaws.com"
STAGES = ["ListUsers", "CreateUser", "AttachUserPolicy", "GetUser", "DetachUserPolicy", "DeleteUser"]
USER_STAGES = STAGES[1:]
LIST_WINDOW_S = 30


def reconstruct(df):
    """Rules (no ground truth used):
    1. Keep successful IAM events.
    2. Events that name a target user (Create/Attach/Get/Detach/Delete) are grouped per user.
    3. ListUsers has no user name: attach the closest unused ListUsers that happened
       up to 30 s before that user's CreateUser (one event is used only once).
    Returns {user: {stage: event_time_as_Timestamp}}."""
    iam = df[(df["event_source"] == IAM) & (df["error_code"].isna())].copy()
    iam["t"] = pd.to_datetime(iam["event_time"], utc=True)
    iam = iam.sort_values("t")

    runs = {}
    for r in iam.itertuples():
        if r.event_name in USER_STAGES and pd.notna(r.target_user):
            runs.setdefault(r.target_user, {}).setdefault(r.event_name, r.t)

    lists = [r.t for r in iam.itertuples() if r.event_name == "ListUsers"]
    used = set()
    for user, steps in sorted(runs.items(), key=lambda kv: kv[1].get("CreateUser", pd.Timestamp.max.tz_localize("UTC"))):
        ct = steps.get("CreateUser")
        if ct is None:
            continue
        best = None
        for i, lt in enumerate(lists):
            if i in used:
                continue
            gap = (ct - lt).total_seconds()
            if 0 <= gap <= LIST_WINDOW_S and (best is None or gap < best[1]):
                best = (i, gap)
        if best:
            used.add(best[0])
            steps["ListUsers"] = lists[best[0]]
    return runs


def evaluate(runs, gt):
    by_user = {}
    for s in gt["steps"]:
        by_user.setdefault(s["target_alias"], []).append(s)

    claimed = sum(len(v) for v in runs.values())
    correct = 0
    rows = []
    stage_hits = {s: 0 for s in STAGES}
    for user, steps in by_user.items():
        got = runs.get(user, {})
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
            "target_user": user,
            "steps_found": len(found),
            "missing": " ".join(s for s in STAGES if s not in found),
            "complete": len(found) == len(STAGES),
            "in_order": in_order,
        })

    n_steps = len(gt["steps"])
    n_runs = len(by_user)
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
