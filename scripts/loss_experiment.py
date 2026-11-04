"""Controlled log-loss experiments. Each experiment works on an in-memory COPY of the
parsed event table; the raw logs and the processed CSV are never modified."""
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

from reconstruct import evaluate, reconstruct

LEVELS = [10, 20, 30, 40, 50]
SEEDS = range(1, 31)
METRICS = ["recall_step_coverage", "precision", "f1", "run_coverage", "ordering_accuracy"]

TARGETED = {
    "drop ListUsers": ["ListUsers"],
    "drop CreateUser": ["CreateUser"],
    "drop AttachUserPolicy": ["AttachUserPolicy"],
    "drop GetUser": ["GetUser"],
    "drop DetachUserPolicy": ["DetachUserPolicy"],
    "drop DeleteUser": ["DeleteUser"],
    "drop privilege changes (Attach+Detach)": ["AttachUserPolicy", "DetachUserPolicy"],
    "drop lifecycle (Create+Delete)": ["CreateUser", "DeleteUser"],
}


def random_loss(df, pct, seed):
    """L1: every event has the same chance of being lost."""
    return df.sample(frac=1 - pct / 100, random_state=seed).sort_index()


def targeted_loss(df, names):
    """L2: all events of chosen types are lost."""
    return df[~df["event_name"].isin(names)]


def file_loss(df, pct, seed):
    """L3: whole delivered log files are lost (source-level loss)."""
    files = sorted(df["log_file"].unique())
    n = int(round(len(files) * pct / 100))
    rng = np.random.default_rng(seed)
    drop = set(rng.choice(files, size=n, replace=False).tolist())
    return df[~df["log_file"].isin(drop)]


def window_loss(df, pct, seed):
    """L4: one continuous block of the time-ordered events is lost (outage).
    The block holds pct% of all events, so it is comparable with the other models."""
    order = pd.to_datetime(df["event_time"], utc=True).sort_values(kind="stable").index
    n = int(round(len(order) * pct / 100))
    rng = np.random.default_rng(seed)
    start = int(rng.integers(0, len(order) - n + 1))
    return df.drop(order[start:start + n])


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    coll = sys.argv[1]
    csv_path = Path(f"data/processed/{coll}_events.csv")
    gt_path = Path(f"data/ground_truth/{coll}.json")
    df = pd.read_csv(csv_path)
    gt = json.loads(gt_path.read_text(encoding="utf-8"))

    rows = []

    def score(model, level, seed, d):
        m, _ = evaluate(reconstruct(d), gt)
        rows.append({"model": model, "loss_pct": level, "seed": seed,
                     "events_kept": len(d), "events_dropped": len(df) - len(d),
                     **{k: m[k] for k in METRICS}})

    score("L0_baseline", 0, 0, df)
    for pct in LEVELS:
        for seed in SEEDS:
            score("L1_random_events", pct, seed, random_loss(df, pct, seed))
            score("L3_log_files", pct, seed, file_loss(df, pct, seed))
            score("L4_time_window", pct, seed, window_loss(df, pct, seed))
    for name, names in TARGETED.items():
        d = targeted_loss(df, names)
        score("L2_targeted: " + name, round(100 * (len(df) - len(d)) / len(df), 1), 0, d)

    out = Path("data/results")
    out.mkdir(parents=True, exist_ok=True)
    runs = pd.DataFrame(rows)
    runs.to_csv(out / f"{coll}_loss_runs.csv", index=False)
    summary = runs.groupby(["model", "loss_pct"])[METRICS].agg(["mean", "std"]).round(3)
    summary.to_csv(out / f"{coll}_loss_summary.csv")

    manifest = {
        "collection_id": coll,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "input_events_csv": str(csv_path), "input_events_sha256": sha256(csv_path),
        "ground_truth": str(gt_path), "ground_truth_sha256": sha256(gt_path),
        "levels_pct": LEVELS, "seeds": [min(SEEDS), max(SEEDS)],
        "models": ["L0_baseline", "L1_random_events", "L2_targeted", "L3_log_files", "L4_time_window"],
        "total_evaluations": len(runs),
    }
    (out / f"{coll}_loss_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.2))
    labels = {"L1_random_events": "L1 random events", "L3_log_files": "L3 whole log files",
              "L4_time_window": "L4 time window"}
    for ax, metric, title in [(axes[0], "recall_step_coverage", "Step recall (coverage)"),
                              (axes[1], "run_coverage", "Fully reconstructed runs")]:
        for model, label in labels.items():
            g = runs[runs["model"] == model].groupby("loss_pct")[metric]
            mean, std = g.mean(), g.std()
            ax.plot(mean.index, mean.values, marker="o", label=label)
            ax.fill_between(mean.index, (mean - std).clip(0, 1), (mean + std).clip(0, 1), alpha=0.15)
        ax.set_xlabel("Log loss (%)")
        ax.set_ylabel(title)
        ax.set_ylim(0, 1.05)
        ax.set_title(title + " vs log loss (mean +/- sd, 30 seeds)", fontsize=10)
        ax.grid(alpha=0.3)
    axes[0].legend()
    fig.tight_layout()
    fig.savefig(out / f"{coll}_loss_curves.png", dpi=200)

    show = runs.groupby(["model", "loss_pct"])[["recall_step_coverage", "precision", "f1", "run_coverage"]].mean().round(3)
    print(show.to_string())
    print()
    print("saved:", out / f"{coll}_loss_runs.csv")
    print("saved:", out / f"{coll}_loss_summary.csv")
    print("saved:", out / f"{coll}_loss_manifest.json")
    print("saved:", out / f"{coll}_loss_curves.png")


if __name__ == "__main__":
    main()
