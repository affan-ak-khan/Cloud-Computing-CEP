"""Run benign IAM test sequences in our own AWS account and record ground truth."""
import argparse
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
ACTOR_ALIAS = "actor-1"
IAM_SRC = "iam.amazonaws.com"


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collection-id", required=True)
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--pause", type=float, default=3.0)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    iam = boto3.client("iam", region_name="us-east-1")
    s3 = boto3.client("s3", region_name="us-east-1")
    ec2 = boto3.client("ec2", region_name="us-east-1")

    noise_pool = [
        ("s3.amazonaws.com", "ListBuckets", lambda: s3.list_buckets()),
        ("ec2.amazonaws.com", "DescribeSecurityGroups", lambda: ec2.describe_security_groups()),
        (IAM_SRC, "ListRoles", lambda: iam.list_roles(MaxItems=5)),
    ]

    result = {
        "collection_id": args.collection_id,
        "seed": args.seed,
        "started_utc": utc_now(),
        "steps": [],
        "noise": [],
    }
    out_dir = Path("data/ground_truth")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{args.collection_id}.json"

    for run in range(1, args.runs + 1):
        user = f"cfr-test-{run:03d}-{rng.randrange(10000):04d}"
        run_id = f"{args.collection_id}-R{run:03d}"
        plan = [
            ("ListUsers", lambda: iam.list_users(MaxItems=5)),
            ("CreateUser", lambda: iam.create_user(UserName=user)),
            ("AttachUserPolicy", lambda: iam.attach_user_policy(UserName=user, PolicyArn=POLICY_ARN)),
            ("GetUser", lambda: iam.get_user(UserName=user)),
            ("DetachUserPolicy", lambda: iam.detach_user_policy(UserName=user, PolicyArn=POLICY_ARN)),
            ("DeleteUser", lambda: iam.delete_user(UserName=user)),
        ]
        failed = False
        for step_no, (event_name, call) in enumerate(plan, start=1):
            start = utc_now()
            try:
                call()
                status = "ok"
            except ClientError as err:
                status = "failed: " + err.response["Error"]["Code"]
                failed = True
            result["steps"].append({
                "run_id": run_id,
                "step": step_no,
                "event_source": IAM_SRC,
                "event_name": event_name,
                "actor_alias": ACTOR_ALIAS,
                "target_alias": user,
                "start_utc": start,
                "end_utc": utc_now(),
                "mandatory": True,
                "status": status,
            })
            print(run_id, step_no, event_name, status)
            if failed:
                break
            if step_no < len(plan) and rng.random() < 0.5:
                src, name, noise_call = rng.choice(noise_pool)
                try:
                    noise_call()
                except ClientError:
                    pass
                result["noise"].append({"event_source": src, "event_name": name, "time_utc": utc_now()})
            time.sleep(args.pause)

        if failed:
            for cleanup in (
                lambda: iam.detach_user_policy(UserName=user, PolicyArn=POLICY_ARN),
                lambda: iam.delete_user(UserName=user),
            ):
                try:
                    cleanup()
                except ClientError:
                    pass
            print("Cleanup attempted for", user)

        out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")

    result["finished_utc"] = utc_now()
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("Ground truth saved to", out_file)


if __name__ == "__main__":
    main()
