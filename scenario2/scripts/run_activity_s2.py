"""Scenario 2: benign S3 + EC2 workflow in our own AWS account, ground truth recorded.
Each run = 12 steps: secure an S3 bucket, launch/tag/terminate one small VM, remove the bucket."""
import argparse
import json
import random
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

REGION = "us-east-1"
PREFIX = "cfr-s2-"
AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
INSTANCE_TYPE = "t3.micro"


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def retry(call, tries=6, wait=2.0):
    """EC2 is eventually consistent: a call made right after RunInstances can fail once or twice."""
    for i in range(tries):
        try:
            return call()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if i == tries - 1 or "NotFound" not in code:
                raise
            time.sleep(wait)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collection-id", required=True)
    ap.add_argument("--runs", type=int, default=1)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--pause", type=float, default=3.0)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    s3 = boto3.client("s3", region_name=REGION)
    ec2 = boto3.client("ec2", region_name=REGION)
    iam = boto3.client("iam", region_name=REGION)
    ssm = boto3.client("ssm", region_name=REGION)
    ami = ssm.get_parameter(Name=AMI_PARAM)["Parameter"]["Value"]

    noise_pool = [
        ("s3.amazonaws.com", "ListBuckets", lambda: s3.list_buckets()),
        ("ec2.amazonaws.com", "DescribeSecurityGroups", lambda: ec2.describe_security_groups()),
        ("iam.amazonaws.com", "ListRoles", lambda: iam.list_roles(MaxItems=5)),
    ]

    result = {"collection_id": args.collection_id, "scenario": "S2_s3_ec2", "seed": args.seed,
              "started_utc": utc_now(), "steps": [], "noise": []}
    out_dir = Path("data/ground_truth")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{args.collection_id}.json"

    for run in range(1, args.runs + 1):
        bucket = f"{PREFIX}{datetime.now(timezone.utc):%m%d%H%M}-{run:03d}-{rng.randrange(10000):04d}"
        run_id = f"{args.collection_id}-R{run:03d}"
        state = {"instance": None, "terminated": False, "bucket": False}
        policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*",
                           "Action": "s3:*",
                           "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                           "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]})

        def create_bucket():
            s3.create_bucket(Bucket=bucket)
            state["bucket"] = True

        def run_instance():
            r = ec2.run_instances(
                ImageId=ami, InstanceType=INSTANCE_TYPE, MinCount=1, MaxCount=1,
                MetadataOptions={"HttpTokens": "required"},
                TagSpecifications=[{"ResourceType": "instance",
                                    "Tags": [{"Key": "Name", "Value": bucket},
                                             {"Key": "Project", "Value": "cfr-s2"}]}])
            state["instance"] = r["Instances"][0]["InstanceId"]

        def terminate():
            ec2.terminate_instances(InstanceIds=[state["instance"]])
            state["terminated"] = True

        plan = [
            ("s3.amazonaws.com", "CreateBucket", create_bucket),
            ("s3.amazonaws.com", "PutBucketVersioning", lambda: s3.put_bucket_versioning(
                Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})),
            ("s3.amazonaws.com", "PutBucketEncryption", lambda: s3.put_bucket_encryption(
                Bucket=bucket, ServerSideEncryptionConfiguration={"Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]})),
            ("s3.amazonaws.com", "PutBucketPublicAccessBlock", lambda: s3.put_public_access_block(
                Bucket=bucket, PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True, "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True, "RestrictPublicBuckets": True})),
            ("s3.amazonaws.com", "PutBucketPolicy", lambda: s3.put_bucket_policy(Bucket=bucket, Policy=policy)),
            ("s3.amazonaws.com", "GetBucketPolicy", lambda: s3.get_bucket_policy(Bucket=bucket)),
            ("ec2.amazonaws.com", "RunInstances", run_instance),
            ("ec2.amazonaws.com", "DescribeInstances", lambda: retry(
                lambda: ec2.describe_instances(InstanceIds=[state["instance"]]))),
            ("ec2.amazonaws.com", "CreateTags", lambda: retry(
                lambda: ec2.create_tags(Resources=[state["instance"]], Tags=[{"Key": "Stage", "Value": "checked"}]))),
            ("ec2.amazonaws.com", "TerminateInstances", terminate),
            ("s3.amazonaws.com", "DeleteBucketPolicy", lambda: s3.delete_bucket_policy(Bucket=bucket)),
            ("s3.amazonaws.com", "DeleteBucket", lambda: s3.delete_bucket(Bucket=bucket)),
        ]

        failed = False
        for step_no, (src, event_name, call) in enumerate(plan, start=1):
            start = utc_now()
            try:
                call()
                status = "ok"
            except ClientError as err:
                status = "failed: " + err.response["Error"]["Code"]
                failed = True
            result["steps"].append({
                "run_id": run_id, "step": step_no, "event_source": src, "event_name": event_name,
                "actor_alias": "actor-1", "target_alias": bucket, "instance_id": state["instance"],
                "start_utc": start, "end_utc": utc_now(), "mandatory": True, "status": status})
            print(run_id, step_no, event_name, status)
            if failed:
                break
            if step_no < len(plan) and rng.random() < 0.5:
                nsrc, nname, noise_call = rng.choice(noise_pool)
                try:
                    noise_call()
                except ClientError:
                    pass
                result["noise"].append({"event_source": nsrc, "event_name": nname, "time_utc": utc_now()})
            time.sleep(args.pause)

        # Safety cleanup: never leave a VM or bucket behind, whatever happened.
        if state["instance"] and not state["terminated"]:
            try:
                ec2.terminate_instances(InstanceIds=[state["instance"]])
            except ClientError:
                pass
        if failed and state["bucket"]:
            for cleanup in (lambda: s3.delete_bucket_policy(Bucket=bucket),
                            lambda: s3.delete_bucket(Bucket=bucket)):
                try:
                    cleanup()
                except ClientError:
                    pass
            print("Cleanup attempted for", bucket)
        out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")

    result["finished_utc"] = utc_now()
    out_file.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("Ground truth saved to", out_file)

    left = ec2.describe_instances(Filters=[
        {"Name": "tag:Project", "Values": ["cfr-s2"]},
        {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]}])
    alive = [i["InstanceId"] for r in left["Reservations"] for i in r["Instances"]]
    print("VMs still alive (must be empty):", alive)


if __name__ == "__main__":
    main()
