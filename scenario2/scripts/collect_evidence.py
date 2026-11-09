"""Collect CloudTrail evidence for one collection: download, hash, write manifest."""
import argparse
import hashlib
import json
import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3

ap = argparse.ArgumentParser()
ap.add_argument("--collection-id", required=True)
ap.add_argument("--bucket", required=True)
args = ap.parse_args()

gt = json.loads(Path(f"data/ground_truth/{args.collection_id}.json").read_text(encoding="utf-8"))
since = datetime.fromisoformat(gt["started_utc"]) - timedelta(minutes=2)
out_dir = Path("data/raw") / args.collection_id
out_dir.mkdir(parents=True, exist_ok=True)

s3 = boto3.client("s3", region_name="us-east-1")
objects = []
for page in s3.get_paginator("list_objects_v2").paginate(Bucket=args.bucket, Prefix="AWSLogs/"):
    for o in page.get("Contents", []):
        if o["LastModified"] >= since:
            body = s3.get_object(Bucket=args.bucket, Key=o["Key"])["Body"].read()
            dest = out_dir / o["Key"]
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(body)
            os.chmod(dest, stat.S_IREAD)
            objects.append({
                "key": o["Key"],
                "size": len(body),
                "sha256": hashlib.sha256(body).hexdigest(),
                "s3_last_modified": o["LastModified"].isoformat(),
                "kind": "digest" if "CloudTrail-Digest" in o["Key"] else "log",
            })

manifest = {
    "collection_id": args.collection_id,
    "bucket": args.bucket,
    "region": "us-east-1",
    "downloaded_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    "objects_since_utc": since.isoformat(),
    "object_count": len(objects),
    "objects": objects,
}
(out_dir / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
print(len(objects), "objects saved to", out_dir)
print("logs:", sum(o["kind"] == "log" for o in objects), "digests:", sum(o["kind"] == "digest" for o in objects))
