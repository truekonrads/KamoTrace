"""Reviewable identity-policy templates for the read-only AWS checks and collection."""
import argparse
import json
from pathlib import Path
import re
import sys

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError


TRAIL_ACTIONS = [
    "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:GetEventSelectors",
    "cloudtrail:GetInsightSelectors", "cloudtrail:LookupEvents", "s3:ListAllMyBuckets",
]
SSM_ACTIONS = [
    "ssm:GetDocument", "ssm:ListDocuments", "ssm:DescribeSessions", "ssm:ListCommands",
    "ssm:ListAssociations", "ssm:DescribeAssociation", "ssm:DescribeMaintenanceWindows",
    "ssm:DescribeMaintenanceWindowTasks", "ssm:GetMaintenanceWindowTask",
    "ssm:ListCommandInvocations", "ssm:GetCommandInvocation",
]
BUCKET_ACTIONS = [
    "s3:GetBucketLocation", "s3:ListBucket", "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketPolicyStatus", "s3:GetBucketPolicy", "s3:GetEncryptionConfiguration",
    "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration", "s3:GetLifecycleConfiguration",
]
INVENTORY_ACTIONS = [
    "sts:GetCallerIdentity", "ec2:DescribeRegions", "ec2:DescribeVpcs", "ec2:DescribeSubnets",
    "ec2:DescribeInstances", "ec2:DescribeNetworkInterfaces", "ec2:DescribeSecurityGroups",
    "ec2:DescribeRouteTables", "ec2:DescribeInternetGateways", "ec2:DescribeNetworkAcls",
    "ec2:GetManagedPrefixListEntries", "rds:DescribeDBInstances", "rds:DescribeDBClusters",
    "elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeListeners",
    "elasticloadbalancing:DescribeRules", "elasticloadbalancing:DescribeLoadBalancerAttributes",
    "elasticloadbalancing:DescribeTags", "elasticloadbalancing:DescribeTargetGroups",
    "elasticloadbalancing:DescribeTargetHealth", "elasticloadbalancing:DescribeTargetGroupAttributes",
    "iam:GetInstanceProfile",
]


def arguments(parser):
    parser.add_argument("--emit-policy", metavar="PATH", help="Write a proposed read-only AWS IAM policy to a new "
                        "file, or - for stdout (summary goes to stderr); review placeholders before use")


def validate(parser, args):
    if not args.emit_policy:
        return
    report_path = getattr(args, "json", None)
    if args.emit_policy == "-" and report_path == "-":
        parser.error("--emit-policy - and --json - cannot share stdout")
    if args.emit_policy != "-":
        target = Path(args.emit_policy)
        if target.exists():
            parser.error(f"{target} exists; choose a new policy path")
        if report_path and report_path != "-" and target.resolve() == Path(report_path).resolve():
            parser.error("policy and report paths must differ")


def policy(report):
    if report["tool"] == "inventory":
        return {"Version": "2012-10-17", "Statement": [{"Sid": "ReadInventory", "Effect": "Allow",
                "Action": INVENTORY_ACTIONS, "Resource": "*"}]}
    trail = report["tool"] == "trailcheck"
    partition = report["partition"]
    buckets, keys, groups = set(), set(), set()
    if trail:
        buckets.update(item["s3_bucket"] for item in report["trails"] if item.get("s3_bucket"))
        buckets.update(report["other_buckets"]["with_cloudtrail"])
        for item in report["trails"]:
            if str(item.get("kms_key_id", "")).startswith(f"arn:{partition}:kms:"):
                keys.add(item["kms_key_id"])
        for bucket in report["buckets"]:
            if bucket["bucket"] not in buckets:
                continue
            for rule in bucket.get("encryption", {}).get("rules", []):
                key = rule.get("KMSMasterKeyID", "")
                if key.startswith(f"arn:{partition}:kms:"):
                    keys.add(key)
    else:
        def destinations(value, region):
            if isinstance(value, list):
                for item in value:
                    destinations(item, region)
            elif isinstance(value, dict):
                s3 = value.get("s3") or {}
                bucket = value.get("s3_bucket") or s3.get("bucket")
                if bucket:
                    buckets.add(bucket)
                group = value.get("cloudwatch_log_group") or (value.get("cloudwatch") or {}).get("log_group")
                if group:
                    groups.add(f"arn:{partition}:logs:{region}:{report['account_id']}:log-group:{group}:*")
                for item in value.values():
                    destinations(item, region)
        for result in report["results"]:
            destinations(result, result["region"])
    # Neither check can discover every historical destination or object encryption key.
    if not buckets or not report["complete"]:
        buckets.add("REPLACE_WITH_ADDITIONAL_CLOUDTRAIL_BUCKET" if trail else "REPLACE_WITH_ADDITIONAL_SSM_BUCKET")
    keys.add(f"arn:{partition}:kms:REPLACE_WITH_REGION:REPLACE_WITH_KEY_ACCOUNT_ID:key/REPLACE_WITH_S3_KMS_KEY_ID")
    statements = [{"Sid": "DiscoveryAndHistory", "Effect": "Allow", "Action": [
        "sts:GetCallerIdentity", "ec2:DescribeRegions", *(TRAIL_ACTIONS if trail else SSM_ACTIONS)], "Resource": "*"},
        {"Sid": "LogBuckets", "Effect": "Allow", "Action": BUCKET_ACTIONS if trail else
         ["s3:GetBucketLocation", "s3:ListBucket"],
         "Resource": [f"arn:{partition}:s3:::{bucket}" for bucket in sorted(buckets)]},
        {"Sid": "DownloadLogObjects", "Effect": "Allow", "Action": ["s3:GetObject"],
         "Resource": [f"arn:{partition}:s3:::{bucket}/*" for bucket in sorted(buckets)]},
        {"Sid": "DecryptS3Logs", "Effect": "Allow", "Action": ["kms:Decrypt"], "Resource": sorted(keys)}]
    if not trail:
        if not groups or not report["complete"]:
            groups.add(f"arn:{partition}:logs:REPLACE_WITH_REGION:REPLACE_WITH_LOG_ACCOUNT_ID:"
                       "log-group:REPLACE_WITH_SSM_LOG_GROUP:*")
        statements.append({"Sid": "ReadSSMCloudWatchOutput", "Effect": "Allow", "Action": ["logs:FilterLogEvents"],
                           "Resource": sorted(groups)})
    return {"Version": "2012-10-17", "Statement": statements}


def emit(report, path):
    if not path:
        return
    document = json.dumps(policy(report), indent=2) + "\n"
    if path == "-":
        sys.stdout.write(document)
    else:
        with open(path, "x", encoding="utf-8") as output:
            output.write(document)
    if report["tool"] == "inventory":
        print("Inventory policy template only: review resource scope before use. "
              "This is not an effective-permissions test; explicit denies still apply.", file=sys.stderr)
        return
    print("Policy template only: review bucket-wide reads and replace/remove REPLACE_WITH placeholders. "
          "Discovery may be denied, truncated or omit historical destinations/keys; add those explicitly. "
          "This is not an effective-permissions test or an exact missing-permissions diff. "
          "Cross-account bucket/KMS key policies and explicit denies still apply. "
          "No log objects were read to generate it.", file=sys.stderr)


def combined(partition, buckets, keys, no_kms):
    buckets = sorted(set(buckets or ["REPLACE_WITH_CLOUDTRAIL_BUCKET", "REPLACE_WITH_SSM_BUCKET"]))
    statements = [
        {"Sid": "AuditAndCollectMetadata", "Effect": "Allow", "Action": sorted(set(
            TRAIL_ACTIONS + SSM_ACTIONS + INVENTORY_ACTIONS)), "Resource": "*"},
        {"Sid": "AuditAndListLogBuckets", "Effect": "Allow", "Action": BUCKET_ACTIONS,
         "Resource": [f"arn:{partition}:s3:::{bucket}" for bucket in buckets]},
        {"Sid": "DownloadLogObjects", "Effect": "Allow", "Action": ["s3:GetObject"],
         "Resource": [f"arn:{partition}:s3:::{bucket}/*" for bucket in buckets]},
        {"Sid": "ReadCloudWatchOutput", "Effect": "Allow", "Action": ["logs:FilterLogEvents"], "Resource": "*"},
    ]
    if not no_kms:
        statements.append({"Sid": "DecryptS3Logs", "Effect": "Allow", "Action": ["kms:Decrypt"],
                           "Resource": sorted(set(keys or [f"arn:{partition}:kms:REPLACE_WITH_REGION:"
                               "REPLACE_WITH_KEY_ACCOUNT_ID:key/REPLACE_WITH_S3_KMS_KEY_ID"]))})
    return {"Version": "2012-10-17", "Statement": statements}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace policy", description=
        "Generate one read-only collection policy for CloudTrail, SSM and inventory without AWS calls. "
        "Optional --validate uses IAM Access Analyzer; it does not test effective access or grant permissions.",
        epilog="Exit status: 0 generated (validation, if requested, has no findings), "
               "1 validation findings or unresolved placeholders, 2 usage, file or AWS failure.")
    parser.add_argument("--output", default="-", metavar="PATH", help="New policy file, or - for stdout (default)")
    parser.add_argument("--bucket", action="append", default=[], metavar="NAME",
                        help="CloudTrail or SSM bucket name; repeat for all current/historical destinations")
    kms = parser.add_mutually_exclusive_group()
    kms.add_argument("--kms-key", action="append", default=[], metavar="ARN", help="S3 encryption key ARN; repeat for old keys too")
    kms.add_argument("--no-kms", action="store_true", help="Omit decryption only if none of the required S3 objects use SSE-KMS")
    parser.add_argument("--partition", choices=["aws", "aws-us-gov", "aws-cn"], default="aws")
    validation = parser.add_mutually_exclusive_group()
    validation.add_argument("--validate", action="store_true", help="Check generated policy with IAM Access Analyzer (requires AWS login)")
    validation.add_argument("--validate-file", type=Path, metavar="PATH",
                            help="Validate an existing policy, without generating or overwriting anything")
    parser.add_argument("--profile", help="Existing AWS profile for validation only")
    parser.add_argument("--region", help="AWS Region for validation; otherwise use SDK configuration")
    args = parser.parse_args(argv)
    if args.validate_file and (args.bucket or args.kms_key or args.no_kms or args.partition != "aws" or args.output != "-"):
        parser.error("--validate-file cannot be combined with generation options")
    for bucket in args.bucket:
        if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket) or ".." in bucket:
            parser.error("--bucket must be an S3 bucket name, not a URL, ARN, prefix or wildcard")
    for key in args.kms_key:
        if not re.fullmatch(rf"arn:{args.partition}:kms:[a-z0-9-]+:\d{{12}}:key/[A-Za-z0-9-]+", key):
            parser.error("--kms-key must be a full KMS key ARN in the selected partition, without wildcards")
    document = json.dumps(combined(args.partition, args.bucket, args.kms_key, args.no_kms), indent=2) + "\n"
    try:
        if args.validate_file:
            document = args.validate_file.read_text(encoding="utf-8")
        else:
            if args.output == "-":
                sys.stdout.write(document)
            else:
                with open(args.output, "x", encoding="utf-8") as output:
                    output.write(document)
            print("Combined policy: review bucket-wide object reads and wildcard metadata/CloudWatch scope. "
                  "Replace placeholders and include historical buckets/keys. No AWS permissions were changed. "
                  "Validation does not prove effective access; cross-account policies and explicit denies still apply.",
                  file=sys.stderr)
        if not args.validate and not args.validate_file:
            return 0
        if "REPLACE_WITH_" in document:
            print("Policy not validated: resolve REPLACE_WITH placeholders; for generation, supply --bucket "
                  "and --kms-key (or --no-kms).", file=sys.stderr)
            return 1
        client = boto3.Session(profile_name=args.profile).client("accessanalyzer", region_name=args.region,
            config=Config(retries={"mode": "standard", "max_attempts": 4}, connect_timeout=15, read_timeout=60))
        findings = 0
        for page in client.get_paginator("validate_policy").paginate(policyDocument=document, policyType="IDENTITY_POLICY"):
            for finding in page["findings"]:
                findings += 1
                print(f"{finding['findingType']} {finding['issueCode']}: {finding['findingDetails']}", file=sys.stderr)
        print(f"IAM Access Analyzer: {findings} finding(s). This checks policy syntax/security, not effective access.",
              file=sys.stderr)
        return 1 if findings else 0
    except (OSError, BotoCoreError, ClientError) as error:
        code = error.response.get("Error", {}).get("Code", "Unknown") if isinstance(error, ClientError) else type(error).__name__
        print(f"kamotrace policy: generation or validation failed ({code}); validation is not confirmed", file=sys.stderr)
        return 2
