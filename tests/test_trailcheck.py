"""Public trailcheck CLI contracts against synthetic AWS responses validated by botocore models (no AWS access)."""
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import re
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from boto3.session import Session
from botocore.exceptions import ClientError, NoCredentialsError
from botocore.validate import ParamValidator, validate_parameters

from kamotrace.cli import main

ACCOUNT, OTHER = "111122223333", "444455556666"
MAIN = f"arn:aws:cloudtrail:us-east-1:{ACCOUNT}:trail/main"
APAC = f"arn:aws:cloudtrail:ap-southeast-1:{ACCOUNT}:trail/apac"
WHEN = datetime(2026, 10, 30, 12, 0, tzinfo=timezone.utc)
MODELS = {}


def model(service):
    if service not in MODELS:
        sdk = Session(aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name="us-east-1")
        MODELS[service] = sdk.client(service).meta.service_model
    return MODELS[service]


def fail(code, operation="Synthetic"):
    # AWS messages can include ARNs; the report must carry codes only.
    raise ClientError({"Error": {"Code": code, "Message": f"User: arn:aws:sts::{ACCOUNT}:assumed-role/secret-role "
                                                          "is not authorized"}}, operation)


def log_key(prefix, account, region, day, name=None):
    year, month, dom = day.split("-")
    return (f"{prefix}AWSLogs/{account}/CloudTrail/{region}/{year}/{month}/{dom}/"
            + (name or f"{account}_CloudTrail_{region}_{year}{month}{dom}T0005Z_a1B2c3.json.gz"))


class FakeAWS:
    """Thread-safe and order-independent, unlike Stubber; every request and response is model-validated."""
    def __init__(self, routes, objects):
        self.routes, self.objects, self.calls = routes, objects, []
        self.lock = threading.Lock()

    def client(self, service, region_name, **_):
        def caller(operation):
            def call(**params):
                operation_model = model(service).operation_model(
                    "".join(part.title() for part in operation.split("_")))
                validate_parameters(params, operation_model.input_shape)
                with self.lock:
                    self.calls.append((service, region_name, operation, params))
                if (service, operation) == ("s3", "list_objects_v2") and (service, operation) not in self.routes:
                    response = self.list_objects(**params)
                else:
                    response = self.routes[service, operation](region_name, **params)
                report = ParamValidator().validate(response, operation_model.output_shape)
                assert not report.has_errors(), report.generate_report()
                return dict(response)
            return call

        class Client:
            def __getattr__(self, operation):
                return caller(operation)
        return Client()

    def list_objects(self, Bucket, Prefix="", Delimiter=None, MaxKeys=1000, ContinuationToken=None):
        if Bucket not in self.objects:
            fail("AccessDenied", "ListObjectsV2")
        entries, seen = [], set()
        for key in sorted(self.objects[Bucket]):
            if not key.startswith(Prefix):
                continue
            rest = key[len(Prefix):]
            if Delimiter and Delimiter in rest:
                child = Prefix + rest.split(Delimiter)[0] + Delimiter
                if child not in seen:
                    seen.add(child)
                    entries.append(("prefix", child))
            else:
                entries.append(("key", key))
        start = int(ContinuationToken or 0)
        page = entries[start:start + MaxKeys]
        response = {"Name": Bucket, "Prefix": Prefix, "MaxKeys": MaxKeys, "KeyCount": len(page),
                    "IsTruncated": start + MaxKeys < len(entries),
                    "CommonPrefixes": [{"Prefix": value} for kind, value in page if kind == "prefix"],
                    "Contents": [{"Key": value, "Size": 0 if value.endswith("empty.json.gz") else 2048,
                                  "LastModified": WHEN} for kind, value in page if kind == "key"]}
        if response["IsTruncated"]:
            response["NextContinuationToken"] = str(start + MaxKeys)
        return response

    def operations(self):
        return {operation for _, _, operation, _ in self.calls}


def trail(name, home, multi, bucket, prefix=None, insights=False):
    item = {"Name": name, "TrailARN": f"arn:aws:cloudtrail:{home}:{ACCOUNT}:trail/{name}", "HomeRegion": home,
            "IsMultiRegionTrail": multi, "IsOrganizationTrail": False, "IncludeGlobalServiceEvents": multi,
            "S3BucketName": bucket, "LogFileValidationEnabled": multi, "HasInsightSelectors": insights,
            "HasCustomEventSelectors": True}
    if prefix:
        item["S3KeyPrefix"] = prefix
    if multi:
        item["KmsKeyId"] = f"arn:aws:kms:us-east-1:{ACCOUNT}:key/synthetic"
    return item


def bucket_routes(readable, location="eu-west-1"):
    """Read-only bucket settings; buckets outside readable are denied, as for another account's bucket."""
    def guarded(build):
        def handler(region, Bucket, **_):
            if Bucket not in readable:
                fail("AccessDenied")
            return build(Bucket)
        return handler

    def policy_document(bucket):
        return json.dumps({"Version": "2012-10-17", "Statement": [
            {"Sid": "AWSCloudTrailWrite", "Effect": "Allow", "Principal": {"Service": "cloudtrail.amazonaws.com"},
             "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket}/audit/AWSLogs/{ACCOUNT}/*",
             "Condition": {"StringEquals": {"aws:SourceArn": MAIN, "s3:x-amz-acl": "bucket-owner-full-control"}}},
            {"Sid": "DenyInsecure", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
             "Resource": f"arn:aws:s3:::{bucket}/*", "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]})

    def settings(bucket):
        return readable[bucket]

    return {
        ("s3", "get_bucket_location"): guarded(lambda b: {"LocationConstraint": settings(b).get("location", location)}),
        ("s3", "get_public_access_block"): guarded(lambda b: settings(b).get("pab") or fail(
            "NoSuchPublicAccessBlockConfiguration")),
        ("s3", "get_bucket_policy_status"): guarded(lambda b: {"PolicyStatus": {"IsPublic": False}}
                                                    if settings(b).get("policy") else fail("NoSuchBucketPolicy")),
        ("s3", "get_bucket_policy"): guarded(lambda b: {"Policy": policy_document(b)} if settings(b).get("policy")
                                             else fail("NoSuchBucketPolicy")),
        ("s3", "get_bucket_encryption"): guarded(lambda b: settings(b).get("encryption") or fail(
            "ServerSideEncryptionConfigurationNotFoundError")),
        ("s3", "get_bucket_versioning"): guarded(lambda b: settings(b).get("versioning", {})),
        ("s3", "get_object_lock_configuration"): guarded(lambda b: fail("ObjectLockConfigurationNotFoundError")),
        ("s3", "get_bucket_lifecycle_configuration"): guarded(lambda b: settings(b).get("lifecycle") or fail(
            "NoSuchLifecycleConfiguration")),
    }


class TrailcheckContract(unittest.TestCase):
    def setUp(self):
        self.folder = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def run_cli(self, aws, *options, status):
        session = Mock(region_name="us-east-1")
        session.client.side_effect = aws.client
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch("kamotrace.trailcheck.boto3.Session", return_value=session), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(["trailcheck", *options])
        self.assertEqual(result, status, stderr.getvalue())
        # Only Describe/Get/List APIs, never a write; no log object is downloaded.
        self.assertTrue(all(re.match(r"(describe|get|list)_", operation) for operation in aws.operations()),
                        aws.operations())
        self.assertNotIn("get_object", aws.operations())
        return stdout.getvalue(), stderr.getvalue()

    def scenario(self):
        """Asymmetric account: a multi-Region trail, a stopped single-Region trail to a denied bucket,
        a denied Region, two accounts in one bucket, month gaps and an unverifiable latest day."""
        main_trail = trail("main", "us-east-1", True, "synthetic-trail-logs", "audit/", insights=True)
        apac = trail("apac", "ap-southeast-1", False, "synthetic-denied-bucket")
        trails = {"us-east-1": [main_trail], "ap-southeast-1": [main_trail, apac], "eu-west-1": [main_trail]}

        def describe_trails(region, includeShadowTrails):
            self.assertTrue(includeShadowTrails)
            if region == "ca-central-1":
                fail("AccessDeniedException", "DescribeTrails")
            return {"trailList": trails[region]}

        def status(region, Name):
            self.assertEqual(region, Name.split(":")[3])  # Asked in the trail's home Region.
            if Name == MAIN:
                return {"IsLogging": True, "StartLoggingTime": datetime(2023, 1, 1, tzinfo=timezone.utc),
                        "LatestDeliveryTime": WHEN}
            return {"IsLogging": False, "StopLoggingTime": datetime(2025, 3, 9, 1, tzinfo=timezone.utc),
                    "LatestDeliveryError": "AccessDenied"}

        def event_selectors(region, TrailName):
            if TrailName == MAIN:
                return {"TrailARN": MAIN, "AdvancedEventSelectors": [
                    {"Name": "Management without KMS", "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Management"]},
                        {"Field": "eventSource", "NotEquals": ["kms.amazonaws.com"]}]},
                    {"Name": "S3 writes", "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Data"]},
                        {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                        {"Field": "readOnly", "Equals": ["false"]}]}]}
            return {"TrailARN": APAC, "EventSelectors": [{
                "ReadWriteType": "WriteOnly", "IncludeManagementEvents": True,
                "ExcludeManagementEventSources": ["rdsdata.amazonaws.com"],
                "DataResources": [{"Type": "AWS::Lambda::Function", "Values": ["arn:aws:lambda"]}]}]}

        prefix = "audit/"
        objects = {"synthetic-trail-logs": [
            log_key(prefix, ACCOUNT, "us-east-1", "2024-11-30"),
            log_key(prefix, ACCOUNT, "us-east-1", "2024-11-05"),
            log_key(prefix, ACCOUNT, "us-east-1", "2024-12-15"),
            log_key(prefix, ACCOUNT, "us-east-1", "2025-01-02"),
            log_key(prefix, ACCOUNT, "us-east-1", "2025-03-01", "notes.txt"),
            f"{prefix}AWSLogs/{ACCOUNT}/CloudTrail/us-east-1/backup/old.json.gz",
            log_key(prefix, ACCOUNT, "ap-southeast-1", "2025-03-09"),
            f"{prefix}AWSLogs/{ACCOUNT}/CloudTrail-Digest/us-east-1/2024/11/05/digest.json.gz",
            log_key(prefix, OTHER, "us-east-1", "2023-01-01")]}
        routes = {
            ("sts", "get_caller_identity"): lambda region: {
                "Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/reader/synthetic", "UserId": "x"},
            ("ec2", "describe_regions"): lambda region, AllRegions: {"Regions": [
                {"RegionName": name} for name in ("us-east-1", "eu-west-1", "ap-southeast-1", "ca-central-1")]},
            ("cloudtrail", "describe_trails"): describe_trails,
            ("cloudtrail", "get_trail_status"): status,
            ("cloudtrail", "get_event_selectors"): event_selectors,
            ("cloudtrail", "get_insight_selectors"): lambda region, TrailName: {
                "TrailARN": TrailName, "InsightSelectors": [{"InsightType": "ApiCallRateInsight"}]},
            ("s3", "list_buckets"): lambda region, **_: {"Buckets": [
                {"Name": "synthetic-trail-logs", "BucketRegion": "eu-west-1"},
                {"Name": "synthetic-old-trail", "BucketRegion": "ap-southeast-1"},
                {"Name": "synthetic-unrelated", "BucketRegion": "us-east-1"}]},
            **bucket_routes({"synthetic-trail-logs": {
                "pab": {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                                           "BlockPublicPolicy": True, "RestrictPublicBuckets": True}},
                "policy": True, "versioning": {"Status": "Enabled"},
                "encryption": {"ServerSideEncryptionConfiguration": {"Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "aws:kms"}}]}},
                "lifecycle": {"Rules": [{"ID": "retain", "Status": "Enabled", "Filter": {"Prefix": "audit/"},
                                         "Expiration": {"Days": 400},
                                         "Transitions": [{"Days": 90, "StorageClass": "GLACIER"}]}]}}})}
        return FakeAWS(routes, objects)

    def test_reports_configuration_observed_prefixes_verified_days_and_unknowns(self):
        aws = self.scenario()
        stdout, stderr = self.run_cli(aws, "--json", "-", status=1)
        report = json.loads(stdout)
        self.assertEqual((report["tool"], report["version"], report["account_id"], report["partition"]),
                         ("trailcheck", 1, ACCOUNT, "aws"))
        self.assertFalse(report["complete"])

        scope = {entry["region"]: entry for entry in report["region_scope"]}
        self.assertEqual((scope["us-east-1"]["state"], scope["us-east-1"]["logging"]), ("configured", "on"))
        self.assertEqual(scope["ap-southeast-1"]["logging_trails"], ["main"])  # apac is stopped.
        # Denied is unknown, never "no trail".
        self.assertEqual((scope["ca-central-1"]["state"], scope["ca-central-1"]["logging"]), ("denied", "unknown"))
        self.assertEqual(report["unknown_regions"], ["ca-central-1"])

        trails = {item["name"]: item for item in report["trails"]}
        main_trail, apac = trails["main"], trails["apac"]
        self.assertEqual(sorted(main_trail["applies_in"]), ["ap-southeast-1", "eu-west-1", "us-east-1"])
        self.assertTrue(main_trail["multi_region"])
        self.assertEqual(main_trail["status"]["state"], "configured")
        self.assertEqual(main_trail["event_selectors"]["kind"], "advanced")
        self.assertIn("eventSource NotEquals kms.amazonaws.com", main_trail["event_selectors"]["summary"][0])
        self.assertEqual(main_trail["insight_selectors"]["types"], ["ApiCallRateInsight"])
        # Configured scope vs observed current-account prefixes: eu-west-1 is configured but has none.
        self.assertEqual(main_trail["s3_regions_observed"], ["ap-southeast-1", "us-east-1"])
        self.assertEqual(main_trail["configured_regions_without_prefix"], ["eu-west-1"])
        self.assertFalse(apac["status"]["IsLogging"])
        self.assertEqual(apac["status"]["LatestDeliveryError"], "AccessDenied")
        self.assertEqual(apac["event_selectors"]["summary"],
                         ["management WriteOnly; excluding rdsdata.amazonaws.com; "
                          "data AWS::Lambda::Function (1 values: arn:aws:lambda)"])
        self.assertEqual(apac["insight_selectors"]["state"], "not_configured")
        self.assertIsNone(apac["configured_regions_without_prefix"])  # Unknown, not "none missing".

        buckets = {item["bucket"]: item for item in report["buckets"]}
        logs = buckets["synthetic-trail-logs"]
        self.assertEqual((logs["region"], logs["coverage"], logs["destination_of"]),
                         ("eu-west-1", "complete", ["main"]))
        self.assertEqual(logs["public_access_block"]["state"], "configured")
        self.assertEqual(logs["policy"]["cloudtrail_put_object"], "configured")
        self.assertEqual(logs["policy"]["deny_statements"], 1)
        self.assertEqual(logs["policy"]["cloudtrail_writes"][0]["condition"]["StringEquals"]["aws:SourceArn"], MAIN)
        self.assertEqual(logs["object_lock"]["state"], "not_configured")
        self.assertEqual(logs["lifecycle"]["rules"][0]["expiration_days"], 400)
        # Once located, S3 calls go to the bucket's own Region, not the trail's.
        self.assertEqual({region for service, region, operation, params in aws.calls
                          if params.get("Bucket") == "synthetic-trail-logs" and operation != "get_bucket_location"},
                         {"eu-west-1"})

        accounts = logs["locations"][0]["accounts"]
        self.assertEqual([item["account_id"] for item in accounts], [ACCOUNT, OTHER])  # Current account first.
        self.assertEqual(set(accounts[0]["services"]), {"CloudTrail", "CloudTrail-Digest"})
        regions = {item["region"]: item for item in accounts[0]["regions"]}
        east = regions["us-east-1"]
        self.assertEqual(east["months"], ["2024-11", "2024-12", "2025-01", "2025-03"])
        self.assertEqual(east["missing_months"], ["2025-02"])
        self.assertEqual((east["first_day"], east["last_day"]), ("2024-11-05", "2025-03-01"))
        self.assertEqual([(item["date"], item["verification"]) for item in east["verified"]],
                         [("2024-11-05", "verified"), ("2025-03-01", "not_verified")])
        self.assertEqual(east["unexpected_prefixes"], [f"audit/AWSLogs/{ACCOUNT}/CloudTrail/us-east-1/backup/"])
        apac_region = regions["ap-southeast-1"]
        self.assertEqual((apac_region["first_day"], apac_region["last_day"]), ("2025-03-09", "2025-03-09"))
        self.assertEqual(len(apac_region["verified"]), 1)
        self.assertEqual(accounts[1]["regions"][0]["months"], ["2023-01"])

        denied = buckets["synthetic-denied-bucket"]
        self.assertEqual((denied["state"], denied["exists"], denied["coverage"]), ("denied", None, "unknown"))
        self.assertEqual(denied["versioning"]["state"], "denied")  # Not "never enabled".
        self.assertFalse(denied["in_account_bucket_list"])
        self.assertEqual(report["other_buckets"], {"listing": "complete", "count": 2, "probed": False,
                                                   "with_awslogs": [], "with_cloudtrail": [], "probe_unknown": []})
        self.assertEqual(report["truncated"], [])
        errors = {(item["api"], item["region"], item["code"]) for item in report["errors"]}
        self.assertIn(("cloudtrail:DescribeTrails", "ca-central-1", "AccessDeniedException"), errors)
        self.assertIn(("s3:ListObjectsV2", "ap-southeast-1", "AccessDenied"), errors)
        self.assertNotIn("secret-role", stdout + stderr)  # AWS error messages are not repeated.

        text = stderr  # With --json -, the readable summary goes to stderr.
        self.assertIn("Result: PARTIAL", text)
        self.assertRegex(text, r"ca-central-1\s+UNKNOWN \(denied\)")
        self.assertIn("missing months 2025-02", text)
        self.assertIn("2024-11-05 verified; 2025-03-01 not_verified", text)
        self.assertIn("Configured Regions with no observed S3 prefix: eu-west-1", text)
        self.assertIn("versioning UNKNOWN (denied)", text)
        self.assertIn("prefixes are not proof of complete logs", text)

    def test_listing_bounds_are_explicitly_partial(self):
        for options, reason in (([ "--max-s3-calls", "4"], "--max-s3-calls reached"),
                                (["--max-items", "1"], "--max-items reached")):
            with self.subTest(options=options):
                aws = self.scenario()
                stdout, _ = self.run_cli(aws, "--json", "-", *options, status=1)
                report = json.loads(stdout)
                logs = next(item for item in report["buckets"] if item["bucket"] == "synthetic-trail-logs")
                self.assertEqual(logs["coverage"], "partial")
                reasons = json.dumps(logs["locations"])
                self.assertIn(reason, reasons)
                # Bounded scans withhold scope comparisons and gaps rather than guessing.
                self.assertIsNone(next(t for t in report["trails"] if t["name"] == "main")[
                    "configured_regions_without_prefix"])
                limit = options[0][2:].replace("-", "_")
                self.assertTrue(report["truncated"])
                self.assertTrue(all(item[limit] == int(options[1]) and item["section"].startswith("s3://")
                                    for item in report["truncated"]), report["truncated"])
                if options[0] == "--max-s3-calls":
                    self.assertEqual(report["s3_list_calls"], 4)
                    self.assertEqual(sum(operation == "list_objects_v2" for _, _, operation, _ in aws.calls), 4)

    def test_complete_report_file_and_probe_of_former_trail_bucket(self):
        current = trail("current", "us-east-1", False, "synthetic-current")
        objects = {"synthetic-current": [log_key("", ACCOUNT, "us-east-1", "2026-10-30")],
                   "synthetic-old-trail": [log_key("", ACCOUNT, "eu-west-1", "2022-06-01",
                                                   f"{ACCOUNT}_CloudTrail_eu-west-1_20220601T0000Z_empty.json.gz"),
                                           log_key("", ACCOUNT, "eu-west-1", "2022-06-02")],
                   # AWSLogs/ of another service is not CloudTrail.
                   "synthetic-flow-logs": [f"AWSLogs/{ACCOUNT}/vpcflowlogs/us-east-1/2026/10/30/flow.log.gz"],
                   "synthetic-unrelated": ["images/cat.png"]}
        routes = {
            ("sts", "get_caller_identity"): lambda region: {
                "Account": ACCOUNT, "Arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/reader/synthetic", "UserId": "x"},
            ("cloudtrail", "describe_trails"): lambda region, includeShadowTrails: {
                "trailList": [current] if region == "us-east-1" else []},
            ("cloudtrail", "get_trail_status"): lambda region, Name: {"IsLogging": True, "LatestDeliveryTime": WHEN},
            ("cloudtrail", "get_event_selectors"): lambda region, TrailName: {"EventSelectors": [
                {"ReadWriteType": "All", "IncludeManagementEvents": True}]},
            ("s3", "list_buckets"): lambda region, **_: {"Buckets": [
                {"Name": name, "BucketRegion": "eu-west-1"} for name in objects]},
            **bucket_routes({name: {} for name in objects}, location="eu-west-1")}
        aws = FakeAWS(routes, objects)
        target = self.folder / "trailcheck.json"
        stdout, stderr = self.run_cli(aws, "--regions", "us-east-1", "eu-west-1", "--probe-buckets",
                                      "--json", str(target), status=0)
        report = json.loads(target.read_text(encoding="utf-8"))
        self.assertTrue(report["complete"], report["errors"])
        self.assertEqual(report["errors"], [])
        scope = {entry["region"]: entry for entry in report["region_scope"]}
        self.assertEqual((scope["eu-west-1"]["state"], scope["eu-west-1"]["logging"]), ("not_configured", None))
        self.assertNotIn("ec2", {service for service, *_ in aws.calls})  # Explicit Regions need no lookup.
        self.assertEqual(report["trails"][0]["configured_regions_without_prefix"], [])
        buckets = {item["bucket"]: item for item in report["buckets"]}
        # Absent settings are answered facts, distinct from denied.
        for setting in ("public_access_block", "policy", "encryption", "versioning", "lifecycle"):
            self.assertEqual(buckets["synthetic-current"][setting]["state"], "not_configured", setting)
        self.assertEqual(report["other_buckets"]["with_awslogs"], ["synthetic-flow-logs", "synthetic-old-trail"])
        self.assertEqual(report["other_buckets"]["with_cloudtrail"], ["synthetic-old-trail"])
        old = buckets["synthetic-old-trail"]
        self.assertEqual(old["destination_of"], [])
        region = old["locations"][0]["accounts"][0]["regions"][0]
        # A zero-byte object does not verify a day; the next day's log does.
        self.assertEqual([(item["date"], item["verification"]) for item in region["verified"]],
                         [("2022-06-01", "not_verified"), ("2022-06-02", "verified")])
        self.assertIn("Result: COMPLETE", stdout)
        self.assertIn("s3://synthetic-old-trail  Region eu-west-1  not a current trail destination; "
                      "AWSLogs/ found by --probe-buckets", stdout)
        self.assertIn("s3://synthetic-flow-logs  AWSLogs/ without CloudTrail/ (found: vpcflowlogs)", stdout)
        self.assertIn("eu-west-1        no trail applies", stdout)
        self.assertNotIn("Result:", stderr)
        # Reports never replace an existing file.
        before = target.read_bytes()
        stdout = io.StringIO()
        with redirect_stderr(stdout), self.assertRaises(SystemExit) as raised:
            main(["trailcheck", "--json", str(target)])
        self.assertEqual(raised.exception.code, 2)
        self.assertEqual(target.read_bytes(), before)

    def test_login_failure_stops_without_report(self):
        def identity(region):
            raise NoCredentialsError()
        aws = FakeAWS({("sts", "get_caller_identity"): identity}, {})
        stdout, stderr = self.run_cli(aws, status=2)
        self.assertEqual(stdout, "")
        self.assertIn("AWS login check failed (NoCredentialsError)", stderr)
        self.assertEqual(aws.operations(), {"get_caller_identity"})


if __name__ == "__main__":
    unittest.main()
