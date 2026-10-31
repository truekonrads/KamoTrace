"""Read-only CloudTrail trail audit: configuration, logging/delivery state, S3 destinations and observed log dates.

Uses the SDK's existing credential chain. Only Describe/Get/List calls are made; log objects are
listed, never downloaded. Denied or failed checks are reported as unknown, never as absent.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
from datetime import date, datetime, timezone
import json
from pathlib import Path
import re
import sys
import threading

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

VERSION = 1
WORKERS = 8  # Concurrent read-only calls across Regions, trails and S3 Region prefixes.
DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedAccess",
          "AuthorizationError", "AllAccessDisabled", "InvalidAccessKeyId", "ExpiredToken", "OptInRequired"}
# The service answered: the setting or resource does not exist. This is a fact, not an unknown.
ABSENT = {"NoSuchBucketPolicy", "NoSuchLifecycleConfiguration", "ServerSideEncryptionConfigurationNotFoundError",
          "NoSuchPublicAccessBlockConfiguration", "ObjectLockConfigurationNotFoundError",
          "InsightNotEnabledException", "NoSuchBucket"}
LOG_NAME = re.compile(r"^(\d{12})_CloudTrail_([a-z0-9-]+)_(\d{8})T\d{4}Z_[A-Za-z0-9]+\.json\.gz$")
LIMITATIONS = [
    "Configured scope is the current trail configuration; earlier StopLogging or selector changes appear only "
    "in CloudTrail events, not here.",
    "Observed S3 date prefixes show that objects were listed under a Region/year/month/day path, not that every "
    "hour, event or Region was delivered. Gaps can also come from lifecycle rules, deletion or prefix changes.",
    "Verified days list an object with a CloudTrail log file name, matching account/Region/date and nonzero size. "
    "Object contents are not downloaded, decrypted or digest-validated.",
    "Day prefixes are listed only for the first and last observed month of each Region; other months are "
    "checked at month level.",
    "Denied or failed checks are unknown, not absent. Listings that reach --max-items or --max-s3-calls are partial.",
    "Not checked: CloudTrail Lake event data stores, Event History (90 days), CloudWatch Logs contents, and "
    "custom key prefixes in buckets that are not trail destinations.",
]


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def api(service, operation):
    return f"{service}:{''.join(part.title() for part in operation.split('_'))}"


class Budget(Exception):
    """The --max-s3-calls budget is spent."""


class Check:
    def __init__(self, session, home, max_items, max_s3_calls):
        self.session, self.home = session, home
        self.max_items, self.max_s3_calls = max_items, max_s3_calls
        self.clients, self.errors, self.truncated, self.s3_calls = {}, [], [], 0
        self.lock = threading.Lock()

    def cut(self, region, section, limit, value):
        with self.lock:
            self.truncated.append({"region": region, "section": section, limit: value})

    def client(self, service, region):
        with self.lock:  # Sessions are not thread-safe; the clients they create are.
            if (service, region) not in self.clients:
                self.clients[service, region] = self.session.client(service, region_name=region, config=Config(
                    retries={"mode": "adaptive", "max_attempts": 8}, connect_timeout=15, read_timeout=60))
            return self.clients[service, region]

    def call(self, service, region, operation, resource=None, **params):
        """Return (response, state): configured, not_configured (service says absent), denied or error."""
        if service == "s3" and operation == "list_objects_v2":
            with self.lock:
                if self.s3_calls >= self.max_s3_calls:
                    raise Budget()
                self.s3_calls += 1
        try:
            response = getattr(self.client(service, region), operation)(**params)
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code") or "Unknown"
            if code in ABSENT:
                return None, "not_configured"
            state = "denied" if code in DENIED or code.startswith("AccessDenied") else "error"
            code = str(code)
        except BotoCoreError as error:
            state, code = "error", type(error).__name__
        else:
            response.pop("ResponseMetadata", None)
            return response, "configured"
        # Error code and API only: AWS messages can echo caller ARNs.
        with self.lock:
            self.errors.append({"region": region, "api": api(service, operation), "code": code,
                                "resource": resource, "state": state})
        return None, state

    def pool(self, function, items):
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            return list(pool.map(function, items))

    # Configuration -----------------------------------------------------------------------------

    def regions(self, requested):
        if requested != ["all"]:
            return sorted(set(requested)), None
        response, state = self.call("ec2", self.home, "describe_regions", AllRegions=False)
        if response is None:
            return [self.home], f"enabled Regions {state}; checked only {self.home}"
        return sorted(item["RegionName"] for item in response["Regions"]), None

    def region_trails(self, region):
        response, state = self.call("cloudtrail", region, "describe_trails", includeShadowTrails=True)
        return region, state, (response or {}).get("trailList", [])

    def trail_details(self, trail):
        arn, region = trail["arn"], trail["home_region"]
        status, state = self.call("cloudtrail", region, "get_trail_status", resource=arn, Name=arn)
        trail["status"] = {"state": state, **({key: value for key, value in status.items()} if status else {})}
        response, state = self.call("cloudtrail", region, "get_event_selectors", resource=arn, TrailName=arn)
        trail["event_selectors"] = selectors(response, state)
        if trail.pop("_insights"):
            response, state = self.call("cloudtrail", region, "get_insight_selectors", resource=arn, TrailName=arn)
            trail["insight_selectors"] = {"state": state if response is None or response.get("InsightSelectors")
                                          else "not_configured",
                                          "types": [item.get("InsightType") for item in
                                                    (response or {}).get("InsightSelectors", [])]}
        else:
            trail["insight_selectors"] = {"state": "not_configured", "types": []}
        return trail

    # S3 destinations ---------------------------------------------------------------------------

    def bucket(self, name, region_hint):
        """Bucket location and restrictions; every unreadable setting stays unknown."""
        result = {"bucket": name}
        location, state = self.call("s3", region_hint, "get_bucket_location", resource=name, Bucket=name)
        if state == "not_configured":
            return {**result, "exists": False, "state": "not_configured", "region": None}
        result["exists"] = True if location is not None else None
        constraint = (location or {}).get("LocationConstraint")
        result["region"] = ({None: "us-east-1", "": "us-east-1", "EU": "eu-west-1"}.get(constraint, constraint)
                            if location is not None else None)
        result["state"] = "configured" if location is not None else state
        region = result["region"] or region_hint

        def get(operation, summarize):
            response, state = self.call("s3", region, operation, resource=name, Bucket=name)
            return {"state": state, **(summarize(response) if response is not None else {})}

        result["public_access_block"] = get("get_public_access_block",
                                            lambda r: dict(r["PublicAccessBlockConfiguration"]))
        result["policy_status"] = get("get_bucket_policy_status", lambda r: dict(r["PolicyStatus"]))
        result["policy"] = get("get_bucket_policy", lambda r: policy(r["Policy"]))
        result["encryption"] = get("get_bucket_encryption", lambda r: {"rules": [
            rule.get("ApplyServerSideEncryptionByDefault", {}) for rule in
            r["ServerSideEncryptionConfiguration"]["Rules"]]})
        versioning = get("get_bucket_versioning", lambda r: {"status": r.get("Status"), "mfa_delete": r.get("MFADelete")})
        if versioning["state"] == "configured" and not versioning["status"]:
            versioning["state"] = "not_configured"  # Never enabled: S3 omits Status.
        result["versioning"] = versioning
        result["object_lock"] = get("get_object_lock_configuration",
                                    lambda r: dict(r.get("ObjectLockConfiguration", {})))
        result["lifecycle"] = get("get_bucket_lifecycle_configuration", lambda r: {"rules": [lifecycle(rule)
                                                                                    for rule in r.get("Rules", [])]})
        return result

    def prefixes(self, bucket, region, prefix):
        """Child prefix names under prefix and the listing's coverage: complete, partial or a failure state."""
        names, token = [], None
        try:
            while True:
                request = {"Bucket": bucket, "Prefix": prefix, "Delimiter": "/",
                           "MaxKeys": min(1000, self.max_items - len(names))}
                if token:
                    request["ContinuationToken"] = token
                response, state = self.call("s3", region, "list_objects_v2", resource=f"s3://{bucket}/{prefix}",
                                            **request)
                if response is None:
                    return names, "unknown" if not names else "partial", f"{state} listing {prefix or '/'}"
                names += [item["Prefix"][len(prefix):].rstrip("/") for item in response.get("CommonPrefixes", [])]
                token = response.get("NextContinuationToken")
                if not token:
                    return names, "complete", None
                if len(names) >= self.max_items:
                    self.cut(region, f"s3://{bucket}/{prefix}", "max_items", self.max_items)
                    return names, "partial", f"--max-items reached listing {prefix or '/'}"
        except Budget:
            self.cut(region, f"s3://{bucket}/{prefix}", "max_s3_calls", self.max_s3_calls)
            return names, "partial" if names else "unknown", f"--max-s3-calls reached listing {prefix or '/'}"

    def verify(self, bucket, region, prefix, account, log_region, day):
        """List a few objects of one day; never download them."""
        try:
            response, state = self.call("s3", region, "list_objects_v2", resource=f"s3://{bucket}/{prefix}",
                                        Bucket=bucket, Prefix=prefix, MaxKeys=20)
        except Budget:
            self.cut(region, f"s3://{bucket}/{prefix}", "max_s3_calls", self.max_s3_calls)
            return {"date": day, "verification": "unknown", "reason": "--max-s3-calls reached"}
        if response is None:
            return {"date": day, "verification": "unknown", "reason": f"listing {state}"}
        compact = day.replace("-", "")
        for item in response.get("Contents", []):
            match = LOG_NAME.match(item["Key"].rsplit("/", 1)[-1])
            if match and match.groups() == (account, log_region, compact) and item.get("Size", 0) > 0:
                return {"date": day, "verification": "verified", "object_key": item["Key"], "size": item["Size"],
                        "last_modified": item.get("LastModified")}
        return {"date": day, "verification": "not_verified",
                "reason": "no CloudTrail log file name with matching account, Region and date among the first "
                          f"{len(response.get('Contents', []))} listed objects"}

    def scan_region(self, task):
        """Observed years/months for one account and Region, plus first/last day verification."""
        bucket, region, base, account, log_region = task
        result = {"region": log_region, "coverage": "complete", "partial_reasons": [], "unexpected_prefixes": []}

        def note(coverage, reason):
            if coverage != "complete":
                result["coverage"] = "partial" if result["coverage"] != "unknown" else "unknown"
                result["partial_reasons"].append(reason)

        root = f"{base}{log_region}/"
        years, coverage, reason = self.prefixes(bucket, region, root)
        if coverage == "unknown":
            result.update(coverage="unknown", partial_reasons=[reason], months=[])
            return result
        note(coverage, reason)
        months = []
        for year in sorted(years):
            if not re.fullmatch(r"\d{4}", year):
                result["unexpected_prefixes"].append(root + year + "/")
                continue
            names, coverage, reason = self.prefixes(bucket, region, f"{root}{year}/")
            note(coverage, reason)
            for month in names:
                if re.fullmatch(r"(0[1-9]|1[0-2])", month):
                    months.append(f"{year}-{month}")
                else:
                    result["unexpected_prefixes"].append(f"{root}{year}/{month}/")
        months.sort()
        result["months"] = months
        result["first_month"], result["last_month"] = (months[0], months[-1]) if months else (None, None)
        if result["coverage"] == "complete" and months:
            # Only a complete month listing can show a gap; it is a gap in observed prefixes, not in events.
            present, missing = set(months), []
            year, month = map(int, months[0].split("-"))
            while f"{year:04d}-{month:02d}" != months[-1]:
                year, month = (year + 1, 1) if month == 12 else (year, month + 1)
                if f"{year:04d}-{month:02d}" not in present:
                    missing.append(f"{year:04d}-{month:02d}")
            result["missing_months"] = missing
        else:
            result["missing_months"] = None
        result["first_day"] = result["last_day"] = None
        result["verified"] = []
        for which, month in (("first_day", result["first_month"]), ("last_day", result["last_month"])):
            if month is None:
                continue
            prefix = f"{root}{month.replace('-', '/')}/"
            days, coverage, reason = self.prefixes(bucket, region, prefix)
            note(coverage, reason)
            days = sorted(day for day in days if re.fullmatch(r"\d{2}", day) and valid(month, day))
            if days:
                day = f"{month}-{days[0] if which == 'first_day' else days[-1]}"
                result[which] = day
                if not any(item["date"] == day for item in result["verified"]):
                    entry = self.verify(bucket, region, f"{prefix}{day[-2:]}/", account, log_region, day)
                    note("complete" if entry["verification"] != "unknown" else "partial",
                         f"{day} verification {entry.get('reason', '')}".strip())
                    result["verified"].append(entry)
        return result

    def scan(self, bucket, region, roots, current_account):
        """Accounts and Regions under each AWSLogs root; Region details are scanned by scan_regions."""
        locations, tasks = [], []
        for root in sorted(roots):
            entry = {"prefix": root, "accounts": []}
            names, entry["coverage"], reason = self.prefixes(bucket, region, root)
            entry["partial_reasons"] = [reason] if reason else []
            accounts = []
            for name in names:
                if re.fullmatch(r"\d{12}", name):
                    accounts.append((None, name))
                elif name.startswith("o-"):
                    members, coverage, reason = self.prefixes(bucket, region, f"{root}{name}/")
                    if coverage != "complete":
                        entry["coverage"] = "partial"
                        entry["partial_reasons"].append(reason)
                    accounts += [(name, member) for member in members if re.fullmatch(r"\d{12}", member)]
            # The current account first, so a small budget is spent where the investigation is.
            for organization, account in sorted(accounts, key=lambda item: (item[1] != current_account, item)):
                base = f"{root}{organization + '/' if organization else ''}{account}/"
                services, coverage, reason = self.prefixes(bucket, region, base)
                record = {"account_id": account, "current_account": account == current_account,
                          "organization": organization, "path": base, "services": services,
                          "coverage": coverage, "partial_reasons": [reason] if reason else [], "regions": []}
                if "CloudTrail" in services:
                    log_regions, coverage, reason = self.prefixes(bucket, region, base + "CloudTrail/")
                    if coverage != "complete":
                        record["coverage"] = "partial" if record["coverage"] != "unknown" else "unknown"
                        record["partial_reasons"].append(reason)
                    for log_region in sorted(log_regions):
                        tasks.append(((bucket, region, base + "CloudTrail/", account, log_region), record))
                entry["accounts"].append(record)
            locations.append(entry)
        return locations, tasks


def valid(month, day):
    try:
        date.fromisoformat(f"{month}-{day}")
        return True
    except ValueError:
        return False


def selectors(response, state):
    """Raw selectors plus one readable line per selector."""
    if response is None:
        return {"state": state, "kind": None, "summary": []}
    advanced, basic = response.get("AdvancedEventSelectors"), response.get("EventSelectors")
    summary = []
    for selector in advanced or []:
        conditions = []
        for field in selector.get("FieldSelectors", []):
            for operator in ("Equals", "NotEquals", "StartsWith", "NotStartsWith", "EndsWith", "NotEndsWith"):
                if field.get(operator):
                    conditions.append(f"{field['Field']} {operator} {','.join(field[operator])}")
        summary.append(f"{selector.get('Name') or 'unnamed'}: " + "; ".join(conditions))
    for selector in basic or []:
        parts = []
        if selector.get("IncludeManagementEvents", True):
            parts.append(f"management {selector.get('ReadWriteType', 'All')}")
            if selector.get("ExcludeManagementEventSources"):
                parts.append("excluding " + ",".join(selector["ExcludeManagementEventSources"]))
        else:
            parts.append("no management events")
        for resource in selector.get("DataResources", []):
            parts.append(f"data {resource['Type']} ({len(resource.get('Values', []))} values: "
                         f"{','.join(resource.get('Values', [])[:3])}{'...' if len(resource.get('Values', [])) > 3 else ''})")
        summary.append("; ".join(parts))
    return {"state": "configured" if summary else "not_configured", "kind": "advanced" if advanced else "basic",
            "summary": summary, "advanced": advanced or [], "basic": basic or []}


def policy(text):
    """Statements letting CloudTrail write, and their conditions; the full policy is not repeated."""
    document = json.loads(text)
    statements = document.get("Statement", [])
    statements = statements if isinstance(statements, list) else [statements]
    writes = []
    for statement in statements:
        principal = statement.get("Principal") or {}
        services = principal.get("Service", []) if isinstance(principal, dict) else []
        services = services if isinstance(services, list) else [services]
        actions = statement.get("Action", [])
        actions = actions if isinstance(actions, list) else [actions]
        if statement.get("Effect") == "Allow" and "cloudtrail.amazonaws.com" in services and \
                any(action in ("s3:PutObject", "s3:*", "*") for action in actions):
            writes.append({"sid": statement.get("Sid"), "resource": statement.get("Resource"),
                           "condition": statement.get("Condition", {})})
    return {"statements": len(statements), "deny_statements": sum(s.get("Effect") == "Deny" for s in statements),
            "cloudtrail_put_object": "configured" if writes else "not_configured", "cloudtrail_writes": writes}


def lifecycle(rule):
    scope = rule.get("Filter", {})
    prefix = rule.get("Prefix", scope.get("Prefix", (scope.get("And") or {}).get("Prefix")))
    return {"id": rule.get("ID"), "status": rule.get("Status"), "prefix": prefix,
            "expiration_days": (rule.get("Expiration") or {}).get("Days"),
            "expiration_date": (rule.get("Expiration") or {}).get("Date"),
            "transitions": [f"{item.get('StorageClass')} after {item.get('Days', item.get('Date'))}"
                            for item in rule.get("Transitions", [])],
            "noncurrent_expiration_days": (rule.get("NoncurrentVersionExpiration") or {}).get("NoncurrentDays")}


def audit(session, args, log):
    home = session.region_name or "us-east-1"
    identity = session.client("sts", region_name=home).get_caller_identity()
    account, partition = identity["Account"], identity["Arn"].split(":")[1]
    check = Check(session, home, args.max_items, args.max_s3_calls)
    partial = []
    log("Resolving Regions")
    regions, reason = check.regions(args.regions)
    if reason:
        partial.append(reason)
    log(f"Reading trails in {len(regions)} Regions")
    trails, scope = {}, []
    for region, state, found in check.pool(check.region_trails, regions):
        scope.append({"region": region, "state": state if state != "configured" or found else "not_configured",
                      "trails": sorted(item["TrailARN"] for item in found)})
        for item in found:
            trail = trails.setdefault(item["TrailARN"], {
                "name": item["Name"], "arn": item["TrailARN"], "home_region": item["HomeRegion"],
                "multi_region": item.get("IsMultiRegionTrail", False),
                "organization_trail": item.get("IsOrganizationTrail", False),
                "include_global_service_events": item.get("IncludeGlobalServiceEvents"),
                "s3_bucket": item.get("S3BucketName"), "s3_key_prefix": item.get("S3KeyPrefix"),
                "kms_key_id": item.get("KmsKeyId"), "log_file_validation": item.get("LogFileValidationEnabled"),
                "cloudwatch_log_group": item.get("CloudWatchLogsLogGroupArn"),
                "sns_topic": item.get("SnsTopicARN"), "applies_in": [],
                "_insights": item.get("HasInsightSelectors", False)})
            trail["applies_in"].append(region)
    log(f"Reading status and selectors for {len(trails)} trails")
    trail_list = sorted(check.pool(check.trail_details, list(trails.values())), key=lambda t: (t["name"], t["arn"]))
    by_arn = {trail["arn"]: trail for trail in trail_list}
    for entry in scope:
        statuses = [by_arn[arn]["status"] for arn in entry["trails"]]
        if entry["state"] in ("denied", "error"):
            entry["logging"] = "unknown"
        elif not statuses:
            entry["logging"] = None
        elif any(status.get("IsLogging") for status in statuses):
            entry["logging"] = "on"
        elif all(status["state"] == "configured" for status in statuses):
            entry["logging"] = "off"
        else:
            entry["logging"] = "unknown"
        entry["logging_trails"] = [by_arn[arn]["name"] for arn in entry["trails"] if by_arn[arn]["status"].get("IsLogging")]

    log("Listing buckets")
    destinations = {}
    for trail in trail_list:
        if trail["s3_bucket"]:
            prefix = (trail["s3_key_prefix"] or "").strip("/")
            target = destinations.setdefault(trail["s3_bucket"], {"trails": [], "roots": set(),
                                                                   "hint": trail["home_region"]})
            target["trails"].append(trail["name"])
            target["roots"].add(f"{prefix}/AWSLogs/" if prefix else "AWSLogs/")
    account_buckets, token, listed = {}, None, "complete"
    while True:
        response, state = check.call("s3", home, "list_buckets", **({"ContinuationToken": token} if token else {}),
                                     MaxBuckets=min(1000, args.max_items))
        if response is None:
            listed = "unknown" if not account_buckets else "partial"
            break
        for item in response.get("Buckets", []):
            account_buckets[item["Name"]] = item.get("BucketRegion")
        token = response.get("ContinuationToken")
        if not token:
            break
        if len(account_buckets) >= args.max_items:
            listed = "partial"
            check.cut(home, "s3:ListBuckets", "max_items", args.max_items)
            break
    others = sorted(name for name in account_buckets if name not in destinations)
    probed = {}
    if args.probe_buckets:
        log(f"Probing {len(others)} other buckets for AWSLogs/")
        def probe(name):
            region = account_buckets[name] or home
            names, coverage, _ = check.prefixes(name, region, "AWSLogs/")
            return name, coverage, names
        for name, coverage, names in check.pool(probe, others):
            probed[name] = {"coverage": coverage, "awslogs_entries": len(names)}
            if names:
                destinations[name] = {"trails": [], "roots": {"AWSLogs/"}, "hint": account_buckets[name] or home}

    log(f"Checking {len(destinations)} buckets")
    buckets = check.pool(lambda name: check.bucket(name, destinations[name]["hint"]), sorted(destinations))
    tasks = []
    for bucket in buckets:
        target = destinations[bucket["bucket"]]
        bucket["destination_of"] = sorted(target["trails"])
        bucket["in_account_bucket_list"] = bucket["bucket"] in account_buckets if listed == "complete" else None
        if bucket.get("exists") is False:
            bucket["locations"] = []
            continue
        bucket["locations"], found = check.scan(bucket["bucket"], bucket["region"] or target["hint"],
                                                target["roots"], account)
        tasks += found
    log(f"Listing date prefixes for {len(tasks)} account/Region paths (at most {args.max_s3_calls} S3 list calls)")
    for (task, record), result in zip(tasks, check.pool(check.scan_region, [task for task, _ in tasks])):
        record["regions"].append(result)
        if result["coverage"] != "complete":
            record["coverage"] = "partial" if record["coverage"] == "complete" else record["coverage"]
    for bucket in buckets:
        # Listing coverage only; unreadable restrictions are separate unknowns in errors.
        coverages = [location["coverage"] for location in bucket["locations"]]
        for location in bucket["locations"]:
            for record in location["accounts"]:
                coverages.append(record["coverage"])
        bucket["coverage"] = ("unknown" if coverages and all(c == "unknown" for c in coverages)
                              else "complete" if all(c == "complete" for c in coverages) else "partial")
        # Configured scope against observed prefixes, for the current account only.
        observed = {region["region"] for location in bucket["locations"] for record in location["accounts"]
                    if record["current_account"] for region in record["regions"]}
        for trail in trail_list:
            if trail["s3_bucket"] == bucket["bucket"]:
                trail["s3_regions_observed"] = sorted(observed) if bucket["coverage"] == "complete" else None
                trail["configured_regions_without_prefix"] = (
                    sorted(set(trail["applies_in"]) - observed) if bucket["coverage"] == "complete" else None)

    unknown_regions = [entry["region"] for entry in scope if entry["state"] in ("denied", "error")]
    if listed != "complete":
        partial.append(f"account bucket list {listed}")
    # AWSLogs/ also holds VPC Flow, ELB and other service logs; only a CloudTrail/ prefix counts.
    with_cloudtrail = sorted(bucket["bucket"] for bucket in buckets if not bucket["destination_of"] and any(
        "CloudTrail" in record["services"] for location in bucket["locations"] for record in location["accounts"]))
    complete = not check.errors and not check.truncated and not partial and all(bucket["coverage"] == "complete" for bucket in buckets) \
        and all(entry["logging"] != "unknown" for entry in scope)
    return {"tool": "trailcheck", "version": VERSION, "generated": iso(datetime.now(timezone.utc)),
            "account_id": account, "partition": partition, "regions": regions,
            "regions_requested": args.regions, "complete": complete, "partial_reasons": partial,
            "limitations": LIMITATIONS, "region_scope": scope, "unknown_regions": unknown_regions,
            "trails": trail_list, "buckets": buckets,
            "other_buckets": {"listing": listed, "count": len(others), "probed": args.probe_buckets,
                              "with_awslogs": sorted(name for name, item in probed.items() if item["awslogs_entries"]),
                              "with_cloudtrail": with_cloudtrail,
                              "probe_unknown": sorted(name for name, item in probed.items()
                                                      if item["coverage"] != "complete")},
            "s3_list_calls": check.s3_calls, "errors": check.errors, "truncated": check.truncated}


def render(report):
    """Readable summary; the JSON report holds every detail."""
    lines = [f"KamoTrace trailcheck: account {report['account_id']} ({report['partition']}), {report['generated']}",
             "Result: " + ("COMPLETE" if report["complete"] else
                           f"PARTIAL ({len(report['errors'])} unknown checks, {len(report['truncated'])} "
                           "truncated listings; see below)"), ""]
    lines.append(f"Trails ({len(report['trails'])})")
    for trail in report["trails"]:
        scope = ["multi-Region" if trail["multi_region"] else "single-Region"]
        if trail["organization_trail"]:
            scope.append("organization")
        if trail["include_global_service_events"]:
            scope.append("global service events")
        lines.append(f"  {trail['name']}  home {trail['home_region']}  {', '.join(scope)}")
        status = trail["status"]
        if status["state"] != "configured":
            lines.append(f"    Logging: UNKNOWN (status {status['state']})")
        else:
            text = "ON" if status.get("IsLogging") else "OFF"
            if status.get("StartLoggingTime") and status.get("IsLogging"):
                text += f" since {iso(status['StartLoggingTime'])}"
            if status.get("StopLoggingTime") and not status.get("IsLogging"):
                text += f" since {iso(status['StopLoggingTime'])}"
            delivery = status.get("LatestDeliveryTime")
            text += f"; latest S3 delivery {iso(delivery) if delivery else 'none reported'}"
            if status.get("LatestDeliveryError"):
                text += f"; delivery error {status['LatestDeliveryError']}"
            if status.get("LatestDigestDeliveryError"):
                text += f"; digest error {status['LatestDigestDeliveryError']}"
            lines.append(f"    Logging: {text}")
        destination = f"s3://{trail['s3_bucket']}/{(trail['s3_key_prefix'] or '').strip('/')}"
        lines.append(f"    Destination: {destination}  KMS: {'yes' if trail['kms_key_id'] else 'no'}  "
                     f"validation: {'on' if trail['log_file_validation'] else 'off'}  "
                     f"CloudWatch Logs: {'yes' if trail['cloudwatch_log_group'] else 'no'}")
        selection = trail["event_selectors"]
        if selection["state"] in ("denied", "error"):
            lines.append(f"    Event selectors: UNKNOWN ({selection['state']})")
        for item in selection["summary"]:
            lines.append(f"    Selector ({selection['kind']}): {item}")
        insights = trail["insight_selectors"]
        lines.append(f"    Insights: {', '.join(insights['types']) or insights['state']}")
        if trail.get("configured_regions_without_prefix"):
            lines.append("    Configured Regions with no observed S3 prefix: "
                         + ", ".join(trail["configured_regions_without_prefix"]))
    lines += ["", f"Region scope ({len(report['region_scope'])} checked)"]
    for entry in report["region_scope"]:
        if entry["state"] in ("denied", "error"):
            text = f"UNKNOWN ({entry['state']})"
        elif not entry["trails"]:
            text = "no trail applies"
        else:
            text = f"logging {entry['logging']}" + (f": {', '.join(entry['logging_trails'])}"
                                                    if entry["logging_trails"] else "")
        lines.append(f"  {entry['region']:<16} {text}")
    lines += ["", "Buckets"]
    for bucket in report["buckets"]:
        role = (f"destination of {', '.join(bucket['destination_of'])}" if bucket["destination_of"]
                else "not a current trail destination; AWSLogs/ found by --probe-buckets")
        if bucket.get("exists") is False:
            lines.append(f"  s3://{bucket['bucket']}  DOES NOT EXIST  {role}")
            continue
        if not bucket["destination_of"] and bucket["coverage"] == "complete" and \
                bucket["bucket"] not in report["other_buckets"]["with_cloudtrail"]:
            found = sorted({service for location in bucket["locations"] for record in location["accounts"]
                            for service in record["services"]})
            lines.append(f"  s3://{bucket['bucket']}  AWSLogs/ without CloudTrail/ (found: {', '.join(found)})")
            continue
        lines.append(f"  s3://{bucket['bucket']}  Region {bucket['region'] or 'unknown'}  {role}")
        lines.append("    Restrictions: " + "; ".join(restrictions(bucket)))
        for location in bucket["locations"]:
            if location["coverage"] == "unknown":
                lines.append(f"    {location['prefix']}: UNKNOWN ({'; '.join(location['partial_reasons'])})")
            for record in location["accounts"]:
                label = record["account_id"] + (" (current)" if record["current_account"] else "")
                label += f" via {record['organization']}" if record["organization"] else ""
                lines.append(f"    Observed date prefixes, account {label} [{record['coverage']}]; "
                             "prefixes are not proof of complete logs")
                if "CloudTrail" not in record["services"]:
                    lines.append(f"      no CloudTrail/ prefix (found: {', '.join(record['services']) or 'nothing'})")
                for region in record["regions"]:
                    lines.append("      " + region_line(region))
    other = report["other_buckets"]
    lines.append(f"  Other buckets in account: {other['count']} ({other['listing']} listing); " +
                 (f"AWSLogs/ found in {len(other['with_awslogs'])}, with CloudTrail/ in "
                  f"{len(other['with_cloudtrail'])}" if other["probed"] else "not probed (use --probe-buckets)"))
    if report["errors"] or report["partial_reasons"] or report["truncated"]:
        lines += ["", "Unknown or partial (not absent)"]
        for reason in report["partial_reasons"]:
            lines.append(f"  {reason}")
        for item in report["truncated"]:
            limit = "max_items" if "max_items" in item else "max_s3_calls"
            lines.append(f"  truncated: {item['section']} at --{limit.replace('_', '-')} {item[limit]}")
        for error in report["errors"]:
            lines.append(f"  {error['state']}: {error['api']} {error['code']} "
                         f"{error['region']}{' ' + error['resource'] if error['resource'] else ''}")
    lines += ["", "Limitations"] + [f"  - {item}" for item in report["limitations"]]
    return "\n".join(lines) + "\n"


def restrictions(bucket):
    parts = []
    block = bucket["public_access_block"]
    if block["state"] == "configured":
        on = [key for key, value in block.items() if key != "state" and value]
        parts.append("public access block " + ("all on" if len(on) == 4 else f"{len(on)}/4 on"))
    else:
        parts.append(f"public access block {state_text(block['state'])}")
    status = bucket["policy_status"]
    if status["state"] == "configured":
        parts.append("policy public" if status.get("IsPublic") else "policy not public")
    item = bucket["policy"]
    if item["state"] == "configured":
        conditioned = any(write["condition"] for write in item["cloudtrail_writes"])
        parts.append("policy allows CloudTrail PutObject" + (" (conditioned)" if conditioned else "")
                     if item["cloudtrail_put_object"] == "configured" else "policy has no CloudTrail PutObject allow")
    else:
        parts.append(f"policy {state_text(item['state'])}")
    item = bucket["encryption"]
    parts.append("default encryption " + (",".join(rule.get("SSEAlgorithm", "?") for rule in item["rules"])
                                          if item["state"] == "configured" else state_text(item["state"])))
    item = bucket["versioning"]
    parts.append("versioning " + (item["status"] if item["state"] == "configured" else state_text(item["state"])))
    item = bucket["object_lock"]
    parts.append("object lock " + (item.get("ObjectLockEnabled", "configured") if item["state"] == "configured"
                                   else state_text(item["state"])))
    item = bucket["lifecycle"]
    if item["state"] == "configured":
        for rule in item["rules"]:
            text = f"lifecycle {rule['id'] or 'rule'} ({rule['status']}, prefix {rule['prefix'] or '*'})"
            if rule["expiration_days"]:
                text += f" expires after {rule['expiration_days']} days"
            if rule["expiration_date"]:
                text += f" expires on {iso(rule['expiration_date'])}"
            if rule["transitions"]:
                text += f" transitions {', '.join(rule['transitions'])}"
            parts.append(text)
    else:
        parts.append(f"lifecycle {state_text(item['state'])}")
    return parts


def state_text(state):
    return {"not_configured": "none", "denied": "UNKNOWN (denied)", "error": "UNKNOWN (error)"}.get(state, state)


def region_line(region):
    if region["coverage"] == "unknown":
        return f"{region['region']:<16} UNKNOWN ({'; '.join(region['partial_reasons'])})"
    years = {}
    for month in region["months"]:
        years[month[:4]] = years.get(month[:4], 0) + 1
    text = f"{region['region']:<16} {region['first_month'] or '-'} .. {region['last_month'] or '-'}"
    text += "  years " + (" ".join(f"{year}({count}m)" for year, count in years.items()) or "none")
    if region["missing_months"]:
        text += f"  missing months {', '.join(region['missing_months'])}"
    verified = [f"{item['date']} {item['verification']}" for item in region["verified"]]
    if verified:
        text += f"  objects: {'; '.join(verified)}"
    if region["coverage"] != "complete":
        text += f"  [partial: {'; '.join(region['partial_reasons'])}]"
    return text


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace trailcheck", description=__doc__,
        epilog="Exit status: 0 complete, 1 report produced but partial/unknown, 2 usage or credential failure.")
    parser.add_argument("--profile", help="Existing AWS profile; otherwise use the normal SDK credential chain")
    parser.add_argument("--regions", nargs="+", default=["all"], help="Region names, or all enabled Regions (default)")
    parser.add_argument("--json", metavar="PATH", help="Write the full JSON report to a new file; '-' for stdout "
                        "(the readable summary then goes to stderr)")
    parser.add_argument("--max-items", type=int, default=1000,
                        help="Maximum entries per S3 prefix or bucket listing (default 1000); beyond it is partial")
    parser.add_argument("--max-s3-calls", type=int, default=2000,
                        help="Maximum S3 ListObjectsV2 calls for the whole run (default 2000); beyond it is partial")
    parser.add_argument("--probe-buckets", action="store_true",
                        help="Also list AWSLogs/ in every other bucket of the account, to find former trail logs")
    args = parser.parse_args(argv)
    if "all" in args.regions and args.regions != ["all"]:
        parser.error("use all alone, or explicit Region names")
    if args.max_items < 1 or args.max_s3_calls < 1:
        parser.error("--max-items and --max-s3-calls must be positive")
    target = Path(args.json) if args.json and args.json != "-" else None
    if target is not None and target.exists():
        parser.error(f"{target} exists; choose a new report path")
    summary = sys.stderr if args.json == "-" else sys.stdout

    def log(message):
        print(f"trailcheck: {message}", file=sys.stderr, flush=True)

    try:
        report = audit(boto3.Session(profile_name=args.profile), args, log)
    except (BotoCoreError, ClientError) as error:
        code = error.response["Error"]["Code"] if isinstance(error, ClientError) else type(error).__name__
        print(f"trailcheck stopped: AWS login check failed ({code}). Log in with your normal AWS tooling, "
              "then rerun.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("trailcheck interrupted; no report written.", file=sys.stderr)
        return 130
    text = json.dumps(report, default=iso, indent=2, sort_keys=True) + "\n"
    if target is not None:
        try:
            with target.open("x", encoding="utf-8", newline="\n") as output:  # Never replace a file.
                output.write(text)
        except OSError as error:
            print(f"trailcheck: cannot write {target}: {error}", file=sys.stderr)
            return 2
    elif args.json == "-":
        sys.stdout.write(text)
    summary.write(render(report))
    if target is not None:
        print(f"JSON report: {target}", file=sys.stderr)
    return 0 if report["complete"] else 1
