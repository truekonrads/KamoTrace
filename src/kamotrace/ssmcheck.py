"""Read-only report of what AWS Systems Manager is configured to log, and where.

Per region it reads Session Manager preferences (SSM-SessionManagerRunShell), the
session type and logging inputs of custom and observed session documents, recent
sessions and Run Command commands, State Manager association output locations, and
maintenance-window Run Command task output settings. Every listing is bounded by
--max-items. It never changes AWS resources, never reads command or session output,
and never reports command, association or task parameter values.
"""
import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

PREFERENCES = "SSM-SessionManagerRunShell"
DENIED = {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedAccess",
          "AuthorizationError", "AuthFailure"}
LOG_INPUTS = ("s3BucketName", "cloudWatchLogGroupName")
LIMITATIONS = [
    "Run Command has no regional output default: each command, association and maintenance-window task "
    "chooses its own S3/CloudWatch destination. Observed commands show what recent senders chose, not a rule "
    "for future commands. Without a destination, output exists only in the SSM API (truncated, ~30 days).",
    "Session Manager preferences (SSM-SessionManagerRunShell) apply per region to shell sessions and to session "
    "documents without their own logging inputs; a custom Standard_Stream document's own inputs apply instead.",
    "Port sessions (SSH via AWS-StartSSHSession and port forwarding) are never content-logged by Session Manager; "
    "only their session records exist.",
    "Configured logging is delivered by the SSM Agent with the instance's permissions; it does not prove that logs "
    "were delivered, retained or readable. Destination existence, retention and access were not checked.",
    "Observed sessions and commands cover only recent history that SSM still returns (generally 30 days), "
    "at most --max-items per listing.",
    "Custom session documents are those owned by this account (Owner=Self); shared documents appear only "
    "when observed in sessions.",
    "Command/session output payloads and parameter values were not retrieved.",
]


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z") if isinstance(value, datetime) else value


def api_name(method):
    return "ssm:" + "".join(part.title() for part in method.split("_"))


def logging_inputs(inputs):
    """Session logging settings from a session document's inputs; values only, no shell profile text."""
    s3, group = inputs.get("s3BucketName") or None, inputs.get("cloudWatchLogGroupName") or None
    return {
        "s3": {"state": "configured" if s3 else "not_configured", "bucket": s3,
               "prefix": inputs.get("s3KeyPrefix") or None,
               "encryption_required": bool(inputs.get("s3EncryptionEnabled"))},
        "cloudwatch": {"state": "configured" if group else "not_configured", "log_group": group,
                       "encryption_required": bool(inputs.get("cloudWatchEncryptionEnabled")),
                       "streaming": bool(inputs.get("cloudWatchStreamingEnabled"))},
        "kms_key_id": inputs.get("kmsKeyId") or None,
        "run_as_enabled": bool(inputs.get("runAsEnabled")),
        "shell_profile_set": any((inputs.get("shellProfile") or {}).values()),
        "idle_session_timeout": inputs.get("idleSessionTimeout") or None,
        "max_session_duration": inputs.get("maxSessionDuration") or None,
    }


class Region:
    """Checks for one region. Failures are recorded per check, so the rest still run."""

    def __init__(self, name, client, limit):
        self.name, self.ssm, self.limit = name, client, limit
        self.errors, self.truncated = [], []

    def guard(self, method, function):
        """(result, None), or (None, "denied"|"error") with the error code recorded."""
        try:
            return function(), None
        except ClientError as error:
            code = error.response.get("Error", {}).get("Code", "Unknown")
        except BotoCoreError as error:
            code = type(error).__name__
        state = "denied" if code in DENIED else "error"
        self.errors.append({"region": self.name, "api": api_name(method), "code": code, "state": state})
        return None, state

    def listing(self, method, key, section, **params):
        """At most --max-items results as (items, truncated), or (None, failure state)."""
        result, failure = self.guard(method, lambda: self.ssm.get_paginator(method).paginate(
            **params, PaginationConfig={"MaxItems": self.limit}).build_full_result())
        if result is None:
            return None, failure
        truncated = bool(result.get("NextToken"))
        if truncated:
            self.truncated.append({"region": self.name, "section": section, "max_items": self.limit})
        return result.get(key, []), truncated

    def document(self, name):
        """Parsed session document content; (None, state) when absent/denied/unreadable."""
        result, failure = self.guard("get_document", lambda: self.ssm.get_document(Name=name, DocumentFormat="JSON"))
        if result is None:
            code = self.errors[-1]["code"]
            if code == "InvalidDocument":  # Never created in this region: a real absence, not an error.
                self.errors.pop()
                return None, "not_configured"
            return None, failure
        try:
            return json.loads(result["Content"]), None
        except (KeyError, ValueError):
            self.errors.append({"region": self.name, "api": "ssm:GetDocument", "code": "UnparsableContent",
                                "state": "error"})
            return None, "error"

    def run(self):
        report = {"region": self.name}
        report["session_preferences"] = self.preferences()
        documents = {}
        report["session_documents"] = self.session_documents(documents)
        report["observed_sessions"] = self.sessions(documents)
        report["observed_commands"] = self.commands()
        report["associations"] = self.associations()
        report["maintenance_window_tasks"] = self.maintenance_tasks()
        return report

    def preferences(self):
        content, failure = self.document(PREFERENCES)
        if content is None:
            return {"state": failure, "document": PREFERENCES}
        return {"state": "configured", "document": PREFERENCES, **logging_inputs(content.get("inputs") or {})}

    def describe_document(self, name, content):
        session_type = content.get("sessionType")
        inputs = content.get("inputs") or {}
        if session_type == "Port":
            applies = "not_logged"
        elif session_type == "Standard_Stream" and any(key in inputs for key in LOG_INPUTS):
            applies = "document_inputs"
        else:
            applies = "regional_preferences"
        entry = {"name": name, "session_type": session_type, "content_logging": applies}
        if applies == "document_inputs":
            entry.update(logging_inputs(inputs))
        return entry

    def session_documents(self, documents):
        items, truncated = self.listing("list_documents", "DocumentIdentifiers", "session_documents", Filters=[
            {"Key": "DocumentType", "Values": ["Session"]}, {"Key": "Owner", "Values": ["Self"]}])
        if items is None:
            return {"state": truncated}
        found = []
        for item in items:
            if item["Name"] == PREFERENCES:
                continue  # Reported as the regional preferences.
            content, failure = self.document(item["Name"])
            documents[item["Name"]] = entry = (self.describe_document(item["Name"], content) if content is not None
                                               else {"name": item["Name"], "state": failure})
            found.append(entry)
        return {"state": "configured" if found else "not_configured", "truncated": truncated, "documents": found}

    def sessions(self, documents):
        records, truncated, failures = [], False, []
        for state in ("Active", "History"):
            items, flag = self.listing("describe_sessions", "Sessions", f"sessions_{state.lower()}", State=state)
            if items is None:
                failures.append(flag)
            else:
                records += items
                truncated |= flag
        if len(failures) == 2:
            return {"state": failures[0]}
        groups = {}
        for record in records:
            name = record.get("DocumentName") or PREFERENCES
            group = groups.setdefault(name, Counter())
            group["sessions"] += 1
            output = record.get("OutputUrl") or {}
            group["with_s3_output_url"] += bool(output.get("S3OutputUrl"))
            group["with_cloudwatch_output_url"] += bool(output.get("CloudWatchOutputUrl"))
        by_document = []
        for name in sorted(groups, key=lambda key: (-groups[key]["sessions"], key)):
            if name == PREFERENCES:
                info = {"session_type": "Standard_Stream", "content_logging": "regional_preferences"}
            else:
                if name not in documents:
                    content, failure = self.document(name)
                    documents[name] = (self.describe_document(name, content) if content is not None
                                       else {"name": name, "state": failure})
                info = {key: value for key, value in documents[name].items() if key != "name"}
            by_document.append({"document": name, **info, **groups[name]})
        starts = [record["StartDate"] for record in records if record.get("StartDate")]
        return {"state": "partial" if failures else "observed", "truncated": truncated, "examined": len(records),
                "oldest_start": iso(min(starts)) if starts else None,
                "newest_start": iso(max(starts)) if starts else None, "by_document": by_document}

    def commands(self):
        items, truncated = self.listing("list_commands", "Commands", "commands")
        if items is None:
            return {"state": truncated}
        destinations = Counter()
        for command in items:
            cloudwatch = command.get("CloudWatchOutputConfig") or {}
            group = None
            if cloudwatch.get("CloudWatchOutputEnabled"):
                group = cloudwatch.get("CloudWatchLogGroupName") or "/aws/ssm/" + command.get("DocumentName", "")
            destinations[(command.get("OutputS3BucketName") or None, command.get("OutputS3KeyPrefix") or None,
                          group)] += 1
        requested = [command["RequestedDateTime"] for command in items if command.get("RequestedDateTime")]
        return {"state": "observed", "truncated": truncated, "examined": len(items),
                "oldest_requested": iso(min(requested)) if requested else None,
                "newest_requested": iso(max(requested)) if requested else None,
                "destinations": [{"s3_bucket": bucket, "s3_prefix": prefix, "cloudwatch_log_group": group,
                                  "inline_only": not bucket and not group, "commands": count}
                                 for (bucket, prefix, group), count in sorted(
                                     destinations.items(), key=lambda pair: (-pair[1], str(pair[0])))]}

    def associations(self):
        items, truncated = self.listing("list_associations", "Associations", "associations")
        if items is None:
            return {"state": truncated}
        found = []
        for item in items:
            entry = {"association_id": item["AssociationId"], "association_name": item.get("AssociationName"),
                     "document": item.get("Name")}
            result, failure = self.guard("describe_association",
                                         lambda: self.ssm.describe_association(AssociationId=item["AssociationId"]))
            if result is None:
                entry["state"] = failure
            else:
                s3 = (result["AssociationDescription"].get("OutputLocation") or {}).get("S3Location") or {}
                entry.update(state="configured" if s3.get("OutputS3BucketName") else "not_configured",
                             s3_bucket=s3.get("OutputS3BucketName"), s3_prefix=s3.get("OutputS3KeyPrefix"),
                             s3_region=s3.get("OutputS3Region"))
            found.append(entry)
        return {"state": "configured" if found else "not_configured", "truncated": truncated, "associations": found}

    def maintenance_tasks(self):
        windows, truncated = self.listing("describe_maintenance_windows", "WindowIdentities", "maintenance_windows")
        if windows is None:
            return {"state": truncated}
        found, other, budget, partial = [], Counter(), self.limit, False
        for window in windows:
            tasks, flag = self.listing("describe_maintenance_window_tasks", "Tasks", "maintenance_window_tasks",
                                       WindowId=window["WindowId"])
            if tasks is None:
                found.append({"window_id": window["WindowId"], "window_name": window.get("Name"), "state": flag})
                continue
            truncated |= flag
            for task in tasks:
                if task.get("Type") != "RUN_COMMAND":
                    other[task.get("Type", "UNKNOWN")] += 1
                    continue
                entry = {"window_id": window["WindowId"], "window_name": window.get("Name"),
                         "task_id": task["WindowTaskId"], "document": task.get("TaskArn")}
                legacy = task.get("LoggingInfo") or {}
                if budget <= 0:
                    entry["state"] = "unknown"
                    partial = True
                    found.append(entry)
                    continue
                budget -= 1
                result, failure = self.guard("get_maintenance_window_task", lambda: self.ssm.get_maintenance_window_task(
                    WindowId=window["WindowId"], WindowTaskId=task["WindowTaskId"]))
                if result is None:
                    entry["state"] = failure
                else:
                    legacy = result.get("LoggingInfo") or legacy
                    run = (result.get("TaskInvocationParameters") or {}).get("RunCommand") or {}
                    cloudwatch = run.get("CloudWatchOutputConfig") or {}
                    group = None
                    if cloudwatch.get("CloudWatchOutputEnabled"):
                        group = cloudwatch.get("CloudWatchLogGroupName") or "/aws/ssm/" + (task.get("TaskArn") or "")
                    bucket = run.get("OutputS3BucketName") or legacy.get("S3BucketName")
                    entry.update(state="configured" if bucket or group else "not_configured", s3_bucket=bucket,
                                 s3_prefix=run.get("OutputS3KeyPrefix") or legacy.get("S3KeyPrefix"),
                                 cloudwatch_log_group=group)
                found.append(entry)
        if partial:
            self.truncated.append({"region": self.name, "section": "maintenance_window_task_details",
                                   "max_items": self.limit})
        return {"state": "configured" if found else "not_configured", "truncated": truncated or partial,
                "windows_examined": len(windows), "run_command_tasks": found, "other_task_types": dict(other)}


def check(session, regions, limit):
    config = Config(retries={"mode": "adaptive", "max_attempts": 10}, connect_timeout=15, read_timeout=60)
    # Sessions are not thread-safe; create every client here, then run regions concurrently.
    checks = [Region(name, session.client("ssm", region_name=name, config=config), limit) for name in regions]
    with ThreadPoolExecutor(max_workers=min(8, max(1, len(checks)))) as pool:
        results = list(pool.map(Region.run, checks))
    return results, [e for c in checks for e in c.errors], [t for c in checks for t in c.truncated]


def yes(value):
    return "yes" if value else "no"


def text_report(report):
    lines = [f"KamoTrace ssmcheck: account {report['account_id']} ({report['partition']}), "
             f"{len(report['regions']['checked'])} region(s), generated {report['generated']}",
             "Coverage: " + ("complete" if report["complete"] else
                             f"PARTIAL ({len(report['errors'])} error(s), {len(report['truncated'])} truncated listing(s))")]
    for region in report["results"]:
        lines.append(f"\n{region['region']}")
        prefs = region["session_preferences"]
        if prefs["state"] == "configured":
            lines.append(f"  Session Manager preferences: configured ({PREFERENCES})")
            s3, cw = prefs["s3"], prefs["cloudwatch"]
            lines.append("    S3 session logging: " + (
                f"configured bucket={s3['bucket']} prefix={s3['prefix'] or '-'} encryption_required={yes(s3['encryption_required'])}"
                if s3["state"] == "configured" else "not configured"))
            lines.append("    CloudWatch session logging: " + (
                f"configured log_group={cw['log_group']} encryption_required={yes(cw['encryption_required'])} streaming={yes(cw['streaming'])}"
                if cw["state"] == "configured" else "not configured"))
            lines.append(f"    KMS session encryption: {prefs['kms_key_id'] or 'not configured'}; "
                         f"run-as: {yes(prefs['run_as_enabled'])}; shell profile set: {yes(prefs['shell_profile_set'])}")
        elif prefs["state"] == "not_configured":
            lines.append("  Session Manager preferences: not configured (no session logging by default)")
        else:
            lines.append(f"  Session Manager preferences: {prefs['state'].upper()} (unknown)")
        docs = region["session_documents"]
        if docs["state"] in ("configured", "not_configured"):
            lines.append(f"  Custom session documents: {len(docs['documents'])}" + (" (truncated)" if docs["truncated"] else ""))
            for doc in docs["documents"]:
                line = f"    {doc['name']}: " + (f"{doc['session_type']}, logging={doc['content_logging']}"
                                                  if "session_type" in doc else doc["state"].upper())
                if doc.get("content_logging") == "document_inputs":
                    line += f" (S3 {doc['s3']['bucket'] or 'none'}, CloudWatch {doc['cloudwatch']['log_group'] or 'none'})"
                lines.append(line)
        else:
            lines.append(f"  Custom session documents: {docs['state'].upper()} (unknown)")
        sessions = region["observed_sessions"]
        if "examined" in sessions:
            lines.append(f"  Sessions observed: {sessions['examined']}" + (" (truncated)" if sessions["truncated"] else "")
                         + (" (partial)" if sessions["state"] == "partial" else ""))
            for group in sessions["by_document"]:
                lines.append(f"    {group['document']}: {group['sessions']} session(s), "
                             f"type={group.get('session_type') or 'unknown'}, logging={group.get('content_logging') or group.get('state')}, "
                             f"S3 URL {group['with_s3_output_url']}, CloudWatch URL {group['with_cloudwatch_output_url']}")
        else:
            lines.append(f"  Sessions observed: {sessions['state'].upper()} (unknown)")
        commands = region["observed_commands"]
        if commands["state"] == "observed":
            lines.append(f"  Run Command commands observed: {commands['examined']}" + (" (truncated)" if commands["truncated"] else ""))
            for dest in commands["destinations"]:
                where = "inline only (SSM API)" if dest["inline_only"] else ", ".join(filter(None, [
                    dest["s3_bucket"] and f"S3 {dest['s3_bucket']}/{dest['s3_prefix'] or ''}",
                    dest["cloudwatch_log_group"] and f"CloudWatch {dest['cloudwatch_log_group']}"]))
                lines.append(f"    {dest['commands']} command(s): {where}")
        else:
            lines.append(f"  Run Command commands observed: {commands['state'].upper()} (unknown)")
        assoc = region["associations"]
        if "associations" in assoc:
            with_output = sum(item.get("state") == "configured" for item in assoc["associations"])
            lines.append(f"  State Manager associations: {len(assoc['associations'])}, {with_output} with S3 output"
                         + (" (truncated)" if assoc["truncated"] else ""))
        else:
            lines.append(f"  State Manager associations: {assoc['state'].upper()} (unknown)")
        tasks = region["maintenance_window_tasks"]
        if "run_command_tasks" in tasks:
            with_output = sum(item.get("state") == "configured" for item in tasks["run_command_tasks"])
            lines.append(f"  Maintenance windows: {tasks['windows_examined']}, Run Command tasks "
                         f"{len(tasks['run_command_tasks'])}, {with_output} with output destination"
                         + (" (truncated)" if tasks["truncated"] else ""))
        else:
            lines.append(f"  Maintenance windows: {tasks['state'].upper()} (unknown)")
    if report["errors"]:
        lines.append("\nUnknown (denied/error):")
        lines += [f"  {e['region']} {e['api']}: {e['code']}" for e in report["errors"]]
    lines.append("\nLimitations:")
    lines += [f"  - {item}" for item in report["limitations"]]
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace ssmcheck", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--profile", help="Existing AWS profile; otherwise use the normal SDK credential chain")
    parser.add_argument("--regions", nargs="+", default=["all"], help="Region names, or all enabled regions (default)")
    parser.add_argument("--json", metavar="PATH", help="Write the JSON report to a new file, or - for stdout "
                        "(the text summary then goes to stderr)")
    parser.add_argument("--max-items", type=int, default=200,
                        help="Maximum items per listing per region (default 200); hitting it marks coverage partial")
    args = parser.parse_args(argv)
    if "all" in args.regions and args.regions != ["all"]:
        parser.error("use all alone, or explicit region names")
    if args.max_items < 1:
        parser.error("--max-items must be at least 1")
    target = None if args.json in (None, "-") else Path(args.json)
    if target is not None and target.exists():
        parser.error(f"{target} already exists; choose a new report path")
    try:
        session = boto3.Session(profile_name=args.profile)
        bootstrap = session.region_name or "us-east-1"
        identity = session.client("sts", region_name=bootstrap).get_caller_identity()
    except (BotoCoreError, ClientError) as error:
        print(f"kamotrace ssmcheck: cannot use the AWS login: {type(error).__name__}", file=sys.stderr)
        return 2
    errors = []
    if args.regions == ["all"]:
        try:
            response = session.client("ec2", region_name=bootstrap).describe_regions(AllRegions=False)
            regions = sorted(item["RegionName"] for item in response["Regions"])
        except (BotoCoreError, ClientError) as error:
            code = error.response.get("Error", {}).get("Code", "Unknown") if isinstance(error, ClientError) else type(error).__name__
            errors.append({"region": bootstrap, "api": "ec2:DescribeRegions", "code": code,
                           "state": "denied" if code in DENIED else "error"})
            regions = [bootstrap]
            print(f"Warning: cannot list enabled regions ({code}); checking only {bootstrap}", file=sys.stderr)
    else:
        regions = sorted(set(args.regions))
    results, region_errors, truncated = check(session, regions, args.max_items)
    errors += region_errors
    report = {"tool": "ssmcheck", "version": 1, "generated": iso(datetime.now(timezone.utc)),
              "account_id": identity["Account"], "partition": identity["Arn"].split(":")[1],
              "regions": {"requested": args.regions, "checked": regions}, "max_items": args.max_items,
              "complete": not errors and not truncated, "errors": errors, "truncated": truncated,
              "limitations": LIMITATIONS, "results": results}
    document = json.dumps(report, indent=2, sort_keys=False, default=str) + "\n"
    summary = text_report(report)
    if args.json == "-":
        sys.stdout.write(document)
        sys.stderr.write(summary)
    else:
        if target is not None:
            with open(target, "x", encoding="utf-8") as output:  # Never overwrite an earlier report.
                output.write(document)
        sys.stdout.write(summary)
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    sys.exit(main())
