"""Collect AWS-only EKS context and existing CloudWatch logs; never contact Kubernetes."""
import argparse
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

import boto3
from botocore.exceptions import BotoCoreError, ClientError
import duckdb
import simplejson as json

from . import other_events
from .importer import in_staging, lock_path, publish, sha256, staging, write_lock
from .inventory import CONFIG

KIND = "kamotrace-eks-v1"
ORIGIN = "AWS EKS context and CloudWatch logs (AWS APIs only)"
LIMITATIONS = [
    "Inventory is a non-atomic current observation, not incident-time configuration or effective access.",
    "AWS EKS APIs do not enumerate Kubernetes workloads, RBAC or aws-auth. No Kubernetes endpoint, pod or node is contacted.",
    "Log timestamps come from the CloudWatch event envelope; original messages and ingestion times are retained unchanged.",
    "A completed retrieval is not proof of historical logging coverage. Missing, denied, expired and truncated sources are not absence.",
    "Existing AWS-hosted workload logs need no node access. Only explicitly named workload groups are read.",
    "No logging or permissions are changed. Enabling logging now cannot recreate absent historical logs.",
]


def now():
    return datetime.now(timezone.utc).isoformat()


def encode(value):
    return json.dumps(value, ensure_ascii=False, use_decimal=True, default=str, allow_nan=False)


def milliseconds(value):
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if stamp.tzinfo is None or stamp.microsecond % 1000:
            raise ValueError()
        return (stamp - datetime(1970, 1, 1, tzinfo=timezone.utc)) // timedelta(milliseconds=1)
    except (ValueError, AttributeError):
        raise ValueError("EKS log bounds require ISO timestamps with timezone and at most millisecond precision") from None


def scope(regions, profile, start, end, log_groups, max_calls, max_events, max_bytes):
    regions = sorted(set(regions))
    if not regions or ("all" in regions and regions != ["all"]):
        raise ValueError("Use named regions or all alone")
    if bool(start) != bool(end):
        raise ValueError("Supply both EKS log --start and --end, or neither for inventory only")
    low, high = (milliseconds(start), milliseconds(end)) if start and end else (None, None)
    if low is not None and low >= high:
        raise ValueError("EKS log start must be before exclusive end")
    if min(max_calls, max_events, max_bytes) < 1:
        raise ValueError("EKS collection limits must be positive")
    for group in log_groups:
        region, sep, name = group.partition(":")
        if not sep or not region or not name or (regions != ["all"] and region not in regions):
            raise ValueError("Log groups must be REGION:NAME in a selected region")
    if log_groups and low is None:
        raise ValueError("Reading explicit log groups requires --start and --end")
    return {"regions": regions, "profile": profile, "start_ms": low, "end_exclusive_ms": high,
            "log_groups": sorted(set(log_groups)), "max_calls": max_calls,
            "max_events": max_events, "max_bytes": max_bytes}


class Collector:
    def __init__(self, session, out, settings, identity):
        self.session, self.out, self.settings, self.identity = session, out, settings, identity
        self.clients, self.operations = {}, []
        self.warnings = []
        self.calls = self.events = self.log_bytes = 0
        self.received_log_bytes = 0
        self.raw = (out / "raw.jsonl").open("w", encoding="utf-8")
        self.rows = (out / "events.jsonl").open("w", encoding="utf-8")

    def close(self):
        self.raw.close()
        self.rows.close()

    def row(self, date, content):
        self.rows.write(encode({"date": date, "content": content}) + "\n")

    def pages(self, region, service, operation, **params):
        entry = {"region": region, "service": service, "operation": operation,
                 "parameters": params, "started_at": now(), "pages": 0, "status": "unknown"}
        self.operations.append(entry)
        if (region, service) not in self.clients:
            self.clients[region, service] = self.session.client(service, region_name=region, config=CONFIG)
        client = self.clients[region, service]
        token = None
        seen = set()
        try:
            while True:
                if self.calls >= self.settings["max_calls"]:
                    entry["status"] = "call_limit"
                    return
                if operation == "filter_log_events" and (self.events >= self.settings["max_events"]
                        or self.received_log_bytes >= self.settings["max_bytes"]):
                    entry["status"] = "log_limit"
                    return
                request = dict(params)
                if token:
                    request["nextToken"] = token
                self.calls += 1
                response = getattr(client, operation)(**request)
                stamp = now()
                page = {"account": self.identity["Account"], "region": region, "service": service,
                        "operation": operation, "parameters": request, "acquired_at": stamp,
                        "response": response}
                if operation == "filter_log_events":
                    self.received_log_bytes += sum(len(e["message"].encode("utf-8")) for e in response.get("events", []))
                self.raw.write(encode(page) + "\n")
                entry["pages"] += 1
                if service != "logs" or operation != "filter_log_events":
                    self.row(stamp, {"kind": "current AWS API observation", **page})
                yield page
                token = response.get("nextToken")
                if not token:
                    entry["status"] = "retrieved"
                    return
                if token in seen:
                    entry["status"] = "repeated_token"
                    return
                seen.add(token)
        except (ClientError, BotoCoreError) as error:
            entry.update(status="error", error=str(error))
        finally:
            entry["finished_at"] = now()
            if entry["status"] == "unknown":
                entry["status"] = "consumer_limit"

    def items(self, region, operation, key, **params):
        return [item for page in self.pages(region, "eks", operation, **params)
                for item in page["response"].get(key, [])]

    def inventory(self, region):
        for cluster in self.items(region, "list_clusters", "clusters"):
            self.items(region, "describe_cluster", "unused", name=cluster)
            for principal in self.items(region, "list_access_entries", "accessEntries", clusterName=cluster):
                self.items(region, "describe_access_entry", "unused", clusterName=cluster, principalArn=principal)
                self.items(region, "list_associated_access_policies", "associatedAccessPolicies",
                           clusterName=cluster, principalArn=principal)
            for association in self.items(region, "list_pod_identity_associations", "associations", clusterName=cluster):
                self.items(region, "describe_pod_identity_association", "unused", clusterName=cluster,
                           associationId=association["associationId"])
            for list_op, key, describe_op, param in [
                ("list_nodegroups", "nodegroups", "describe_nodegroup", "nodegroupName"),
                ("list_fargate_profiles", "fargateProfileNames", "describe_fargate_profile", "fargateProfileName"),
                ("list_addons", "addons", "describe_addon", "addonName"),
            ]:
                for name in self.items(region, list_op, key, clusterName=cluster):
                    self.items(region, describe_op, "unused", clusterName=cluster, **{param: name})
            for provider in self.items(region, "list_identity_provider_configs", "identityProviderConfigs", clusterName=cluster):
                self.items(region, "describe_identity_provider_config", "unused", clusterName=cluster,
                           identityProviderConfig=provider)

    def logs(self, region):
        explicit = {name.partition(":")[2] for name in self.settings["log_groups"] if name.partition(":")[0] == region}
        groups = {}
        for prefix in sorted({"/aws/eks/", *explicit}):
            for page in self.pages(region, "logs", "describe_log_groups", logGroupNamePrefix=prefix):
                for group in page["response"].get("logGroups", []):
                    name = group["logGroupName"]
                    if name in explicit or (name.startswith("/aws/eks/") and name.endswith("/cluster")):
                        groups[name] = group
        for missing in sorted(explicit - groups.keys()):
            self.operations.append({"region": region, "operation": "log_group_selection", "group": missing,
                                    "status": "not_found_or_not_discovered"})
        if self.settings["start_ms"] is not None:
            stored_bytes = sum(group.get("storedBytes", 0) for group in groups.values())
            if stored_bytes >= 1_000_000_000:
                warning = (
                    f"{region}: selected CloudWatch log groups report {stored_bytes:,} stored bytes "
                    f"({stored_bytes / 1_000_000_000:.2f} GB; warning threshold 1 GB). "
                    "This is group-wide storage, not an estimate for the requested time window or download size; "
                    "missing size metadata and undiscovered groups are not included. "
                    f"The global log-message download budget remains {self.settings['max_bytes']:,} bytes; "
                    "raw retrieval may exceed it by one CloudWatch page, plus metadata/JSON overhead."
                )
                self.warnings.append(warning)
                print(f"WARNING: {warning}", file=sys.stderr, flush=True)
        for name, group in sorted(groups.items()):
            # Stream names and metadata are useful even for inventory-only collection and deleted clusters.
            for _ in self.pages(region, "logs", "describe_log_streams", logGroupName=name):
                pass
            if self.settings["start_ms"] is None:
                continue
            entry = {"region": region, "operation": "log_retrieval", "group": name,
                     "status": "unknown", "events": 0}
            self.operations.append(entry)
            if group.get("logGroupClass", "STANDARD") != "STANDARD":
                entry["status"] = "unsupported_log_class"
                continue
            if self.events >= self.settings["max_events"] or self.received_log_bytes >= self.settings["max_bytes"]:
                entry["status"] = "log_limit"
                continue
            pages = self.pages(region, "logs", "filter_log_events", logGroupName=name,
                               startTime=self.settings["start_ms"], endTime=self.settings["end_exclusive_ms"],
                               limit=min(1000, self.settings["max_events"] - self.events))
            try:
                for page in pages:
                    for event in page["response"].get("events", []):
                        if not self.settings["start_ms"] <= event["timestamp"] < self.settings["end_exclusive_ms"]:
                            continue
                        size = len(event["message"].encode("utf-8"))
                        if self.events >= self.settings["max_events"] or self.log_bytes + size > self.settings["max_bytes"]:
                            entry["status"] = "log_limit"
                            break
                        self.row((datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=event["timestamp"])).isoformat(),
                                 {"kind": "CloudWatch log event", "account": self.identity["Account"],
                                  "region": region, "log_group": name, "acquired_at": page["acquired_at"],
                                  "event": event})
                        self.events += 1
                        self.log_bytes += size
                        entry["events"] += 1
                    if entry["status"] == "log_limit":
                        break
                if entry["status"] != "log_limit":
                    entry["status"] = self.operations[-1]["status"]
            finally:
                pages.close()


def read_export(folder):
    folder = Path(folder).resolve()
    info = json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    if info.get("kind") != KIND or info.get("complete") is not True or set(info.get("files", {})) != {"events.jsonl", "raw.jsonl"}:
        raise ValueError("Not a completed KamoTrace EKS export")
    for name, digest in info["files"].items():
        if sha256(folder / name) != digest:
            raise ValueError(f"EKS source changed: {name}")
    return info


def build(output, *, profile=None, regions=("all",), start=None, end=None, log_groups=(),
          max_calls=2000, max_events=100000, max_bytes=100 * 1024 * 1024):
    output = Path(output).resolve()
    settings = scope(regions, profile, start, end, log_groups, max_calls, max_events, max_bytes)
    if in_staging(output):
        raise ValueError("EKS output cannot be inside a staging folder")
    with write_lock(output):
        if output.exists():
            raise FileExistsError("EKS exports are never overwritten; use a new output folder")
        session = boto3.Session(profile_name=profile)
        identity = session.client("sts", config=CONFIG).get_caller_identity()
        selected = settings["regions"]
        if selected == ["all"]:
            selected = sorted(r["RegionName"] for r in session.client("ec2", config=CONFIG).describe_regions(AllRegions=False)["Regions"])
        if {s.partition(":")[0] for s in log_groups} - set(selected):
            raise ValueError("Explicit log groups must be in enabled selected regions")
        with staging(output) as staged:
            out = staged.parent / "export"
            out.mkdir()
            collector = Collector(session, out, settings, identity)
            started = now()
            try:
                for region in selected:
                    collector.inventory(region)
                    collector.logs(region)
                info = {"kind": KIND, "complete": True, "scope": settings, "identity": identity,
                        "regions": selected, "started_at": started, "finished_at": now(),
                        "limitations": LIMITATIONS, "operations": collector.operations, "warnings": collector.warnings,
                        "calls": collector.calls, "log_events": collector.events, "log_message_bytes": collector.log_bytes,
                        "received_log_message_bytes": collector.received_log_bytes}
                collector.row(info["finished_at"], {**info, "kind": "EKS collection coverage (not historical completeness)"})
            finally:
                collector.close()
            info["files"] = {name: sha256(out / name) for name in ("raw.jsonl", "events.jsonl")}
            (out / "manifest.json").write_text(encode(info), encoding="utf-8")
            publish(out, output)
    return output


def import_export(folder, database):
    folder, database = Path(folder).resolve(), Path(database).resolve()
    read_export(folder)
    if database.is_relative_to(folder) or lock_path(database).is_relative_to(folder) or in_staging(database):
        raise ValueError("Import output and lock must be outside the original EKS export and staging folders")
    other_events.build([folder / "events.jsonl"], database, ORIGIN)


def prepare_import(folder, database):
    """Auto recovery: reuse only the same verified source, never overwrite an existing dataset."""
    folder, database = Path(folder).resolve(), Path(database).resolve()
    info = read_export(folder)
    if not database.exists():
        import_export(folder, database)
        return
    with duckdb.connect(str(database), read_only=True) as connection:
        metadata = json.loads(connection.execute("SELECT metadata FROM build_info").fetchone()[0])
    source = folder / "events.jsonl"
    if (metadata.get("format") != other_events.FORMAT or metadata.get("origin") != ORIGIN
            or metadata.get("sources") != [{"source_file": str(source), "source_sha256": info["files"]["events.jsonl"],
                                            "source_bytes": source.stat().st_size}]):
        raise ValueError("Existing EKS database belongs to different inputs; use a new database/TARGET")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace eks", description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--output", type=Path, help="New immutable export directory")
    mode.add_argument("--from-export", type=Path, help="Verified existing export; offline import only")
    parser.add_argument("--database", type=Path, help="Import into a new other-events DuckDB outside the export")
    parser.add_argument("--profile")
    parser.add_argument("--regions", nargs="+", default=["all"])
    parser.add_argument("--start", help="CloudWatch start inclusive, ISO timestamp with timezone; omit both bounds for inventory only")
    parser.add_argument("--end", help="CloudWatch end EXCLUSIVE, ISO timestamp with timezone")
    parser.add_argument("--log-group", action="append", default=[], metavar="REGION:NAME", help="Additional existing workload log group; repeatable")
    parser.add_argument("--max-calls", type=int, default=2000, help="Global EKS/Logs request limit (SDK retries and identity/region discovery extra)")
    parser.add_argument("--max-events", type=int, default=100000)
    parser.add_argument("--max-bytes", type=int, default=100 * 1024 * 1024, help="Global log-message byte budget; raw retrieval may exceed by one CloudWatch page, plus metadata/JSON overhead")
    args = parser.parse_args(argv)
    if args.from_export and not args.database:
        parser.error("--from-export requires --database")
    if args.from_export and (args.profile or args.regions != ["all"] or args.start or args.end or args.log_group):
        parser.error("Offline import cannot be combined with collection options")
    if args.output and args.database and (args.database.resolve().is_relative_to(args.output.resolve())
                                         or lock_path(args.database.resolve()).is_relative_to(args.output.resolve())):
        parser.error("Database and lock must be outside the original export")
    try:
        folder = args.from_export or build(args.output, profile=args.profile, regions=args.regions,
            start=args.start, end=args.end, log_groups=args.log_group, max_calls=args.max_calls,
            max_events=args.max_events, max_bytes=args.max_bytes)
        info = read_export(folder)
        if args.database:
            import_export(folder, args.database)
        gaps = sum(op["status"] != "retrieved" for op in info["operations"])
        print(f"EKS export: {folder}; {info['log_events']} log events; {gaps} operations with coverage gaps. "
              "See manifest.json; completed retrieval is not proof of historical completeness.")
        return 0
    except (OSError, ValueError, BotoCoreError, ClientError, duckdb.Error) as error:
        print(f"kamotrace eks: {error}", file=sys.stderr)
        return 1
