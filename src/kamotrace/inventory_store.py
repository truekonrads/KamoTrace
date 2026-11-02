"""Read-only inventory with scope-aware exact reference and IP network range lookups."""
import ipaddress
import json
import logging
from pathlib import Path
import re
import time


logger = logging.getLogger(__name__)
COLLECTIONS = ("resources", "vpcs", "security_groups", "relationships", "forwarding_paths", "listener_actions", "errors")


class Inventory:
    def __init__(self, folder=None):
        self.report = {"loaded": False, "metadata": None, "counts": {}, **{key: [] for key in COLLECTIONS}}
        self.index = {}
        self.networks = []
        if folder is None:
            return
        path = Path(folder) / "report.json"
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
            if (not isinstance(report, dict) or not isinstance(report.get("metadata"), dict)
                    or not isinstance(report["metadata"].get("account"), str)
                    or any(not isinstance(report.get(key), list) for key in COLLECTIONS)
                    or not isinstance(report.get("counts"), dict)):
                raise ValueError("Expected an AWS inventory report with metadata, resource lists and counts")
            self.report = {**report, "loaded": True}
            account = report["metadata"]["account"]
            iam = report.get("iam", {})
            policies = {p["Arn"]: {**p, "aws_managed": managed}
                        for key, managed in (("policies", False), ("aws_managed_policies", True))
                        for p in iam.get(key, [])}
            groups = {g["GroupName"]: g for g in iam.get("groups", [])}
            for collection, name_key in (("users", "UserName"), ("roles", "RoleName"), ("groups", "GroupName")):
                for entity in iam.get(collection, []):
                    memberships = [groups[g] for g in entity.get("GroupList", []) if g in groups]
                    attached = {p["PolicyArn"] for owner in [entity, *memberships]
                                for p in owner.get("AttachedManagedPolicies", [])}
                    boundary = entity.get("PermissionsBoundary", {}).get("PermissionsBoundaryArn")
                    if boundary:
                        attached.add(boundary)
                    match = {"kind": "identity", "id": entity["Arn"], "name": entity[name_key],
                             "account": account, "region": "global", "source": "inventory", "iam": entity,
                             "iam_groups": memberships,
                             "iam_members": [{"UserName": u["UserName"], "Arn": u["Arn"]} for u in iam.get("users", [])
                                             if collection == "groups" and entity[name_key] in u.get("GroupList", [])],
                             "iam_policies": [policies[p] for p in sorted(attached) if p in policies]}
                    for value in (entity["Arn"], entity[name_key], entity.get(name_key.replace("Name", "Id"))):
                        self.add("identity", value, match)
                    if collection == "roles":
                        # STS omits the IAM role path. Role names are unique within an account.
                        partition = entity["Arn"].split(":")[1]
                        self.add("assumed-role", f"arn:{partition}:sts::{account}:assumed-role/{entity[name_key]}", match)
            # Subnets are optional so older snapshots still supply VPC range context.
            for collection, kind in (("vpcs", "VPC"), ("subnets", "Subnet")):
                for network in report.get(collection, []):
                    for cidr in network.get("cidr", "").split(","):
                        if cidr.strip():
                            prefix = ipaddress.ip_network(cidr.strip())
                            match = {"kind": kind, "id": network["id"], "name": network.get("name", network["id"]),
                                     "account": account, "region": network["region"], "source": "inventory",
                                     "network": {**network, "kind": kind, "cidr": str(prefix)}}
                            self.networks.append((prefix, match))
            for resource in report["resources"]:
                if not isinstance(resource.get("id"), str) or not isinstance(resource.get("region"), str):
                    raise ValueError("Inventory resources must have an id and region")
                match = {"kind": "machine", "id": resource["id"], "name": resource.get("name", resource["id"]),
                         "account": account, "region": resource["region"], "source": "inventory", "resource": resource}
                for value in {resource["id"], resource.get("name", "")}:
                    self.add("machine", value, match)
                for value in resource.get("addresses", []):
                    try:
                        self.add("ip", str(ipaddress.ip_address(value)), match)
                    except ValueError:
                        self.add("machine", value, match)  # DNS endpoints are names, not resolved IPs.
                for arn, name in zip(resource.get("iam_role_arns", []), resource.get("iam_roles", [])):
                    role = {"kind": "identity", "id": arn, "name": name, "account": account,
                            "region": resource["region"], "source": "inventory", "resource": resource}
                    self.add("identity", arn, role)
                    self.add("identity", name, role)
        except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
            raise ValueError(f"Cannot load inventory export {path}: {error}") from error

    def add(self, kind, value, match):
        if value:
            matches = self.index.setdefault((kind, value), [])
            if match not in matches:
                matches.append(match)

    def lookup(self, kind, value, account, region):
        matches = self.index.get((kind, value), [])
        if kind == "identity" and re.fullmatch(r"arn:[^:]+:sts::[^:]+:assumed-role/[^/]+/[^/]+", value):
            matches = self.index.get(("assumed-role", value.rsplit("/", 1)[0]), [])
        return [match for match in matches
                if (not account or match["account"] == account)
                and (not region or match["region"] in (region, "global"))]


def reference(body, inventory, connection, commands, enrichment):
    """Only historical lookups need the Store lock. Missing history is never negative evidence."""
    kind, value = body.get("kind"), body.get("value")
    if kind not in ("identity", "machine", "ip") or not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("Reference requires kind identity, machine or ip and a value up to 2048 characters")
    account, region = body.get("account"), body.get("region")
    if any(v is not None and (not isinstance(v, str) or len(v) > 256) for v in (account, region)):
        raise ValueError("Reference account and region must be strings up to 256 characters")
    include_history = body.get("include_history", True)
    if not isinstance(include_history, bool):
        raise ValueError("Reference include_history must be a boolean")
    lookup_value = value
    if kind == "ip":
        try:
            lookup_value = str(ipaddress.ip_address(value))
        except ValueError:
            raise ValueError("Reference ip must be an IPv4 or IPv6 address") from None
    matches = inventory.lookup(kind, lookup_value, account, region)
    network_matches = []
    history_association = None
    if kind == "ip":
        address = ipaddress.ip_address(lookup_value)
        network_matches = [match for prefix, match in inventory.networks
                           if address in prefix and (not account or match["account"] == account)
                           and (not region or match["region"] == region)]
    if include_history and kind in ("identity", "ip"):
        # Group by account AND region: repeated names/addresses must never collapse scope.
        identity = "coalesce(e.identity_arn, e.user_identity->>'$.userName', e.user_identity->>'$.principalId', e.user_identity->>'$.invokedBy', '(unattributed)')"
        actor_account = f"coalesce(e.user_identity->>'$.accountId', CASE WHEN starts_with({identity}, 'arn:') THEN split_part({identity}, ':', 5) END, e.recipient_account_id, '')"
        scope = actor_account if kind == "identity" else "coalesce(e.recipient_account_id, '')"
        predicate = f"({identity} = ? OR e.user_identity->>'$.userName' = ?)" if kind == "identity" else "e.source_ip = ?"
        params = [value, value] if kind == "identity" else [value]
        association = "Exact event identity; no incident-time association to the current IAM snapshot is established"
        iam_matches = [m for m in matches if m.get("iam")]
        if kind == "identity" and len(iam_matches) == 1:
            entity = iam_matches[0]["iam"]
            if entity.get("UserName"):
                predicate = "e.identity_arn = ? AND e.user_identity->>'$.principalId' = ?"
                params = [entity["Arn"], entity["UserId"]]
                association = "Exact IAM user ARN and stable principal ID; events missing that ID are excluded"
            elif entity.get("RoleName") and value in (entity["Arn"], entity["RoleName"], entity["RoleId"]):
                predicate = "e.user_identity->>'$.sessionContext.sessionIssuer.arn' = ? AND e.user_identity->>'$.sessionContext.sessionIssuer.principalId' = ?"
                params = [entity["Arn"], entity["RoleId"]]
                association = "Exact role session-issuer ARN and stable ID; sessions remain separate and do not identify the human actor"
            elif entity.get("GroupName"):
                predicate, params = "false", []
                association = "IAM groups are not event principals; member activity is not attributed to the group"
        history_association = association
        if account:
            predicate += f" AND {scope} = ?"
            params.append(account)
        if region:
            predicate += " AND e.aws_region = ?"
            params.append(region)
        started = time.monotonic()
        # Classify only explicitly reported values. False session context is not proof
        # of no upstream IdP MFA, and failed sign-ins are not successful authentication.
        buckets = {
            "console_success_with_mfa": "console AND login_result = 'Success' AND console_mfa = 'Yes'",
            "console_success_without_mfa": "console AND login_result = 'Success' AND console_mfa = 'No'",
            "console_success_mfa_unknown": "console AND login_result = 'Success' AND (console_mfa IS NULL OR console_mfa NOT IN ('Yes', 'No'))",
            "console_failed_or_result_unknown": "console AND (login_result IS NULL OR login_result <> 'Success')",
            "session_mfa_authenticated": "NOT console AND session_mfa = 'true'",
            "session_mfa_not_authenticated": "NOT console AND session_mfa = 'false'",
            "session_mfa_unknown": "NOT console AND (session_mfa IS NULL OR session_mfa NOT IN ('true', 'false'))",
        }
        counts = ", ".join(f"count(*) FILTER (WHERE {test})" for test in buckets.values())
        samples = ", ".join(f"min(record_sha256) FILTER (WHERE {test})" for test in buckets.values())
        rows = connection.execute(f"""WITH observed AS (
                SELECT {identity} AS identity, {scope} AS account, e.aws_region AS region,
                    e.user_identity->>'$.principalId' AS principal_id, e.event_time, e.record_sha256,
                    coalesce(e.event_source = 'signin.amazonaws.com' AND e.event_name = 'ConsoleLogin', false) AS console,
                    CASE WHEN e.error_code IS NULL THEN e.raw_event->>'$.responseElements.ConsoleLogin' END AS login_result,
                    e.raw_event->>'$.additionalEventData.MFAUsed' AS console_mfa,
                    e.user_identity->>'$.sessionContext.attributes.mfaAuthenticated' AS session_mfa
                FROM events e WHERE {predicate})
            SELECT identity, account, region, principal_id, count(*), min(event_time)::VARCHAR, max(event_time)::VARCHAR,
                {counts}, {samples}
            FROM observed GROUP BY ALL ORDER BY account, region, identity, principal_id""", params).fetchall()
        logger.debug("query operation=reference.events kind=%s elapsed_ms=%.3f rows=%d",
                     kind, (time.monotonic() - started) * 1000, len(rows))
        for identity, acct, rn, principal_id, count, first, last, *activity in rows:
            matches.append({"kind": kind, "id": identity if kind == "identity" else value,
                            "name": identity if kind == "identity" else value, "account": acct, "region": rn,
                            "source": "cloudtrail", "identity": {"arn": identity, "event_count": count,
                            "principal_id": principal_id, "first_seen": first, "last_seen": last},
                            "association": association,
                            "mfa": {**dict(zip(buckets, activity[:len(buckets)])),
                                    "samples": [{"category": key, "record_sha256": hash_}
                                                for key, hash_ in zip(buckets, activity[len(buckets):]) if hash_]}})
    elif include_history and kind == "machine":
        started = time.monotonic()
        systems = {}
        for command in commands.commands.values():
            if (account and command["account"] != account) or (region and command["region"] != region):
                continue
            for system in command["systems"]:
                if value not in (system["instance_id"], (system["invocation"] or {}).get("InstanceName")):
                    continue
                key = (command["account"], command["region"], system["instance_id"])
                systems[key] = systems.get(key, 0) + 1
        for (acct, rn, identifier), count in sorted(systems.items()):
            matches.append({"kind": kind, "id": identifier, "name": value, "account": acct, "region": rn,
                            "source": "ssm", "command_count": count})
        logger.debug("reference operation=reference.ssm elapsed_ms=%.3f groups=%d",
                     (time.monotonic() - started) * 1000, len(systems))
    if kind == "ip" and value in enrichment:
        matches.append({"kind": kind, "id": value, "name": value, "account": "", "region": "",
                        "source": "enrichment", "enrichment": enrichment[value]})
    # A lookup about an IP is not an assertion that historical traffic came from its current owner.
    # Flag competing owners/scopes without treating enrichment as another candidate entity.
    relevant = [m for m in matches if m["source"] != "enrichment"]
    if kind == "ip":
        scopes = {(m["account"], m["region"]) for m in relevant}
        owners = {(m["account"], m["region"], m["id"]) for m in relevant if m["source"] == "inventory"}
        ambiguous = len(scopes) > 1 or len(owners) > 1
    else:
        entities = {(m["account"], "" if kind == "identity" else m["region"], m["id"]) for m in relevant}
        ambiguous = len(entities) > 1
    history_coverage = None
    if include_history and kind in ("identity", "ip"):
        first, last = connection.execute("SELECT min(event_time)::VARCHAR, max(event_time)::VARCHAR FROM events").fetchone()
        history_coverage = {"first_event": first, "last_event": last, "account": account, "region": region,
                            "scope": "Entire imported CloudTrail database, independent of the active event filters; gaps and uncollected dates may exist"}
    return {"kind": kind, "value": value, "matches": matches, "network_matches": network_matches, "ambiguous": ambiguous,
            "snapshot": inventory.report["metadata"], "history_included": include_history,
            "history_coverage": history_coverage,
            "history_association": history_association,
            "iam_coverage": {key: inventory.report.get("iam", {}).get(key) for key in ("started_at_utc", "completed_at_utc", "errors")}}
