"""Read-only current-configuration inventory and exact, scope-aware reference lookups."""
import ipaddress
import json
from pathlib import Path


COLLECTIONS = ("resources", "vpcs", "security_groups", "relationships", "forwarding_paths", "listener_actions", "errors")


class Inventory:
    def __init__(self, folder=None):
        self.report = {"loaded": False, "metadata": None, "counts": {}, **{key: [] for key in COLLECTIONS}}
        self.index = {}
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
        return [match for match in self.index.get((kind, value), [])
                if (not account or match["account"] == account) and (not region or match["region"] == region)]


def reference(body, inventory, connection, commands):
    """Caller holds the Store lock. Context narrows exact matches; it never supplies missing evidence."""
    kind, value = body.get("kind"), body.get("value")
    if kind not in ("identity", "machine", "ip") or not isinstance(value, str) or not 1 <= len(value) <= 2048:
        raise ValueError("Reference requires kind identity, machine or ip and a value up to 2048 characters")
    account, region = body.get("account"), body.get("region")
    if any(v is not None and (not isinstance(v, str) or len(v) > 256) for v in (account, region)):
        raise ValueError("Reference account and region must be strings up to 256 characters")
    lookup_value = value
    if kind == "ip":
        try:
            lookup_value = str(ipaddress.ip_address(value))
        except ValueError:
            raise ValueError("Reference ip must be an IPv4 or IPv6 address") from None
    matches = inventory.lookup(kind, lookup_value, account, region)
    if kind in ("identity", "ip"):
        # Group by account AND region: repeated names/addresses must never collapse scope.
        actor_account = "coalesce(e.user_identity->>'$.accountId', CASE WHEN starts_with(b.identity, 'arn:') THEN split_part(b.identity, ':', 5) END, e.recipient_account_id, '')"
        scope = actor_account if kind == "identity" else "coalesce(e.recipient_account_id, '')"
        predicate = "(b.identity = ? OR e.user_identity->>'$.userName' = ?)" if kind == "identity" else "b.source_ip = ?"
        params = [value, value] if kind == "identity" else [value]
        if account:
            predicate += f" AND {scope} = ?"
            params.append(account)
        if region:
            predicate += " AND b.region = ?"
            params.append(region)
        rows = connection.execute(f"""SELECT b.identity, {scope} AS account, b.region,
                count(*), min(e.event_time)::VARCHAR, max(e.event_time)::VARCHAR
            FROM browse_events b JOIN events e ON e.source_record = b.id
            WHERE {predicate} GROUP BY ALL ORDER BY account, b.region, b.identity""", params).fetchall()
        for identity, acct, rn, count, first, last in rows:
            matches.append({"kind": kind, "id": identity if kind == "identity" else value,
                            "name": identity if kind == "identity" else value, "account": acct, "region": rn,
                            "source": "cloudtrail", "identity": {"arn": identity, "event_count": count,
                            "first_seen": first, "last_seen": last}})
        if kind == "ip":
            row = connection.execute("SELECT country, city, asn, isp, ip_info FROM ip_enrichment WHERE ip = ?", [value]).fetchone()
            if row:
                matches.append({"kind": kind, "id": value, "name": value, "account": "", "region": "",
                                "source": "enrichment", "enrichment": dict(zip(("country", "city", "asn", "isp", "ip_info"), row))})
    elif kind == "machine":
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
    return {"kind": kind, "value": value, "matches": matches, "ambiguous": ambiguous,
            "snapshot": inventory.report["metadata"]}
