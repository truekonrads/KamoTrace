"""Read retained native Iwatobi alerts and attach exact occurrences in declared coverage.

No detector is invoked and no evidence or retained alert is rewritten. Matching is
deliberately conservative: every reference of every member must identify the same
single physical observation, and every member must resolve before an alert links.
"""
from collections import Counter, defaultdict
import hashlib
import re

import simplejson as json

from .suzaku import LEVELS, evidence_identity


def reference_key(acquisition, reference):
    """The full supplied acquisition/source/physical-locator identity, never text/time."""
    if not isinstance(acquisition, dict) or not isinstance(reference, dict):
        return None
    locator = reference.get("locator")
    if (acquisition.get("status") != "supplied" or not isinstance(acquisition.get("id"), str) or not acquisition["id"]
            or reference.get("exact") is not True or not isinstance(locator, dict)
            or set(locator) != {"kind", "coordinate", "line"}
            or locator.get("kind") != "text_line"
            or locator.get("coordinate") != "decoded_decompressed_1_based"
            or type(locator.get("line")) is not int or locator["line"] < 1
            or not all(isinstance(reference.get(k), str) and reference[k]
                       for k in ("collection_id", "path", "sha256"))
            or re.fullmatch(r"[0-9a-f]{64}", reference["sha256"]) is None):
        return None
    return (acquisition["id"], acquisition["status"], reference["collection_id"],
            reference["path"], reference["sha256"], locator["line"])


def load(connection, path, event_sources):
    """Populate shared detection relations; return provenance and compact alert receipts."""
    if path is None:
        return None, []
    data = path.read_bytes()
    bundle_sha256 = hashlib.sha256(data).hexdigest()
    bundle = json.loads(data, use_decimal=True, allow_nan=False)
    if (not isinstance(bundle, dict) or bundle.get("schema") != "iwatobi-forensic-1.0.0"
            or bundle.get("source_reference_profile") != "uac-1.0.0"
            or not isinstance(bundle.get("run"), dict)
            or not isinstance(bundle.get("alerts"), list)):
        raise ValueError("Expected native Iwatobi iwatobi-forensic-1.0.0 / uac-1.0.0 bundle")
    if not isinstance(bundle["run"].get("id"), str) or not bundle["run"]["id"].strip():
        raise ValueError("Invalid native Iwatobi run identity: expected a non-empty string")
    if not isinstance(bundle["run"].get("rules", []), list):
        raise ValueError("Invalid native Iwatobi run.rules: expected an array")
    if not isinstance(bundle.get("sources", []), list):
        raise ValueError("Invalid native Iwatobi sources: expected an array")
    targets = set()
    for alert in bundle["alerts"]:
        if (not isinstance(alert, dict) or not isinstance(alert.get("id"), str) or not alert["id"].strip()
                or not isinstance(alert.get("rule"), dict)
                or not isinstance(alert["rule"].get("id"), str) or not alert["rule"]["id"].strip()):
            raise ValueError("Invalid native Iwatobi alert/rule identity: expected non-empty strings")
        if (not isinstance(alert.get("members"), list) or not isinstance(alert.get("uac", {}), dict)):
            raise ValueError("Invalid native Iwatobi member/acquisition structure")
        native_run = alert.get("uac", {})
        if "run_id" in native_run and (not isinstance(native_run["run_id"], str) or not native_run["run_id"].strip()):
            raise ValueError("Invalid native Iwatobi member run identity: expected a non-empty string")
        acquisition = alert.get("uac", {}).get("acquisition")
        for member in alert.get("members", []):
            if (not isinstance(member, dict) or not isinstance(member.get("evidence"), dict)
                    or not isinstance(member["evidence"].get("location"), dict)
                    or not isinstance(member["evidence"]["location"].get("source_refs", []), list)):
                raise ValueError("Invalid native Iwatobi evidence location structure")
            for ref in member.get("evidence", {}).get("location", {}).get("source_refs", []):
                key = reference_key(acquisition, ref)
                if key is not None:
                    targets.add(key)
    candidates = defaultdict(set)
    # Only selected admitted parse-only units. Stream bounded batches of original
    # JSON text: DuckDB JSON subtree extraction can round numeric locator values.
    units = [s["unit_id"] for s in event_sources if s.get("adapter") == "tracequarry-parse-only-v1"]
    connection.execute("""SELECT source_record, raw_event FROM events
        WHERE unit_id IN (SELECT unnest(?::VARCHAR[]))""", [units])
    while rows := connection.fetchmany(2048):
        for record, text in rows:
            uac = json.loads(text, use_decimal=True).get("uac", {}) if text else {}
            for ref in uac.get("source_refs", []):
                key = reference_key(uac.get("acquisition"), ref)
                if key in targets:
                    candidates[key].add(record)
    receipts, rule_numbers = [], {}
    next_rule = connection.execute("SELECT coalesce(max(detection_rule), 0) FROM detection_rules").fetchone()[0]
    for ordinal, alert in enumerate(bundle["alerts"], 1):
        members = []
        acquisition = alert.get("uac", {}).get("acquisition")
        for index, member in enumerate(alert.get("members", []), 1):
            location = member.get("evidence", {}).get("location", {})
            refs = location.get("source_refs", [])
            keys = [reference_key(acquisition, ref) for ref in refs]
            supported = location.get("status") == "exact" and bool(keys) and all(k is not None for k in keys)
            sets = [candidates[k] for k in keys] if supported else []
            # Each reference must uniquely identify the SAME observation. Multiple
            # emissions/import occurrences remain ambiguous even with equal hashes.
            ids = set.union(set(), *sets)
            status = ("unsupported" if not supported else "ambiguous" if len(ids) > 1
                      else "no_match" if any(not s for s in sets) else "linked")
            members.append({"member": index, "status": status, "candidates": len(ids),
                            "event_ids": sorted(ids) if status == "linked" else []})
        complete = (bool(members) and alert.get("evidence_status") == "exact"
                    and alert.get("kind") in ("single", "correlation")
                    and alert.get("members_truncated") is False
                    and type(alert.get("members_total")) is int
                    and alert.get("members_total") == len(members))
        statuses = {m["status"] for m in members}
        status = ("unsupported" if not complete or "unsupported" in statuses else
                  "ambiguous" if "ambiguous" in statuses else "no_match" if "no_match" in statuses else "linked")
        rule = alert["rule"]
        rule_id = "iwatobi:" + rule["id"]
        receipt = {"ordinal": ordinal, "id": alert["id"], "kind": alert.get("kind"),
                   "bundle_sha256": bundle_sha256, "run_id": bundle["run"]["id"],
                   "native_run_id": alert.get("uac", {}).get("run_id"),
                   "rule_id": rule_id, "native_rule_id": rule.get("id"), "title": rule.get("name"),
                   "evidence_status": alert.get("evidence_status"), "members_total": alert.get("members_total"),
                   "members_truncated": alert.get("members_truncated"),
                   "status": status, "members": members,
                   "event_ids": sorted({r for m in members for r in m["event_ids"]}) if status == "linked" else []}
        receipts.append(receipt)
        if status != "linked":
            continue
        level = str(rule.get("level", "informational")).lower()
        if level not in LEVELS:
            level = "informational"
        title = "Iwatobi · " + str(rule.get("name") or rule.get("id") or "Unnamed rule")
        metadata = (rule_id, title, level)
        if metadata not in rule_numbers:
            next_rule += 1
            rule_numbers[metadata] = next_rule
            connection.execute("INSERT INTO detection_rules VALUES (?,?,?,?,?,?,?)",
                               [next_rule, rule_id, title, level, LEVELS.index(level), [], []])
        for record in receipt["event_ids"]:
            connection.execute("INSERT INTO detection_links VALUES (?,?)", [record, rule_numbers[metadata]])
    counts = Counter(r["status"] for r in receipts)
    return {"schema": bundle["schema"], "source_reference_profile": bundle["source_reference_profile"],
            "bundle_sha256": bundle_sha256,
            "run": {k: v for k, v in bundle["run"].items() if k not in ("rules", "loaded_rules", "loaded_correlations")},
            "rules_count": len(bundle["run"].get("rules", [])), "sources_count": len(bundle.get("sources", [])),
            "uac": bundle.get("uac"), "alerts": len(receipts),
            "counts": {s: counts[s] for s in ("linked", "no_match", "ambiguous", "unsupported")},
            "member_counts": dict(Counter(m["status"] for r in receipts for m in r["members"])),
            "selection_id": evidence_identity(connection)[0],
            "link_basis": "Supplied acquisition, exact collection/path/source SHA256 and full physical locator; "
                          "every reference uniquely resolves to one occurrence, all members required. "
                          "Only text_line decoded_decompressed_1_based locators supported; no time/text/IP guesses."}, receipts
