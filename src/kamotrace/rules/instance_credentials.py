"""Find explicitly EC2-issued credentials used outside supplied network context."""
from bisect import bisect_right
from datetime import datetime
import ipaddress
import re

ID = "kamotrace:ec2-credentials-unexpected-source"
VERSION = 1
TITLE = "KamoTrace: Possible EC2 credential use from unexpected source"
LEVEL = "medium"
TACTICS = ["credential-access"]
TECHNIQUES = ["T1552.005"]


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("Context timestamps must be ISO 8601 strings with an offset")
    stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if stamp.tzinfo is None:
        raise ValueError("Context timestamps must include an offset")
    return stamp


def prepare(context):
    """Validate explicit historical context, never discover current network state."""
    if not isinstance(context, dict) or not isinstance(context.get("source"), str) or not context["source"].strip():
        raise ValueError("Network context requires a source description")
    start, end = timestamp(context["valid_from"]), timestamp(context["valid_until"])
    if start >= end:
        raise ValueError("Context valid_until must be after valid_from")

    def networks(values):
        if not isinstance(values, list) or not values or any(not isinstance(v, str) for v in values):
            raise ValueError("Network prefixes must be a nonempty list of CIDR strings")
        return [ipaddress.ip_network(value, strict=True) for value in values]

    aws = networks(context["aws_prefixes"]) if "aws_prefixes" in context else []
    instances = {}
    if not isinstance(context.get("instances", []), list):
        raise ValueError("instances must be a list")
    for entry in context.get("instances", []):
        if not isinstance(entry, dict):
            raise ValueError("Each instance context must be an object")
        account, instance = entry["account"], entry["instance_id"]
        if (not isinstance(account, str) or not isinstance(instance, str)
                or not re.fullmatch(r"\d{12}", account) or not re.fullmatch(r"i-(?:[0-9a-f]{8}|[0-9a-f]{17})", instance)):
            raise ValueError("Expected a 12-digit account and EC2 instance ID")
        key = (account, instance)
        if key in instances:
            raise ValueError("Duplicate instance network context")
        instances[key] = networks(entry["expected_egress"])
    if not aws and not instances:
        raise ValueError("Supply aws_prefixes and/or instances with expected_egress")
    return start, end, aws, instances


def run(connection, context):
    """Return exact evidence matches plus explicit assessment/coverage counters."""
    if context is None:
        return [], {"status": "skipped", "reason": "No network context supplied"}
    start, end, aws, instances = prepare(context)
    # Collapse overlaps once, then use logarithmic lookup rather than scanning
    # thousands of AWS prefixes for every CloudTrail record.
    aws_ranges = {}
    for version in (4, 6):
        networks = list(ipaddress.collapse_addresses(n for n in aws if n.version == version))
        aws_ranges[version] = ([int(n.network_address) for n in networks],
                               [int(n.broadcast_address) for n in networks])
    counts = {"status": "completed", "candidates": 0, "assessed": 0, "matches": 0,
              "outside_context_interval": 0, "non_public_or_non_ip_source": 0,
              "missing_network_context": 0, "service_mediated": 0}
    counts["assumed_role_events_without_ec2_marker"] = connection.execute("""SELECT count(*) FROM ev.events
        WHERE identity_type = 'AssumedRole' AND coalesce(
        user_identity->>'$.sessionContext.ec2RoleDelivery', '') NOT IN ('1.0', '2.0')""").fetchone()[0]
    matches = []
    connection.execute("""SELECT source_record, record_sha256, epoch(event_time), source_ip,
        user_identity->>'$.accountId', user_identity->>'$.arn',
        user_identity->>'$.accessKeyId', user_identity->>'$.invokedBy', error_code,
        user_identity->>'$.sessionContext.ec2RoleDelivery'
        FROM ev.events WHERE identity_type = 'AssumedRole'
        AND user_identity->>'$.sessionContext.ec2RoleDelivery' IN ('1.0', '2.0')""")
    while rows := connection.fetchmany(8192):
        for record, digest, time, source, account, arn, key, invoked_by, error, delivery in rows:
            counts["candidates"] += 1
            if time is None or not start.timestamp() <= time < end.timestamp():
                counts["outside_context_interval"] += 1
                continue
            if invoked_by:
                counts["service_mediated"] += 1
                continue
            try:
                address = ipaddress.ip_address(source)
            except ValueError:
                counts["non_public_or_non_ip_source"] += 1
                continue
            if not address.is_global:
                counts["non_public_or_non_ip_source"] += 1
                continue
            # The delivery marker proves credential origin; the ARN's session suffix only
            # selects supplied per-instance context. Never infer origin from that suffix alone.
            identity = re.fullmatch(r"arn:[^:]+:sts::(\d{12}):assumed-role/.+/(i-(?:[0-9a-f]{8}|[0-9a-f]{17}))", arn or "")
            instance = identity[2] if identity and identity[1] == account else None
            expected = instances.get((account, instance), [])
            starts, ends = aws_ranges[address.version]
            if not starts and not expected:
                counts["missing_network_context"] += 1
                continue
            counts["assessed"] += 1
            position = bisect_right(starts, int(address)) - 1
            inside_aws = position >= 0 and int(address) <= ends[position]
            inside_expected = any(address in network for network in expected)
            reasons = []
            if expected and not inside_expected:
                reasons.append("outside supplied expected instance egress")
            # Expected egress explicitly allows legitimate non-AWS gateways.
            if starts and not inside_aws and not inside_expected:
                reasons.append("outside supplied AWS address ranges (not proof of non-AWS ownership)")
            if reasons:
                matches.append((record, digest, {"reasons": reasons, "source_ip": source,
                    "account": account, "instance_id": instance, "session_arn": arn,
                    "access_key_id": key, "ec2_role_delivery": delivery, "error_code": error,
                    "context_source": context["source"], "expected_egress": [str(n) for n in expected]}))
    counts["matches"] = len(matches)
    return matches, counts
