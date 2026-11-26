"""Bounded, evidence-only computer context; never infer machines from network peers."""
import ipaddress
import json


SCAN_LIMIT = 10000
VALUE_LIMIT = 8


def object_at(value, *path):
    for key in path:
        value = value.get(key) if isinstance(value, dict) else None
    return value


def text(value):
    return value if isinstance(value, str) and 0 < len(value) <= 256 else None


def summarize(connection, dataset, metadata, inventory):
    """Read only projected ECS context, not commands or producer analysis outputs.

    A label is not a stable computer ID. Unidentified observations are not folded
    into a named computer, even when only one name occurs in an acquisition.
    """
    manifest = metadata["tracequarry"]["manifest"]
    settings = manifest.get("settings", {})
    groups = {}
    cursor = connection.execute("""SELECT source_record, record_sha256,
        json_extract(raw_event, '$.host'), json_extract(raw_event, '$.cloud'),
        json_extract(raw_event, '$.uac'),
        json_extract(raw_event, '$.tracequarry.extra.host_basis')
        FROM events WHERE dataset_index=? ORDER BY source_record LIMIT ?""", [dataset, SCAN_LIMIT + 1])
    scanned = 0
    while row := cursor.fetchone():
        if scanned == SCAN_LIMIT:
            break
        scanned += 1
        record, digest, host, cloud, uac, basis = row
        host, cloud, uac = (json.loads(v) if v else {} for v in (host, cloud, uac))
        host = host if isinstance(host, dict) else {}
        acquisition = text(object_at(uac, "acquisition", "id"))
        collection = text(object_at(uac, "collection", "id"))
        host_id = text(host.get("id"))
        name = text(host.get("name"))
        # Host labels remain explicitly unverified groups, never claimed unique computers.
        key = (acquisition, collection, "id" if host_id else "label" if name else "unbound", host_id or name)
        if key not in groups:
            groups[key] = {"dataset_index": dataset, "acquisition_id": acquisition,
                "collection_id": collection, "identity_basis": key[2], "identity": key[3],
                "sample_record": record,
                "observations": 0, "facts": {}, "aws_claims": [], "aws_claims_overflow": False}
        group = groups[key]
        group["observations"] += 1
        # Original detail remains authoritative; bounded samples identify its exact row/hash.
        provenance = {"record": record, "record_sha256": digest,
            "time_basis": text(object_at(uac, "time", "basis")),
            "selected_time": text(object_at(uac, "time", "selected"))}
        candidates = object_at(uac, "time", "candidates")
        provenance["timestamp"] = next((text(c.get("value")) for c in candidates
            if isinstance(c, dict) and c.get("id") == provenance["selected_time"]), None) if isinstance(candidates, list) else None

        def add(field, value):
            if value is None or value == "":
                return
            values = group["facts"].setdefault(field, {"values": [], "overflow": False})
            if any(v["value"] == value for v in values["values"]):
                return
            if len(values["values"]) == VALUE_LIMIT:
                values["overflow"] = True
                return
            values["values"].append({"value": value, "provenance": provenance})

        add("hostname", name)
        add("host_id", host_id)
        add("host_basis", text(json.loads(basis)) if basis else None)
        for field in ("architecture", "type"):
            add(field, text(host.get(field)))
        for field in ("name", "version", "kernel"):
            add("os_" + field, text(object_at(host, "os", field)))
        uptime = host.get("uptime")
        if type(uptime) in (int, float) and 0 <= uptime < 10**12:
            add("uptime_seconds", uptime)
        ips = host.get("ip", [])
        for ip in ips if isinstance(ips, list) else [ips]:
            if not isinstance(ip, str):
                continue
            try:
                add("host_ip", str(ipaddress.ip_address(ip)))
            except (ValueError, TypeError):
                pass
        claim = {"provider": text(object_at(cloud, "provider")),
            "account": text(object_at(cloud, "account", "id")),
            "region": text(object_at(cloud, "region")),
            "instance": text(object_at(cloud, "instance", "id"))}
        if any(claim.values()) and claim not in group["aws_claims"]:
            if len(group["aws_claims"]) < VALUE_LIMIT:
                group["aws_claims"].append(claim)
            else:
                group["aws_claims_overflow"] = True
        if any(claim.values()):
            add("cloud_identity", claim)
    if not groups:
        groups[(None, None, "unbound", None)] = {"dataset_index": dataset,
            "acquisition_id": settings.get("acquisition_id"), "collection_id": manifest.get("collection_id"),
            "identity_basis": "unbound", "identity": None, "sample_record": None, "observations": 0, "facts": {},
            "aws_claims": [], "aws_claims_overflow": False}
    for group in groups.values():
        claims = group.pop("aws_claims")
        overflow = group.pop("aws_claims_overflow")
        link = {"status": "unavailable", "reason": "No complete, host-bound AWS identity in acquired evidence"}
        # A label/collection does not prove all records refer to one computer.
        if metadata["records"] > scanned and claims:
            link = {"status": "ambiguous", "reason": "Summary scan truncated; unseen identity conflicts cannot be excluded"}
        elif group["identity_basis"] != "id" and claims:
            link = {"status": "ambiguous", "reason": "AWS claim lacks a stable host ID; no automatic association"}
        elif len(claims) > 1 or overflow:
            link = {"status": "ambiguous", "reason": "Conflicting or incomplete AWS identity claims; no automatic association"}
        elif claims and claims[0]["provider"] == "aws" and all(claims[0].values()):
            claim = claims[0]
            matches = [m for m in inventory.lookup("machine", claim["instance"], claim["account"], claim["region"])
                       if m["id"] == claim["instance"] and m["region"] == claim["region"]
                       and m.get("resource", {}).get("kind") == "EC2"]
            link = {"status": "matched" if len(matches) == 1 else "ambiguous" if matches else "no_match",
                "reason": ("Exact acquired instance ID, account and region" if len(matches) == 1 else
                           "Multiple exact EC2 inventory candidates" if matches else "No exact EC2 match in loaded inventory")
                          + "; inventory is a separate snapshot, not incident-time state",
                **claim}
        group["aws"] = link
        group["run_id"] = manifest.get("run_id")
        group["acquisition_time"] = settings.get("acquisition_time")
        group["acquisition_basis"] = settings.get("acquisition_basis")
        group["collection_label"] = settings.get("host")
    return {"dataset_index": dataset, "imported_at": metadata.get("imported_at"),
        "manifest_sha256": metadata.get("source_sha256"), "run_id": manifest.get("run_id"),
        "records": metadata["records"], "scanned": scanned, "scan_limit": SCAN_LIMIT,
        "truncated": metadata["records"] > scanned, "cards": list(groups.values())}
