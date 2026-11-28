"""Admit a completed TraceQuarry parse-only acquisition into a fresh case.

Envelope checks and occurrence review identity are ported from preserved source
20e6cca/1ce0825, not from that branch's older viewer or recovery machinery.
"""
import argparse
from datetime import datetime
import hashlib
import ipaddress
from pathlib import Path

import duckdb
import simplejson as json

from .importer import publish, sha256, staging, write_lock
from .other_events import EVENTS_VIEW, FORMAT, initialize, insert_batch, now

EVENT_PROJECTION = (EVENTS_VIEW.replace("NULL::VARCHAR AS event_id", "raw_event->>'$.event.id' AS event_id")
                    .replace("$.date", "$.@timestamp")
                    .replace("raw_event->>'$.ip'", "coalesce(raw_event->>'$.source.ip', raw_event->>'$.client.ip', raw_event->>'$.destination.ip', raw_event->>'$.server.ip')")
                    .replace("$.identity", "$.user.name").replace("$.content", "$.message"))


def ip_attributes(value, record):
    """Retain the preserved adapter's typed IP attributes and multiplicity."""
    for namespace in ("source", "destination", "client", "server", "host", "related"):
        candidates = value.get(namespace, {}).get("ip", [])
        for candidate in candidates if isinstance(candidates, list) else [candidates]:
            try:
                ipaddress.ip_address(candidate)
            except (ValueError, TypeError):
                continue
            yield record, namespace + ".ip", candidate


def insert_observations(connection, batch, ips):
    insert_batch(connection, batch)
    for start in range(0, len(ips), 1000):
        rows = ips[start:start + 1000]
        connection.execute("INSERT INTO uac_ip_attributes VALUES "
                           + ",".join(["(?::BIGINT,?::VARCHAR,?::VARCHAR)"] * len(rows)),
                           [value for row in rows for value in row])


def load_object(path):
    value = json.loads(path.read_text(encoding="utf-8"), use_decimal=True, allow_nan=False)
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path.name}")
    return value


def check_manifest(manifest):
    required = {"mode": "parse_only", "status": "complete", "ecs_version": "8.17.0",
                "time_policy": "claim-time-v1", "identity_policy": "source-emission-v1",
                "deduplication": "none", "input_verification": "hash_size_mtime_verified"}
    if any(manifest.get(k) != v for k, v in required.items()):
        raise ValueError("Expected a completed, input-verified compatible TraceQuarry parse-only run")
    if manifest.get("uac_profile_version") not in ("1.0.0", "1.1.0"):
        raise ValueError("Unsupported UAC profile version")
    if manifest.get("analysis") != {"status": "not_run"} or not manifest.get("run_id"):
        raise ValueError("Expected analysis not_run and an explicit run_id")
    if not isinstance(manifest.get("coverage"), dict) or type(manifest["coverage"].get("events")) is not int:
        raise ValueError("Missing TraceQuarry event coverage count")


def check_record(value, manifest):
    """Check interchange, not a second implementation of upstream parsers."""
    try:
        event, uac = value["event"], value["uac"]
        identity, timing = uac["identity"], uac["time"]
        if (value["ecs"]["version"] != manifest["ecs_version"]
                or uac["profile_version"] != manifest["uac_profile_version"]
                or uac["run_id"] != manifest["run_id"]
                or identity["policy"] != manifest["identity_policy"]
                or timing["policy"] != manifest["time_policy"]
                or event["module"] != "tracequarry"
                or not isinstance(event["id"], str) or not event["id"]
                or event["id"] != identity["emission_id"]
                or not isinstance(uac["source_refs"], list)):
            raise ValueError("Observation envelope disagrees with run manifest")
        timestamp = value.get("@timestamp")
        selected = next((c for c in timing["candidates"] if c["id"] == timing["selected"]), None)
        if timestamp is None:
            if timing["selected"] is not None:
                raise ValueError("Selected time is missing @timestamp")
        else:
            if not isinstance(timestamp, str):
                raise ValueError("Invalid @timestamp")
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None or selected is None or selected["value"] != timestamp:
                raise ValueError("Timestamp must retain its explicit selected time basis")
        if uac["collection"]["id"] != manifest["collection_id"]:
            raise ValueError("Observation collection differs from manifest")
    except (KeyError, TypeError, AttributeError, StopIteration) as error:
        raise ValueError("Invalid TraceQuarry observation envelope") from error


def build(source, database, *, allocate, case_unit):
    source, database = Path(source).resolve(), Path(database).resolve()
    manifest_path = source / "run_manifest.json"
    with write_lock(database):
        if database.exists():
            raise FileExistsError("Use a new database path; existing datasets are never overwritten")
        manifest_hash = sha256(manifest_path)
        manifest = load_object(manifest_path)
        check_manifest(manifest)
        outputs = manifest.get("outputs", [])
        if (not isinstance(outputs, list) or len(outputs) != 2 or
                {o.get("name") for o in outputs if isinstance(o, dict)} != {"observations.jsonl", "source_index.json"}):
            raise ValueError("Expected exactly the finalized observations and source index outputs")
        expected = {manifest_path: manifest_hash}
        for output in outputs:
            path = source / output["name"]
            if path.stat().st_size != output.get("size") or sha256(path) != output.get("sha256"):
                raise ValueError(f"TraceQuarry output size/hash mismatch: {path.name}")
            expected[path] = output["sha256"]
        index = load_object(source / "source_index.json")
        if index.get("analysis") != {"status": "not_run"} or not isinstance(index.get("sources"), list):
            raise ValueError("Missing source coverage ledger or analysis not_run")
        coverage = manifest["coverage"]
        origin = (f"TraceQuarry parse-only; analysis not run; selected parser patterns only; "
                  f"sources partial={coverage.get('sources_partial', 'unknown')}, "
                  f"error={coverage.get('sources_error', 'unknown')}, "
                  f"unsupported={coverage.get('sources_unsupported', 'unknown')}")
        imported, count, undated = now(), 0, 0
        with staging(database) as target:
            connection = duckdb.connect(str(target))
            try:
                connection.execute("SET threads=2; SET memory_limit='1GB'; SET TimeZone='UTC'")
                connection.execute("BEGIN TRANSACTION")
                initialize(connection)
                connection.execute("CREATE TABLE uac_ip_attributes(source_record BIGINT, field VARCHAR, ip VARCHAR)")
                connection.execute("CREATE OR REPLACE VIEW events AS " + EVENT_PROJECTION)
                batch, ips, batch_bytes = [], [], 0
                with (source / "observations.jsonl").open(encoding="utf-8") as stream:
                    for line, text in enumerate(stream, 1):
                        raw = text.rstrip("\r\n")
                        try:
                            value = json.loads(raw, use_decimal=True, allow_nan=False)
                            check_record(value, manifest)
                        except (ValueError, TypeError) as error:
                            raise ValueError(f"observations.jsonl line {line}: {error}") from None
                        count += 1
                        undated += value.get("@timestamp") is None
                        identifier = allocate(1)
                        ips.extend(ip_attributes(value, identifier))
                        digest = hashlib.sha256(raw.encode()).hexdigest()
                        key = hashlib.sha256(f"kamotrace-tracequarry-v1:{manifest_hash}:{line}".encode()).hexdigest()
                        batch.append((identifier, raw, key, str(source / "observations.jsonl"), line,
                                      origin, None, imported, None, digest))
                        batch_bytes += len(raw.encode())
                        if len(batch) == 1000 or batch_bytes >= 8 * 1024 * 1024:
                            insert_observations(connection, batch, ips)
                            batch.clear()
                            ips.clear()
                            batch_bytes = 0
                insert_observations(connection, batch, ips)
                if count != coverage["events"] or not count:
                    raise ValueError("Observation count is empty or differs from manifest coverage")
                verified = connection.execute("SELECT count(*) FROM raw_events WHERE sha256(raw_event::VARCHAR)=content_sha256").fetchone()[0]
                if verified != count:
                    raise ValueError("Stored content hashes differ from source observations")
                metadata = {"format": FORMAT, "schema_version": 1, "source_sha256": manifest_hash,
                            "records": count, "undated": undated, "origin": origin, "imported_at": imported,
                            "adapter": "tracequarry-parse-only-v1", "tracequarry": {"manifest": manifest, "source_index": index},
                            "case_unit": case_unit,
                            "identity_policy": "manifest-sha256-and-physical-line; no cross-run deduplication"}
                connection.execute("INSERT INTO build_info VALUES (?)", [json.dumps(metadata, use_decimal=True)])
                for path, digest in expected.items():
                    if sha256(path) != digest:
                        raise ValueError(f"TraceQuarry output changed during import: {path.name}")
                connection.execute("COMMIT")
            finally:
                connection.close()
            publish(target, database)
    return metadata


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path, help="Completed external parse-only output directory")
    parser.add_argument("--case", required=True, type=Path)
    parser.add_argument("--unit", required=True, help="Stable acquisition key")
    args = parser.parse_args(argv)
    from .datasets import admit
    try:
        result = admit(args.case, args.unit, "uac", [args.source])
    except (ValueError, OSError, duckdb.Error) as error:
        parser.error(str(error))
    print(f"Raw-complete: {result['raw']['records']:,} observations; preparation pending")
    return 0
