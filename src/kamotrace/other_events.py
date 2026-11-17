"""Provider-neutral JSONL imports and revisioned investigator-entered key events."""
import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
from pathlib import Path
import re
import shutil
import uuid

import duckdb
import simplejson as json

from .importer import open_json, publish, sha256, staging, write_lock

FORMAT = "kamotrace-other-v1"
MANUAL_BASE = 2 ** 52  # Exact JavaScript integers; never overlaps ordinary imported row IDs.
RAW_SCHEMA = """source_record BIGINT PRIMARY KEY, raw_event JSON, record_sha256 VARCHAR,
    source_file VARCHAR, source_ordinal BIGINT, origin VARCHAR, author VARCHAR,
    created VARCHAR, updated VARCHAR, content_sha256 VARCHAR"""
EVENTS_VIEW = """SELECT source_record, NULL::VARCHAR AS event_id,
    raw_event->>'$.date' AS event_time_text, (raw_event->>'$.date')::TIMESTAMPTZ AS event_time,
    NULL::VARCHAR AS event_source, NULL::VARCHAR AS event_name, NULL::VARCHAR AS aws_region,
    raw_event->>'$.ip' AS source_ip, NULL::VARCHAR AS user_agent,
    NULL::VARCHAR AS identity_type, NULL::VARCHAR AS identity_arn,
    NULL::VARCHAR AS recipient_account_id, NULL::VARCHAR AS error_code, NULL::VARCHAR AS error_message,
    NULL::BOOLEAN AS read_only, NULL::JSON AS user_identity,
    NULL::JSON AS request_parameters, NULL::JSON AS response_elements,
    raw_event, record_sha256, source_file, source_ordinal,
    CASE WHEN updated IS NULL THEN 'other' ELSE 'manual' END AS event_type,
    origin, raw_event->>'$.identity' AS generic_identity,
    left(raw_event->>'$.content', 240) AS content_preview,
    author, created, updated, content_sha256 FROM raw_events"""


def now():
    return datetime.now(timezone.utc).isoformat()


def record(text):
    """Validate without rounding numbers; content stays JSON, never Python/JS floats."""
    value = json.loads(text, use_decimal=True, allow_nan=False)
    if not isinstance(value, dict) or set(value) - {"date", "content", "ip", "identity"}:
        raise ValueError("Expected an object containing date, content and optional ip/identity only")
    date = value.get("date")
    if not isinstance(date, str) or not re.fullmatch(
            r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)", date):
        raise ValueError("date must be an RFC 3339 timestamp with an explicit timezone")
    datetime.fromisoformat(date.replace("Z", "+00:00"))
    if value.get("content") is None:
        raise ValueError("content is required and cannot be null")
    if "ip" in value:
        if not isinstance(value["ip"], str):
            raise ValueError("ip must be an IPv4 or IPv6 address; omit it if unknown")
        ipaddress.ip_address(value["ip"])
    if "identity" in value and not isinstance(value["identity"], str):
        raise ValueError("identity must be text; omit it if unknown")
    return json.dumps(value, ensure_ascii=False, use_decimal=True, allow_nan=False, sort_keys=True, separators=(",", ":"))


def description(value, name="origin", required=True):
    if not isinstance(value, str) or len(value) > 2000 or (required and not value.strip()):
        raise ValueError(f"{name} must be {'nonempty ' if required else ''}text up to 2,000 characters")
    return value


def initialize(connection):
    connection.execute(f"CREATE TABLE raw_events ({RAW_SCHEMA})")
    connection.execute("CREATE VIEW events AS " + EVENTS_VIEW)
    connection.execute("CREATE TABLE build_info(metadata JSON)")


def build(sources, database, origin):
    """Stream immutable generic imports into a new DuckDB, with per-file provenance."""
    description(origin)
    database = Path(database).resolve()
    sources = [Path(p).resolve() for p in sources]
    with write_lock(database):
        if database.exists():
            raise FileExistsError("Use a new database path; existing datasets are never overwritten")
        with staging(database) as target:
            connection = duckdb.connect(str(target))
            try:
                connection.execute("SET threads=2; SET memory_limit='4GB'; SET TimeZone='UTC'")
                connection.execute("BEGIN TRANSACTION")
                initialize(connection)
                connection.execute("CREATE TABLE import_sources(source_file VARCHAR, source_sha256 VARCHAR, source_bytes BIGINT)")
                count, provenance = 0, []
                imported = now()
                for source in sources:
                    digest, size = sha256(source), source.stat().st_size
                    provenance.append({"source_file": str(source), "source_sha256": digest, "source_bytes": size})
                    batch = []
                    with open_json(source) as stream:
                        for line, text in enumerate(stream, 1):
                            if not text.strip():
                                continue
                            try:
                                raw = record(text)
                            except (ValueError, UnicodeError) as error:
                                raise ValueError(f"{source}: line {line}: {error}") from None
                            count += 1
                            content_hash = hashlib.sha256(raw.encode()).hexdigest()
                            key = hashlib.sha256((FORMAT + ":" + raw).encode()).hexdigest()
                            batch.append((count, raw, key, str(source), line, origin, None, imported, None, content_hash))
                            if len(batch) == 1000:
                                connection.executemany("INSERT INTO raw_events VALUES (?,?,?,?,?,?,?,?,?,?)", batch)
                                batch.clear()
                    if batch:
                        connection.executemany("INSERT INTO raw_events VALUES (?,?,?,?,?,?,?,?,?,?)", batch)
                    if sha256(source) != digest:
                        raise ValueError(f"Source changed during import: {source}")
                    connection.execute("INSERT INTO import_sources VALUES (?,?,?)", [str(source), digest, size])
                if not count:
                    raise ValueError("No events found")
                verified = connection.execute("""SELECT count(*) FROM raw_events
                    WHERE sha256(raw_event::VARCHAR) = content_sha256
                    AND sha256(? || raw_event::VARCHAR) = record_sha256""", [FORMAT + ":"]).fetchone()[0]
                if verified != count:
                    raise ValueError("Stored event hashes differ from validated source records")
                for source, entry in zip(sources, provenance):
                    if sha256(source) != entry["source_sha256"]:
                        raise ValueError(f"Source changed during import: {source}")
                identity = hashlib.sha256(json.dumps([p["source_sha256"] for p in provenance]).encode()).hexdigest()
                metadata = {"format": FORMAT, "schema_version": 1, "source_sha256": identity,
                            "records": count, "origin": origin, "imported_at": imported, "sources": provenance}
                connection.execute("INSERT INTO build_info VALUES (?)", [json.dumps(metadata)])
                connection.execute("COMMIT")
            finally:
                connection.close()
            publish(target, database)
    return metadata


def manual_rows(path, evidence):
    """Read a positively identified manual dataset; never adopt an arbitrary existing file."""
    if not path.exists():
        return []
    connection = duckdb.connect(str(path), read_only=True)
    try:
        info = json.loads(connection.execute("SELECT metadata FROM build_info").fetchone()[0])
        if info != {"format": FORMAT + "-manual", "evidence": list(evidence)}:
            raise ValueError("Manual events database belongs to a different case or format")
        return connection.execute("SELECT * FROM raw_events ORDER BY source_record").fetchall()
    finally:
        connection.close()


def save_manual(path, evidence, body):
    """Copy-on-write publication keeps a failed edit from damaging saved key events."""
    from .server import StaleSelection
    if set(body) - {"id", "updated", "record_json", "origin", "author"}:
        raise ValueError("Unknown manual event fields")
    raw = record(body.get("record_json", ""))
    origin = description(body.get("origin"))
    author = description(body.get("author", ""), "author", required=False)
    identifier = body.get("id")
    if identifier is not None and (type(identifier) is not int or identifier <= MANUAL_BASE):
        raise ValueError("Only investigator-entered manual events can be edited")
    with write_lock(path):
        manual_rows(path, evidence)  # Validate before copying/replacing anything.
        with staging(path) as target:
            if path.exists():
                shutil.copyfile(path, target)
            connection = duckdb.connect(str(target))
            try:
                if not path.exists():
                    initialize(connection)
                    connection.execute("INSERT INTO build_info VALUES (?)", [json.dumps(
                        {"format": FORMAT + "-manual", "evidence": list(evidence)})])
                    connection.execute("CREATE TABLE revisions AS SELECT * FROM raw_events WHERE false")
                old = None
                if identifier is not None:
                    old = connection.execute("SELECT * FROM raw_events WHERE source_record=?", [identifier]).fetchone()
                    if old is None:
                        raise ValueError("Manual event not found")
                    if not isinstance(body.get("updated"), str) or body["updated"] != old[8]:
                        raise StaleSelection("Manual event changed; reopen it before editing again")
                    connection.execute("INSERT INTO revisions SELECT * FROM raw_events WHERE source_record=?", [identifier])
                    connection.execute("DELETE FROM raw_events WHERE source_record=?", [identifier])
                else:
                    identifier = connection.execute("SELECT coalesce(max(source_record), ?) + 1 FROM raw_events", [MANUAL_BASE]).fetchone()[0]
                stamp = now()
                key = old[2] if old else hashlib.sha256(("manual:" + uuid.uuid4().hex).encode()).hexdigest()
                row = (identifier, raw, key, "investigator-entered", 1, origin, author,
                       old[7] if old else stamp, stamp, hashlib.sha256(raw.encode()).hexdigest())
                connection.execute("INSERT INTO raw_events VALUES (?,?,?,?,?,?,?,?,?,?)", row)
            finally:
                connection.close()
            publish(target, path, replace=path.exists())
    return row


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, action="extend", nargs="+", required=True, help="JSONL files (plain or gzip); repeatable")
    parser.add_argument("--database", type=Path, required=True, help="New immutable other-events DuckDB")
    parser.add_argument("--origin", required=True, help="Where the events came from, including any transformation")
    args = parser.parse_args(argv)
    try:
        result = build(args.source, args.database, args.origin)
    except (ValueError, OSError, duckdb.Error) as error:
        parser.error(str(error))
    print(f"Imported {result['records']:,} other events into {args.database}")
    return 0
