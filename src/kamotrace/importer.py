"""Load a CloudTrail event-history export without inferring or flattening JSON."""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import hashlib
from pathlib import Path
import shutil
import sys
import tempfile
import time

import duckdb
import ijson
import simplejson as json


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


@contextmanager
def open_json(path):
    """Open plain or gzip JSON by magic bytes, including streams spooled without a suffix."""
    with path.open("rb") as raw:
        compressed = raw.read(2) == b"\x1f\x8b"
        raw.seek(0)
        if compressed:
            with gzip.GzipFile(fileobj=raw) as stream:
                yield stream
        else:
            yield raw


def records(stream):
    """CloudTrail Records from a binary stream, skipping a UTF-8 byte-order mark (common on Windows)."""
    if stream.read(3) != b"\xef\xbb\xbf":
        stream.seek(0)
    events = ijson.parse(stream)
    if next(events, None) != ("", "start_map", None):
        raise ValueError("Expected a JSON object with a Records array")
    for prefix, event, value in events:
        if prefix == "Records":
            if event != "start_array":
                raise ValueError("Expected a Records array")
            yield from ijson.items(events, "Records.item")
            return
    raise ValueError("Expected a JSON object with a Records array")


def build(source, database):
    # Paths remain rereadable; binary streams are spooled privately for independent verification.
    inputs = [source] if isinstance(source, (str, Path)) or hasattr(source, "read") else list(source)
    sources = []
    for item in inputs:
        if hasattr(item, "read"):
            sources.append(item)
        else:
            path = Path(item).resolve()
            if path.is_dir():
                members = sorted(p for p in path.rglob("*") if p.is_file() and
                                 (p.name.lower().endswith(".json") or p.name.lower().endswith(".json.gz")))
                if not members:
                    raise ValueError(f"No .json or .json.gz sources in {path}")
                sources.extend(members)
            else:
                sources.append(path)
    if not sources:
        raise ValueError("At least one source is required")
    database = database.resolve()
    building = database.with_suffix(database.suffix + ".building")
    if database.exists() or building.exists():
        raise FileExistsError("Use a new database path; existing databases are never overwritten")
    started = time.monotonic()
    database.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cloudtrail-") as temp:
        staged = Path(temp) / "records.jsonl"
        count = 0
        provenance, originals = [], []
        with staged.open("w", encoding="utf-8", newline="\n") as output:
            for index, item in enumerate(sources):
                if hasattr(item, "read"):
                    path = Path(temp) / f"stdin-{index}"
                    with path.open("wb") as target:
                        shutil.copyfileobj(item, target)
                    label = "<stdin>"
                else:
                    path, label = item, str(item)
                original = path.stat()
                source_hash = sha256(path)
                entry = {"source_file": label, "source_bytes": original.st_size,
                         "source_sha256": source_hash, "source_records": 0, "first_record": count + 1}
                with open_json(path) as stream:
                    for ordinal, record in enumerate(records(stream), 1):
                        if not isinstance(record, dict):
                            raise ValueError(f"{label}: record {ordinal} is not an object")
                        output.write(json.dumps(record, ensure_ascii=False, use_decimal=True,
                                                allow_nan=False, separators=(",", ":")) + "\n")
                        count += 1
                        entry["source_records"] += 1
                entry["last_record"] = count
                provenance.append(entry)
                originals.append((path, original, entry))
                if sha256(path) != source_hash or path.stat().st_mtime_ns != original.st_mtime_ns:
                    raise ValueError(f"Source changed during import: {label}")
        if not count:
            raise ValueError("No CloudTrail Records found")
        connection = duckdb.connect(str(building))
        try:
            connection.execute("SET threads=2; SET memory_limit='4GB'; SET TimeZone='UTC'")
            connection.execute("""CREATE TABLE import_sources (
                source_file VARCHAR, source_bytes BIGINT, source_sha256 VARCHAR,
                source_records BIGINT, first_record BIGINT, last_record BIGINT)""")
            connection.executemany("INSERT INTO import_sources VALUES (?,?,?,?,?,?)",
                [(entry["source_file"], entry["source_bytes"], entry["source_sha256"],
                  entry["source_records"], entry["first_record"], entry["last_record"]) for entry in provenance])
            connection.execute("""
                CREATE TABLE raw_events (
                    source_record BIGINT PRIMARY KEY, raw_event JSON,
                    record_sha256 VARCHAR, source_file VARCHAR, source_ordinal BIGINT
                )
            """)
            connection.execute("""
                INSERT INTO raw_events
                SELECT ordinal, json, sha256(json::VARCHAR), source_file, ordinal - first_record + 1
                FROM (SELECT row_number() OVER () AS ordinal, json
                      FROM read_json_objects(?, format='newline_delimited'))
                JOIN import_sources ON ordinal BETWEEN first_record AND last_record
            """, [str(staged)])
            connection.execute("""
                CREATE VIEW events AS
                SELECT source_record,
                    raw_event->>'$.eventID' AS event_id,
                    raw_event->>'$.eventTime' AS event_time_text,
                    try_cast(raw_event->>'$.eventTime' AS TIMESTAMPTZ) AS event_time,
                    raw_event->>'$.eventSource' AS event_source,
                    raw_event->>'$.eventName' AS event_name,
                    raw_event->>'$.awsRegion' AS aws_region,
                    raw_event->>'$.sourceIPAddress' AS source_ip,
                    raw_event->>'$.userAgent' AS user_agent,
                    raw_event->>'$.userIdentity.type' AS identity_type,
                    raw_event->>'$.userIdentity.arn' AS identity_arn,
                    raw_event->>'$.recipientAccountId' AS recipient_account_id,
                    raw_event->>'$.errorCode' AS error_code,
                    raw_event->>'$.errorMessage' AS error_message,
                    try_cast(raw_event->>'$.readOnly' AS BOOLEAN) AS read_only,
                    raw_event->'$.userIdentity' AS user_identity,
                    raw_event->'$.requestParameters' AS request_parameters,
                    raw_event->'$.responseElements' AS response_elements,
                    raw_event, record_sha256, source_file, source_ordinal
                FROM raw_events
            """)
            quality = connection.execute("""
                SELECT count(*) AS records, count(DISTINCT event_id) AS distinct_event_ids,
                    count(*) FILTER (WHERE event_id IS NULL) AS missing_event_ids,
                    count(*) FILTER (WHERE event_time IS NULL) AS invalid_timestamps,
                    min(event_time)::VARCHAR AS first_event_utc,
                    max(event_time)::VARCHAR AS last_event_utc
                FROM events
            """)
            report = dict(zip([c[0] for c in quality.description], quality.fetchone()))
            if report["records"] != count:
                raise ValueError("Imported count differs from source")
            # Independently re-stream every source record and compare its canonical hash.
            rows = connection.execute(
                "SELECT source_record, record_sha256 FROM raw_events ORDER BY source_record"
            )
            ordinal = 0
            for path, original, entry in originals:
                verified = 0
                with open_json(path) as stream:
                    for record in records(stream):
                        ordinal += 1
                        verified += 1
                        canonical = json.dumps(record, ensure_ascii=False, use_decimal=True,
                                               allow_nan=False, separators=(",", ":"))
                        expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                        if rows.fetchone() != (ordinal, expected):
                            raise ValueError(f"Record integrity mismatch: {ordinal}")
                if (verified != entry["source_records"] or sha256(path) != entry["source_sha256"]
                        or path.stat().st_mtime_ns != original.st_mtime_ns):
                    raise ValueError(f"Source changed during import: {entry['source_file']}")
            if rows.fetchone() is not None:
                raise ValueError("Source/database reconciliation failed")
            # Keep legacy single-file identities. Multi-source identity is ordered and path-independent,
            # since reordering inputs changes source_record IDs used by derived sidecars.
            identity = provenance[0]["source_sha256"] if len(provenance) == 1 else hashlib.sha256(
                json.dumps({"format": "kamotrace-source-set-v1", "sha256": [
                    entry["source_sha256"] for entry in provenance]}, separators=(",", ":")).encode()).hexdigest()
            report.update(source_file=provenance[0]["source_file"] if len(provenance) == 1 else None,
                          source_bytes=sum(entry["source_bytes"] for entry in provenance),
                          source_sha256=identity, source_records=count, sources=provenance,
                          source_identity="file-sha256" if len(provenance) == 1 else "kamotrace-source-set-v1",
                          all_record_hashes_verified=True, schema_version=2,
                          built_at_utc=datetime.now(timezone.utc).isoformat(),
                          duckdb_version=duckdb.__version__, loader_sha256=sha256(Path(__file__)),
                          elapsed_seconds=round(time.monotonic() - started, 3))
            metadata = json.dumps(report, default=str)
            connection.execute("CREATE TABLE build_info (metadata JSON)")
            connection.execute("INSERT INTO build_info VALUES (?)", [metadata])
            connection.execute("CHECKPOINT")
        except BaseException:
            connection.close()
            building.unlink(missing_ok=True)
            Path(str(building) + ".wal").unlink(missing_ok=True)
            raise
        else:
            connection.close()
        building.rename(database)
    print(json.dumps(report, default=str, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace import", description=__doc__)
    parser.add_argument("--source", action="extend", nargs="+", required=True,
                        help="JSON/gzip files or folders (recursive, sorted); repeatable; - reads binary stdin")
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.source.count("-") > 1:
        parser.error("stdin (-) can only be read once")
    try:
        build([sys.stdin.buffer if item == "-" else Path(item) for item in args.source], args.database)
    except (OSError, ValueError, EOFError, ijson.JSONError) as error:
        parser.error(str(error))
