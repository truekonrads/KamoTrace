"""Load a CloudTrail event-history export without inferring or flattening JSON."""
import argparse
from datetime import datetime, timezone
import hashlib
from pathlib import Path
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


def build(source, database):
    source = source.resolve()
    database = database.resolve()
    building = database.with_suffix(database.suffix + ".building")
    if database.exists() or building.exists():
        raise FileExistsError("Use a new database path; existing databases are never overwritten")
    started = time.monotonic()
    original = source.stat()
    source_hash = sha256(source)
    database.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="cloudtrail-") as temp:
        staged = Path(temp) / "records.jsonl"
        count = 0
        with source.open("rb") as stream, staged.open("w", encoding="utf-8", newline="\n") as output:
            for count, record in enumerate(ijson.items(stream, "Records.item"), 1):
                if not isinstance(record, dict):
                    raise ValueError(f"Record {count} is not an object")
                output.write(json.dumps(record, ensure_ascii=False, use_decimal=True,
                                        allow_nan=False, separators=(",", ":")) + "\n")
        if not count:
            raise ValueError("No CloudTrail Records found")
        if sha256(source) != source_hash or source.stat().st_mtime_ns != original.st_mtime_ns:
            raise ValueError("Source changed during import")
        connection = duckdb.connect(str(building))
        try:
            connection.execute("SET threads=2; SET memory_limit='4GB'; SET TimeZone='UTC'")
            connection.execute("""
                CREATE TABLE raw_events (
                    source_record BIGINT PRIMARY KEY, raw_event JSON,
                    record_sha256 VARCHAR
                )
            """)
            connection.execute("""
                INSERT INTO raw_events
                SELECT row_number() OVER (), json, sha256(json::VARCHAR)
                FROM read_json_objects(?, format='newline_delimited')
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
                    raw_event, record_sha256
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
            rows = iter(connection.execute(
                "SELECT source_record, record_sha256 FROM raw_events ORDER BY source_record"
            ).fetchall())
            with source.open("rb") as stream:
                for ordinal, record in enumerate(ijson.items(stream, "Records.item"), 1):
                    canonical = json.dumps(record, ensure_ascii=False, use_decimal=True,
                                           allow_nan=False, separators=(",", ":"))
                    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
                    if next(rows) != (ordinal, expected):
                        raise ValueError(f"Record integrity mismatch: {ordinal}")
            if next(rows, None) is not None or sha256(source) != source_hash:
                raise ValueError("Source/database reconciliation failed")
            report.update(source_file=str(source), source_bytes=original.st_size,
                          source_sha256=source_hash, source_records=count,
                          all_record_hashes_verified=True, schema_version=1,
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
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--database", type=Path, required=True)
    args = parser.parse_args(argv)
    build(args.source, args.database)
