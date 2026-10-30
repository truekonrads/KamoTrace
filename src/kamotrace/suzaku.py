"""Import Suzaku (Yamato Security) Sigma detections as a derived, read-only KamoTrace sidecar.

Suzaku's `aws-ct-timeline -t duckdb` output is read as untrusted data and re-expressed in KamoTrace's
own model: one row per (evidence record, rule match), linked by exact eventID, region and event time.
The evidence database is attached read-only and never modified; Suzaku itself is never bundled.
"""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

import duckdb

LEVELS = ("informational", "low", "medium", "high", "critical")
SCHEMA = 1  # KamoTrace detections sidecar layout


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def evidence_identity(connection, schema="main"):
    """Provenance of an evidence database as recorded by `kamotrace import`."""
    row = connection.execute(f"SELECT metadata FROM {schema}.build_info").fetchone()
    info = json.loads(row[0])
    return info["source_sha256"], int(info["records"])


def import_timeline(database, timeline, output, replace=False, source=None, label=None):
    """Link a Suzaku aws-ct-timeline DuckDB file to evidence records and write `output`."""
    database, timeline, output = database.resolve(), timeline.resolve(), output.resolve()
    if output.exists() and not replace:
        raise FileExistsError(f"{output} exists; pass --replace to rebuild it from this timeline")
    building = output.with_suffix(output.suffix + ".building")
    building.unlink(missing_ok=True)
    connection = duckdb.connect(str(building))
    try:
        connection.execute("SET TimeZone='UTC'")
        connection.execute("ATTACH ? AS ev (READ_ONLY)", [str(database)])
        connection.execute("ATTACH ? AS tl (READ_ONLY)", [str(timeline)])
        tables = {r[0] for r in connection.execute(
            "SELECT table_name FROM duckdb_tables() WHERE database_name='tl'").fetchall()}
        if not {"timeline", "suzaku_meta"} <= tables:
            raise ValueError("Not a Suzaku DuckDB timeline: run `suzaku aws-ct-timeline ... -t duckdb`")
        # As JSON text: avoids converting Suzaku's TIMESTAMPTZ columns to Python (which needs pytz).
        meta = json.loads(connection.execute("SELECT to_json(m)::VARCHAR FROM tl.suzaku_meta m LIMIT 1").fetchone()[0])
        if meta["schema_version"] != 1 or meta["command"] != "aws-ct-timeline":
            raise ValueError(f"Unsupported Suzaku output: schema {meta['schema_version']}, command {meta['command']}; "
                             "only aws-ct-timeline schema 1 (Suzaku 3.x) is supported")
        if meta["timestamp_tz"] != "UTC":
            raise ValueError("Suzaku timestamps are not UTC; rerun Suzaku without -l/--localtime")
        source_sha256, records = evidence_identity(connection, "ev")
        # Exact linkage: same eventID, region and instant. A detection links only when those
        # match exactly one canonical record (identical duplicate records share a hash and all link).
        connection.execute("""
            CREATE TABLE detections AS
            WITH t AS (
                SELECT row_number() OVER () AS suzaku_row, *, timezone('UTC', "Timestamp") AS event_time
                FROM tl.timeline
            ), m AS (
                SELECT t.suzaku_row, e.source_record, e.record_sha256,
                    count(DISTINCT e.record_sha256) OVER (PARTITION BY t.suzaku_row) AS hashes
                FROM t JOIN ev.events e ON e.event_id = t.EventID
                    AND e.aws_region IS NOT DISTINCT FROM t.AwsRegion AND e.event_time = t.event_time
            ), links AS (
                -- One row per linked evidence record; unlinked Suzaku rows are kept once, for the record.
                SELECT suzaku_row, source_record, record_sha256, 'linked' AS link_status FROM m WHERE hashes = 1
                UNION ALL
                SELECT suzaku_row, NULL, NULL,
                    CASE WHEN suzaku_row IN (SELECT suzaku_row FROM m) THEN 'ambiguous' ELSE 'no_match' END
                FROM t WHERE suzaku_row NOT IN (SELECT suzaku_row FROM m WHERE hashes = 1)
            )
            SELECT t.suzaku_row, l.source_record, l.record_sha256, l.link_status,
                t.RuleID AS rule_id, t.RuleTitle AS rule_title, t.Level::VARCHAR AS level,
                list_position(?, t.Level::VARCHAR) - 1 AS level_rank, t.RuleAuthor AS rule_author,
                coalesce(t.Tactics, []) AS tactics, coalesce(t.TechniqueIDs, []) AS technique_ids,
                coalesce(t.OtherTags, []) AS other_tags,
                t.EventID AS event_id, t.AwsRegion AS aws_region, t.event_time, t.EventName AS event_name
            FROM links l JOIN t USING (suzaku_row)
            ORDER BY t.event_time, t.suzaku_row, l.source_record
        """, [list(LEVELS)])
        counts = dict(connection.execute(
            "SELECT link_status, count(DISTINCT suzaku_row) FROM detections GROUP BY 1").fetchall())
        run = {"schema_version": SCHEMA, "imported_at": datetime.now(timezone.utc).isoformat(),
               "timeline_file": label or str(timeline), "timeline_sha256": sha256(timeline),
               "evidence_source_sha256": source_sha256, "evidence_records": records,
               "suzaku_source": str(source) if source else None,
               "suzaku_source_matches_evidence": (sha256(source) == source_sha256) if source and source.is_file() else None,
               **{k if k.startswith("suzaku") else f"suzaku_{k}": v for k, v in meta.items()},
               "linked_rows": counts.get("linked", 0), "no_match_rows": counts.get("no_match", 0),
               "ambiguous_rows": counts.get("ambiguous", 0)}
        connection.execute("CREATE TABLE suzaku_run (metadata JSON)")
        connection.execute("INSERT INTO suzaku_run VALUES (?)", [json.dumps(run)])
        connection.execute("DETACH ev; DETACH tl; CHECKPOINT")
    except BaseException:
        connection.close()
        building.unlink(missing_ok=True)
        Path(str(building) + ".wal").unlink(missing_ok=True)
        raise
    connection.close()
    building.replace(output)
    return run


def run_suzaku(executable, source, rules=None, min_level=None):
    """Run the analyst's Suzaku binary on the original CloudTrail export; returns (tempdir, timeline)."""
    executable, source = executable.resolve(), source.resolve()
    work = tempfile.TemporaryDirectory(prefix="kamotrace-suzaku-")
    target = Path(work.name) / "timeline"
    command = [str(executable), "aws-ct-timeline", "-d" if source.is_dir() else "-f", str(source),
               "-o", str(target), "-t", "duckdb", "-q", "-K", "-N", "-C"]
    if rules:
        command += ["-r", str(rules.resolve())]
    if min_level:
        command += ["-m", min_level]
    # Suzaku resolves ./rules and ./config relative to its working directory: run from its folder.
    result = subprocess.run(command, cwd=executable.parent, capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
    timeline = target.with_suffix(".duckdb")
    if result.returncode != 0 or not timeline.exists():
        work.cleanup()
        raise RuntimeError(f"Suzaku failed (exit {result.returncode}):\n{result.stderr or result.stdout}")
    return work, timeline


def load_detections(connection, path):
    """Server side: copy linked detections into a temp table. Returns the run metadata or None."""
    connection.execute("""CREATE TEMP TABLE detections(source_record BIGINT, rule_id VARCHAR, rule_title VARCHAR,
        level VARCHAR, level_rank TINYINT, tactics VARCHAR[], technique_ids VARCHAR[])""")
    if path is None:
        return None
    # A separate read-only connection, not ATTACH: DuckDB shares one instance per database file in a
    # process, and the evidence instance may already have external file access disabled.
    sidecar = duckdb.connect(str(path), read_only=True)
    try:
        run = json.loads(sidecar.execute("SELECT metadata FROM suzaku_run").fetchone()[0])
        if run.get("schema_version") != SCHEMA:
            raise ValueError(f"{path}: unsupported detections sidecar; rebuild it with `kamotrace suzaku --replace`")
        if (run["evidence_source_sha256"], run["evidence_records"]) != evidence_identity(connection):
            raise ValueError(f"{path} was built for a different evidence database; rebuild it with `kamotrace suzaku`")
        rows = sidecar.execute("""SELECT source_record, rule_id, rule_title, level, level_rank, tactics, technique_ids
            FROM detections WHERE link_status = 'linked'""").fetchall()
    finally:
        sidecar.close()
    if rows:
        connection.executemany("INSERT INTO detections VALUES (?,?,?,?,?,?,?)", rows)
    return run


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace suzaku", description=__doc__.splitlines()[0])
    parser.add_argument("--database", type=Path, required=True, help="Evidence DuckDB built by `kamotrace import`")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--timeline", type=Path, help="Existing `suzaku aws-ct-timeline -t duckdb` output (.duckdb)")
    group.add_argument("--suzaku", type=Path, help="Suzaku executable to run on --source")
    parser.add_argument("--source", type=Path, help="CloudTrail export (file or folder) the database was imported from")
    parser.add_argument("--rules", type=Path, help="Suzaku rules folder (default: Suzaku's ./rules)")
    parser.add_argument("--min-level", choices=LEVELS, help="Minimum Sigma level for Suzaku to load")
    parser.add_argument("--output", type=Path, help="Detections sidecar (default: <database>.detections.duckdb)")
    parser.add_argument("--replace", action="store_true", help="Replace an existing detections sidecar")
    args = parser.parse_args(argv)
    if args.suzaku and not args.source:
        parser.error("--suzaku needs --source")
    if (args.rules or args.min_level) and not args.suzaku:
        parser.error("--rules/--min-level only apply when running --suzaku")
    for path in (args.database, args.timeline, args.suzaku, args.source):
        if path is not None and not path.exists():
            parser.error(f"not found: {path}")
    output = args.output or args.database.with_suffix(".detections.duckdb")
    work = None
    try:
        timeline = args.timeline
        if args.suzaku:
            work, timeline = run_suzaku(args.suzaku, args.source, args.rules, args.min_level)
        run = import_timeline(args.database, timeline, output, args.replace, args.source,
                              "(temporary output of the Suzaku run, deleted)" if work else None)
    finally:
        if work:
            work.cleanup()
    print(json.dumps({"output": str(output.resolve()), **run}, indent=2, default=str))
