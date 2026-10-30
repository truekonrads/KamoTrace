"""Import Suzaku (Yamato Security) Sigma detections as a derived, read-only KamoTrace sidecar.

Suzaku's `aws-ct-timeline -t duckdb` output is read as untrusted data and re-expressed in KamoTrace's
own model: one row per (evidence record, rule match), linked by exact eventID, region and event time.
The evidence database is attached read-only and never modified; Suzaku itself is never bundled.
"""
import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
import hashlib
import json
import logging
from pathlib import Path
import subprocess
import tempfile
import time

import duckdb

from .importer import discard_abandoned, lock_path, publish, staging, write_lock

logger = logging.getLogger(__name__)
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


def identify_sidecar(path, table, tables):
    """Run metadata if `path` is positively a KamoTrace sidecar with exactly `tables`; otherwise None."""
    try:
        connection = duckdb.connect(str(path), read_only=True)
        try:
            found = {r[0] for r in connection.execute("""SELECT table_name FROM duckdb_tables()
                WHERE database_name = current_database() AND NOT temporary""").fetchall()}
            run = json.loads(connection.execute(f"SELECT metadata FROM {table}").fetchone()[0]) if found == tables else None
        finally:
            connection.close()
    except (duckdb.Error, TypeError, ValueError):
        return None
    return run if isinstance(run, dict) and "schema_version" in run else None


def check_output(output, replace, kind, table, tables, inputs):
    """Refuse to write a derived sidecar over any input, or over a file that is not that kind of sidecar."""
    if any(Path(p).resolve() in (output, lock_path(output)) for p in inputs if p is not None):
        raise ValueError(f"{output} is also an input; choose a different output path")
    if output.exists():
        if not replace:
            raise FileExistsError(f"{output} exists; pass --replace to rebuild it")
        if identify_sidecar(output, table, tables) is None:
            raise ValueError(f"{output} exists but is not a KamoTrace {kind} sidecar; refusing to replace it")


def tree_sha256(path):
    """Content digest of a file, or of a folder's relative file names and contents."""
    if path.is_file():
        return sha256(path)
    digest = hashlib.sha256()
    for item in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(json.dumps([item.relative_to(path).as_posix(), sha256(item)]).encode())
    return digest.hexdigest()


def run_options(executable, rules=None, min_level=None):
    """Everything besides the input that decides a Suzaku run's output, recorded to detect stale sidecars."""
    executable = executable.resolve()
    folders = {"rules": rules.resolve() if rules else executable.parent / "rules", "config": executable.parent / "config"}
    return {"executable_sha256": sha256(executable), "min_level": min_level,
            **{f"{name}_sha256": tree_sha256(path) if path.exists() else None for name, path in folders.items()}}


def import_timeline(database, timeline, output, replace=False, source=None, label=None, options=None, lock=True):
    """Link a Suzaku aws-ct-timeline DuckDB file to evidence records and write `output`.

    Pass lock=False only while already holding write_lock(output)."""
    with write_lock(output) if lock else nullcontext():
        return _import_timeline(database.resolve(), timeline.resolve(), output.resolve(), replace, source, label, options)


def _import_timeline(database, timeline, output, replace, source, label, options):
    inputs = [database, timeline, source]
    check_output(output, replace, "detections", "suzaku_run", {"detections", "suzaku_run"}, inputs)
    discard_abandoned(output, inputs)
    with staging(output) as building:
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
            # Exact linkage by eventID. A single-event row must also match region and instant. A correlation
            # row lists its members' eventIDs (and regions) joined by " ¦ " with the latest member's time, so
            # each member must match one of those regions at or before that time. A row links only when every
            # member matches exactly one canonical record (identical duplicate records share a hash and all link).
            connection.execute("""
                CREATE TABLE detections AS
                WITH t AS (
                    SELECT row_number() OVER () AS suzaku_row, *, timezone('UTC', "Timestamp") AS event_time,
                        list_distinct(string_split(EventID, ' ¦ ')) AS ids, string_split(AwsRegion, ' ¦ ') AS regions
                    FROM tl.timeline
                ), p AS (
                    SELECT suzaku_row, unnest(ids) AS member_id, len(ids) AS members, regions, event_time, AwsRegion
                    FROM t
                ), m AS (
                    SELECT p.suzaku_row, p.member_id, p.members, e.source_record, e.record_sha256,
                        count(DISTINCT e.record_sha256) OVER (PARTITION BY p.suzaku_row, p.member_id) AS hashes
                    FROM p JOIN ev.events e ON e.event_id = p.member_id AND CASE WHEN p.members = 1
                        THEN e.aws_region IS NOT DISTINCT FROM p.AwsRegion AND e.event_time = p.event_time
                        ELSE list_contains(p.regions, e.aws_region) AND e.event_time <= p.event_time END
                ), complete AS (
                    SELECT suzaku_row FROM m GROUP BY suzaku_row, members
                    HAVING count(DISTINCT member_id) FILTER (WHERE hashes = 1) = members
                ), links AS (
                    -- One row per linked evidence record; unlinked Suzaku rows are kept once, for the record.
                    SELECT suzaku_row, source_record, record_sha256, 'linked' AS link_status
                    FROM m WHERE suzaku_row IN (SELECT suzaku_row FROM complete)
                    UNION ALL
                    SELECT suzaku_row, NULL, NULL,
                        CASE WHEN suzaku_row IN (SELECT suzaku_row FROM m WHERE hashes > 1) THEN 'ambiguous' ELSE 'no_match' END
                    FROM t WHERE suzaku_row NOT IN (SELECT suzaku_row FROM complete)
                )
                SELECT t.suzaku_row, l.source_record, l.record_sha256, l.link_status, len(t.ids) AS members,
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
                   "suzaku_options": options,
                   **{k if k.startswith("suzaku") else f"suzaku_{k}": v for k, v in meta.items()},
                   "linked_rows": counts.get("linked", 0), "no_match_rows": counts.get("no_match", 0),
                   "ambiguous_rows": counts.get("ambiguous", 0)}
            connection.execute("CREATE TABLE suzaku_run (metadata JSON)")
            connection.execute("INSERT INTO suzaku_run VALUES (?)", [json.dumps(run)])
            connection.execute("DETACH ev; DETACH tl; CHECKPOINT")
        finally:
            connection.close()
        # Recheck just before publication: the output may have changed while this was built.
        check_output(output, replace, "detections", "suzaku_run", {"detections", "suzaku_run"}, inputs)
        publish(building, output, replace)
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
    started = time.monotonic()
    logger.info("Opening and validating Suzaku sidecar: %s", path)
    sidecar = duckdb.connect(str(path), read_only=True)
    try:
        run = json.loads(sidecar.execute("SELECT metadata FROM suzaku_run").fetchone()[0])
        if run.get("schema_version") != SCHEMA:
            raise ValueError(f"{path}: unsupported detections sidecar; rebuild it with `kamotrace suzaku --replace`")
        if (run["evidence_source_sha256"], run["evidence_records"]) != evidence_identity(connection):
            raise ValueError(f"{path} was built for a different evidence database; rebuild it with `kamotrace suzaku`")
        logger.info("Reading linked Suzaku detection rows")
        total = sidecar.execute("SELECT count(*) FROM detections WHERE link_status = 'linked'").fetchone()[0]
        logger.info("Copying %s linked Suzaku detections into the in-memory table", format(total, ","))
        sidecar.execute("""SELECT source_record, rule_id, rule_title, level, level_rank, tactics, technique_ids
            FROM detections WHERE link_status = 'linked'""")
        # Transfer bounded column batches: executemany runs an insert per detection. Typed UNNEST
        # preserves empty/NULL lists without dependencies or ATTACH (external access may be disabled).
        while rows := sidecar.fetchmany(8192):
            connection.execute("""INSERT INTO detections SELECT
                unnest(?::BIGINT[]), unnest(?::VARCHAR[]), unnest(?::VARCHAR[]),
                unnest(?::VARCHAR[]), unnest(?::TINYINT[]), unnest(?::VARCHAR[][]), unnest(?::VARCHAR[][])
            """, list(zip(*rows)))
    finally:
        sidecar.close()
    logger.info("Loaded %s linked Suzaku detections in %.1fs", format(total, ","), time.monotonic() - started)
    return run


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace suzaku", description=__doc__.splitlines()[0])
    parser.add_argument("--database", type=Path, required=True, help="Evidence DuckDB built by `kamotrace import`")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--timeline", type=Path, help="Existing `suzaku aws-ct-timeline -t duckdb` output (.duckdb)")
    group.add_argument("--suzaku", type=Path,
                       help="Suzaku executable to run on --source (default: the copy from `kamotrace get-suzaku`)")
    parser.add_argument("--source", type=Path, help="CloudTrail export (file or folder) the database was imported from")
    parser.add_argument("--rules", type=Path, help="Suzaku rules folder (default: Suzaku's ./rules)")
    parser.add_argument("--min-level", choices=LEVELS, help="Minimum Sigma level for Suzaku to load")
    parser.add_argument("--output", type=Path, help="Detections sidecar (default: <database>.detections.duckdb)")
    parser.add_argument("--replace", action="store_true", help="Replace an existing detections sidecar")
    args = parser.parse_args(argv)
    if not args.timeline and not args.suzaku:
        from .get_suzaku import installed, tools_folder
        args.suzaku = installed()
        if args.suzaku is None:
            parser.error(f"no Suzaku in {tools_folder()}: run `kamotrace get-suzaku`, or pass --suzaku or --timeline")
    if args.suzaku and not args.source:
        parser.error("running Suzaku needs --source (the export you imported), or pass --timeline")
    if (args.rules or args.min_level) and not args.suzaku:
        parser.error("--rules/--min-level only apply when running --suzaku")
    for path in (args.database, args.timeline, args.suzaku, args.source):
        if path is not None and not path.exists():
            parser.error(f"not found: {path}")
    output = args.output or args.database.with_suffix(".detections.duckdb")
    work = None
    try:
        with write_lock(output):  # Before running Suzaku, so a busy output fails fast
            timeline = args.timeline
            if args.suzaku:
                work, timeline = run_suzaku(args.suzaku, args.source, args.rules, args.min_level)
            run = import_timeline(args.database, timeline, output, args.replace, args.source,
                                  "(temporary output of the Suzaku run, deleted)" if work else None,
                                  run_options(args.suzaku, args.rules, args.min_level) if work else None, lock=False)
    except (FileExistsError, BlockingIOError, ValueError, RuntimeError) as error:  # Without a KamoTrace traceback
        parser.error(str(error))
    finally:
        if work:
            work.cleanup()
    print(json.dumps({"output": str(output.resolve()), **run}, indent=2, default=str))
