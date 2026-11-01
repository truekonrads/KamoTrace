"""Run built-in Python/SQL rules offline into a separate evidence-bound sidecar."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

import duckdb

from .importer import discard_abandoned, publish, staging, write_lock
from .enrich import load_enrichment
from .rules import breadth, instance_credentials, rarity, volume
from .suzaku import LEVELS, check_output, evidence_identity, sha256

SCHEMA = 2
TABLES = {"native_run", "matches"}


def prepare_analysis(connection, bucket_minutes, enrichment):
    """Materialize deduplicated observed windows without changing evidence or filling log gaps."""
    connection.execute("CREATE TEMP VIEW events AS SELECT * FROM ev.events")
    connection.execute("CREATE TEMP VIEW build_info AS SELECT * FROM ev.build_info")
    enrichment_hash = sha256(enrichment) if enrichment else None
    enrichment_run = load_enrichment(connection, enrichment)
    seconds = bucket_minutes * 60
    connection.execute("""CREATE TEMP TABLE analysis_candidates AS WITH unique_events AS (
        SELECT * FROM ev.events QUALIFY row_number() OVER
            (PARTITION BY record_sha256 ORDER BY source_record)=1
    ), normalized AS (
        SELECT e.*, nullif(user_identity->>'$.accountId', '') AS account,
            coalesce(CASE WHEN identity_type='AssumedRole' THEN
                nullif(user_identity->>'$.sessionContext.sessionIssuer.arn', '') END,
                nullif(identity_arn, ''), nullif(user_identity->>'$.principalId', ''),
                nullif(user_identity->>'$.userName', '')) AS principal,
            (floor(epoch(event_time) / ?) * ?)::BIGINT AS bucket,
            CASE WHEN nullif(event_source, '') IS NOT NULL AND nullif(event_name, '') IS NOT NULL
                THEN event_source || ':' || event_name END AS operation,
            g.asn, CASE WHEN g.country NOT LIKE '(%' THEN nullif(g.country, '') END AS country,
            coalesce(error_code NOT IN ('', 'Success'), false) AS failed,
            raw_event->'$.resources' AS resources
        FROM unique_events e LEFT JOIN ip_enrichment g ON e.source_ip=g.ip
    ) SELECT *, json_array(account, identity_type, principal)::VARCHAR AS actor,
        min(bucket) OVER (PARTITION BY account) AS first_bucket,
        max(bucket) OVER (PARTITION BY account) AS last_bucket FROM normalized""", [seconds, seconds])
    connection.execute("""CREATE TEMP TABLE analysis_events AS SELECT * FROM analysis_candidates
        WHERE account IS NOT NULL AND principal IS NOT NULL AND identity_type IS NOT NULL
        AND bucket > first_bucket AND bucket < last_bucket""")
    connection.execute("""CREATE TEMP TABLE analysis_dimensions AS
        SELECT e.actor, e.bucket, e.failed, v.dimension, v.value FROM analysis_events e,
        LATERAL (VALUES ('all', 'all'), ('operation', e.operation), ('asn', e.asn),
            ('country', e.country)) v(dimension, value) WHERE v.value IS NOT NULL""")
    unique, usable, unknown_identity, missing_time, edges = connection.execute("""SELECT count(*),
        count(*) FILTER (WHERE account IS NOT NULL AND principal IS NOT NULL AND identity_type IS NOT NULL
            AND bucket > first_bucket AND bucket < last_bucket),
        count(*) FILTER (WHERE account IS NULL OR principal IS NULL OR identity_type IS NULL),
        count(*) FILTER (WHERE bucket IS NULL),
        count(*) FILTER (WHERE bucket=first_bucket OR bucket=last_bucket) FROM analysis_candidates""").fetchone()
    return {"baseline_mode": "retrospective, not a trained model or chronological alert",
        "bucket_minutes": bucket_minutes, "bucket_timezone": "UTC", "bucket_interval": "[start, end)",
        "deduplicated_records": unique, "scored_records": usable,
        "unknown_identity_records": unknown_identity, "missing_time_records": missing_time,
        "excluded_edge_records": edges, "edge_policy": "omit first/last observed bucket per identity account",
        "identity_grouping": "account + identity type + session issuer ARN; otherwise recorded ARN/principal/name",
        "deduplication": "canonical record SHA-256; leads attach to the first source-record representative",
        "enrichment": enrichment_run, "enrichment_sha256": enrichment_hash,
        "limitations": "Observed activity is not proof of complete collection. ASN/country are correlated lookup context, not independent corroboration."}


def build(database, output, context_path=None, replace=False, *, anomalies=False, enrichment=None, bucket_minutes=5):
    database, output = database.resolve(), output.resolve()
    context_path = context_path.resolve() if context_path else None
    if not isinstance(bucket_minutes, int) or not 1 <= bucket_minutes <= 1440:
        raise ValueError("bucket-minutes must be between 1 and 1440")
    if enrichment is not None and not anomalies:
        raise ValueError("--enrichment requires --anomalies")
    if anomalies:
        default = database.with_suffix(".enrichment.duckdb")
        enrichment = enrichment or (default if default.exists() else None)
    enrichment = enrichment.resolve() if enrichment else None
    inputs = [database, context_path, enrichment]
    with write_lock(output):
        check_output(output, replace, "native detections", "native_run", TABLES, inputs)
        discard_abandoned(output, inputs)
        # Hash and parse the same bytes, so provenance cannot describe a different read.
        data = context_path.read_bytes() if context_path else None
        context = json.loads(data) if data is not None else None
        if data is not None and not isinstance(context, dict):
            raise ValueError("Network context must be a JSON object")
        with staging(output) as building:
            connection = duckdb.connect(str(building))
            try:
                connection.execute("ATTACH ? AS ev (READ_ONLY)", [str(database)])
                identity = evidence_identity(connection, "ev")
                analysis = prepare_analysis(connection, bucket_minutes, enrichment) if anomalies else None
                connection.execute("CREATE TABLE matches(source_record BIGINT, record_sha256 VARCHAR, rule_id VARCHAR, details JSON)")
                rules = []
                for rule in [instance_credentials] + ([rarity, volume, breadth] if anomalies else []):
                    matches, assessment = rule.run(connection, context)
                    if analysis and rule is not instance_credentials:
                        for _, _, details in matches:
                            details["bucket_minutes"] = bucket_minutes
                            details["bucket_timezone"] = "UTC"
                            for signal in details["signals"]:
                                if "window_start_epoch" in signal:
                                    signal["window_end_epoch"] = signal["window_start_epoch"] + bucket_minutes * 60
                    if matches:
                        connection.executemany("INSERT INTO matches VALUES (?, ?, ?, ?)",
                            [(record, digest, rule.ID, json.dumps(details)) for record, digest, details in matches])
                    rules.append({"rule_id": rule.ID, "rule_version": rule.VERSION, "rule_title": rule.TITLE,
                        "level": rule.LEVEL, "tactics": rule.TACTICS, "techniques": rule.TECHNIQUES,
                        "assessment": assessment})
                run = {"schema_version": SCHEMA, "created_at": datetime.now(timezone.utc).isoformat(),
                    "evidence_source_sha256": identity[0], "evidence_records": identity[1],
                    "rule_id": instance_credentials.ID, "rule_version": instance_credentials.VERSION,
                    "rule_title": instance_credentials.TITLE,
                    "context": context, "context_sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
                    "assessment": rules[0]["assessment"], "rules": rules, "analysis": analysis}
                connection.execute("CREATE TABLE native_run(metadata JSON)")
                connection.execute("INSERT INTO native_run VALUES (?)", [json.dumps(run)])
                if enrichment and sha256(enrichment) != analysis["enrichment_sha256"]:
                    raise ValueError("Enrichment changed during analysis; rerun with a stable sidecar")
                connection.execute("CHECKPOINT")
            finally:
                connection.close()
            check_output(output, replace, "native detections", "native_run", TABLES, inputs)
            publish(building, output, replace)
    return run


def load(connection, path):
    connection.execute("CREATE TEMP TABLE native_details(source_record BIGINT, rule_id VARCHAR, details JSON)")
    if path is None:
        return None
    with duckdb.connect(str(path), read_only=True) as sidecar:
        run = json.loads(sidecar.execute("SELECT metadata FROM native_run").fetchone()[0])
        if run.get("schema_version") != SCHEMA:
            raise ValueError("Unsupported native detections sidecar; rebuild with kamotrace detect --replace")
        if (run["evidence_source_sha256"], run["evidence_records"]) != evidence_identity(connection):
            raise ValueError("Native detections sidecar was built for a different evidence database")
        for rule in run["rules"]:
            sidecar.execute("SELECT source_record, record_sha256, details::VARCHAR FROM matches WHERE rule_id=?", [rule["rule_id"]])
            while rows := sidecar.fetchmany(8192):
                records, hashes, details = map(list, zip(*rows))
                connection.execute("""INSERT INTO native_details SELECT e.source_record, ?, m.details::JSON
                    FROM (SELECT unnest(?::BIGINT[]) AS source_record, unnest(?::VARCHAR[]) AS hash,
                    unnest(?::VARCHAR[]) AS details) m JOIN events e
                    ON e.source_record=m.source_record AND e.record_sha256=m.hash""",
                    [rule["rule_id"], records, hashes, details])
            connection.execute("""INSERT INTO detections SELECT DISTINCT source_record, rule_id, ?, ?, ?,
                ?::VARCHAR[], ?::VARCHAR[] FROM native_details WHERE rule_id=?""",
                [rule["rule_title"], rule["level"], LEVELS.index(rule["level"]),
                 rule["tactics"], rule["techniques"], rule["rule_id"]])
    return run


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace detect", description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--network-context", type=Path, help="Dated AWS prefixes and/or historical expected instance egress JSON")
    parser.add_argument("--anomalies", action="store_true", help="Add retrospective rarity, volume/failure and breadth analyses")
    parser.add_argument("--enrichment", type=Path, help="Offline IP sidecar (default: <database>.enrichment.duckdb if present; requires --anomalies)")
    parser.add_argument("--bucket-minutes", type=int, default=5, help="UTC analysis window size, 1–1440 minutes (default: 5)")
    parser.add_argument("--output", type=Path, help="Default: <database>.native.duckdb")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args(argv)
    try:
        run = build(args.database, args.output or args.database.with_suffix(".native.duckdb"), args.network_context, args.replace,
                    anomalies=args.anomalies, enrichment=args.enrichment, bucket_minutes=args.bucket_minutes)
    except (OSError, ValueError, KeyError, TypeError, duckdb.Error) as error:
        print(f"Native detection stopped: {error}", file=sys.stderr)
        return 1
    print(json.dumps(run["rules"] if args.anomalies else run["assessment"]))
    return 0
