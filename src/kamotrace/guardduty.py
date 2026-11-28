"""Import GuardDuty findings as contextual, read-only event enrichment, never exact detections."""
import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
from decimal import Decimal
import hashlib
import json
from pathlib import Path
import sys

import duckdb
import simplejson

from .importer import discard_abandoned, publish, staging, write_lock
from .suzaku import LEVELS, check_output, evidence_identity, sha256

SCHEMA = 2
TABLES = {"guardduty_run", "findings", "links"}
LINK_BASIS = "context only: identity account + region + access key + observed interval [first, last); not an exact CloudTrail event match"


def read_findings(source):
    document = simplejson.loads(source.read_text(encoding="utf-8-sig"), use_decimal=True)
    findings = document.get("Findings") if isinstance(document, dict) else document
    if not isinstance(findings, list) or any(not isinstance(f, dict) for f in findings):
        raise ValueError("Expected a GuardDuty GetFindings JSON object with Findings, or a findings array")
    if isinstance(document, dict) and "coverage" in document and (
            not isinstance(document["coverage"], dict) or not document["coverage"].get("complete")):
        raise ValueError("GuardDuty collection is incomplete")
    return document, findings


def finding_row(ordinal, finding):
    """Shared admission/link-producer validation; raw JSON retains decimal precision."""
    arn = finding.get("Arn")
    if not all(isinstance(finding.get(key), str) and finding[key] for key in ("Arn", "Id", "AccountId", "Region", "Type")):
        raise ValueError("GuardDuty findings require Arn, Id, AccountId, Region and Type")
    severity = finding.get("Severity")
    if isinstance(severity, bool) or not isinstance(severity, (int, float, Decimal)) or not 0 <= severity <= 10:
        raise ValueError(f"{arn}: invalid GuardDuty severity")
    level = "critical" if severity >= 9 else "high" if severity >= 7 else "medium" if severity >= 4 else "low" if severity >= 1 else "informational"
    service, resource = finding.get("Service") or {}, finding.get("Resource") or {}
    if not isinstance(service, dict) or not isinstance(resource, dict):
        raise ValueError(f"{arn}: Service and Resource must be objects")
    access = resource.get("AccessKeyDetails") or {}
    if not isinstance(access, dict) or (access.get("AccessKeyId") is not None and not isinstance(access["AccessKeyId"], str)):
        raise ValueError(f"{arn}: invalid AccessKeyDetails")
    if finding.get("Title") is not None and not isinstance(finding["Title"], str):
        raise ValueError(f"{arn}: Title must be text")
    first, last = service.get("EventFirstSeen"), service.get("EventLastSeen")
    for stamp in (first, last, finding.get('CreatedAt'), finding.get('UpdatedAt')):
        if stamp is not None and (not isinstance(stamp, str) or datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None):
            raise ValueError(f"{arn}: observed timestamps must include an offset")
    if first and last and datetime.fromisoformat(first.replace("Z", "+00:00")) > datetime.fromisoformat(last.replace("Z", "+00:00")):
        raise ValueError(f"{arn}: observed interval is reversed")
    return [ordinal, arn, finding["Id"], "GuardDuty context (not exact): " + (finding.get("Title") or finding["Type"]),
            level, LEVELS.index(level), finding["AccountId"], finding["Region"], access.get("AccessKeyId"), first, last,
            simplejson.dumps(finding, use_decimal=True)]


def build_raw(source, output, *, allocate, case_unit):
    """One immutable snapshot acquisition; browse IDs are reserved before insertion."""
    from .other_events import EVENTS_VIEW, FORMAT, initialize, insert_batch
    source = Path(source).resolve()
    before = sha256(source)
    document, findings = read_findings(source)
    if not findings:
        raise ValueError("A GuardDuty snapshot unit must contain at least one finding")
    with write_lock(output), staging(output) as target:
        connection = duckdb.connect(str(target))
        try:
            initialize(connection)
            stamp = "coalesce(raw_event->>'$.Service.EventFirstSeen', raw_event->>'$.CreatedAt', raw_event->>'$.UpdatedAt', raw_event->>'$.Service.EventLastSeen')"
            connection.execute("CREATE OR REPLACE VIEW events AS SELECT * REPLACE ("
                "raw_event->>'$.Arn' AS event_id, " + stamp + " AS event_time_text, (" + stamp +
                ")::TIMESTAMPTZ AS event_time, raw_event->>'$.Region' AS aws_region, "
                "'guardduty' AS event_type, raw_event->>'$.AccountId' AS generic_identity, "
                "left('GuardDuty snapshot: ' || coalesce(raw_event->>'$.Title', raw_event->>'$.Type'),240) AS content_preview) FROM (" + EVENTS_VIEW + ")")
            batch, size = [], 0
            for ordinal, finding in enumerate(findings, 1):
                raw = finding_row(ordinal, finding)[-1]
                canonical = simplejson.dumps(finding, use_decimal=True, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
                key = hashlib.sha256(('guardduty-snapshot-v1:' + canonical).encode()).hexdigest()
                if batch and (len(batch) >= 1000 or size + len(raw.encode()) > 8 * 1024 * 1024):
                    insert_batch(connection, batch)
                    batch, size = [], 0
                batch.append((allocate(1), raw, key, str(source), ordinal,
                    'GuardDuty derived finding snapshot (not CloudTrail evidence)', None,
                    finding.get('CreatedAt'), finding.get('UpdatedAt'), hashlib.sha256(raw.encode()).hexdigest()))
                size += len(raw.encode())
            if batch:
                insert_batch(connection, batch)
            if connection.execute("SELECT count(*) FROM raw_events").fetchone()[0] != len(findings):
                raise ValueError("GuardDuty snapshot count mismatch")
            metadata = {"format": FORMAT, "records": len(findings), "source_sha256": before,
                        "origin": "GuardDuty derived finding snapshots", "case_unit": case_unit,
                        "coverage": document.get("coverage") if isinstance(document, dict) else None}
            connection.execute("INSERT INTO build_info VALUES (?)", [json.dumps(metadata)])
            connection.execute("CHECKPOINT")
        finally:
            connection.close()
        if sha256(source) != before:
            raise ValueError("GuardDuty source changed during admission")
        publish(target, output)


def build(database, source, output, replace=False, lock=True, *, case=False, units=None, snapshot_unit=None):
    database, source, output = database.resolve(), source.resolve(), output.resolve()
    with write_lock(output) if lock else nullcontext():
        check_output(output, replace, "GuardDuty", "guardduty_run", TABLES, [database, source])
        discard_abandoned(output, [database, source])
        document, findings = read_findings(source)
        with staging(output) as building:
            connection = duckdb.connect(str(building))
            try:
                if case:
                    from .datasets import read_case
                    from .event_index import attach_case
                    info = read_case(database)
                    attach_case(connection, info, units)
                    unit = next((u for u in info["units"] if u["unit_id"] == snapshot_unit), None)
                    if (unit is None or unit["kind"] != "guardduty" or unit["input"]["sources"] !=
                            [{"path": str(source), "sha256": sha256(source)}]):
                        raise ValueError("Select the registered GuardDuty snapshot unit for exactly these findings")
                    record_map = dict(connection.execute("SELECT source_ordinal, source_record FROM events WHERE unit_id=?",
                                                         [snapshot_unit]).fetchall())
                    if not record_map:
                        raise ValueError("GuardDuty snapshot unit must be in the declared prepared selection")
                else:
                    connection.execute("ATTACH ? AS ev (READ_ONLY)", [str(database)])
                input_events = "events" if case else "ev.events"
                identity = evidence_identity(connection, "ev")
                connection.execute("""CREATE TABLE findings(finding_record BIGINT PRIMARY KEY, arn VARCHAR, finding_id VARCHAR,
                    title VARCHAR, level VARCHAR, level_rank TINYINT, account VARCHAR, region VARCHAR,
                    access_key VARCHAR, first_seen TIMESTAMPTZ, last_seen TIMESTAMPTZ, raw_finding JSON)""")
                for ordinal, finding in enumerate(findings, 1):
                    if case and ordinal not in record_map:
                        continue  # Explicit partial preparation, not a missing source finding.
                    connection.execute("INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        finding_row(record_map[ordinal] if case else ordinal, finding))
                connection.execute(f"""CREATE TABLE links AS SELECT e.source_record, e.record_sha256, f.arn, f.finding_record
                    FROM findings f JOIN {input_events} e ON
                        e.user_identity->>'$.accountId' = f.account AND e.aws_region = f.region
                        AND e.user_identity->>'$.accessKeyId' = f.access_key
                        AND f.access_key IS NOT NULL AND f.access_key <> ''
                        AND e.event_time >= f.first_seen AND e.event_time < f.last_seen""")
                total, linked = connection.execute("""SELECT count(*), count(*) FILTER
                    (WHERE finding_record IN (SELECT finding_record FROM links)) FROM findings""").fetchone()
                run = {"schema_version": SCHEMA, "imported_at": datetime.now(timezone.utc).isoformat(),
                       "source_file": str(source), "source_sha256": sha256(source),
                       "evidence_source_sha256": identity[0], "evidence_records": identity[1],
                       "findings": total, "linked_findings": linked, "unlinked_findings": total - linked,
                       "link_basis": LINK_BASIS,
                       "coverage": document.get("coverage") if isinstance(document, dict) else None}
                connection.execute("CREATE TABLE guardduty_run(metadata JSON)")
                connection.execute("INSERT INTO guardduty_run VALUES (?)", [json.dumps(run)])
                if not case:
                    connection.execute("DETACH ev")
                connection.execute("CHECKPOINT")
            finally:
                connection.close()
            check_output(output, replace, "GuardDuty", "guardduty_run", TABLES, [database, source])
            publish(building, output, replace)
        return run


def load(connection, path):
    """Load immutable finding snapshots and their separately labelled AWS context."""
    from .other_events import RAW_SCHEMA, EVENTS_VIEW
    connection.execute("""CREATE TEMP TABLE guardduty_findings(finding_record BIGINT, rule_id VARCHAR,
        raw_finding VARCHAR, sample_status VARCHAR, time_basis VARCHAR, link_status VARCHAR,
        title VARCHAR, level VARCHAR, level_rank TINYINT)""")
    connection.execute(f"CREATE TEMP TABLE guardduty_raw ({RAW_SCHEMA})")
    # The generic event-column contract, not a second query engine or a JSONL conversion.
    stamp = "coalesce(raw_event->>'$.Service.EventFirstSeen', raw_event->>'$.CreatedAt', raw_event->>'$.UpdatedAt', raw_event->>'$.Service.EventLastSeen')"
    projection = EVENTS_VIEW.replace("FROM raw_events", "FROM guardduty_raw")
    connection.execute(f"""CREATE TEMP VIEW guardduty_events AS SELECT e.* REPLACE (
        raw_event->>'$.Arn' AS event_id, {stamp} AS event_time_text,
        ({stamp})::TIMESTAMPTZ AS event_time, raw_event->>'$.Region' AS aws_region,
        NULL::VARCHAR AS source_ip,
        'guardduty' AS event_type, raw_event->>'$.AccountId' AS generic_identity,
        left('GuardDuty [' || f.sample_status || '] ' || coalesce(raw_event->>'$.Title', raw_event->>'$.Type'), 240) AS content_preview)
        FROM ({projection}) e JOIN guardduty_findings f ON f.finding_record=e.source_record""")
    connection.execute("CREATE TEMP TABLE guardduty_event_links(finding_record BIGINT, source_record BIGINT)")
    if path is None:
        return None
    sidecar = duckdb.connect(str(path), read_only=True)
    try:
        run = json.loads(sidecar.execute("SELECT metadata FROM guardduty_run").fetchone()[0])
        if run.get("schema_version") not in (1, SCHEMA):
            raise ValueError("Unsupported GuardDuty sidecar; rebuild with kamotrace guardduty --replace")
        if (run["evidence_source_sha256"], run["evidence_records"]) != evidence_identity(connection):
            raise ValueError("GuardDuty sidecar was built for a different evidence database")
        ordinal = "finding_record" if run["schema_version"] == 2 else "row_number() OVER (ORDER BY arn)"
        sidecar.execute(f"CREATE TEMP TABLE snapshots AS SELECT {ordinal} AS snapshot_record, * FROM findings")
        sidecar.execute("SELECT snapshot_record, arn, raw_finding::VARCHAR, title, level, level_rank FROM snapshots ORDER BY snapshot_record")
        while rows := sidecar.fetchmany(8192):
            for number, arn, raw, title, level, level_rank in rows:
                value = simplejson.loads(raw, use_decimal=True)
                canonical = simplejson.dumps(value, use_decimal=True, sort_keys=True, separators=(',', ':'), ensure_ascii=False)
                digest = hashlib.sha256(raw.encode()).hexdigest()
                review_key = hashlib.sha256(('guardduty-snapshot-v1:' + canonical).encode()).hexdigest()
                service = value.get("Service") or {}
                basis = next((key for key, stamp in (
                    ('Service.EventFirstSeen', service.get('EventFirstSeen')), ('CreatedAt', value.get('CreatedAt')),
                    ('UpdatedAt', value.get('UpdatedAt')), ('Service.EventLastSeen', service.get('EventLastSeen'))) if stamp), 'unknown')
                sample = sample_status(service)
                resource = value.get('Resource') or {}
                first, last = service.get('EventFirstSeen'), service.get('EventLastSeen')
                if not (resource.get('AccessKeyDetails') or {}).get('AccessKeyId'):
                    status = 'missing access key'
                elif not first or not last:
                    status = 'missing observed time'
                elif datetime.fromisoformat(first.replace('Z', '+00:00')) == datetime.fromisoformat(last.replace('Z', '+00:00')):
                    status = 'point observation excluded by context-v1 [first,last)'
                else:
                    status = 'no matching collected event'
                connection.execute("INSERT INTO guardduty_findings VALUES (?,?,?,?,?,?,?,?,?)",
                    [number, 'guardduty:' + arn, raw, sample, basis, status, title, level, level_rank])
                connection.execute("INSERT INTO guardduty_raw VALUES (?,?,?,?,?,?,?,?,?,?)", [number, raw, review_key,
                    run['source_file'], number,
                    'GuardDuty derived finding snapshot (not CloudTrail evidence)', None,
                    value.get('CreatedAt'), value.get('UpdatedAt'), digest])
        # Append to main's compact catalog, not the read-only detections projection.
        offset = connection.execute("SELECT coalesce(max(detection_rule), 0) FROM detection_rules").fetchone()[0]
        sidecar.execute("""CREATE TEMP TABLE finding_rules AS
            SELECT row_number() OVER (ORDER BY snapshot_record) + ? AS detection_rule, snapshot_record, arn, title, level, level_rank
            FROM snapshots""", [offset])
        sidecar.execute("""SELECT detection_rule, 'guardduty:' || arn, title, level, level_rank
            FROM finding_rules ORDER BY detection_rule""")
        while rows := sidecar.fetchmany(8192):
            connection.execute("""INSERT INTO detection_rules SELECT unnest(?::BIGINT[]), unnest(?::VARCHAR[]),
                unnest(?::VARCHAR[]), unnest(?::VARCHAR[]), unnest(?::TINYINT[]), []::VARCHAR[], []::VARCHAR[]""",
                list(zip(*rows)))
        join = 'l.finding_record=f.snapshot_record' if run['schema_version'] == 2 else 'l.arn=f.arn'
        sidecar.execute(f"SELECT l.source_record, f.detection_rule, f.snapshot_record FROM links l JOIN finding_rules f ON {join}")
        while rows := sidecar.fetchmany(8192):
            connection.execute("INSERT INTO detection_links SELECT unnest(?::BIGINT[]), unnest(?::BIGINT[])",
                               list(zip(*[(r[0], r[1]) for r in rows])))
            connection.execute("INSERT INTO guardduty_event_links SELECT unnest(?::BIGINT[]), unnest(?::BIGINT[])",
                               list(zip(*[(r[2], r[0]) for r in rows])))
        connection.execute("""UPDATE guardduty_findings SET link_status='context-v1: collected event associations (not exact)'
            WHERE finding_record IN (SELECT finding_record FROM guardduty_event_links)""")
        return run
    finally:
        sidecar.close()


def sample_status(service):
    """Only explicit provider flags establish sample status; unknown never means real."""
    additional = service.get('AdditionalInfo') or {}
    flags = [additional.get('Sample')] if isinstance(additional, dict) else []
    if isinstance(additional, dict) and isinstance(additional.get('Value'), str):
        try:
            parsed = json.loads(additional['Value'])
            if isinstance(parsed, dict):
                flags.append(parsed.get('sample'))
        except ValueError:
            pass
    normalized = {str(flag).lower() for flag in flags if isinstance(flag, (bool, str)) and str(flag).lower() in ('true', 'false')}
    return 'sample=true' if normalized == {'true'} else 'sample=false' if normalized == {'false'} else 'sample=unknown'


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace guardduty", description=__doc__)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--database", type=Path)
    destination.add_argument("--case", type=Path)
    parser.add_argument("--unit", action="append", help="Explicit prepared selection for links (default: all units)")
    parser.add_argument("--snapshot-unit", help="Registered GuardDuty acquisition key; required with --case")
    parser.add_argument("--findings", required=True, type=Path, help="Downloaded guardduty.json or AWS GetFindings JSON")
    parser.add_argument("--output", type=Path, help="Default: <database>.guardduty.duckdb")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args(argv)
    if bool(args.case) != bool(args.snapshot_unit) or args.unit and not args.case:
        parser.error("--case requires --snapshot-unit; --unit requires --case")
    database = args.case or args.database
    try:
        if args.case:
            from .datasets import admit
            from .event_index import prepare
            admit(args.case, args.snapshot_unit, "guardduty", [args.findings])
            prepare(args.case, [args.snapshot_unit])
        run = build(database, args.findings, args.output or database.with_suffix(".guardduty.duckdb"), args.replace,
                    case=bool(args.case), units=args.unit, snapshot_unit=args.snapshot_unit)
    except (OSError, ValueError, duckdb.Error) as error:
        print(f"GuardDuty import stopped: {error}", file=sys.stderr)
        return 1
    print(f"GuardDuty: {run['findings']} findings; {run['linked_findings']} with contextual event links; {run['unlinked_findings']} unlinked. {LINK_BASIS}")
    return 0
