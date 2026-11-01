"""Import GuardDuty findings as contextual, read-only event enrichment, never exact detections."""
import argparse
from contextlib import nullcontext
from datetime import datetime, timezone
from decimal import Decimal
import json
from pathlib import Path
import sys

import duckdb
import simplejson

from .importer import discard_abandoned, publish, staging, write_lock
from .suzaku import LEVELS, check_output, evidence_identity, sha256

SCHEMA = 1
TABLES = {"guardduty_run", "findings", "links"}
LINK_BASIS = "context only: identity account + region + access key + observed interval [first, last); not an exact CloudTrail event match"


def build(database, source, output, replace=False, lock=True):
    database, source, output = database.resolve(), source.resolve(), output.resolve()
    with write_lock(output) if lock else nullcontext():
        check_output(output, replace, "GuardDuty", "guardduty_run", TABLES, [database, source])
        discard_abandoned(output, [database, source])
        # Keep JSON numbers intact; never rewrite original finding JSON through JavaScript.
        document = simplejson.loads(source.read_text(encoding="utf-8-sig"), use_decimal=True)
        findings = document.get("Findings") if isinstance(document, dict) else document
        if not isinstance(findings, list) or any(not isinstance(f, dict) for f in findings):
            raise ValueError("Expected a GuardDuty GetFindings JSON object with Findings, or a findings array")
        if isinstance(document, dict) and "coverage" in document and (
                not isinstance(document["coverage"], dict) or not document["coverage"].get("complete")):
            raise ValueError("GuardDuty collection is incomplete")
        with staging(output) as building:
            connection = duckdb.connect(str(building))
            try:
                connection.execute("ATTACH ? AS ev (READ_ONLY)", [str(database)])
                identity = evidence_identity(connection, "ev")
                connection.execute("""CREATE TABLE findings(arn VARCHAR PRIMARY KEY, finding_id VARCHAR,
                    title VARCHAR, level VARCHAR, level_rank TINYINT, account VARCHAR, region VARCHAR,
                    access_key VARCHAR, first_seen TIMESTAMPTZ, last_seen TIMESTAMPTZ, raw_finding JSON)""")
                for finding in findings:
                    arn = finding.get("Arn")
                    if not all(isinstance(finding.get(key), str) and finding[key] for key in ("Arn", "Id", "AccountId", "Region", "Type")):
                        raise ValueError("GuardDuty findings require Arn, Id, AccountId, Region and Type")
                    severity = finding.get("Severity")
                    if isinstance(severity, bool) or not isinstance(severity, (int, float, Decimal)) or not 0 <= severity <= 10:
                        raise ValueError(f"{arn}: invalid GuardDuty severity")
                    level = "critical" if severity >= 9 else "high" if severity >= 7 else "medium" if severity >= 4 else "low" if severity >= 1 else "informational"
                    service = finding.get("Service") or {}
                    resource = finding.get("Resource") or {}
                    if not isinstance(service, dict) or not isinstance(resource, dict):
                        raise ValueError(f"{arn}: Service and Resource must be objects")
                    access = resource.get("AccessKeyDetails") or {}
                    if not isinstance(access, dict) or (access.get("AccessKeyId") is not None and not isinstance(access["AccessKeyId"], str)):
                        raise ValueError(f"{arn}: invalid AccessKeyDetails")
                    if finding.get("Title") is not None and not isinstance(finding["Title"], str):
                        raise ValueError(f"{arn}: Title must be text")
                    first, last = service.get("EventFirstSeen"), service.get("EventLastSeen")
                    for stamp in (first, last):
                        if stamp is not None and (not isinstance(stamp, str) or datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is None):
                            raise ValueError(f"{arn}: observed timestamps must include an offset")
                    if first and last and datetime.fromisoformat(first.replace("Z", "+00:00")) > datetime.fromisoformat(last.replace("Z", "+00:00")):
                        raise ValueError(f"{arn}: observed interval is reversed")
                    key = access.get("AccessKeyId")
                    connection.execute("INSERT INTO findings VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        [arn, finding["Id"], "GuardDuty context (not exact): " + (finding.get("Title") or finding["Type"]),
                         level, LEVELS.index(level), finding["AccountId"], finding["Region"], key, first, last,
                         simplejson.dumps(finding, use_decimal=True)])
                connection.execute("""CREATE TABLE links AS SELECT e.source_record, e.record_sha256, f.arn
                    FROM findings f JOIN ev.events e ON
                        e.user_identity->>'$.accountId' = f.account AND e.aws_region = f.region
                        AND e.user_identity->>'$.accessKeyId' = f.access_key
                        AND f.access_key IS NOT NULL AND f.access_key <> ''
                        AND e.event_time >= f.first_seen AND e.event_time < f.last_seen""")
                total, linked = connection.execute("""SELECT count(*), count(*) FILTER
                    (WHERE arn IN (SELECT arn FROM links)) FROM findings""").fetchone()
                run = {"schema_version": SCHEMA, "imported_at": datetime.now(timezone.utc).isoformat(),
                       "source_file": str(source), "source_sha256": sha256(source),
                       "evidence_source_sha256": identity[0], "evidence_records": identity[1],
                       "findings": total, "linked_findings": linked, "unlinked_findings": total - linked,
                       "link_basis": LINK_BASIS,
                       "coverage": document.get("coverage") if isinstance(document, dict) else None}
                connection.execute("CREATE TABLE guardduty_run(metadata JSON)")
                connection.execute("INSERT INTO guardduty_run VALUES (?)", [json.dumps(run)])
                connection.execute("DETACH ev; CHECKPOINT")
            finally:
                connection.close()
            check_output(output, replace, "GuardDuty", "guardduty_run", TABLES, [database, source])
            publish(building, output, replace)
        return run


def load(connection, path):
    """Append labelled context to the shared read-only detection projection."""
    connection.execute("CREATE TEMP TABLE guardduty_findings(rule_id VARCHAR, raw_finding VARCHAR)")
    if path is None:
        return None
    sidecar = duckdb.connect(str(path), read_only=True)
    try:
        run = json.loads(sidecar.execute("SELECT metadata FROM guardduty_run").fetchone()[0])
        if run.get("schema_version") != SCHEMA:
            raise ValueError("Unsupported GuardDuty sidecar; rebuild with kamotrace guardduty --replace")
        if (run["evidence_source_sha256"], run["evidence_records"]) != evidence_identity(connection):
            raise ValueError("GuardDuty sidecar was built for a different evidence database")
        sidecar.execute("SELECT 'guardduty:' || arn, raw_finding::VARCHAR FROM findings")
        while rows := sidecar.fetchmany(8192):
            connection.execute("INSERT INTO guardduty_findings SELECT unnest(?::VARCHAR[]), unnest(?::VARCHAR[])",
                               list(zip(*rows)))
        # Append to main's compact catalog, not the read-only detections projection.
        offset = connection.execute("SELECT coalesce(max(detection_rule), 0) FROM detection_rules").fetchone()[0]
        sidecar.execute("""CREATE TEMP TABLE finding_rules AS
            SELECT row_number() OVER (ORDER BY arn) + ? AS detection_rule, arn, title, level, level_rank
            FROM findings""", [offset])
        sidecar.execute("""SELECT detection_rule, 'guardduty:' || arn, title, level, level_rank
            FROM finding_rules ORDER BY detection_rule""")
        while rows := sidecar.fetchmany(8192):
            connection.execute("""INSERT INTO detection_rules SELECT unnest(?::BIGINT[]), unnest(?::VARCHAR[]),
                unnest(?::VARCHAR[]), unnest(?::VARCHAR[]), unnest(?::TINYINT[]), []::VARCHAR[], []::VARCHAR[]""",
                list(zip(*rows)))
        sidecar.execute("SELECT l.source_record, f.detection_rule FROM links l JOIN finding_rules f USING (arn)")
        while rows := sidecar.fetchmany(8192):
            connection.execute("INSERT INTO detection_links SELECT unnest(?::BIGINT[]), unnest(?::BIGINT[])",
                               list(zip(*rows)))
        return run
    finally:
        sidecar.close()


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace guardduty", description=__doc__)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--findings", required=True, type=Path, help="Downloaded guardduty.json or AWS GetFindings JSON")
    parser.add_argument("--output", type=Path, help="Default: <database>.guardduty.duckdb")
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args(argv)
    try:
        run = build(args.database, args.findings, args.output or args.database.with_suffix(".guardduty.duckdb"), args.replace)
    except (OSError, ValueError, duckdb.Error) as error:
        print(f"GuardDuty import stopped: {error}", file=sys.stderr)
        return 1
    print(f"GuardDuty: {run['findings']} findings; {run['linked_findings']} with contextual event links; {run['unlinked_findings']} unlinked. {LINK_BASIS}")
    return 0
