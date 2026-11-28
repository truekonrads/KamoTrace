"""Disposable normalized-field cache; original JSON always stays in read-only evidence."""
import hashlib
import argparse
import json
import logging
from pathlib import Path
import uuid

import duckdb

from .importer import sha256, staging


logger = logging.getLogger(__name__)
FORMAT = "kamotrace-event-index"
CORE_PROFILE = "core-v1"


def core_projection(connection, catalog="raw_source"):
    """Scalar core only; nested/raw JSON remains in the immutable raw artifact.

    SQL NULL, timestamp casts and string extraction retain producer semantics.
    Identity precedence is the existing browser contract, not a new inference.
    """
    metadata = json.loads(connection.execute(f"SELECT metadata FROM {catalog}.build_info").fetchone()[0])
    extra = "" if metadata.get("format") == "kamotrace-other-v1" else """, 'cloudtrail'::VARCHAR AS event_type,
        NULL::VARCHAR AS origin, NULL::VARCHAR AS generic_identity, NULL::VARCHAR AS content_preview,
        NULL::VARCHAR AS author, NULL::VARCHAR AS created, NULL::VARCHAR AS updated,
        record_sha256 AS content_sha256"""
    return ("SELECT * EXCLUDE(raw_event, user_identity, request_parameters, response_elements), "
            "coalesce(generic_identity, identity_arn, user_identity->>'$.userName', "
            "user_identity->>'$.principalId', user_identity->>'$.invokedBy', '(unattributed)') AS core_identity, "
            "user_identity->>'$.accessKeyId' AS key_id, "
            "coalesce(request_parameters->>'$.target', request_parameters->>'$.instanceIds', "
            "request_parameters->>'$.instanceId') AS target, "
            "request_parameters->>'$.documentName' AS document_name FROM (SELECT *" + extra +
            f" FROM {catalog}.events)")


def scope_sql(ranges):
    # Only validated Python integers, never user SQL. Keep base-column predicates
    # below JSON projection; no computed/global ID arithmetic exists here.
    return "(" + " OR ".join(f"(source_record >= {a} AND source_record < {b})" for a, b in ranges) + ")"


def core_signature(connection, table):
    columns = [r[0] for r in connection.execute(f"DESCRIBE {table}").fetchall()]
    fields = ",".join('"' + name.replace('"', '""') + '"::VARCHAR' for name in columns)
    cursor = connection.cursor()
    digest, count, previous = hashlib.sha256(), 0, 0
    try:
        cursor.execute(f"SELECT source_record, unhex(sha256(to_json([{fields}]))) FROM {table} ORDER BY source_record")
        while batch := cursor.fetchmany(1000):
            for record, value in batch:
                if type(record) is not int or record <= previous:
                    raise ValueError("Prepared source_record IDs must be unique positive integers")
                previous = record
                count += 1
                digest.update(value)
    finally:
        cursor.close()
    return [count, digest.hexdigest()]


def prepare(case, keys, ranges=None, *, rebuild=False):
    """Explicit per-unit preparation. A replacement scope is never implicitly unioned."""
    from .datasets import case_writer, durable_publish, intervals, save_case, verify_artifact
    case = Path(case).resolve()
    with case_writer(case) as info:
        selected = [u for u in info["units"] if u["unit_id"] in keys]
        if not keys or len(set(keys)) != len(keys) or len(selected) != len(keys):
            raise ValueError("Select explicit, unique registered unit keys")
        if ranges is not None and len(selected) != 1:
            raise ValueError("Physical-ID ranges require exactly one selected unit")
        for unit in selected:
            raw = verify_artifact(info, unit, "raw")
            scope = unit["raw"]["ranges"] if ranges is None else intervals(ranges, info["next_record"])
            if any(not any(a <= start < end <= b for a, b in unit["raw"]["ranges"]) for start, end in scope):
                raise ValueError("Selected preparation ranges are outside the raw unit")
            previous = unit.get("prepared")
            if previous and previous["ranges"] == scope and not rebuild:
                # Reuse still verifies the entire declared output, not existence.
                verify_prepared(info, unit)
                continue
            output = case.parent / f"{case.stem}.prepared-{uuid.uuid4().hex}.duckdb"
            with staging(output) as target:
                connection = duckdb.connect(str(target))
                try:
                    connection.execute("SET threads=2; SET memory_limit='2GB'; SET TimeZone='UTC'")
                    connection.execute(f"ATTACH {quote(raw)} AS raw_source (READ_ONLY)")
                    projection = core_projection(connection)
                    predicate = scope_sql(scope)
                    connection.execute("CREATE TABLE event_index AS " + projection + " WHERE false")
                    cursor = connection.cursor()
                    try:
                        cursor.execute("SELECT source_record, octet_length(encode(raw_event::VARCHAR)) "
                                       "FROM raw_source.raw_events WHERE " + predicate + " ORDER BY source_record")
                        start, end, rows, size = None, None, 0, 0
                        while batch := cursor.fetchmany(512):
                            for identifier, length in batch:
                                if rows and (rows >= 512 or size + length > 4 * 1024 * 1024):
                                    connection.execute("INSERT INTO event_index " + projection +
                                                       " WHERE " + predicate + " AND source_record >= ? AND source_record < ?", [start, end])
                                    start, rows, size = None, 0, 0
                                if start is None:
                                    start = identifier
                                end, rows, size = identifier + 1, rows + 1, size + length
                        if rows:
                            connection.execute("INSERT INTO event_index " + projection +
                                               " WHERE " + predicate + " AND source_record >= ? AND source_record < ?", [start, end])
                    finally:
                        cursor.close()
                    keys_sql = "source_record, record_sha256, source_file, source_ordinal"
                    expected = f"SELECT {keys_sql} FROM raw_source.raw_events WHERE {predicate}"
                    actual = f"SELECT {keys_sql} FROM event_index"
                    mismatch = connection.execute("SELECT count(*) FROM ((" + expected + " EXCEPT ALL " + actual +
                        ") UNION ALL (" + actual + " EXCEPT ALL " + expected + "))").fetchone()[0]
                    if mismatch:
                        raise ValueError("Prepared occurrences/provenance differ from declared raw coverage")
                    signature_value = core_signature(connection, "event_index")
                    if not signature_value[0]:
                        raise ValueError("Selected preparation coverage contains no records")
                    # Independent complete normalized-field comparison at publication.
                    mismatch = connection.execute("SELECT count(*) FROM ((" + projection + " WHERE " + predicate +
                        " EXCEPT ALL SELECT * FROM event_index) UNION ALL (SELECT * FROM event_index EXCEPT ALL " +
                        projection + " WHERE " + predicate + "))").fetchone()[0]
                    if mismatch:
                        raise ValueError("Prepared scalar fields differ from the core projection")
                    membership = {"case_id": info["case_id"], "unit_id": unit["unit_id"],
                                  "ranges": scope, "records": signature_value[0]}
                    run = {"format": FORMAT, "profile": CORE_PROFILE, "duckdb_version": duckdb.__version__,
                           "raw_sha256": unit["raw"]["sha256"], "projection": projection,
                           "case_unit": membership, "signature": signature_value, "complete": True}
                    connection.execute("CREATE TABLE index_run(metadata JSON)")
                    connection.execute("INSERT INTO index_run VALUES (?)", [json.dumps(run)])
                    connection.execute("CHECKPOINT")
                finally:
                    connection.close()
                if sha256(raw) != unit["raw"]["sha256"]:
                    raise ValueError("Raw artifact changed during preparation")
                durable_publish(target, output)
            unit["prepared"] = {"path": str(output), "sha256": sha256(output), "ranges": scope,
                                "records": signature_value[0], "profile": CORE_PROFILE}
            save_case(case, info, info["revision"])
        return info


def verify_prepared(info, unit):
    from .datasets import verify_artifact
    path = verify_artifact(info, unit, "prepared")
    with duckdb.connect(str(path), read_only=True) as connection:
        run = json.loads(connection.execute("SELECT metadata FROM index_run").fetchone()[0])
        connection.execute(f"ATTACH {quote(unit['raw']['path'])} AS raw_source (READ_ONLY)")
        if (run.get("format") != FORMAT or run.get("complete") is not True or run.get("profile") != CORE_PROFILE
                or run.get("duckdb_version") != duckdb.__version__ or run.get("raw_sha256") != unit["raw"]["sha256"]
                or run.get("projection") != core_projection(connection)
                or core_signature(connection, "event_index") != run.get("signature")):
            raise ValueError("Prepared output incompatible or damaged; run prepare --rebuild to publish a new output")
    return path


def attach_case(connection, info, keys=None):
    """Attach-only case composition, shared by serving and explicit sidecar producers.

    No preparation, registration, ID arithmetic or fallback to a smaller scope.
    The manifest snapshot pins immutable paths until this connection is closed.
    """
    from .datasets import verify_artifact
    selected = info["units"] if keys is None else [u for u in info["units"] if u["unit_id"] in keys]
    if not selected or keys is not None and (len(set(keys)) != len(keys) or len(selected) != len(keys)):
        raise ValueError("Select nonempty registered case units explicitly")
    selects, originals, metadata, coverage = [], [], [], []
    for index, unit in enumerate(selected):
        raw = verify_artifact(info, unit, "raw")
        prepared = verify_prepared(info, unit)
        connection.execute(f"ATTACH {quote(raw)} AS case_raw_{index} (READ_ONLY)")
        connection.execute(f"ATTACH {quote(prepared)} AS case_prepared_{index} (READ_ONLY)")
        item = json.loads(connection.execute(f"SELECT metadata FROM case_raw_{index}.build_info").fetchone()[0])
        item["prepared_coverage"] = unit["prepared"]
        item["unit_id"] = unit["unit_id"]
        item["case_catalog"] = f"case_raw_{index}"
        metadata.append(item)
        nested = ("r.raw_event->'$.userIdentity' AS user_identity, r.raw_event->'$.requestParameters' AS request_parameters, "
                  "r.raw_event->'$.responseElements' AS response_elements" if unit["kind"] == "cloudtrail" else
                  "NULL::JSON AS user_identity, NULL::JSON AS request_parameters, NULL::JSON AS response_elements")
        selects.append(f"SELECT i.*, r.raw_event, {nested}, {index} AS dataset_index, " + quote(unit["unit_id"]) +
                       f" AS unit_id FROM case_prepared_{index}.event_index i JOIN case_raw_{index}.raw_events r USING(source_record)")
        originals.append(f"SELECT r.* FROM case_raw_{index}.raw_events r "
                         f"JOIN case_prepared_{index}.event_index i USING(source_record)")
        coverage.append({"unit_id": unit["unit_id"], "raw_sha256": unit["raw"]["sha256"],
                         "raw_records": unit["raw"]["records"], "ranges": unit["prepared"]["ranges"],
                         "records": unit["prepared"]["records"], "profile": CORE_PROFILE})
    connection.execute("CREATE TEMP VIEW prepared_events AS " + " UNION ALL BY NAME ".join(selects))
    connection.execute("CREATE TEMP VIEW events AS SELECT * FROM prepared_events")
    connection.execute("CREATE TEMP VIEW raw_events AS " + " UNION ALL BY NAME ".join(originals))
    identity = hashlib.sha256(json.dumps({"case_id": info["case_id"], "coverage": sorted(coverage, key=lambda u: u["unit_id"])},
                                        sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    connection.execute("CREATE TEMP TABLE case_binding(source_sha256 VARCHAR, records BIGINT)")
    connection.execute("INSERT INTO case_binding VALUES (?,?)", [identity, sum(c["records"] for c in coverage)])
    return metadata, {"case_id": info["case_id"], "selection_id": identity, "revision": info["revision"], "units": coverage,
                      "excluded_units": [u["unit_id"] for u in info["units"] if u not in selected]}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Explicitly prepare selected fresh-case units; never modifies raw artifacts")
    parser.add_argument("--case", type=Path, required=True)
    parser.add_argument("--unit", action="append", required=True)
    parser.add_argument("--range", nargs=2, type=int, action="append", dest="ranges", metavar=("START", "END"))
    parser.add_argument("--rebuild", action="store_true", help="Publish a new artifact even for an already prepared scope; retain the old file")
    args = parser.parse_args(argv)
    try:
        info = prepare(args.case, args.unit, args.ranges, rebuild=args.rebuild)
    except (ValueError, OSError, duckdb.Error) as error:
        parser.error(str(error))
    print(f"Prepared selected units; reopen viewer to select case revision {info['revision']}")
    return 0


def quote(path):
    return "'" + str(path).replace("'", "''") + "'"
