"""Disposable normalized-field cache; original JSON always stays in read-only evidence."""
import hashlib
import json
import logging
from pathlib import Path

import duckdb

from .importer import discard_abandoned, lock_path, publish, sha256, staging, write_lock
from .suzaku import identify_sidecar


logger = logging.getLogger(__name__)
FORMAT = "kamotrace-event-index"
SCHEMA = 2  # Ordered SHA256 plus explicit physical-ID/dataset membership validation.
TABLES = {"event_index", "index_run"}


def quote(path):
    return "'" + str(path).replace("'", "''") + "'"


def signature(connection, table, sources):
    """SHA256 of ordered fixed-size row digests; also verify every physical ID's dataset.

    Cast fields to text BEFORE JSON encoding: JSON fields retain exact stored lexemes,
    SQL NULL differs from the string "null", and timestamp conversion stays SQL-side.
    Python fetches only IDs and 32-byte row digests, in bounded batches. DuckDB owns
    the scan/sort and can spill under its managed-memory limit. This is integrity
    detection, not authentication against a writer forging the cache and manifest.
    """
    columns = [r[0] for r in connection.execute(f"DESCRIBE {table}").fetchall()]
    fields = ",".join('"' + name.replace('"', '""') + '"::VARCHAR' for name in columns)
    boundaries = [(offset + count, dataset) for dataset, (_, _, _, count, offset) in enumerate(sources) if count]
    connection.execute(f"SELECT source_record, dataset_index, unhex(sha256(to_json([{fields}]))) "
                       f"FROM {table} ORDER BY source_record")
    digest, count, position = hashlib.sha256(), 0, 0
    while rows := connection.fetchmany(1000):
        for record, dataset, row_digest in rows:
            count += 1
            while position < len(boundaries) and count > boundaries[position][0]:
                position += 1
            if position == len(boundaries) or record != count or dataset != boundaries[position][1]:
                raise ValueError("Normalized cache physical IDs or dataset membership differ from sources")
            digest.update(row_digest)
    if count != sum(s[3] for s in sources):
        raise ValueError("Normalized event count differs from source membership")
    return [count, digest.hexdigest()]


def bind(connection, database, sources):
    """Build once per ordered immutable source set, then attach the validated cache READ_ONLY.

    sources: (path, normalized SELECT, raw SELECT, declared count, global offset).
    The caller alone supplies startup paths/SQL; no request can choose either.
    """
    output = Path(database).with_suffix(".event-index.duckdb").resolve()
    inputs = [Path(s[0]).resolve() for s in sources]
    if any(output == p or lock_path(output) == p for p in inputs):
        raise ValueError("Event index cache path conflicts with an evidence input")
    projection = "SELECT * EXCLUDE(raw_event) FROM (" + sources[0][1] + ")"
    with write_lock(output):
        discard_abandoned(output, inputs)
        columns = [list(r[:2]) for r in connection.execute("DESCRIBE " + projection).fetchall()]
        expected = {"format": FORMAT, "schema_version": SCHEMA, "duckdb_version": duckdb.__version__,
                    "columns": columns, "sources": []}
        for path, select, raw, count, offset in sources:
            expected["sources"].append({"path": str(Path(path).resolve()), "sha256": sha256(path),
                                        "select": select, "records": count, "offset": offset})
        previous = identify_sidecar(output, "index_run", TABLES) if output.exists() else None
        if output.exists() and (previous is None or previous.get("format") != FORMAT):
            raise ValueError(f"{output} is not an identifiable KamoTrace event index; refusing to replace it")
        if previous and previous.get("schema_version") == SCHEMA and previous.get("identity") == expected and previous.get("complete") is True:
            connection.execute(f"ATTACH {quote(output)} AS normalized_cache (READ_ONLY)")
            try:
                actual_columns = [list(r[:2]) for r in connection.execute(
                    "DESCRIBE normalized_cache.event_index").fetchall()]
                manifests = connection.execute("SELECT count(*) FROM normalized_cache.index_run").fetchone()[0]
                valid = (manifests == 1 and actual_columns == columns and
                         signature(connection, "normalized_cache.event_index", sources) == previous.get("signature"))
            except (duckdb.Error, ValueError):
                valid = False
            if valid:
                logger.info("Reusing validated normalized event index: %s", output)
                return "reused"
            connection.execute("DETACH normalized_cache")
        logger.info("Building normalized event index with one set-based insert per source: %s", output)
        with staging(output) as target:
            connection.execute(f"ATTACH {quote(target)} AS normalized_cache")
            try:
                connection.execute("CREATE TABLE normalized_cache.event_index AS " + projection + " WHERE false")
                for dataset, (path, select, raw, count, offset) in enumerate(sources):
                    stats = connection.execute("SELECT count(*), min(source_record), max(source_record), "
                        "count(DISTINCT source_record) FROM (" + raw + ")").fetchone()
                    if stats != (count, offset + 1 if count else None, offset + count if count else None, count):
                        raise ValueError("Event source IDs must be exactly 1..records before applying dataset offsets")
                    connection.execute("INSERT INTO normalized_cache.event_index SELECT * EXCLUDE(raw_event) FROM (" + select + ")")
                    # Compare physical occurrences and provenance, not distinct hashes/event IDs.
                    keys = "source_record, record_sha256, source_file, source_ordinal"
                    cached = f"SELECT {keys} FROM normalized_cache.event_index WHERE dataset_index={dataset}"
                    original = f"SELECT {keys} FROM ({raw})"
                    mismatch = connection.execute("SELECT count(*) FROM ((" + original + " EXCEPT ALL " + cached +
                        ") UNION ALL (" + cached + " EXCEPT ALL " + original + "))").fetchone()[0]
                    if mismatch:
                        raise ValueError("Normalized event view does not preserve source occurrences and provenance")
                run = {"format": FORMAT, "schema_version": SCHEMA, "identity": expected,
                       "complete": True, "signature": signature(connection, "normalized_cache.event_index", sources)}
                # Recheck sources before publishing, not just before the build.
                if any(sha256(path) != item["sha256"] for path, item in zip(inputs, expected["sources"])):
                    raise ValueError("Evidence source changed while building the normalized event index")
                connection.execute("CREATE TABLE normalized_cache.index_run(metadata JSON)")
                connection.execute("INSERT INTO normalized_cache.index_run VALUES (?)", [json.dumps(run)])
                connection.execute("CHECKPOINT normalized_cache")
            finally:
                connection.execute("DETACH normalized_cache")
            publish(target, output, replace=previous is not None)
        connection.execute(f"ATTACH {quote(output)} AS normalized_cache (READ_ONLY)")
        return "built"
