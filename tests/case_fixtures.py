"""Construct fresh-format synthetic units for investigation contract fixtures.

Only tests import this module. Producer outputs here are disposable synthetic
fixtures, not migration inputs accepted by the application. Admission itself is
tested through CLI in CaseManifestContract; these fixtures keep the much larger
HTTP/browser suite focused on query behavior without retaining legacy serving.
"""
import json
from pathlib import Path
import shutil
import uuid

import duckdb

from kamotrace.datasets import ID_BLOCK, case_writer, read_case, reserve, save_case
from kamotrace.event_index import prepare
from kamotrace.importer import sha256
from kamotrace.server import Store as CaseStore
from kamotrace.enrich import build as build_enrichment
from kamotrace.suzaku import import_timeline as build_detections
from kamotrace.guardduty import build as build_guardduty


def case_for(database, additional=()):
    database = Path(database).resolve()
    case = database.with_suffix(".fixture-case.json")
    with case_writer(case) as info:
        for index, source in enumerate((database, *map(Path, additional))):
            source = source.resolve()
            key = "primary" if not index else str(source)
            existing = next((u for u in info["units"] if u["unit_id"] == key), None)
            digest = sha256(source)
            if existing:
                if existing["input"]["sha256"] != digest:
                    raise ValueError("Synthetic fixture changed; different evidence database")
                continue
            target = case.parent / ("fixture-unit-" + uuid.uuid4().hex + ".duckdb")
            shutil.copyfile(source, target)
            with duckdb.connect(str(target)) as connection:
                metadata = json.loads(connection.execute("SELECT metadata FROM build_info").fetchone()[0])
                count = connection.execute("SELECT count(*) FROM raw_events").fetchone()[0]
                if count < 1:
                    raise ValueError("Empty acquisitions are not registered in fresh cases")
                start, _ = reserve(case, info, ((count + ID_BLOCK - 1) // ID_BLOCK) * ID_BLOCK)
                connection.execute("UPDATE raw_events SET source_record=source_record+?", [start - 1])
                membership = {"case_id": info["case_id"], "unit_id": key,
                              "ranges": [[start, start + count]], "records": count}
                metadata["case_unit"] = membership
                connection.execute("UPDATE build_info SET metadata=?", [json.dumps(metadata)])
                connection.execute("CHECKPOINT")
            kind = "uac" if metadata.get("adapter") == "tracequarry-parse-only-v1" else (
                "generic" if metadata.get("format") == "kamotrace-other-v1" else "cloudtrail")
            info["units"].append({"unit_id": key, "kind": kind, "labels": {},
                "input": {"sha256": digest}, "raw": {"path": str(target), "sha256": sha256(target),
                    "records": count, "ranges": membership["ranges"]}, "prepared": None})
            save_case(case, info, info["revision"])
    prepare(case, [u["unit_id"] for u in read_case(case)["units"]])
    return case


def open_fixture(database=None, enrichment=None, annotations=None, *args, case=None, other_events=(), **kwargs):
    if case is not None:
        return CaseStore(database, enrichment, annotations, *args, case=case, other_events=other_events, **kwargs)
    database = Path(database)
    case = case_for(database, other_events)
    for option, suffix in (("detections", ".detections.duckdb"), ("guardduty", ".guardduty.duckdb")):
        default = database.with_suffix(suffix)
        if option not in kwargs and default.exists():
            kwargs[option] = default
    default = database.with_suffix(".enrichment.duckdb")
    enrichment = enrichment or (default if default.exists() else None)
    units = read_case(case)["units"]
    snapshots = [u["unit_id"] for u in units if u["kind"] == "guardduty"]
    if snapshots:
        kwargs.setdefault("units", [u["unit_id"] for u in units if u["kind"] != "guardduty"] + snapshots[-1:])
    return CaseStore(None, enrichment, annotations or database.with_suffix(".annotations.sqlite3"),
                     *args, case=case, **kwargs)


def enrich(database, output, sources, *args, **kwargs):
    return build_enrichment(case_for(database), output, sources, *args, case=True, **kwargs)


def import_timeline(database, timeline, output, *args, **kwargs):
    return build_detections(case_for(database), timeline, output, *args, case=True, **kwargs)


def guardduty(database, source, output, *args, **kwargs):
    from kamotrace.datasets import admit
    case = case_for(database)
    key = "snapshot-" + sha256(source)
    admit(case, key, "guardduty", [source])
    prepare(case, [key])
    units = [u["unit_id"] for u in read_case(case)["units"] if u["kind"] != "guardduty"] + [key]
    return build_guardduty(case, source, output, *args, case=True, units=units, snapshot_unit=key, **kwargs)
