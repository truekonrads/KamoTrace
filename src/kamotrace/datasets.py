"""Fresh-case manifests; never adopt existing databases or unreferenced files."""
from contextlib import contextmanager
import os
from pathlib import Path
import uuid

import duckdb
import simplejson as json

from .importer import in_staging, lock_path, publish, sha256, staging, write_lock
CASE_FORMAT = "kamotrace-case-v1"
ID_BLOCK = 65536


def intervals(value, upper):
    """Validate canonical, nonoverlapping half-open physical-ID intervals."""
    if not isinstance(value, list) or not value:
        raise ValueError("Expected nonempty physical-ID intervals")
    previous = 0
    for pair in value:
        if (not isinstance(pair, list) or len(pair) != 2
                or any(type(n) is not int for n in pair)
                or not 1 <= pair[0] < pair[1] <= upper or pair[0] <= previous):
            raise ValueError("ID intervals must be sorted, disjoint and nonadjacent [start,end) ranges")
        previous = pair[1]
    return value


def validate_case(info, path):
    """Validate metadata without scanning evidence; attachment verifies artifacts separately."""
    from .other_events import MANUAL_BASE
    if (not isinstance(info, dict) or info.get("format") != CASE_FORMAT
            or info.get("schema_version") != 1):
        raise ValueError("Not a fresh KamoTrace case manifest; create a new case and re-ingest (no migration)")
    try:
        uuid.UUID(info["case_id"])
    except (KeyError, ValueError, TypeError, AttributeError):
        raise ValueError("Invalid case identity") from None
    if (type(info.get("revision")) is not int or info["revision"] < 0
            or type(info.get("next_record")) is not int or not 1 <= info["next_record"] <= MANUAL_BASE
            or not isinstance(info.get("units"), list)):
        raise ValueError("Invalid case revision, ID high-water mark or units")
    seen, files, assigned = set(), {path, lock_path(path)}, []
    for unit in info["units"]:
        if (not isinstance(unit, dict) or not isinstance(unit.get("unit_id"), str)
                or not unit["unit_id"].strip() or len(unit["unit_id"]) > 200
                or unit["unit_id"] in seen or unit.get("kind") not in ("cloudtrail", "generic", "uac", "eks", "guardduty")
                or not isinstance(unit.get("labels"), dict) or not isinstance(unit.get("input"), dict)):
            raise ValueError("Invalid or duplicated acquisition unit")
        seen.add(unit["unit_id"])
        for field in ("raw", "prepared"):
            artifact = unit.get(field)
            if artifact is None and field == "prepared":
                continue
            if (not isinstance(artifact, dict) or not isinstance(artifact.get("path"), str)
                    or not isinstance(artifact.get("sha256"), str) or len(artifact["sha256"]) != 64
                    or any(c not in "0123456789abcdef" for c in artifact["sha256"])
                    or type(artifact.get("records")) is not int or artifact["records"] < 1):
                raise ValueError("Invalid artifact identity/count")
            resolved = Path(artifact["path"]).resolve()
            if resolved in files or in_staging(resolved) or str(resolved) != artifact["path"]:
                raise ValueError("Case artifacts must be distinct, resolved paths outside private staging")
            files.add(resolved)
            intervals(artifact.get("ranges"), info["next_record"])
            if field == "raw":
                assigned.extend(artifact["ranges"])
            else:
                if (artifact.get("profile") != "core-v1" or any(
                        not any(a <= start < end <= b for a, b in unit["raw"]["ranges"])
                        for start, end in artifact["ranges"])):
                    raise ValueError("Prepared coverage must be within its raw unit and use core-v1")
    assigned.sort()
    if any(right[0] < left[1] for left, right in zip(assigned, assigned[1:])):
        raise ValueError("Acquisition units cannot share issued IDs")
    return info


def read_case(path):
    path = Path(path).resolve()
    return validate_case(json.loads(path.read_text(encoding="utf-8")), path)


def sync_directory(path):
    """Persist rename/link state on systems supporting directory fsync.

    Windows does not expose directory fsync through Python. Atomic replacement
    still applies there; this is not a universal power-loss durability promise.
    """
    if os.name != "nt":
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def durable_publish(staged, output, replace=False):
    with Path(staged).open("rb") as stream:
        os.fsync(stream.fileno())
    publish(staged, output, replace=replace)
    sync_directory(Path(output).parent)


def save_case(path, info, revision):
    """Caller holds the case lock. Reject stale snapshots before replacement."""
    current = read_case(path) if path.exists() else None
    if (None if current is None else current["revision"]) != revision:
        raise ValueError("Case manifest changed; reopen it before writing")
    validate_case(info, path)
    if current is not None and (info["case_id"] != current["case_id"]
            or info["next_record"] < current["next_record"]):
        raise ValueError("Case identity and issued ID high-water mark cannot be reset")
    info["revision"] = 0 if revision is None else revision + 1
    with staging(path) as target:
        target.write_text(json.dumps(info, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        durable_publish(target, path, replace=current is not None)


@contextmanager
def case_writer(path):
    """One fail-fast writer, including first initialization; no implicit recovery/adoption."""
    path = Path(path).resolve()
    if in_staging(path):
        raise ValueError("A case manifest cannot live in private staging")
    with write_lock(path):
        if not path.exists():
            save_case(path, {"format": CASE_FORMAT, "schema_version": 1, "case_id": str(uuid.uuid4()),
                             "revision": 0, "next_record": 1, "units": []}, None)
        yield read_case(path)


def reserve(path, info, size=ID_BLOCK):
    """Durably burn a block before use. Failed/abandoned work never returns IDs.

    The caller holds case_writer throughout reservation, build and registration.
    Only the high-water mark is persisted, never a per-record allocation ledger.
    """
    from .other_events import MANUAL_BASE
    if type(size) is not int or size < 1 or info["next_record"] + size > MANUAL_BASE:
        raise ValueError("ID reservation exceeds the ordinary exact-integer namespace")
    start = info["next_record"]
    info["next_record"] += size
    save_case(Path(path).resolve(), info, info["revision"])
    return start, info["next_record"]


def completed_unit(info, key, identity):
    """Retry identity is acquisition key plus input/options, not content deduplication."""
    for unit in info["units"]:
        if unit["unit_id"] == key:
            if unit["input"] != identity:
                raise ValueError("Acquisition key already registered with different inputs/options; use a new key")
            verify_artifact(info, unit, "raw")
            return unit
    return None


def verify_artifact(info, unit, field):
    """Fail closed on file identity and case/unit metadata; never repair a reader's inputs."""
    artifact = unit.get(field)
    if artifact is None:
        raise ValueError(f"Preparation required for unit {unit['unit_id']}; run kamotrace prepare")
    path = Path(artifact["path"])
    if sha256(path) != artifact["sha256"]:
        raise ValueError(f"{field} artifact changed for unit {unit['unit_id']}")
    table = "build_info" if field == "raw" else "index_run"
    with duckdb.connect(str(path), read_only=True) as connection:
        rows = connection.execute(f"SELECT metadata FROM {table}").fetchall()
    expected = {"case_id": info["case_id"], "unit_id": unit["unit_id"],
                "ranges": artifact["ranges"], "records": artifact["records"]}
    if len(rows) != 1 or json.loads(rows[0][0]).get("case_unit") != expected:
        raise ValueError("Artifact metadata disagrees with case/unit membership")
    return path


def admit(path, key, kind, sources, origin=None, labels=None):
    """Import one new acquisition, artifact first and manifest last.

    IDs are passed into the existing insertion paths, never added to a view or
    rewritten after publication. Published orphans are retained and not adopted.
    """
    from . import importer, other_events
    path = Path(path).resolve()
    if kind == "uac":
        from . import tracequarry
        if len(sources) != 1:
            raise ValueError("UAC admission requires one completed parse-only export directory")
        source = Path(sources[0]).resolve()
        inputs = [source / name for name in ("run_manifest.json", "observations.jsonl", "source_index.json")]
    elif kind == "eks":
        from . import eks
        if len(sources) != 1:
            raise ValueError("EKS admission requires one verified export directory")
        source = Path(sources[0]).resolve()
        eks.read_export(source)
        inputs = [source / name for name in ("manifest.json", "raw.jsonl", "events.jsonl")]
        origin = eks.ORIGIN
    else:
        inputs = importer.expand(sources) if kind == "cloudtrail" else [Path(p).resolve() for p in sources]
    if not inputs or any(not isinstance(p, Path) or p in (path, lock_path(path)) or in_staging(p) for p in inputs):
        raise ValueError("Case imports require rereadable input files separate from the manifest/lock/staging")
    identity = {"kind": kind, "sources": [{"path": str(p), "sha256": sha256(p)} for p in inputs], "origin": origin}
    with case_writer(path) as info:
        previous = completed_unit(info, key, identity)
        if previous is not None:
            return previous
        output = path.parent / f"{path.stem}.raw-{uuid.uuid4().hex}.duckdb"
        metadata = {"case_id": info["case_id"], "unit_id": key, "ranges": [], "records": 0}
        unit = {"unit_id": key, "kind": kind, "input": identity, "labels": labels or {},
                "raw": {"path": str(output), "sha256": "0" * 64, "records": 1,
                        "ranges": [[info["next_record"], info["next_record"] + 1]]}, "prepared": None}
        # Validate caller identity/kind/labels before issuing IDs or building.
        candidate = dict(info, next_record=info["next_record"] + 1, units=[*info["units"], unit])
        validate_case(candidate, path)
        cursor = info["next_record"]

        def allocate(count):
            nonlocal cursor
            if type(count) is not int or count < 1:
                raise ValueError("Cannot allocate an empty occurrence set")
            needed = cursor + count - info["next_record"]
            if needed > 0:
                reserve(path, info, ((needed + ID_BLOCK - 1) // ID_BLOCK) * ID_BLOCK)
            start = cursor
            cursor += count
            metadata["records"] += count
            metadata["ranges"] = [[metadata["ranges"][0][0] if metadata["ranges"] else start, cursor]]
            return start

        if kind == "cloudtrail":
            importer.build(inputs, output, allocate=allocate, case_unit=metadata)
        elif kind == "uac":
            tracequarry.build(source, output, allocate=allocate, case_unit=metadata)
        elif kind == "generic":
            other_events.build(inputs, output, origin, allocate=allocate, case_unit=metadata)
        elif kind == "eks":
            other_events.build([source / "events.jsonl"], output, origin, allocate=allocate, case_unit=metadata)
        elif kind == "guardduty" and len(inputs) == 1:
            from .guardduty import build_raw
            build_raw(inputs[0], output, allocate=allocate, case_unit=metadata)
        else:
            raise ValueError("Unsupported raw admission kind")
        # The producer has closed/checkpointed and independently reconciled input.
        with output.open("rb") as stream:
            os.fsync(stream.fileno())
        sync_directory(output.parent)
        if any(sha256(p) != item["sha256"] for p, item in zip(inputs, identity["sources"])):
            raise ValueError(f"Source changed; unregistered artifact retained at {output}")
        unit["raw"].update(sha256=sha256(output), records=metadata["records"], ranges=metadata["ranges"])
        verify_artifact(info, unit, "raw")
        info["units"].append(unit)
        save_case(path, info, info["revision"])
        return unit
