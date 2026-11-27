"""Evidence-bound, append-only startup bindings for immutable additional datasets."""
from pathlib import Path

import duckdb
import simplejson as json

from .importer import in_staging, lock_path, publish, sha256, staging, write_lock
from .other_events import FORMAT
from .suzaku import evidence_identity

KIND = "kamotrace-datasets-v1"


def entry(path, offset):
    path = Path(path).resolve()
    with duckdb.connect(str(path), read_only=True) as connection:
        metadata = json.loads(connection.execute("SELECT metadata FROM build_info").fetchone()[0])
    if metadata.get("format") != FORMAT or type(metadata.get("records")) is not int or metadata["records"] < 1:
        raise ValueError("Additional datasets must be immutable import-other databases")
    return {"database": str(path), "sha256": sha256(path), "records": metadata["records"], "offset": offset}


def read(database):
    database = Path(database).resolve()
    output = database.with_suffix(".datasets.json")
    with duckdb.connect(str(database), read_only=True) as connection:
        identity = list(evidence_identity(connection))
    if not output.exists():
        return {"kind": KIND, "evidence": identity, "datasets": []}
    info = json.loads(output.read_text(encoding="utf-8"))
    if (not isinstance(info, dict) or info.get("kind") != KIND or info.get("evidence") != identity
            or not isinstance(info.get("datasets"), list)):
        raise ValueError("Dataset bindings do not belong to this evidence database")
    offset, seen = identity[1], set()
    for item in info["datasets"]:
        if not isinstance(item, dict) or not isinstance(item.get("database"), str):
            raise ValueError("Invalid dataset binding")
        actual = entry(item["database"], offset)
        if actual != item or actual["database"] in seen:
            raise ValueError("A bound dataset changed, duplicated or moved; existing bindings are never silently replaced")
        seen.add(actual["database"])
        offset += actual["records"]
    return info


def append(database, paths):
    """Keep every existing binding and append only new paths, regardless of source type."""
    database = Path(database).resolve()
    output = database.with_suffix(".datasets.json")
    paths = [Path(p).resolve() for p in paths]
    if in_staging(output) or any(in_staging(p) or p in (database, output, lock_path(output)) for p in paths):
        raise ValueError("Dataset inputs must be separate from the primary, binding output/lock and staging folders")
    with write_lock(output):
        info = read(database)
        seen = {item["database"] for item in info["datasets"]}
        offset = info["evidence"][1] + sum(item["records"] for item in info["datasets"])
        changed = False
        for path in paths:
            if str(path) in seen:
                continue
            item = entry(path, offset)
            info["datasets"].append(item)
            seen.add(str(path))
            offset += item["records"]
            changed = True
        if changed:
            with staging(output) as staged:
                staged.write_text(json.dumps(info, indent=2), encoding="utf-8")
                publish(staged, output, replace=output.exists())
        return info
