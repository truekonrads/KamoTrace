"""Read-only discovery of prepared acquisitions bound to the startup evidence.

This module cannot register, prepare, repair or resume an acquisition. Paths
come only from the local sidecar selected by the server's startup database.
"""
from pathlib import Path

import duckdb
import simplejson as json

from .importer import sha256
from .suzaku import evidence_identity


def registered(database):
    database = Path(database)
    path = database.with_suffix(".uac.duckdb")
    with duckdb.connect(str(database), read_only=True) as connection:
        identity = list(evidence_identity(connection))
    if not path.exists():
        return {"format": "kamotrace-uac-registry-v1", "evidence": identity,
                "imports": [], "attempts": []}
    with duckdb.connect(str(path), read_only=True) as connection:
        rows = connection.execute("SELECT metadata FROM build_info").fetchall()
    if len(rows) != 1:
        raise ValueError("Expected one acquisition registry metadata row")
    value = json.loads(rows[0][0], use_decimal=True, allow_nan=False)
    if (not isinstance(value, dict) or value.get("format") != "kamotrace-uac-registry-v1"
            or value.get("evidence") != identity
            or not isinstance(value.get("imports"), list)
            or not isinstance(value.get("attempts"), list)):
        raise ValueError("Acquisition registry does not belong to this evidence database")
    for entry in value["imports"]:
        if (not isinstance(entry, dict) or not isinstance(entry.get("database"), str)
                or not isinstance(entry.get("sha256"), str)):
            raise ValueError("Invalid registered acquisition binding")
        source = Path(entry["database"])
        if not source.is_file() or sha256(source) != entry["sha256"]:
            raise ValueError("Registered acquisition changed or is missing")
    return value
