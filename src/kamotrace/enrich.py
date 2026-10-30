"""Build an IP enrichment sidecar from GeoLite2 databases and/or provider-neutral JSONL.

Enrichment is a labelled lookup about source IP addresses, never evidence. Each source keeps its
name, file hash or database build date, and the sidecar is bound to one evidence database.
Sources are layered in the order given: for country, city, ASN and network, the first source with
a value wins; every source's extra `attributes` are kept, prefixed with the source label.
"""
import argparse
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re

import duckdb

from .suzaku import evidence_identity, sha256

SCHEMA = 1
FIELDS = ("country", "country_code", "city", "asn", "as_org")  # Provider-neutral JSONL fields
ATTRIBUTE_KEY = re.compile(r"[A-Za-z0-9_.-]{1,64}")


def canonical_ip(value):
    return str(ipaddress.ip_address(value))


def read_jsonl(path):
    """Validate a provider-neutral JSONL file. Returns {canonical ip: (fields..., attributes)}."""
    rows = {}
    with path.open(encoding="utf-8-sig") as stream:  # -sig: Windows tools often write a BOM
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            where = f"{path.name}:{number}"
            try:
                record = json.loads(line)
            except ValueError:
                raise ValueError(f"{where}: not a JSON object") from None
            if not isinstance(record, dict):
                raise ValueError(f"{where}: not a JSON object")
            unknown = set(record) - {"ip", *FIELDS, "attributes"}
            if unknown:
                raise ValueError(f"{where}: unknown keys {sorted(unknown)}; put provider-specific values in \"attributes\"")
            try:
                ip = canonical_ip(record.get("ip"))
            except (TypeError, ValueError):
                raise ValueError(f"{where}: \"ip\" must be an IPv4 or IPv6 address") from None
            if ip in rows:
                raise ValueError(f"{where}: duplicate ip {ip}")
            for key in ("country", "country_code", "city", "as_org"):
                value = record.get(key)
                if value is not None and (not isinstance(value, str) or len(value) > 256):
                    raise ValueError(f"{where}: \"{key}\" must be text up to 256 characters or null")
            asn = record.get("asn")
            if asn is not None and (isinstance(asn, bool) or not isinstance(asn, int) or asn < 0):
                raise ValueError(f"{where}: \"asn\" must be a non-negative integer or null")
            attributes = record.get("attributes") or {}
            if not isinstance(attributes, dict) or len(attributes) > 50:
                raise ValueError(f"{where}: \"attributes\" must be an object with at most 50 entries")
            for key, value in attributes.items():
                if not ATTRIBUTE_KEY.fullmatch(key):
                    raise ValueError(f"{where}: attribute names use letters, digits, _ . - (up to 64)")
                if not (value is None or isinstance(value, (str, int, float, bool))) or isinstance(value, str) and len(value) > 1000:
                    raise ValueError(f"{where}: attribute \"{key}\" must be text (up to 1,000), a number, true/false or null")
            rows[ip] = tuple(record.get(k) for k in FIELDS) + (attributes,)
    return rows


def read_geolite2(folder, ips):
    """Look up IPs offline in MaxMind GeoLite2/GeoIP2 City or Country plus ASN databases."""
    import maxminddb

    if not folder.is_dir():
        raise ValueError(f"--geolite2 needs a folder of .mmdb files, not {folder}")
    readers, provenance = {}, []
    # Case-insensitive, so DB-IP's dbip-city-lite-*.mmdb is found on Linux too.
    files = sorted(p for p in folder.iterdir() if p.suffix.lower() == ".mmdb")
    for kind, words in (("location", ("city", "country")), ("asn", ("asn",))):
        path = next((p for word in words for p in files if word in p.name.lower()), None)
        if path:
            reader = maxminddb.open_database(str(path))
            readers[kind] = reader
            meta = reader.metadata()
            provenance.append({"file": path.name, "sha256": sha256(path), "database_type": meta.database_type,
                               "build_date": datetime.fromtimestamp(meta.build_epoch, timezone.utc).isoformat()})
    if not readers:
        raise ValueError(f"No GeoLite2 City/Country or ASN .mmdb files in {folder}")
    def lookup(kind, ip):
        try:
            return (readers[kind].get(ip) if kind in readers else None) or {}
        except ValueError:  # e.g. an IPv6 address in an IPv4-only database
            return {}

    rows = {}
    try:
        for ip in ips:
            location, network = lookup("location", ip), lookup("asn", ip)
            country = location.get("country") or {}
            values = ((country.get("names") or {}).get("en"), country.get("iso_code"),
                      ((location.get("city") or {}).get("names") or {}).get("en"),
                      network.get("autonomous_system_number"), network.get("autonomous_system_organization"))
            if any(v is not None for v in values):
                rows[ip] = values + ({},)
    finally:
        for reader in readers.values():
            reader.close()
    return rows, provenance


def build(database, output, sources, replace=False):
    """Write `output` from `sources`, a list of ("geolite2", folder) or ("jsonl", file), highest priority first."""
    database, output = database.resolve(), output.resolve()
    if output.exists() and not replace:
        raise FileExistsError(f"{output} exists; pass --replace to rebuild it")
    labels = ["geolite2" if kind == "geolite2" else path.stem for kind, path in sources]
    if len(set(labels)) != len(labels):
        raise ValueError(f"Source labels must be unique: {labels} (JSONL labels are file names without extension)")
    evidence = duckdb.connect(str(database), read_only=True)
    try:
        source_sha256, records = evidence_identity(evidence)
        # Rows are keyed by the evidence's own source_ip text, so the server's join is exact.
        by_ip = {}
        for (value,) in evidence.execute("SELECT DISTINCT source_ip FROM events WHERE source_ip IS NOT NULL").fetchall():
            try:
                by_ip.setdefault(canonical_ip(value), []).append(value)
            except ValueError:
                pass  # AWS service names such as ec2.amazonaws.com are not addresses.
    finally:
        evidence.close()
    building = output.with_suffix(output.suffix + ".building")
    building.unlink(missing_ok=True)
    connection = duckdb.connect(str(building))
    try:
        connection.execute("""CREATE TABLE ip_enrichment(ip VARCHAR, source VARCHAR, priority INTEGER,
            country VARCHAR, country_code VARCHAR, city VARCHAR, asn BIGINT, as_org VARCHAR, attributes JSON)""")
        summary = []
        for priority, ((kind, path), label) in enumerate(zip(sources, labels)):
            path = path.resolve()
            if kind == "geolite2":
                found, detail = read_geolite2(path, sorted(by_ip))
                about = {"databases": detail}
            else:
                found, about = read_jsonl(path), {"file": str(path), "sha256": sha256(path)}
            rows = [(raw, label, priority, *values[:-1], json.dumps(values[-1]) if values[-1] else None)
                    for ip, values in found.items() for raw in by_ip.get(ip, [])]
            if rows:
                connection.executemany("INSERT INTO ip_enrichment VALUES (?,?,?,?,?,?,?,?,?)", rows)
            summary.append({"label": label, "kind": kind, **about, "entries": len(found),
                            "evidence_ips_matched": len({r[0] for r in rows}),
                            "entries_not_in_evidence": sum(ip not in by_ip for ip in found),
                            "attribute_keys": sorted({k for v in found.values() for k in v[-1]})})
        run = {"schema_version": SCHEMA, "built_at": datetime.now(timezone.utc).isoformat(),
               "evidence_source_sha256": source_sha256, "evidence_records": records,
               "evidence_ips": len(by_ip), "sources": summary}
        connection.execute("CREATE TABLE enrichment_run (metadata JSON)")
        connection.execute("INSERT INTO enrichment_run VALUES (?)", [json.dumps(run)])
        connection.execute("CHECKPOINT")
    except BaseException:
        connection.close()
        building.unlink(missing_ok=True)
        Path(str(building) + ".wal").unlink(missing_ok=True)
        raise
    connection.close()
    building.replace(output)
    return run


def load_enrichment(connection, path):
    """Server side: merge sources by priority into a temp table. Returns the run metadata or None."""
    connection.execute("""CREATE TEMP TABLE ip_enrichment(ip VARCHAR, country VARCHAR, city VARCHAR,
        asn VARCHAR, isp VARCHAR, ip_info VARCHAR)""")
    if path is None:
        return None
    # A separate read-only connection, as for detections: the evidence instance may disable file access.
    sidecar = duckdb.connect(str(path), read_only=True)
    try:
        run = json.loads(sidecar.execute("SELECT metadata FROM enrichment_run").fetchone()[0])
        if run.get("schema_version") != SCHEMA:
            raise ValueError(f"{path}: unsupported enrichment sidecar; rebuild it with `kamotrace enrich --replace`")
        if (run["evidence_source_sha256"], run["evidence_records"]) != evidence_identity(connection):
            raise ValueError(f"{path} was built for a different evidence database; rebuild it with `kamotrace enrich`")
        rows = sidecar.execute("""SELECT ip, source, country, country_code, city, asn, as_org, attributes
            FROM ip_enrichment ORDER BY ip, priority""").fetchall()
    finally:
        sidecar.close()
    merged = {}
    for ip, source, country, code, city, asn, org, attributes in rows:
        values, info = merged.setdefault(ip, ({}, []))
        for name, value in (("country", country or code), ("city", city),
                            ("asn", None if asn is None else f"AS{asn}"), ("isp", org)):
            if value is not None:
                values.setdefault(name, value)
        for key, value in sorted(json.loads(attributes or "{}").items()):
            info.append(f"{source}.{key}={value if isinstance(value, str) else json.dumps(value)}")
    if merged:
        connection.executemany("INSERT INTO ip_enrichment VALUES (?,?,?,?,?,?)",
                               [(ip, v.get("country"), v.get("city"), v.get("asn"), v.get("isp"), "; ".join(i) or None)
                                for ip, (v, i) in merged.items()])
    return run


class Source(argparse.Action):
    """--geolite2 and --jsonl append to one list so their command-line order is their priority."""
    def __call__(self, parser, namespace, value, option_string=None):
        items = getattr(namespace, self.dest, None) or []
        items.append((option_string.lstrip("-"), Path(value)))
        setattr(namespace, self.dest, items)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace enrich", description=__doc__.splitlines()[0])
    parser.add_argument("--database", type=Path, required=True, help="Evidence DuckDB built by `kamotrace import`")
    parser.add_argument("--geolite2", dest="sources", action=Source, metavar="FOLDER",
                        help="Folder with GeoLite2-format City (or Country) and/or ASN .mmdb files, "
                             "e.g. MaxMind GeoLite2/GeoIP2 or DB-IP Lite from `kamotrace get-dbip`")
    parser.add_argument("--jsonl", dest="sources", action=Source, metavar="FILE",
                        help="Provider-neutral JSONL (see README); repeatable. Label = file name without extension")
    parser.add_argument("--output", type=Path, help="Enrichment sidecar (default: <database>.enrichment.duckdb)")
    parser.add_argument("--replace", action="store_true", help="Replace an existing enrichment sidecar")
    args = parser.parse_args(argv)
    if not args.sources:
        parser.error("give at least one --geolite2 FOLDER or --jsonl FILE (earlier sources take priority)")
    for path in (args.database, *(p for _, p in args.sources)):
        if not path.exists():
            parser.error(f"not found: {path}")
    output = args.output or args.database.with_suffix(".enrichment.duckdb")
    try:
        run = build(args.database, output, args.sources, args.replace)
    except (FileExistsError, ValueError) as error:  # Invalid input: report it without a traceback.
        parser.error(str(error))
    print(json.dumps({"output": str(output.resolve()), **run}, indent=2))
