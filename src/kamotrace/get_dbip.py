"""Download the free DB-IP Lite City and ASN databases and verify DB-IP's published SHA-1.

DB-IP Lite (https://db-ip.com) needs no account and is licensed CC BY 4.0: credit
"IP Geolocation by DB-IP" wherever you share the data. Its `.mmdb` files use the
GeoLite2 layout, so `kamotrace enrich --geolite2 FOLDER` reads them. DB-IP publishes
a monthly release; this helper fetches the one its download pages currently list,
checks each decompressed file against the SHA-1 shown there, and installs the pair
into <tools>/dbip-lite-YYYY-MM. Lite data is less accurate than commercial GeoIP.
"""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import tempfile
from urllib.request import Request, urlopen

import maxminddb

from .get_suzaku import tools_folder

PAGES = {"city": "https://db-ip.com/db/download/ip-to-city-lite",
         "asn": "https://db-ip.com/db/download/ip-to-asn-lite"}
LICENCE = "CC BY 4.0: credit 'IP Geolocation by DB-IP' (https://db-ip.com)"


def release(page, kind):
    """(download URL, YYYY-MM, SHA-1) of the MMDB release listed on a DB-IP download page."""
    # Each format's block lists its SHA1SUM before its download link; the CSV block comes first.
    match = re.search(r"SHA1SUM</dt>\s*<dd[^>]*>([0-9a-f]{40})</dd>(?:(?!SHA1SUM).)*?"
                      rf"href='(https://download\.db-ip\.com/free/dbip-{kind}-lite-(\d{{4}}-\d{{2}})\.mmdb\.gz)'",
                      page, re.S)
    if not match:
        raise RuntimeError(f"No MMDB download with a SHA-1 found on {PAGES[kind]}; download it manually")
    return match.group(2), match.group(3), match.group(1)


def install(compressed, sha1, kind, month, folder):
    """Decompress into folder/dbip-<kind>-lite-<month>.mmdb only if it matches `sha1` and opens as DB-IP Lite."""
    target = folder / f"dbip-{kind}-lite-{month}.mmdb"
    staging = folder / f".{target.name}.part"
    digest = hashlib.sha1()
    try:
        with gzip.open(compressed) as source, staging.open("wb") as stream:
            for chunk in iter(lambda: source.read(1 << 20), b""):
                digest.update(chunk)
                stream.write(chunk)
        if digest.hexdigest() != sha1:
            raise RuntimeError(f"{target.name}: SHA-1 {digest.hexdigest()} does not match the published {sha1}")
        with maxminddb.open_database(str(staging)) as reader:
            database_type = reader.metadata().database_type
        if not database_type.startswith("DBIP-"):
            raise RuntimeError(f"{target.name}: unexpected database type {database_type!r}")
        staging.replace(target)
    except BaseException:
        staging.unlink(missing_ok=True)
        raise
    return target, database_type


def get(url):
    return urlopen(Request(url, headers={"User-Agent": "kamotrace"}), timeout=120)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace get-dbip", description=__doc__.splitlines()[0])
    parser.add_argument("--dest", type=Path, help="Tools folder (default: $KAMOTRACE_TOOLS or ~/.kamotrace/tools)")
    args = parser.parse_args(argv)
    destination = (args.dest or tools_folder()).resolve()
    try:
        releases = {}
        for kind, page in PAGES.items():
            with get(page) as response:
                releases[kind] = release(response.read().decode("utf-8", "replace"), kind)
        months = {month for _, month, _ in releases.values()}
        if len(months) != 1:
            raise RuntimeError(f"DB-IP lists different City/ASN releases {sorted(months)}; retry later")
        month = months.pop()
        folder = destination / f"dbip-lite-{month}"
        folder.mkdir(parents=True, exist_ok=True)
        files = []
        for kind, (url, _, sha1) in releases.items():
            with tempfile.TemporaryDirectory(dir=folder) as work:
                compressed = Path(work) / Path(url).name
                print(f"Downloading {url}", file=sys.stderr)
                with get(url) as response, compressed.open("wb") as stream:
                    shutil.copyfileobj(response, stream)
                target, database_type = install(compressed, sha1, kind, month, folder)
            files.append({"file": target.name, "sha1": sha1, "database_type": database_type, "source": url})
        (folder / "kamotrace-download.json").write_text(json.dumps(
            {"release": month, "files": files, "licence": LICENCE}, indent=2), encoding="utf-8")
    except (OSError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({"folder": str(folder), "release": month, "files": [f["file"] for f in files],
                      "next": f"kamotrace enrich --database CASE.duckdb --geolite2 {folder}",
                      "licence": LICENCE}, indent=2))
