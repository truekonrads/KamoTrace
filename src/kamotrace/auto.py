"""Full-auto case preparation: tools, AWS collection, import, enrichment and detections, then the UI.

Stages run in dependency order and reuse the other commands' code: get-suzaku, get-dbip, download,
import, enrich, suzaku, serve. Rerun the same command after a failure or interruption: each stage
keeps verified completed work and redoes only what is missing or partial.
"""
import argparse
import json
from pathlib import Path
import sqlite3
import sys

import duckdb
import ijson

from . import download, get_dbip, get_suzaku, server
from .enrich import SCHEMA as ENRICH_SCHEMA, Source, build as enrich, read_geolite2
from .importer import build as import_evidence, expand, sha256
from .suzaku import LEVELS, SCHEMA as SUZAKU_SCHEMA, evidence_identity, import_timeline, run_suzaku

STAGES = ("get-suzaku", "get-dbip", "download", "import", "enrich", "suzaku", "serve")


class StageError(Exception):
    def __init__(self, message, status=1):
        super().__init__(message)
        self.status = status


def say(stage, message):
    print(f"[{STAGES.index(stage) + 1}/{len(STAGES)} {stage}] {message}", file=sys.stderr, flush=True)


def run_command(main, argv, what):
    """Run another kamotrace command's main(); its argparse errors become a stage failure."""
    try:
        status = main(argv)
    except SystemExit as exit:
        status = exit.code
    if status not in (None, 0):
        raise StageError(f"{what} failed (exit status {status})", status if isinstance(status, int) else 1)


def dbip_installed(tools):
    """Newest complete DB-IP Lite folder from `kamotrace get-dbip`; its record is written last."""
    found = []
    for meta in tools.glob("dbip-lite-*/kamotrace-download.json"):
        try:
            info = json.loads(meta.read_text(encoding="utf-8"))
            files = [meta.parent / item["file"] for item in info["files"]]
        except (OSError, ValueError, KeyError, TypeError):
            continue  # An interrupted install: get-dbip writes the record only after verifying both files.
        if len(files) == 2 and all(f.is_file() for f in files):
            found.append((info["release"], meta.parent))
    return max(found)[1] if found else None


def collection(folder):
    """The download manifest, or None. `complete` is set only after every selected output is published."""
    try:
        return json.loads((folder / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def matches_request(manifest, args):
    """True when a completed snapshot was collected with these options (account is checked by AWS)."""
    wanted = {"regions": sorted(set(args.regions)), "services": sorted(set(args.services)),
              "compress": args.compress, "session_s3": sorted(set(args.session_s3)),
              "session_log_groups": sorted(set(args.session_log_group)),
              "start": download.iso(download.timestamp(args.start)) if args.start else None}
    if any(manifest.get(key, False if key == "compress" else None) != value for key, value in wanted.items()):
        return False
    if args.end:
        return not manifest.get("end_default") and manifest["end"] == download.iso(download.timestamp(args.end, end=True))
    return bool(manifest.get("end_default"))


def sidecar_run(path, table, schema, identity):
    """A derived sidecar's run metadata if it is complete, current and bound to this evidence; else None."""
    if not path.is_file():
        return None
    try:
        connection = duckdb.connect(str(path), read_only=True)
        try:
            run = json.loads(connection.execute(f"SELECT metadata FROM {table}").fetchone()[0])
        finally:
            connection.close()
    except (duckdb.Error, TypeError, ValueError):
        return None
    if run.get("schema_version") != schema or (run.get("evidence_source_sha256"), run.get("evidence_records")) != identity:
        return None
    return run


def enrichment_inputs(sources):
    """What `enrich` records about each source, so a sidecar from identical inputs can be reused."""
    result = []
    for kind, path in sources:
        if kind == "geolite2":
            result.append({"label": "geolite2", "kind": kind, "databases": read_geolite2(path.resolve(), [])[1]})
        else:
            result.append({"label": path.stem, "kind": kind, "sha256": sha256(path)})
    return result


def parser():
    parser = argparse.ArgumentParser(
        prog="kamotrace auto", description=__doc__.splitlines()[0],
        epilog="Recovery: rerun the same command. Completed tools, the collection checkpoint (including its "
               "frozen default end time), a verified evidence database and current sidecars are reused; "
               "partial outputs are discarded or redone. Use a new TARGET for a fresh snapshot.")
    parser.add_argument("target", type=Path, help="Case folder (created if needed); everything else has a default")
    paths = parser.add_argument_group("paths")
    paths.add_argument("--database", type=Path, help="Evidence DuckDB (default: TARGET/case.duckdb); never overwritten")
    paths.add_argument("--download-dir", type=Path, help="Collection folder (default: TARGET/download)")
    paths.add_argument("--tools", type=Path, help="Tools folder for Suzaku and DB-IP (default: $KAMOTRACE_TOOLS or ~/.kamotrace/tools)")
    aws = parser.add_argument_group("collection (kamotrace download)")
    aws.add_argument("--profile", help="Existing AWS profile; otherwise the normal SDK credential chain")
    aws.add_argument("--regions", nargs="+", default=["all"], help="Region names, or all enabled regions (default: all)")
    aws.add_argument("--start", help="Inclusive ISO timestamp with offset, or UTC date (default: all available history)")
    aws.add_argument("--end", help="Inclusive ISO timestamp with offset, or entire UTC date (default: first run's start time, kept on resume)")
    aws.add_argument("--services", nargs="+", choices=("cloudtrail", "ssm"), default=["cloudtrail", "ssm"])
    aws.add_argument("--compress", action="store_true", help="Gzip generated CloudTrail/SSM/CloudWatch JSON")
    aws.add_argument("--progress", choices=("auto", "bar", "log", "off"), default="auto")
    aws.add_argument("--session-s3", action="append", default=[], metavar="s3://BUCKET/PREFIX")
    aws.add_argument("--session-log-group", action="append", default=[])
    inputs = parser.add_argument_group("existing inputs (skip the AWS download)")
    inputs.add_argument("--skip-download", action="store_true",
                        help="Use the completed collection in --download-dir without contacting AWS")
    inputs.add_argument("--source", action="extend", nargs="+", type=Path,
                        help="Existing CloudTrail JSON/gzip files or folder to import instead of downloading")
    inputs.add_argument("--ssm-export", type=Path, help="Existing SSM export to show in the UI (with --source/--skip-download)")
    enrichment = parser.add_argument_group("IP enrichment (kamotrace get-dbip / enrich)")
    enrichment.add_argument("--skip-enrich", action="store_true", help="No IP enrichment")
    enrichment.add_argument("--geolite2", dest="sources", action=Source, metavar="FOLDER",
                            help="Use this .mmdb folder instead of DB-IP Lite; repeatable with --jsonl, first wins")
    enrichment.add_argument("--jsonl", dest="sources", action=Source, metavar="FILE",
                            help="Provider-neutral JSONL instead of DB-IP Lite; repeatable, first wins")
    detections = parser.add_argument_group("detections (kamotrace get-suzaku / suzaku)")
    detections.add_argument("--skip-suzaku", action="store_true", help="No Suzaku detections")
    detections.add_argument("--suzaku", type=Path, help="Suzaku executable (default: installed copy, else get-suzaku)")
    detections.add_argument("--suzaku-version", help="Version for get-suzaku when none is installed (default: latest 3.x)")
    detections.add_argument("--timeline", type=Path, help="Existing `suzaku aws-ct-timeline -t duckdb` output to import")
    detections.add_argument("--rules", type=Path, help="Suzaku rules folder")
    detections.add_argument("--min-level", choices=LEVELS)
    parser.add_argument("--rebuild-sidecars", action="store_true",
                        help="Rebuild enrichment and detections even if current (e.g. after updating Suzaku or DB-IP)")
    ui = parser.add_argument_group("browser UI (kamotrace serve)")
    ui.add_argument("--no-serve", action="store_true", help="Prepare the case and exit without starting the UI")
    ui.add_argument("--port", type=int, default=8765)
    return parser


def main(argv=None):
    options = parser()
    args = options.parse_args(argv)
    if args.source and args.skip_download:
        options.error("--source already skips the download; omit --skip-download")
    if "cloudtrail" not in args.services:
        options.error("full-auto imports CloudTrail; --services must include cloudtrail")
    if args.timeline and (args.suzaku or args.rules or args.min_level):
        options.error("--timeline imports existing output; it cannot be combined with --suzaku/--rules/--min-level")
    if args.skip_suzaku and (args.timeline or args.suzaku or args.rules or args.min_level):
        options.error("--skip-suzaku cannot be combined with other Suzaku options")
    if args.skip_enrich and args.sources:
        options.error("--skip-enrich cannot be combined with --geolite2/--jsonl")
    if args.ssm_export and not (args.source or args.skip_download):
        options.error("--ssm-export replaces the downloaded SSM export; use it with --source or --skip-download")
    for path in (*(args.source or []), args.ssm_export, args.suzaku, args.timeline, args.rules,
                 *(p for _, p in args.sources or [])):
        if path is not None and not path.exists():
            options.error(f"not found: {path}")
    try:
        for value, end in ((args.start, False), (args.end, True)):
            if value:
                download.timestamp(value, end)
    except ValueError as error:
        options.error(str(error))

    target = args.target.resolve()
    database = (args.database or target / "case.duckdb").resolve()
    folder = (args.download_dir or target / "download").resolve()
    tools = (args.tools or get_suzaku.tools_folder()).resolve()
    stage = STAGES[0]
    lock = None
    try:
        target.mkdir(parents=True, exist_ok=True, mode=0o700)
        # One run per case: SQLite's exclusive lock is portable and released if the process dies.
        lock = sqlite3.connect(target / ".kamotrace-auto.lock", timeout=0, isolation_level=None)
        try:
            lock.execute("PRAGMA locking_mode=EXCLUSIVE")
            lock.execute("BEGIN EXCLUSIVE")
            lock.execute("COMMIT")
        except sqlite3.OperationalError:
            raise StageError(f"another `kamotrace auto` run is using {target}") from None

        # 1. Suzaku: tools are set up first, so a missing tool fails before a long collection.
        suzaku = args.suzaku
        if args.skip_suzaku or args.timeline:
            say(stage, "skipped" if args.skip_suzaku else f"using existing timeline {args.timeline}")
        elif suzaku:
            say(stage, f"using {suzaku}")
        else:
            suzaku = get_suzaku.installed(tools)
            if suzaku is None:
                say(stage, f"no Suzaku in {tools}; downloading the official release")
                tools.mkdir(parents=True, exist_ok=True)
                run_command(get_suzaku.main, ["--dest", str(tools)] +
                            (["--version", args.suzaku_version] if args.suzaku_version else []), "get-suzaku")
                suzaku = get_suzaku.installed(tools)
            else:
                say(stage, f"using installed {suzaku}")

        # 2. DB-IP Lite, unless other enrichment sources were given.
        stage = STAGES[1]
        sources = args.sources
        if args.skip_enrich or sources:
            say(stage, "skipped" if args.skip_enrich else "using the given enrichment sources")
        else:
            dbip = dbip_installed(tools)
            if dbip is None:
                say(stage, f"no DB-IP Lite in {tools}; downloading (CC BY 4.0: IP Geolocation by DB-IP)")
                tools.mkdir(parents=True, exist_ok=True)
                run_command(get_dbip.main, ["--dest", str(tools)], "get-dbip")
                dbip = dbip_installed(tools)
                if dbip is None:
                    raise StageError(f"get-dbip did not leave a complete DB-IP folder in {tools}")
            else:
                say(stage, f"using {dbip} (IP Geolocation by DB-IP, CC BY 4.0)")
            sources = [("geolite2", dbip)]

        # 3. Collection: the downloader's own checkpoint makes this resumable and keeps its range frozen.
        stage = STAGES[2]
        ssm_export = args.ssm_export
        if args.source:
            say(stage, "skipped: importing --source")
            inputs = list(args.source)
        else:
            manifest = collection(folder)
            if args.skip_download:
                say(stage, f"skipped: using the collection in {folder}")
            elif manifest and manifest.get("complete") and matches_request(manifest, args):
                say(stage, f"already complete in {folder}; reused without contacting AWS")
            else:
                say(stage, f"collecting into {folder} with the existing AWS login")
                argv = ["--dest", str(folder), "--regions", *args.regions, "--services", *args.services,
                        "--progress", args.progress]
                for flag, value in (("--profile", args.profile), ("--start", args.start), ("--end", args.end)):
                    if value:
                        argv += [flag, value]
                argv += ["--compress"] if args.compress else []
                for location in args.session_s3:
                    argv += ["--session-s3", location]
                for group in args.session_log_group:
                    argv += ["--session-log-group", group]
                run_command(download.main, argv, "download")
                manifest = collection(folder)
            if not manifest or not manifest.get("complete"):
                raise StageError(f"{folder} has no completed collection; run without --skip-download to resume it")
            if "cloudtrail" not in manifest["services"]:
                raise StageError(f"{folder} contains no CloudTrail collection; pass --source")
            suffix = ".json.gz" if manifest.get("compress") else ".json"
            inputs = [folder / ("cloudtrail" + suffix)]
            if ssm_export is None and "ssm" in manifest["services"]:
                ssm_export = folder / ("ssm" + suffix)

        # 4. Evidence: imported once, never overwritten; an existing database must match these inputs.
        stage = STAGES[3]
        files = expand(inputs)
        if database.exists():
            evidence = duckdb.connect(str(database), read_only=True)
            try:
                info = json.loads(evidence.execute("SELECT metadata FROM build_info").fetchone()[0])
            except (duckdb.Error, TypeError, ValueError):
                raise StageError(f"{database} exists but is not a KamoTrace evidence database; "
                                 "choose another --database or TARGET") from None
            finally:
                evidence.close()
            recorded = [(s.get("source_file"), s.get("source_sha256")) for s in info.get("sources", [])]
            if recorded != [(str(path), sha256(path)) for path in files]:
                raise StageError(f"{database} was imported from different inputs; it is never overwritten. "
                                 "Use a new TARGET (or --database) for different evidence")
            say(stage, f"verified existing {database} against its sources; reused")
        else:
            building = database.with_suffix(database.suffix + ".building")
            for stale in (building, Path(str(building) + ".wal")):
                if stale.exists():
                    # Only ever published by rename after full verification, so this is an abandoned partial.
                    say(stage, f"removing unfinished import {stale.name}")
                    stale.unlink()
            say(stage, f"importing {len(files)} source file(s) into {database}")
            import_evidence(files, database)
        connection = duckdb.connect(str(database), read_only=True)
        try:
            identity = evidence_identity(connection)
        finally:
            connection.close()

        # 5. Enrichment: a derived sidecar, rebuilt atomically unless current for these exact inputs.
        stage = STAGES[4]
        output = database.with_suffix(".enrichment.duckdb")
        if args.skip_enrich:
            say(stage, "skipped")
        else:
            expected = enrichment_inputs(sources)
            run = sidecar_run(output, "enrichment_run", ENRICH_SCHEMA, identity)
            recorded = run and [{"label": s["label"], "kind": s["kind"], **(
                {"databases": s.get("databases")} if s["kind"] == "geolite2" else {"sha256": s.get("sha256")})}
                for s in run["sources"]]
            if recorded == expected and not args.rebuild_sidecars:
                say(stage, f"{output.name} is current; reused")
            else:
                say(stage, f"building {output.name}")
                enrich(database, output, sources, replace=True)

        # 6. Detections: derived leads, rebuilt atomically unless built from the same CloudTrail input.
        stage = STAGES[5]
        output = database.with_suffix(".detections.duckdb")
        if args.skip_suzaku:
            say(stage, "skipped")
        else:
            run = sidecar_run(output, "suzaku_run", SUZAKU_SCHEMA, identity)
            if args.timeline:
                current = run and run.get("timeline_sha256") == sha256(args.timeline.resolve())
            else:
                if len(inputs) != 1:
                    raise StageError("Suzaku runs on one CloudTrail file or folder; pass --timeline or --skip-suzaku")
                current = run and run.get("suzaku_source") == str(inputs[0].resolve())
            if current and not args.rebuild_sidecars:
                say(stage, f"{output.name} is current; reused")
            elif args.timeline:
                say(stage, f"importing {args.timeline}")
                import_timeline(database, args.timeline, output, replace=True)
            else:
                say(stage, f"running {suzaku}")
                work, timeline = run_suzaku(suzaku, inputs[0], args.rules, args.min_level)
                try:
                    import_timeline(database, timeline, output, True, inputs[0].resolve(),
                                    "(temporary output of the Suzaku run, deleted)")
                finally:
                    work.cleanup()

        # 7. UI: serve's defaults pick up the sidecars beside the database.
        stage = STAGES[6]
        if args.no_serve:
            say(stage, f"skipped; start later with: kamotrace serve --database {database}"
                + (f" --ssm-export {ssm_export}" if ssm_export else ""))
            return 0
        say(stage, "starting the local browser UI (Ctrl+C to stop)")
        run_command(server.main, ["--database", str(database), "--port", str(args.port)] +
                    (["--ssm-export", str(ssm_export)] if ssm_export else []), "serve")
        return 0
    except KeyboardInterrupt:
        print(f"kamotrace auto interrupted during {stage}; rerun the same command to resume.", file=sys.stderr)
        return 130
    except (StageError, OSError, ValueError, RuntimeError, duckdb.Error, ijson.JSONError) as error:
        print(f"kamotrace auto stopped during {stage}: {error}\nCompleted work is kept; fix the cause "
              "(e.g. renew your AWS login), then rerun the same command to resume.", file=sys.stderr)
        return getattr(error, "status", 1)
    finally:
        if lock is not None:
            lock.close()
