"""Explicit offline acquisition admission, preparation and optional local investigation.

Collection and tool installation remain separate commands. Existing evidence,
legacy bindings and sidecars are never discovered, converted or overwritten.
"""
import argparse
from pathlib import Path
import sys

import duckdb

from . import datasets, guardduty, server
from .enrich import Source, build as enrich
from .event_index import prepare
from .suzaku import import_timeline


def main(argv=None):
    options = argparse.ArgumentParser(prog="kamotrace auto", description=__doc__)
    options.add_argument("--case", type=Path)
    options.add_argument("--unit")
    options.add_argument("--kind", choices=("cloudtrail", "generic", "uac", "eks"))
    options.add_argument("--source", nargs="+", type=Path)
    options.add_argument("--origin")
    options.add_argument("--jsonl", dest="sources", action=Source, metavar="FILE")
    options.add_argument("--geolite2", dest="sources", action=Source, metavar="FOLDER")
    options.add_argument("--timeline", type=Path, help="Completed offline Suzaku timeline")
    options.add_argument("--guardduty-findings", type=Path)
    options.add_argument("--snapshot-unit", help="Acquisition key for optional GuardDuty snapshots")
    options.add_argument("--ssm-export", type=Path)
    options.add_argument("--inventory-export", type=Path)
    options.add_argument("--eks-export", type=Path)
    options.add_argument("--no-serve", action="store_true")
    options.add_argument("--port", type=int, default=8765)
    argv = sys.argv[1:] if argv is None else argv
    if "--help" not in argv and "-h" not in argv and not any(str(a).split("=", 1)[0] == "--case" for a in argv):
        options.error("Legacy auto startup is unsupported; re-ingest original inputs into a new case with "
                      "auto --case CASE.json --unit UNIT --kind KIND --source INPUT --no-serve. "
                      "Run download/eks/get-suzaku/get-dbip separately when needed; existing evidence is not migrated")
    args = options.parse_args(argv)
    if not all((args.case, args.unit, args.kind, args.source)):
        options.error("--case, --unit, --kind and --source are required")
    if bool(args.guardduty_findings) != bool(args.snapshot_unit):
        options.error("--guardduty-findings and --snapshot-unit are required together")
    try:
        print("[raw] Admitting explicit acquisition; completed identical keys are reused", flush=True)
        datasets.admit(args.case, args.unit, args.kind, args.source, args.origin)
        print("[prepare] Explicit core preparation of selected unit only", flush=True)
        prepare(args.case, [args.unit])
        if args.guardduty_findings:
            datasets.admit(args.case, args.snapshot_unit, "guardduty", [args.guardduty_findings])
            prepare(args.case, [args.snapshot_unit])
            print("[guardduty] Bind snapshot context to the declared prepared case selection", flush=True)
            output = args.case.with_suffix(".guardduty.duckdb")
            guardduty.build(args.case, args.guardduty_findings, output, replace=output.exists(),
                            case=True, snapshot_unit=args.snapshot_unit)
        if args.sources:
            print("[enrich] Offline enrichment of the declared prepared case selection", flush=True)
            output = args.case.with_suffix(".enrichment.duckdb")
            enrich(args.case, output, args.sources, replace=output.exists(), case=True)
        if args.timeline:
            print("[suzaku] Exact links within the declared prepared case selection", flush=True)
            output = args.case.with_suffix(".detections.duckdb")
            import_timeline(args.case, args.timeline, output, replace=output.exists(), case=True)
        print(f"Prepared {args.unit}; reopen with kamotrace serve --case {args.case}", flush=True)
        if not args.no_serve:
            # Never silently serve only the last imported unit when others are pending.
            return server.main(["--case", str(args.case), "--port", str(args.port)] +
                [arg for flag, value in (("--ssm-export", args.ssm_export),
                    ("--inventory-export", args.inventory_export), ("--eks-export", args.eks_export))
                 if value is not None for arg in (flag, str(value))])
        return 0
    except (ValueError, OSError, duckdb.Error) as error:
        print(f"Case preparation stopped: {error}; completed units retained", file=sys.stderr)
        return 1
