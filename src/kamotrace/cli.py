"""KamoTrace command line: load evidence and enrichment, then browse it.

  kamotrace auto     --case case.json --unit ACQUISITION --kind cloudtrail --source export.json [--no-serve]
  kamotrace import   --source event_history.json --case case.json --unit ACQUISITION
  kamotrace prepare  --case case.json --unit ACQUISITION [--range START END]
  kamotrace download --dest CASE --regions all --start 2026-10-01 --end 2026-10-02
  kamotrace trailcheck [--profile NAME] [--regions all] [--json report.json|-] [--probe-buckets] [--emit-policy policy.json|-]
  kamotrace get-suzaku [--version 3.0.0]
  kamotrace get-iwatobi [--dest FOLDER]
  kamotrace suzaku   --case case.json --timeline suzaku.duckdb
  kamotrace get-dbip [--dest FOLDER]
  kamotrace enrich   --case case.json (--geolite2 FOLDER | --jsonl FILE)...
  kamotrace ssmcheck [--profile NAME] [--regions all] [--json report.json] [--max-items 200] [--emit-policy policy.json|-]
  kamotrace inventory [--output FOLDER] [--profile NAME] [--regions all] [--from-export FOLDER] [--emit-policy policy.json|-]
  kamotrace policy [--output policy.json|-] [--bucket NAME]... [--kms-key ARN]... [--validate]
  kamotrace serve    --case case.json [--unit ACQUISITION] [--ssm-export ...]
  kamotrace mcp      --url http://127.0.0.1:8765
"""
import sys

COMMANDS = {
    "auto": ("kamotrace.auto", "Explicit offline acquisition admission, selected preparation, optional sidecars and UI"),
    "import": ("kamotrace.importer", "Load CloudTrail JSON/gzip files, folders or stdin into a new, read-only evidence DuckDB"),
    "import-other": ("kamotrace.other_events", "Stream other-event JSONL into a new immutable DuckDB with required origin provenance"),
    "import-uac": ("kamotrace.tracequarry", "Admit a completed external TraceQuarry parse-only acquisition into a fresh case"),
    "prepare": ("kamotrace.event_index", "Explicitly prepare selected fresh-case units or physical-ID ranges"),
    "download": ("kamotrace.download", "Resume CloudTrail and SSM collection using an existing AWS login"),
    "eks": ("kamotrace.eks", "Collect AWS-only EKS context and bounded existing CloudWatch logs; import offline"),
    "trailcheck": ("kamotrace.trailcheck", "Read-only audit of trails, logging/delivery state, S3 destinations and log dates"),
    "get-suzaku": ("kamotrace.get_suzaku", "Download and verify the official Suzaku 3.x release for this platform"),
    "get-iwatobi": ("kamotrace.get_iwatobi", "Build and verify the pinned Iwatobi forensic-export fork (Git and Rust 1.88+)"),
    "suzaku": ("kamotrace.suzaku", "Import or run Suzaku Sigma detections into a detections sidecar"),
    "guardduty": ("kamotrace.guardduty", "Enrich events with contextual GuardDuty findings from downloaded JSON"),
    "get-dbip": ("kamotrace.get_dbip", "Download and verify the free DB-IP Lite City/ASN databases (no account)"),
    "enrich": ("kamotrace.enrich", "Add offline IP enrichment from GeoLite2-format .mmdb and/or provider-neutral JSONL"),
    "ssmcheck": ("kamotrace.ssmcheck", "Read-only report of what SSM sessions and commands log, and where"),
    "inventory": ("kamotrace.inventory", "Export current AWS network configuration or analyze an existing export offline"),
    "policy": ("kamotrace.aws_policy", "Generate a combined CloudTrail, SSM and inventory policy; optionally validate with AWS"),
    "serve": ("kamotrace.server", "Start the local browser UI and HTTP MCP at /mcp on 127.0.0.1"),
    "mcp": ("kamotrace.mcp_server", "Stdio MCP adapter for agents, backed by a running `kamotrace serve`"),
}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] in ("-h", "--help") or argv[0] not in COMMANDS:
        print(__doc__)
        for name, (_, summary) in COMMANDS.items():
            print(f"  {name:<10} {summary}")
        print("\nRun `kamotrace <command> --help` for options.")
        return 0 if argv and argv[0] in ("-h", "--help") else 2
    from importlib import import_module
    module = import_module(COMMANDS[argv[0]][0])
    return module.main(argv[1:])


if __name__ == "__main__":
    sys.exit(main())
