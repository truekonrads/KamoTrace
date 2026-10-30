"""KamoTrace command line: load evidence and enrichment, then browse it.

  kamotrace auto     CASE_FOLDER [--profile NAME] [--start ...] [--no-serve] ...
  kamotrace import   --source event_history.json --database case.duckdb
  kamotrace download --dest CASE --regions all --start 2026-10-01 --end 2026-10-02
  kamotrace get-suzaku [--version 3.0.0]
  kamotrace suzaku   --database case.duckdb (--source event_history.json [--suzaku suzaku.exe] | --timeline suzaku.duckdb)
  kamotrace get-dbip [--dest FOLDER]
  kamotrace enrich   --database case.duckdb (--geolite2 FOLDER | --jsonl FILE)...
  kamotrace serve    --database case.duckdb [--ssm-export ...]
  kamotrace mcp      --url http://127.0.0.1:8765
"""
import sys

COMMANDS = {
    "auto": ("kamotrace.auto", "Full-auto, resumable: tools, AWS download, import, enrichment, detections, then the UI"),
    "import": ("kamotrace.importer", "Load CloudTrail JSON/gzip files, folders or stdin into a new, read-only evidence DuckDB"),
    "download": ("kamotrace.download", "Resume CloudTrail and SSM collection using an existing AWS login"),
    "get-suzaku": ("kamotrace.get_suzaku", "Download and verify the official Suzaku 3.x release for this platform"),
    "suzaku": ("kamotrace.suzaku", "Import or run Suzaku Sigma detections into a detections sidecar"),
    "get-dbip": ("kamotrace.get_dbip", "Download and verify the free DB-IP Lite City/ASN databases (no account)"),
    "enrich": ("kamotrace.enrich", "Add offline IP enrichment from GeoLite2-format .mmdb and/or provider-neutral JSONL"),
    "serve": ("kamotrace.server", "Start the local browser UI on 127.0.0.1"),
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
