"""KamoTrace command line: load evidence and enrichment, then browse it.

  kamotrace import   --source event_history.json --database case.duckdb
  kamotrace get-suzaku [--version 3.0.0]
  kamotrace suzaku   --database case.duckdb (--source event_history.json [--suzaku suzaku.exe] | --timeline suzaku.duckdb)
  kamotrace enrich   --database case.duckdb (--geolite2 FOLDER | --jsonl FILE)...
  kamotrace serve    --database case.duckdb [--ssm-export ...]
  kamotrace mcp      --url http://127.0.0.1:8765
"""
import sys

COMMANDS = {
    "import": ("kamotrace.importer", "Load a CloudTrail Records JSON export into a new, read-only evidence DuckDB"),
    "get-suzaku": ("kamotrace.get_suzaku", "Download and verify the official Suzaku 3.x release for this platform"),
    "suzaku": ("kamotrace.suzaku", "Import or run Suzaku Sigma detections into a detections sidecar"),
    "enrich": ("kamotrace.enrich", "Add offline IP enrichment from GeoLite2 and/or provider-neutral JSONL"),
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
