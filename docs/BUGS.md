# Known bugs and limitations

Outstanding issues, most important first. Each entry says what goes wrong, who
it affects, and the intended fix. The [review log](#fixed-in-the-october-2026-review)
at the end lists what has already been fixed.

## Open

### 2. Free-text search does not cover enrichment fields

`search` matches the raw event JSON only. Country, ASN, network and provider
attributes (`ip_info`) are searchable only with field filters (for example
`ip_info contains spur.tunnel=`). Documented, but easy to miss.

### 3. New sidecars and SSM exports need a server restart

`serve` loads detections, enrichment and the SSM export once at startup. Rerunning
`kamotrace suzaku` or `kamotrace enrich` while the browser runs has no effect
until it is restarted.

### 4. One server per notes sidecar

The server keeps a working copy of tags and notes for queries. A second server
on the same sidecar does not see the first one's writes until restarted, and
both write to it. Run one server per case.

### 5. Long provider attributes are truncated in the grid

`ip_info` (for example a Spur record with many fields) is one cell, ellipsized
like any other. The full value is available through cell copy, prevalence and
filters.

### 6. Docker: untested paths

- `--user "$(id -u):$(id -g)"` with Linux bind mounts is documented but untested.
- SQLite/DuckDB file locking on Docker Desktop bind mounts (Windows/macOS) is
  untested under concurrent browser and MCP writes.
- The host and container ports must be equal (the Host/Origin check uses the
  container's port).

### 7. Suzaku correlation linkage is exact per member, but not per time

A correlation row carries only its latest member's timestamp, so each member is
matched by exact eventID, region set and "no later than" that time, not by its
own instant. EventIDs are unique per region in practice, but a reused eventID in
the same region before that time would make the row `ambiguous` (it is never
attached to a guessed event).

## Fixed in the October 2026 review

An independent review focused on inconsistencies between components, data
shapes and critical usability bugs. Fixed, with regression tests where noted:

| Issue | Fix |
| --- | --- |
| One database accepted only one plain CloudTrail JSON file | `import --source` now accepts multiple files, recursive folders, gzip and binary stdin, with per-source provenance and record hashes. Multi-source identity uses ordered file hashes so reordered record IDs cannot reuse a sidecar; single-source identities stay unchanged. See [import examples](preparation.md#multiple-files-gzip-and-stdin). |
| Search missed values containing `"` or `\` (Windows paths, command lines), because raw JSON stores them escaped | Search also matches the JSON-escaped form (test) |
| Suzaku 3 correlation rules (several eventIDs joined by ` ¦ `) were always `no_match`, hiding critical multi-step detections | Each member eventID links exactly; partial chains stay unlinked (test, plus a real Suzaku 3.0.0 run) |
| `get-suzaku` chose the gnu Linux build on glibc < 2.39, where it cannot run | gnu only on glibc 2.39+, otherwise musl; aarch64 on old glibc asks for a manual download |
| A UTF-8 BOM (Windows PowerShell 5.1) broke CloudTrail, JSONL and SSM readers | All three accept a BOM (test for CloudTrail and JSONL) |
| README said `--geolite2` could be repeated; a second one fails on duplicate labels | README corrected |
| An agent note saved with `min_level` reopened in the browser without it | The browser keeps `min_level` as a removable "Sigma ≥ level" scope |
| `kamotrace suzaku` printed a traceback when the sidecar existed, and a misleading "--suzaku needs --source" with the downloaded copy | Clean errors with the right wording; `serve` reports bad sidecars cleanly too |
| README said `list_detections` takes `query.rules` / `min_level` | README corrected: those filters belong to `search_events` and friends |
| Search results lacked `user_agent`, which the skill and walkthrough rely on | `user_agent` is returned with every row (test) |
| A notes/tags sidecar could be opened with another case's database, mixing cases silently | The sidecar records its evidence on first open and refuses a different one (test) |
