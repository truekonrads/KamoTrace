# KamoTrace repository guidance

## Purpose and boundaries

This is a local, desktop-oriented incident-investigation tool: a small Python
HTTP server with static HTML/JavaScript, not a hosted service. Keep it simple;
there is no frontend build or runtime Node dependency. Mobile compatibility is
not a requirement.

## Code map

Package layout: `src/kamotrace/`, installed as the `kamotrace` command
(`pyproject.toml`). Loading data and enrichment are CLI steps; the browser UI
only reads them.

- `cli.py`: `kamotrace auto | import | download | get-suzaku | suzaku | get-dbip | enrich | serve | mcp` dispatcher.
- `auto.py`: full-auto, rerunnable pipeline over the other modules (tools, download, import, enrich,
  suzaku, serve). It holds no logic of its own beyond deciding per stage whether verified
  completed work can be reused; never let it overwrite evidence or trust unpublished partials.
  Derived sidecars are replaced only when positively identified, never over an input.
  Every writer of a database or sidecar holds `importer.write_lock(output)` (`<stem>.lock`) through
  validation, private staging (`importer.staging`) and publication (`importer.publish`); never
  stage at, or delete, a predictable path.
- `get_suzaku.py`: downloads the official Suzaku 3.x release for the platform,
  verifies GitHub's published SHA-256, refuses unsafe archive paths, and installs
  into `$KAMOTRACE_TOOLS` (default `~/.kamotrace/tools`), where `kamotrace suzaku`
  finds it. Suzaku is fetched by the user at run time, never baked into the image.
- `Dockerfile`: two-stage `uv sync --locked` image on Debian trixie (Suzaku's gnu
  build needs glibc 2.39+). It sets `KAMOTRACE_BIND=0.0.0.0`; docs must always
  publish `-p 127.0.0.1:PORT:PORT` with equal host/container ports.
- `importer.py`: streaming CloudTrail JSON importer, canonical hashes and source
  provenance (`build_info`). Refuses to overwrite existing evidence databases.
- `suzaku.py`: runs or imports Suzaku 3.x `aws-ct-timeline -t duckdb` output into
  a derived `<db>.detections.duckdb`, linked by exact eventID + region + event
  time; also the server-side read-only loader. Never bundle Suzaku (AGPL-3.0).
- `enrich.py`: offline IP enrichment from GeoLite2 `.mmdb` (via `maxminddb`)
  and/or provider-neutral JSONL (schema in README) into `<db>.enrichment.duckdb`,
  bound to the evidence identity; also the server-side priority-merging loader.
  `.mmdb` files are matched by name case-insensitively (city/country, asn).
  Never bundle geolocation data or download MaxMind databases (EULA, account);
  never call online lookup services.
- `get_dbip.py`: downloads the free DB-IP Lite City/ASN `.mmdb` release listed on
  DB-IP's download pages, verifies the published SHA-1 of each decompressed file
  and its `DBIP-` database type, and installs into `$KAMOTRACE_TOOLS/dbip-lite-YYYY-MM`.
  Keep the CC BY 4.0 attribution in its output and docs.
- `server.py`: loopback HTTP endpoints, allowlisted parameterized DuckDB queries,
  enrichment, detections, and SQLite annotation/tag persistence.
- `ssm.py`: local SSM export loading, account/region/command joins, separate
  system/plugin outputs, and command/spreadsheet query endpoints.
- `mcp_server.py`: stdio MCP adapter (official `mcp` SDK). It owns no database or
  sidecar handle; every tool calls `server.py`'s loopback REST endpoints, so the
  browser and agents share one Store, its validation and its review temp tables.
  Add capabilities to `server.py`/`ssm.py` first; keep the adapter a thin mapping.
  Write tools take explicit `record_sha256` lists, never a whole query.
- `skills/investigating-with-kamotrace/SKILL.md`: the end-user agent skill for
  the MCP tools. When a tool, argument, operator, error message or identity rule
  changes, update the skill too, and recheck its examples through a real MCP session.
- `static/app.js`, `app.css`, `index.html`: desktop UI. Reuse the vendored
  Tabulator grid and noUiSlider rather than introducing a framework. The UI calls
  notes **Findings** (evidence-linked observations, not necessarily confirmed)
  and keeps **Event tags** separate; the API, sidecar and MCP keep note/annotation
  names. The left sidebar collapses to a persistent tag rail, never disappears.
- `static/vendor/`: unmodified third-party assets and their licenses.
- `tests/test_contract.py`: synthetic end-to-end HTTP contract tests using real
  DuckDB, a real stdio MCP client session, and Suzaku import/linkage.
- `README.md`: human installation, usage, storage and safety documentation.

## Evidence and security contracts

- Open the CloudTrail database read-only. Temporary tables/views are allowed;
  investigator annotations/tags belong in the separate SQLite sidecar.
- KamoTrace's own model is authoritative: original records and canonical hashes.
  Suzaku detections are derived, read-only leads linked to records; never merge
  them into the evidence database, never link by guesses (time-only, IP), and
  keep unmatched/ambiguous Suzaku rows counted but unattached.
- IP enrichment is a labelled lookup about addresses, not evidence: keep it in
  its own sidecar with per-source provenance, and keep the JSONL schema
  provider-neutral (provider-specific values go in `attributes`).
- SSM command/output data is currently JSON-backed in memory, not persistent
  DuckDB tables. Do not describe it as imported into DuckDB.
- Preserve raw JSON numeric precision and canonical record hashes. Never use
  JavaScript-parsed JSON to replace original evidence JSON.
- Match SSM links by account, region and exact command ID, never time/IP guesses.
  Keep separate systems and plugins distinct, even for one command. Preserve
  missing vs empty output and combined-only vs separate stdout/stderr.
- Supplemental CloudTrail events must be labeled; do not silently insert them
  into the original database or claim reconstructed JSON is original evidence.
- Display evidence as plaintext using `textContent`. Never execute commands or
  decoded payloads. Markdown notes must pass through the existing sanitizer.
  A note's saved query context is inert JSON; reopening it must go through the
  normal validated query path (`build_query`), never be trusted as SQL or paths.
- Tag/note writes patch loaded rows in place (keep scroll, loaded rows and
  selection); counts and filtered results are refreshed explicitly, not silently.
- Note edit/delete require the note's current `updated` stamp (optimistic
  concurrency between browser tabs and MCP agents); never make them last-write-wins.
- The MCP adapter has no authentication by request: keep it stdio-only and its
  `--url` restricted to loopback. Do not add a network MCP listener, SQL/path
  tools, or bulk writes without explicit event hashes.
- Keep loopback binding, Host/Origin checks, CSP, parameter binding and sort/field
  allowlists. Do not introduce an arbitrary-SQL, arbitrary-path or network-fetch
  endpoint. Server startup paths come from CLI arguments, not browser requests.
- Displayed time and bucket boundaries use the selected IANA timezone (default UTC); ranges are
  start-inclusive/end-exclusive. Counts, sorting and prevalence apply to the
  entire filtered selection, not just loaded rows. SSM search matches commands
  and keeps their system/plugin results together.
- Never commit real exports, databases, enrichment, investigator notes, secrets,
  or screenshots containing real evidence. Use synthetic fixtures. Keep private
  files outside this repository or in ignored `data/`; inspect staged files.

## Development and verification

Run from the repository root with Python 3.11+ and uv; dependencies are in
`pyproject.toml`, and `uv run` installs the package into a local environment.

```powershell
uv run python -m unittest discover -s tests
node --check src/kamotrace/static/app.js
uv build
git diff --check
```

Node is optional for running the app, but useful for the JavaScript syntax check.
For formatting changed frontend files, use the existing Prettier style:

```powershell
npx --yes prettier@3.6.2 --write src/kamotrace/static/app.js src/kamotrace/static/app.css src/kamotrace/static/index.html
```

Add public HTTP contract coverage to `tests/test_contract.py` for behavior changes.
Use asymmetric multi-system/plugin fixtures and both sides of time boundaries.
Tests must never write to real evidence. For UI changes, render the affected
desktop states, exercise interactions and inspect screenshots; syntax checks
alone are not visual verification. Use synthetic data for review artifacts.

The surrounding investigation workspace may have a separately configured copy
of this app. Repository defaults must stay portable: no account IDs, incident
dates, absolute investigation paths or automatic private-export discovery here.
Do not overwrite that copy's local configuration when syncing approved changes.
