# KamoTrace repository guidance

## Purpose and boundaries

This is a local, desktop-oriented incident-investigation tool: a small Python
HTTP server with static HTML/JavaScript, not a hosted service. Keep it simple;
there is no frontend build or runtime Node dependency. Mobile compatibility is
not a requirement.

## Navigation and scope

Code lives in `src/kamotrace/`, with static frontend assets under `static/` and
synthetic tests under `tests/`. Read [components and design choices](docs/architecture.md)
for ownership boundaries and rationale; use the [user guide](docs/user-guide.md)
and [preparation reference](docs/preparation.md) for usage. Keep component details
in `docs/`; this file holds rules and recurring-mistake guardrails.

Reuse existing stage implementations, the shared REST/Store query and write paths,
and vendored Tabulator/noUiSlider. Do not introduce a parallel query engine or
modify third-party assets under `static/vendor/`. Keep documentation and the
[investigation skill](skills/investigating-with-kamotrace/SKILL.md) aligned with
public interface changes; recheck changed skill examples through a real MCP session.

## Evidence and security contracts

- Open the CloudTrail database read-only. Temporary tables/views are allowed;
  investigator annotations/tags belong in the separate SQLite sidecar.
- Never overwrite original evidence or inputs. Hold `importer.write_lock(output)`
  through validation, private `staging()` and `publish()` for database/sidecar writes.
  Replace only positively identified derived outputs; never trust a partial file
  merely because it exists, or stage at/delete a predictable temporary path.
- KamoTrace's own model is authoritative: original records and canonical hashes.
  Suzaku detections are derived, read-only leads linked to records; never merge
  them into evidence or link by time/IP guesses. Keep unmatched/ambiguous rows
  counted but unattached. GuardDuty associations are contextual, not exact matches.
- IP enrichment is a labelled lookup about addresses, not evidence: keep it in
  its own sidecar with per-source provenance, and keep the JSONL schema
  provider-neutral (provider-specific values go in `attributes`). Keep enrichment
  offline; never call online lookup services.
- Configuration snapshots are not incident-time observations or effective-access
  calculations. Keep configured, observed, absent and unknown distinct: denied,
  failed, partial or uncollected data is not absence. Report truncation and coverage
  gaps; neither date prefixes nor an event-time extent proves complete logs.
- Keep AWS audits read-only and bounded. `trailcheck` never reads object bodies;
  `ssmcheck` never reads output payloads or reports parameter values/caller ARNs.
  Browsing never triggers AWS/DNS/network lookups. Do not bundle Suzaku or geolocation
  data, download MaxMind databases, or remove DB-IP Lite's CC BY 4.0 attribution.
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
- The MCP adapter has no authentication: serve HTTP MCP only at `/mcp` on the
  existing web server, with the same Host/Origin checks and loopback defaults.
  Keep the optional stdio adapter's `--url` restricted to loopback. Do not add
  a separate MCP listener, SQL/path tools, or bulk writes without explicit event hashes.
- Keep loopback binding, Host/Origin checks, CSP, parameter binding and sort/field
  allowlists. Do not introduce an arbitrary-SQL, arbitrary-path or network-fetch
  endpoint. Server startup paths come from CLI arguments, not browser requests.
- Docker examples must publish `-p 127.0.0.1:PORT:PORT` with equal host/container
  ports; a wildcard container bind is not permission to expose this unauthenticated app.
- Displayed time and bucket boundaries use the selected IANA timezone (default UTC); ranges are
  start-inclusive/end-exclusive. Counts, sorting and prevalence apply to the
  entire filtered selection, not just loaded rows. SSM search matches commands
  and keeps their system/plugin results together.
- Preserve all query restrictions across rows, summaries, histograms, saved queries
  and MCP. OR must not escape external scopes; legacy tag/rule arrays remain all-of.
  Follow the [pipeline contract](docs/pipeline-language-v1.md), not a second interpretation.
- Keep drafts separate from applied results. Stale asynchronous responses must not
  overwrite newer edits; errors must not silently relax filters or present old
  results as matching the failed query. Preserve recovery controls in simplified views.
- Initial reference cards must not launch historical scans; expensive history is
  explicit optional work, and **not searched** is not **no activity**.
- The UI calls notes **Findings** and keeps **Event tags** separate. The collapsed
  sidebar remains a usable tag rail, not a hidden panel.
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

Test changes through the affected public interface: collector/CLI tests for
preparation, HTTP contracts for REST, real client sessions for MCP, and browser
interactions for UI behavior. Unittest discovery does not run browser smoke;
follow the [browser-check instructions](docs/user-guide.md#run-the-browser-check-locally)
and CI's dependency pin. Use asymmetric multi-system/plugin fixtures and both
sides of time boundaries. For UI changes, render affected desktop states,
exercise interactions and inspect screenshots; syntax checks alone are not
visual verification. Tests and review artifacts must use synthetic evidence.

The surrounding investigation workspace may have a separately configured copy
of this app. Repository defaults must stay portable: no account IDs, incident
dates, absolute investigation paths or automatic private-export discovery here.
Do not overwrite that copy's local configuration when syncing approved changes.
