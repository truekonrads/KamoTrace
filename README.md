# KamoTrace

KamoTrace is a local, read-only investigation browser for AWS CloudTrail. Load
an export into DuckDB from the command line, optionally add
[Suzaku](https://github.com/Yamato-Security/suzaku) Sigma detections and SSM
command evidence, then search, pivot, tag and annotate in a desktop browser.
Local AI agents can join through an MCP adapter that shares the same state.

KamoTrace keeps its own data model: the original CloudTrail records, their
canonical SHA-256 hashes and provenance stay authoritative. Suzaku results are a
derived, read-only layer linked to those records, never a replacement for them.

The app is a small Python package with a stdlib HTTP server and static
HTML/JavaScript. No Node build, Docker, database server, account, cloud upload
or runtime CDN is required. The evidence database is opened **read-only**; notes
and tags are saved in a separate sidecar.

## What you can do

- Slice events by Jakarta time; brush or click the filtered histogram to narrow it.
- Search nested event content, pivot on cell values/tags/notes, and go Back/Forward.
- Inspect top/bottom values and exact cell prevalence across the selected data.
- Browse colored tags and shared Markdown notes as findings, with linked evidence.
- Browse Suzaku (Sigma) detections by rule and severity, and pivot on them.
- Enrich source IPs offline from GeoLite2 and/or your own provider's JSONL.
- Browse SSM commands, decoded payloads and per-system/plugin output, either in
  a detailed browser or a dense spreadsheet, with links back to CloudTrail.
- Let local AI agents search, tag/untag and write notes through an MCP adapter
  that shares the running browser's state.

Jump to [Quick start](#quick-start), [Suzaku detections](#suzaku-detections),
[IP enrichment](#ip-enrichment),
[CloudTrail workflow](#cloudtrail-workflow),
[findings: tags and notes](#findings-tags-and-notes), [SSM views](#ssm-command-browser-desktop),
[agent access (MCP)](#agent-access-mcp) or [storage and backups](#storage-and-backups).

## Quick start

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/getting-started/installation/).
Install the `kamotrace` command from a checkout (or from a built wheel):

```powershell
uv tool install C:\path\to\KamoTrace
```

From a checkout you can also skip installing and prefix every command with
`uv run` (for example `uv run kamotrace serve ...`).

Loading data is a command-line step; the browser never imports files. Import an
AWS CloudTrail event-history JSON export (a top-level `Records` array):

```powershell
kamotrace import --source C:\evidence\event_history.json --database C:\evidence\case.duckdb
```

The importer preserves nested JSON and numeric precision, verifies every canonical
record hash, records source-file provenance, and refuses to overwrite an existing
database. It stages records in an automatically cleaned OS temporary directory.
Use a private local disk for both the source and temporary directory: events may
contain secrets.

Optionally add Suzaku detections (see [Suzaku detections](#suzaku-detections)):

```powershell
kamotrace suzaku --database C:\evidence\case.duckdb --suzaku C:\tools\suzaku\suzaku-3.0.0-win-x64.exe --source C:\evidence\event_history.json
```

Start the browser server:

```powershell
kamotrace serve --database C:\evidence\case.duckdb
```

Open **http://127.0.0.1:8765** on the same computer and leave the server running.
It listens on loopback only. Access from a different computer requires a trusted
port forward or another explicitly secured arrangement. It is deliberately not
exposed on the LAN or Internet and is not a multi-user production service. Host
and Origin checks protect loopback access; there is no arbitrary-SQL API. Do not
bypass these checks or publish the evidence with an unauthenticated tunnel.

### Commands

| Command | Purpose |
| --- | --- |
| `kamotrace import --source FILE --database NEW.duckdb` | Build a new evidence database from a CloudTrail `Records` JSON export |
| `kamotrace suzaku --database DB (--timeline FILE \| --suzaku EXE --source FILE)` | Import Suzaku detections into `<database>.detections.duckdb` |
| `kamotrace enrich --database DB (--geolite2 FOLDER \| --jsonl FILE)...` | Add offline IP enrichment into `<database>.enrichment.duckdb` |
| `kamotrace serve --database DB [options]` | Start the browser UI on `127.0.0.1` |
| `kamotrace mcp --url http://127.0.0.1:8765` | Stdio MCP adapter for agents, backed by a running `serve` |

`kamotrace <command> --help` lists every option. `python -m kamotrace` works too.

### `serve` options

| Option | Purpose | Default |
| --- | --- | --- |
| `--database PATH` | Imported evidence database (required) | — |
| `--enrichment PATH` | IP enrichment sidecar from `kamotrace enrich` | `<database stem>.enrichment.duckdb` if present; otherwise countries show as unmapped |
| `--annotations PATH` | Notes and tags SQLite sidecar | `<database stem>.annotations.sqlite3` |
| `--detections PATH` | Suzaku detections sidecar | `<database stem>.detections.duckdb` if present |
| `--ssm-export PATH` | Consolidated SSM command/output JSON | None; optional |
| `--port NUMBER` | Local listening port | `8765` |

Paths are relative to your terminal's current folder unless absolute. Quote
paths containing spaces. A path that does not exist stops startup with an error.
For example, load all optional evidence:

```powershell
kamotrace serve --database "C:\evidence\case.duckdb" --ssm-export "C:\evidence\ssm_command_session_activity.enriched.json"
```

The server never calls external services. Detections and IP enrichment sidecars
beside the database are picked up automatically. Changing enrichment, detections
or the SSM export requires restarting the server.

Only code, synthetic tests and third-party browser assets belong in this
repository. Databases, `event_history*.json`, enrichment JSONL, `.mmdb` files and
the `data/` directory are gitignored; keep evidence outside the repository.

## Suzaku detections

[Suzaku](https://yamato-security.github.io/suzaku/) (Yamato Security) is a
Sigma-based threat-hunting and timeline tool for cloud logs. KamoTrace does not
bundle it (Suzaku is AGPL-3.0); install it yourself and point KamoTrace at it.
Supported input is Suzaku 3.x `aws-ct-timeline` DuckDB output (`suzaku_meta`
schema version 1, UTC timestamps).

Either let KamoTrace run Suzaku on the same export you imported:

```powershell
kamotrace suzaku --database C:\evidence\case.duckdb --suzaku C:\tools\suzaku\suzaku-3.0.0-win-x64.exe --source C:\evidence\event_history.json [--rules C:\tools\suzaku\rules] [--min-level low]
```

or import a timeline you already produced with
`suzaku aws-ct-timeline -f event_history.json -o timeline -t duckdb` (without `-l`):

```powershell
kamotrace suzaku --database C:\evidence\case.duckdb --timeline C:\evidence\timeline.duckdb
```

KamoTrace runs Suzaku from its own folder (so its default `rules` and `config`
are found), writes its output to a temporary folder and deletes it afterwards.

How detections join KamoTrace's model:

- Each Suzaku row is one event × rule match. It is linked to an evidence record
  only when **eventID, AWS region and event time all match exactly**. Identical
  duplicate records (same canonical hash) all receive the match. Rows matching
  no record, or several different records, are kept in the sidecar as
  `no_match`/`ambiguous` and counted, but never shown on an event.
- Output goes to a separate `<database stem>.detections.duckdb`. The evidence
  database is attached read-only and never modified. An existing sidecar is
  only replaced with `--replace`.
- The sidecar records provenance: Suzaku version, command line, rules revision
  and count, timeline SHA-256, evidence source SHA-256 and record count, whether
  `--source` matches the imported file, and linked/unmatched/ambiguous counts.
  `serve` refuses a sidecar built for a different evidence database.

In the browser, the **Findings** sidebar gains a **Detections** tab listing each
rule, most severe first, with its severity letter (I/L/M/H/C), ATT&CK tags (on
hover) and linked event count. Click a rule to add it to the query as a
`Sigma: <rule>` scope; several rule scopes must all match, like tags. The grid's
**Sigma** column shows the most severe level and the match count on one line;
click it for the full rule list. The inspector lists an event's detections too.
Detections are leads, not findings: tag or annotate what you confirm.

## IP enrichment

Source IPs can be enriched offline with country, city, ASN and network, plus any
extra fields your own provider supplies. Enrichment is a labelled lookup about
an address, not evidence, and is never written into the evidence database.
There are two options, which can be combined:

1. **GeoLite2 (convenience).** Download the free MaxMind GeoLite2 **City** (or
   **Country**) and **ASN** databases in `.mmdb` format (requires a free MaxMind
   account and acceptance of the
   [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula); KamoTrace does not
   bundle or download them). Put them in one folder. Commercial GeoIP2 `.mmdb`
   files with the same layout work too.
2. **Your own data (provider-neutral JSONL).** Convert any provider's output
   (Spur, ipinfo, an ip-api cache, an internal list) into the schema below.

```powershell
kamotrace enrich --database C:\evidence\case.duckdb --geolite2 C:\geoip
kamotrace enrich --database C:\evidence\case.duckdb --jsonl C:\evidence\spur.jsonl --geolite2 C:\geoip --replace
```

`--geolite2` and `--jsonl` can each be repeated. **Order is priority:** for
country, city, ASN and network, the first source given that has a value wins.
Extra `attributes` from every source are kept, prefixed with the source label.
The label is `geolite2` or the JSONL file name without its extension (`spur`),
and labels must be unique. Only addresses that appear as a source IP in the
evidence are stored; AWS service names such as `ec2.amazonaws.com` are skipped.

Output goes to `<database stem>.enrichment.duckdb` (or `--output`), which `serve`
loads automatically. An existing sidecar is only rebuilt with `--replace`. It
records the evidence database it was built for (and `serve` refuses another),
the build time, and per source the file SHA-256 (or each `.mmdb` file's hash,
type and build date), entries, evidence IPs matched and attribute names.

### JSONL schema

One JSON object per line; blank lines are ignored. Unknown top-level keys,
invalid values and duplicate addresses stop the run with the file and line.

| Key | Type | Notes |
| --- | --- | --- |
| `ip` | string, required | IPv4 or IPv6 address, normalised (`2001:0db8::1` matches `2001:db8::1`) |
| `country` | string or null | Country name, up to 256 characters |
| `country_code` | string or null | Shown when `country` is absent |
| `city` | string or null | |
| `asn` | non-negative integer or null | Displayed as `AS64500` |
| `as_org` | string or null | Network / AS organisation |
| `attributes` | object, optional | Up to 50 provider-specific values: names of letters, digits, `_ . -` (up to 64), values text (up to 1,000), number, `true`/`false` or null |

A Spur-style example, `spur.jsonl`:

```json
{"ip": "198.51.100.7", "country": "Germany", "as_org": "Example VPN Ltd", "asn": 64501, "attributes": {"proxy_score": 92, "tunnel": "vpn-example", "residential": false}}
{"ip": "2001:db8::1", "attributes": {"risk": "high"}}
```

With a sidecar loaded, the grid shows **Country**, **City**, **ASN** and
**Network / ISP** columns, plus **IP attributes** (for example
`spur.proxy_score=92; spur.tunnel=vpn-example`) when a source supplied
attributes. They work with field filters, is/is-not pivots, prevalence and
value summaries like other fields; free-text search covers raw event JSON only,
not enrichment. Proxy and VPN exits make geography misleading; it is not proof
of a person's location.

## Findings: tags and notes

Tags and notes are browsable findings, not just row metadata. The **Findings**
sidebar (toggle it from the top bar; it collapses to give the grid full width)
has two tabs:

- **Tags** lists every tag with its color and the number of evidence events it is
  on across the whole database (not just the current query). Click a name to add
  that tag to the current query, or click it again to remove it. Several tag
  scopes must **all** match. Click a swatch to recolor a tag everywhere.
- **Notes** lists shared Markdown notes, newest first, with a search box. A note's
  first line is its title. Expand a note to read it, see its linked events (oldest
  25, each opening the inspector), and:
  **Filter to note** (adds it to the current query), **All linked** (the whole
  export, only that note's events), **Reopen query** (the query the note was
  written from), **Link/Unlink N selected**, **Edit** and **Delete**. Editing or
  deleting a shared note affects all its linked events; a note keeps at least one
  linked event (delete it instead). Notes accept up to 30,000 characters. Markdown
  is sanitized: scripts, raw HTML controls and embedded images are not rendered.
  If another tab or an [agent](#agent-access-mcp) changed a note after you opened
  it, **Save**/**Delete** is refused rather than overwriting their change; copy
  your text, reopen the note and reapply it. Each **Run** (or pivot) also
  refreshes both tabs, so tags and notes written by agents appear there.

Tag and annotate selected events from the bar above the grid:

- Check events, or use the header checkbox to select **loaded rows only**.
  Selection persists while scrolling and while tagging/annotating, but resets when
  the query or sort changes. Up to 5,000 events can be changed at once.
- **Quick tag** (or press `T`) lists every tag with an all/some/none checkbox and
  a count such as `2/3` for the selected events. Ticking a tag that is on none or
  some adds it to all selected events (other tags are untouched); unticking a tag
  that is on all removes it from all of them. Type to search, or type a new slug
  and choose a color to create it. Tags are lowercase ASCII letters and digits with
  hyphen separators, at most 256 characters (e.g. `needs-review`).
- **Add to note** creates a new note on the selected events (recording the current
  query) or links them to an existing note.
- Changes update loaded rows in place: scroll position, loaded batches and the
  selection are kept. If a tag or note scope is active and the change could alter
  which events match, a **Refresh results** notice appears instead of reloading.
- Rows stay one line high. The **Tags** column shows up to three initial-letter
  squares, or two plus `+N`; click any of them for the full tag names (each filters)
  and **Edit tags on this event**. The **Notes** column shows a note icon and count;
  click it to open those notes in the sidebar.
- Reviews persist in a separate SQLite sidecar, defaulting to
  `<evidence-stem>.annotations.sqlite3` beside the DuckDB file. Use `--annotations`
  to override its location. Back it up along with the evidence (stop the server
  before copying it). Notes/tags are keyed by canonical record SHA-256, not row
  order; identical canonical records share reviews. The evidence remains read-only.
  The sidecar can contain sensitive investigator notes and is gitignored. Each
  new note also stores the browser query it was written from (as inert JSON that
  is re-validated when reopened); older sidecars gain that column automatically
  and their existing notes simply have no saved query.

## CloudTrail workflow

The page is laid out for laptops: a slim top bar and the time/histogram panel
scroll away normally, while the query bar, selection actions and grid headers
stay pinned and the grid fills the rest of the window.

- All times are **Asia/Jakarta (UTC+7)**, independent of browser/computer timezone,
  and are entered and shown as 24-hour `YYYY-MM-DD HH:MM:SS`.
- Drag either time-slider handle or its selected band, type timestamps and press
  Enter/**Apply**, click a day in the daily context strip, or use an all /
  last-3-days / last-7-days preset relative to the end of the export.
- Ranges include the start and exclude the end: `[start, end)`. The full-export
  default includes the last event. Boundary days are partial.
- **Applied query.** Chips under the search box show everything the grid, counts,
  histogram and prevalence currently use: time, search, field filters, tags, a
  note and an SSM command link. Click × to remove one (the query reruns), or click
  a field filter to edit it. Typing in the search or time boxes, or an unfinished
  filter, is a **Draft** until you press **Run**/Enter; **Revert** discards it.
  **Clear all** removes every scope except the time range.
- **Back/Forward** (‹ ›, or Alt+←/→) step through applied queries: pivots, tag and
  note filters, histogram brushing and time changes. Sort order and loaded rows
  are not part of the history.
- Search performs a case-insensitive **literal substring search of the entire
  raw event**, including nested requests/responses. `%` and `_` are not wildcards.
  Press `/` to focus it.
- **+ Filter** adds filters for operation, service, identity, IP, country, access
  key ID, target, errors, document, etc. Filters combine with AND. `is one of`
  accepts a comma-separated list of exact values (not CSV quoting). Equality is
  case-sensitive; contains/not-contains are case-insensitive.
- The SSM shortcut selects SendCommand, StartSession and CancelCommand. It does
  not include routine agent reporting or prove that commands executed.
- Column headers sort **all matching events in DuckDB**, not just the current
  loaded rows. Shift-click adds sort columns. Scroll down inside the grid to load
  another 100 events automatically. The selection bar shows the matching count and
  how many are loaded. Changing filters, time or sorting starts over at the first
  batch. Counts and charts always describe the entire selection.
- Each column's **≡** button opens a compact top/bottom-five frequency summary
  for the full applied time range, search, and filters. Counts are not page-limited.
  Missing and empty values are included separately; ties use ascending value order.
  Lists can overlap, and show fewer than five entries when fewer values exist.
  **=** / **≠** beside a value adds that exact filter. Close with the Close button
  or Escape; clicking the summary button does not sort.
- Hover a cell (or focus its buttons with the keyboard) for **copy** and **%**
  actions. Copy preserves the complete value, including text truncated in the grid;
  a missing value copies as an empty string. The % modal shows exact-match count
  and percentage across all selected events. Missing and empty values are distinct.
  Copy and % do not open row details or change filters. The **funnel** button opens
  **is / is not**, appending an exact-value AND filter and immediately rerunning the
  query. Missing cells use explicit null filters; empty strings remain distinct.
  This works for every column, including second-resolution Jakarta timestamps.
  Touch devices show the buttons
  without hovering. Clipboard access requires browser permission on a secure origin
  (loopback qualifies); a denied copy shows a manual-copy message.
- Click a row to open the **inspector**, a side panel that leaves the grid usable:
  original JSON, canonical record hash, the event's full tag names (each filters)
  with **Edit tags…**, its notes, and SSM command backlinks. **‹ Prev / Next ›** (or
  `K` / `J`) step through loaded rows; Escape or Close dismisses it. Numeric JSON
  tokens are never round-tripped through JavaScript floating point.
- Expand Generated SQL to inspect the executed SELECT and its bound parameters.
  Copy SQL substitutes safely quoted values. `browse_events` is a temporary,
  enriched view created by `Store` in `kamotrace/server.py`, not a table written to the
  evidence database; copied queries require that view in their SQL session.
- **Selected event frequency** counts the entire filtered selection, not just the
  loaded rows. Choose minute/hour/day/week presets or any custom whole-minute
  width. Buckets are aligned in Jakarta local time, empty buckets stay visible,
  and boundary buckets can be partial. The Y axis shows 0, half and the peak.
  Zero-count buckets have amber marks below the baseline (not negative counts).
  Positive bars are at least one pixel high, including when context sets a much
  larger scale, so zero and one remain distinct. Tooltips retain exact counts.
  Hover for counts; **drag across buckets** to select that time range, or click
  (or press Enter on) a bucket to narrow to it; Back undoes either. Tick
  **Context: all events** to draw the unfiltered count for the same buckets behind
  the filtered bars. More than 2,000 buckets produces a message asking for a
  coarser bucket or shorter range; the event grid remains available.
  Frequency-query SQL and bound parameters appear in the SQL panel too.
- Below it, the **daily context strip** is unfiltered, with SSM starts in red; days
  outside the chosen range are dimmed. **Hide histogram** collapses both charts.
- Raw JSON can contain credentials and personal information. Do not share raw
  screenshots or exports without reviewing them.

## SSM command browser (desktop)

Load the local consolidated SSM export, preferably the base64-enriched version:

```powershell
kamotrace serve --database C:\\evidence\\case.duckdb --ssm-export C:\evidence\ssm_command_session_activity.enriched.json
```

The file has `account_id`, `commands`, `invocations`, `invocation_details`, and
optional `cloudtrail_records`, `coverage` and `base64_enrichment` fields. Each
command/invocation/detail is wrapped as `{ "region": "...", "record": {...} }`;
commands may additionally contain per-parameter `base64_enrichment` arrays.
Without this option, CloudTrail browsing still works and the SSM tab explains
how to load an export. Exports remain local and read-only; restart to reload.

- **SSM commands** opens a searchable, sortable list and a command/output pane.
  Search includes parameters, decoded payloads, system IDs, stdout/stderr and
  linked event identities. Results load in batches of 100. The shared WIB slicer
  filters requested time, start-inclusive/end-exclusive. Events without a known
  requested time are excluded when a time bound is applied. CloudTrail field/tag
  filters are separate from command search.
- **Spreadsheet** is an alternative, full-width command/output grid. One row
  represents a system/plugin output record; command parameters and decoded
  payloads repeat alongside each system's own stdout, stderr, status and code.
  Missing output and combined-only fallback output remain distinct. No systems
  or plugins are merged. The same command-level search and WIB slicer apply;
  matching a command keeps all of its system/plugin rows visible.
  The grid fills the window height. Resize columns, scroll horizontally, or set
  **Rows** to **Expanded** for longer snippets. Headers sort the entire matching
  result before pagination; Shift-click adds sort columns. Scroll down to load
  another 100 rows (or use **Load more rows**). Click a cell, or focus it and press Enter, to read/copy its
  full value. Click a system ID or the cell inspector's **Open command and
  CloudTrail links** to return to the detailed command browser. Switching layouts
  retains time and command search. SSM records remain JSON-backed in memory;
  this view does not import them into persistent DuckDB tables.
- Commands group by **account + region + CommandId**. Each system has its own
  invocation and each plugin has its own status, response code and stdout/stderr.
  Known targets lacking invocation/output records are explicitly marked missing.
  Combined plugin output is shown when separate output details were not collected.
  Reported target counts are not inferred from the available output records.
- Original parameters and static base64 enrichment appear together. Nested decoded
  payloads are displayed as plaintext data, never evaluated as shell or HTML.
  Output may be truncated by AWS; preserved output URLs are shown but not fetched.
  Raw collected command/invocation/enrichment records are expandable at the bottom.
- CloudTrail links require an exact command ID in `requestParameters.commandId`
  or `responseElements.command.commandId`, plus matching account and region.
  They are not inferred from timestamps or IPs. The link list distinguishes
  original DuckDB events from supplemental export events. Duplicates use the
  original DuckDB JSON/hash. Supplemental JSON is reconstructed from the export.
- Open a linked event to inspect it, then use **Open SSM command** to return.
  CloudTrail row details also offer that backlink. **Show linked events in
  CloudTrail grid** switches to the whole export with only an exact linkage scope
  (a command chip); **Back** returns to your previous CloudTrail query. The
  histogram and prevalence counts use that scope too. Only original
  DuckDB events appear in the grid—supplemental events are not silently inserted.
  Remove the command chip (×) or **Clear all** to drop the command-link scope.
- The tab covers collected Run Commands, not interactive session transcripts.
  Uncollected commands/outputs and denied calls cannot establish what executed.
  The export's coverage/limitations are expandable above the command list.

## Agent access (MCP)

`kamotrace mcp` lets local AI agents (Claude Code, Amp, Claude Desktop or any
[Model Context Protocol](https://modelcontextprotocol.io/) client) search the
evidence, tag/untag events and read/write notes. It uses the official MCP
Python SDK over **stdio**: the client starts it as a subprocess, so it opens no
port of its own. It has **no authentication** and holds no database handle.
Every tool calls the already running browser server's REST API on loopback, so
the browser and agents share one authoritative state: the same read-only
evidence connection, the same validation, and the same notes/tags sidecar.

```text
agent client ──stdio──▶ kamotrace mcp ──HTTP, 127.0.0.1──┐
browser tab ─────────────────────────────HTTP, 127.0.0.1──┴─▶ kamotrace serve ─┬─▶ evidence DuckDB (read-only)
                                                                               ├─▶ detections DuckDB (read-only)
                                                                               └─▶ notes/tags SQLite sidecar
```

Start the browser server first (as in [Quick start](#quick-start)), then register
the adapter with your client. Use the browser's port if you changed it with
`--port`. These examples assume `kamotrace` is installed (`uv tool install`);
otherwise use `uv run --directory C:\path\to\KamoTrace kamotrace mcp ...`.

Claude Code:

```powershell
claude mcp add kamotrace -- kamotrace mcp --url http://127.0.0.1:8765
```

Amp:

```powershell
amp mcp add kamotrace -- kamotrace mcp --url http://127.0.0.1:8765
```

Other clients (for example Claude Desktop's `claude_desktop_config.json`, or a
project `.mcp.json`; Amp's settings file uses the key `amp.mcpServers`):

```json
{
  "mcpServers": {
    "kamotrace": {
      "command": "kamotrace",
      "args": ["mcp", "--url", "http://127.0.0.1:8765"]
    }
  }
}
```

`--url` only accepts `http://127.0.0.1:<port>` or `http://localhost:<port>`, and
the adapter ignores system proxies. If the browser server is not running, tools
return a "cannot reach" error; start it and retry.

**Trust boundary.** There is no authentication: any local process that can start
the adapter, or reach the loopback server directly, can read evidence and change
notes/tags, exactly like the browser UI. Nothing is exposed beyond this machine.
The browser server still binds `127.0.0.1` only and keeps its Host/Origin checks
and CSP; the adapter sends no `Origin` and the server accepts it as a local,
same-host client. There is no SQL, file path or network-fetch tool. Agents
cannot modify the CloudTrail evidence; they can only add, change or remove
notes and tags in the sidecar, so back it up as usual. Treat agent changes like
your own: review them in the **Findings** sidebar.

**Identities.** Tags and notes attach to `record_sha256`, the canonical SHA-256
of the original record (identical duplicate records share it, as in the browser).
`id` is the record's 1-based position in the imported export. It is stable for
that evidence database and is used to fetch raw detail. Write tools change only
the hashes passed to them, 1 to 5,000 per call; there is no "tag the whole
query" tool, so an agent must page through results and pass the events it means.
Note edits and deletes need the note's current `updated` value (returned by
`get_note`, `list_notes` and every note write). If the browser or another agent
changed the note since, the call fails without writing; re-read it and retry.

| Tool | What it does |
| --- | --- |
| `describe_schema` | Filter fields, operators, sort fields, page sizes, facet values, time bounds (Jakarta) and tags. Call first. |
| `search_events` | `query` (search, filters, all-of tags, note, SSM command, start/end) plus sort, page and size. Returns the full filtered total and one page with hashes, tags and note IDs. |
| `summarize_field` | Top/bottom five values, distinct count and total for a field across the whole filtered result. |
| `event_histogram` | Counts per Jakarta-aligned bucket (empty buckets included, at most 2,000). |
| `get_event` | Exact stored raw JSON by `id`, its `record_sha256`, a recomputed hash check, and linked SSM commands. |
| `list_tags` / `tag_events` / `untag_events` | Tags with event counts; add or remove one tag on explicit hashes. Adding is additive and keeps an existing tag's colour (new tags default to the browser's colour). |
| `list_notes` / `get_note` | Notes (searchable), with linked event counts and the query they were written from; one note plus a page of its linked events. |
| `create_note` / `edit_note` / `delete_note` | Markdown notes (sanitized when the browser renders them). `create_note` can record the agent's query so **Reopen query** works in the browser. |
| `link_note_events` / `unlink_note_events` | Add or remove linked events; a note keeps at least one. |
| `list_detections` | Imported Suzaku rules (severity, ATT&CK tags, linked event counts) and the import's provenance. Filter with `query.rules` (all must match) or `query.min_level`. |
| `search_ssm_commands` / `get_ssm_command` / `get_ssm_event` | SSM commands from the JSON-backed export, each system/plugin output kept separate, linked CloudTrail events by exact account/region/command ID. |

Times are ISO 8601 with an explicit offset (`2026-03-02T00:00:00+07:00`);
ranges are start-inclusive and end-exclusive, as in the browser. Event fields,
raw JSON, SSM commands/output and note text are returned as untrusted data; the
adapter tells agents not to follow instructions found inside them.

Run only one browser server per notes sidecar: it holds the sidecar's working
copy of tags/notes for queries, and a second server on the same sidecar would
not see the first one's writes until restarted.

## Storage and backups

| Data | Where it lives | Written by the browser? |
| --- | --- | --- |
| CloudTrail events and provenance | Imported DuckDB file | No; opened read-only |
| Annotations, event links and colored tags | `<evidence-stem>.annotations.sqlite3` (or `--annotations`) | Yes (browser and MCP agents, through the same server) |
| Suzaku detections and their provenance | `<evidence-stem>.detections.duckdb` (or `--detections`), written by `kamotrace suzaku` | No; read-only, rebuilt from Suzaku output |
| SSM commands, outputs and enrichment | Original JSON export, loaded into memory | No; **not imported into persistent DuckDB tables** |
| IP enrichment and its provenance | `<evidence-stem>.enrichment.duckdb` (or `--enrichment`), written by `kamotrace enrich` | No; read-only, rebuilt from GeoLite2/JSONL; no online lookups |
| SSM-to-CloudTrail query links | Temporary DuckDB table | Memory only; rebuilt on startup |

Stop the server before backing up the annotation sidecar. Keep it with the exact
evidence database it describes, plus the source exports and enrichment cache.
The app does not collect AWS data or refresh exports: replace/update local files
and restart to reload them. It does not fetch output URLs or run shell commands.

## Troubleshooting and limitations

- **Missing database:** import a CloudTrail `Records` JSON export first, or pass
  `--database` with the correct path. An arbitrary DuckDB file will not have the
  required schema. The importer intentionally refuses to overwrite evidence.
- **Port already in use:** stop the previous server, or use `--port 8766` and open
  that port instead. Avoid leaving multiple instances on the same port.
- **No SSM commands:** supply `--ssm-export` with the consolidated format described
  above, then check the requested-time range. Individual AWS API response files
  are not a substitute for the consolidated export.
- **Countries unmapped:** run `kamotrace enrich` (private and service addresses
  stay unmapped), or pass `--enrichment` if the sidecar is elsewhere. A sidecar
  built for another database is refused: rebuild it with `--replace`. IP geography
  is not proof of a person's location; proxies and service IPs can mislead.
- **No matching results:** widen the time range and clear filters. CloudTrail
  and SSM command search/filter selections are separate.
- **Missing or truncated output:** AWS retention and collection limits apply.
  Missing output does not prove a command did not execute. Interactive SSM
  session transcripts are not included in the command viewer.
- **Copy denied:** allow clipboard access or select text in the cell inspector
  and copy manually. Loopback is a browser secure context.

This is a local, single-user desktop tool, not a public or multi-user service.
Real evidence may contain credentials, financial data and personal information.
Review screenshots and exports before sharing them. No CI workflow is currently
included; run the local checks below before changing or distributing the app.

## Open-source components

KamoTrace is released under the [MIT License](LICENSE). Suzaku is a separate,
AGPL-3.0 tool that you install yourself; KamoTrace only runs it or reads its output.

[DuckDB](https://duckdb.org/) handles local event queries;
[Tabulator](https://github.com/olifolkerd/tabulator) provides the grids and
[noUiSlider](https://github.com/leongersen/noUiSlider) provides the time slicer.
Markdown notes use Marked and DOMPurify for parsing and sanitization.

Vendored, unmodified browser assets: `tabulator-tables@6.3.1` JS/CSS and
`nouislider@15.8.1` JS/CSS, obtained from the matching npm packages through
jsDelivr. Both MIT licenses are in `static/vendor/`. No runtime dependency on
jsDelivr; no package manager is needed to serve the app.

Markdown uses vendored `marked@15.0.12` (MIT) and `dompurify@3.2.7`
(Apache-2.0 or MPL-2.0); their licenses are also in `static/vendor/`.

## Verification

```powershell
uv run python -m unittest discover -s tests
node --check src/kamotrace/static/app.js
uv build
```

Only the optional JavaScript syntax check needs Node. There is no Node build.

Tests use synthetic records and a disposable database built through the bundled importer,
real HTTP requests, asymmetric Jakarta-midnight boundaries, combined filters,
literal search, sorting, invalid input, cross-origin rejection, exact JSON
integers, local histogram boundaries/custom widths/empty buckets, and a database
SHA-256 before/after check. Coverage also includes annotation/tag persistence,
stale note edit/delete rejection, SSM account/region linkage, multiple
systems/plugins, missing/combined output, spreadsheet search/sorting, and a
real stdio MCP client session (search, tag/untag, note create/edit/link/unlink,
invalid input, raw-hash check) whose writes are checked through the browser API,
and Suzaku import (exact eventID/region/time linkage, unmatched rows kept but not
shown, rule AND filters, minimum level, refusal to overwrite) against the
DuckDB schema Suzaku 3.0.0 writes.
They never modify the real CloudTrail evidence database. For contributor
architecture and evidence-handling rules, see [AGENTS.md](AGENTS.md).
