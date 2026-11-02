# Components and design choices

KamoTrace separates case preparation from investigation. CLI commands collect
and prepare local files; the Python HTTP server opens those files and serves
the browser and MCP clients. There is no database service or frontend build.
This keeps the evidence boundary explicit and lets an offline case remain useful.

For installation and commands, use the [README](../README.md),
[preparation reference](preparation.md) and [user guide](user-guide.md).
[AGENTS.md](../AGENTS.md) holds contributor guardrails, not component specifications.

## Ownership map

Python modules live in `src/kamotrace/`; frontend files are in its `static/` directory.

| Component | Responsibility |
| --- | --- |
| `cli.py`, `auto.py` | Dispatch commands and orchestrate recoverable preparation; reuse stage implementations rather than reimplementing them. |
| `download.py` | Checkpointed collection of selected CloudTrail, SSM, GuardDuty and inventory data using an existing AWS login. |
| `trailcheck.py`, `ssmcheck.py`, `aws_policy.py` | Audit collection configuration/coverage and generate reviewable permission templates; never grant permissions or change AWS configuration. |
| `importer.py` | Stream CloudTrail JSON into evidence DuckDB, verify canonical hashes and provenance, and provide output locking/staging/publication helpers. |
| `suzaku.py`, `guardduty.py`, `enrich.py` | Build evidence-bound derived sidecars and load them read-only for investigation. |
| `get_suzaku.py`, `get_dbip.py` | Download and verify optional external tools/data, separately from the application distribution. |
| `inventory.py`, `inventory_store.py` | Collect/analyze configuration snapshots, then index them for offline inventory and reference lookups. |
| `server.py`, `pipeline.py` | Own investigation state and REST validation/query execution; parse and compile the versioned filter language. |
| `ssm.py` | Load JSON-backed command/output data, preserve system/plugin structure and link exact command identities to CloudTrail. |
| `mcp_server.py` | Map MCP tools to the running server's REST API, without owning evidence or annotations. |
| `static/app.js`, `index.html`, `app.css` | Event and SSM workspaces, query state, Findings and Event tags. |
| `static/inventory.js`, `inventory.css`, `reference-cards.js`, `reference-cards.css` | Inventory/map workspace and shared identity, machine and IP context cards. |
| `memory.py` | Background memory diagnostics, separate from evidence queries. |

## Preparation and publication

`auto.py` decides whether each stage can reuse verified completed work. The
stage modules own collection, import and enrichment logic. A resumed download
keeps its original request and frozen default end time: resume is recovery, not
a refresh of a changing AWS environment. Use a new destination for a fresh
snapshot. See [recovery rules](user-guide.md#retry-and-recovery).

Database and derived-sidecar writers hold `importer.write_lock(output)` through
validation, private staging and publication. `staging()` creates a unique folder
beside the output, avoiding predictable temporary paths and keeping publication
on the same filesystem. `publish()` publishes completed work; replacement is
allowed only for positively identified derived outputs, never original evidence
or an input. Collection/export directories have their own checkpoints and
completion manifests; their completion must not be inferred from existence alone.

The audits distinguish configuration, observed activity and verified collection
coverage. `trailcheck` does not read S3 object bodies; bounded S3 listings cannot
prove complete logs. `ssmcheck` reports logging destinations without reading
output payloads. `aws_policy.py` generates templates for human review; optional
Access Analyzer validation checks a policy, not the caller's effective access.
Collection and its limits are described in [data preparation](preparation.md).

## Evidence, derived context and investigator state

`importer.py` retains original record content and source provenance without
round-tripping numbers through JavaScript. Canonical `record_sha256` identifies
record content; identical duplicate records share that hash. `source_record`
(exposed as `id`) identifies a row's position in this import. These identities
serve different purposes: annotations attach to hashes, while row detail and
derived links also need the exact imported row. Sidecars validate their evidence
identity so files from another case cannot be silently mixed in.

`server.Store` owns the read-only evidence connection, writable SQLite annotations
and the temporary relations used to join them. One server must own a given
annotations sidecar: another process would have its own stale temporary copy.
Browser and MCP writes go through that Store, including optimistic note-edit
checks. Sidecars and exports are loaded at startup, not live-watched.

The supporting components answer different questions:

- **Suzaku:** rule matches linked under the timeline's identity constraints.
  Correlation rows need different time handling from single-event rows; see
  [linkage rules](user-guide.md#understand-how-detections-link-to-evidence).
  Unmatched or ambiguous results remain accounted for but unattached.
- **GuardDuty:** contextual leads, not exact detections of a CloudTrail event.
  Linking requires identity account, region, exact access key and the observed
  `[first, last)` interval. Raw finding JSON stays separate from CloudTrail JSON.
  See [collection and linkage](../README.md#optional-guardduty-alerts).
- **IP enrichment:** offline lookup context with per-source provenance and
  explicit priority, not proof of a person's location or resource ownership.
  Provider-specific JSONL values belong in `attributes`; see the
  [provider-neutral schema](user-guide.md#jsonl-schema).
- **SSM:** JSON-backed command/system/plugin data in memory, with temporary
  CloudTrail links by account, region and exact command ID. Missing output is
  different from empty output; combined output is not separate stdout/stderr.
  Supplemental records remain labelled rather than inserted into evidence.

The server's temporary detection representation separates numeric links from
rule metadata, exposing a `detections` compatibility view. This avoids repeating
strings for every match. Loaders transfer bounded batches and preserve complete
metadata variants and duplicate multiplicity. This is a runtime layout, not a
change to the persisted Suzaku sidecar's `detections` table.

## Query execution and browser state

`pipeline.py` owns grammar, field metadata, validation and bound predicate
compilation. `server.build_query()` combines those predicates with legacy filters
and external scopes; it remains the common query path for browser and MCP.
Pipes narrow results with AND; OR is explicit within a stage. Dates and other
external scopes constrain the entire expression. Legacy tag/rule arrays still
require every listed membership. The authoritative syntax and interaction
contract is [pipeline language v1](pipeline-language-v1.md).

Rows, totals, histograms and prevalence describe the same full filtered selection,
not merely loaded pages. The browser separates editable drafts from applied
queries: a failed query leaves the previous successful results identified as
such, and a delayed response must not overwrite newer edits. Saved Finding
contexts are inert query data, revalidated when reopened, never stored executable
SQL. Tag/note writes patch loaded rows in place so investigators keep their
selection and scroll; refreshing filtered membership/counts is explicit.

The frontend uses static JavaScript and vendored Tabulator/noUiSlider rather than
a framework. It calls notes **Findings**, separate from **Event tags**; API and
storage names remain annotations/notes. Evidence is plaintext, and rendered
Markdown uses the existing sanitizer.

## Inventory and reference lookups

`inventory.py` preserves raw responses, analyzed reports and collection coverage.
`inventory_store.py` indexes the loaded snapshot; browsing never makes live AWS
calls, DNS lookups or network probes. A permitted network path describes current
configuration, not observed traffic or incident-time reachability. IAM review
signals are leads, not an effective-access calculation or a declaration of safety.

Associating a current IAM user or role with historical activity requires its ARN
and stable identity ID (session-issuer fields for roles), protecting against name
reuse. Resolving current role configuration from an STS ARN is not the same as
proving historical identity. Current MFA enrollment, console login-profile
configuration, observed console MFA and API-session MFA flags are separate facts;
neither snapshot posture nor a missing flag rewrites historical authentication.
See [inventory interpretation](user-guide.md#aws-inventory-and-map).

Initial browser reference cards use indexed inventory and an immutable IP lookup
snapshot, avoiding the shared evidence-query lock. History is explicitly loaded
on request. The REST API retains history by default for compatibility; callers
can send `include_history: false`. Unrequested history means **not searched**,
not no activity. See [request diagnostics](user-guide.md#investigating-slow-requests).

The full-window map dialog reuses the existing panel and its state. A map pop-out
is a separate document with an initial filter/resource selection snapshot, not
live synchronization with the opener. Shared rendering stays in `inventory.js`.

## MCP transport and shared state

HTTP MCP is hosted at `/mcp` on the existing server. The optional stdio process
also calls that server's loopback REST API. Neither adapter opens databases or
implements an independent query/write path; add capabilities to the REST/Store
layer first. This keeps validation, temporary review tables and conflict detection
consistent for investigators and agents. Both transports lack authentication and
retain the server's local-access security boundary. See
[client setup and access rules](user-guide.md#agent-access-mcp).

The HTTP adapter bridges the official SDK's ASGI application through
`httpx2.ASGITransport` into the threaded HTTP server. It uses stateless JSON
responses: the bridge buffers responses and cannot deliver open-ended streams.
GET `/mcp` therefore returns 405, and SDK subscriptions are disabled. Advertising
subscriptions/list-change capabilities can cause clients to wait on a stream
even when ordinary tool calls work. Supporting streaming would require a
streaming-capable bridge and explicit cancellation/lifecycle handling, not just
enabling an SDK flag.

Transport or SDK changes need real HTTP discovery/session tests, including
advertised capabilities and bounded connection behavior; stdio or direct tool
tests alone miss this failure mode. Existing HTTP and stdio tests also check
that MCP writes immediately appear through the browser API.

## Resources, distribution and verification

`memory.py` distinguishes process RSS, DuckDB-managed memory and system/container
headroom. Diagnostic sampling skips a busy Store lock rather than delaying user
queries. Stage snapshots are totals, not additive allocations; high RSS alone
is not a pressure diagnosis. Performance changes need equivalent results and
separate startup, request and peak-memory measurements, not just a faster tiny
fixture. See [diagnostics](user-guide.md#investigating-slow-requests).

Optional assets are fetched at runtime: `get_suzaku.py` verifies the official
release checksum and archive paths; `get_dbip.py` verifies published decompressed
checksums and database types. Suzaku (AGPL-3.0) and geolocation data are not
bundled. Do not download MaxMind data; users supply it under their licence.
Keep DB-IP Lite's CC BY 4.0 attribution. The two-stage Docker image uses Debian
trixie for Suzaku's glibc requirements; its wildcard container bind requires
loopback-only host port publishing. See [Docker](user-guide.md#docker).

Tests use synthetic evidence: `test_contract.py` covers real DuckDB, HTTP and MCP;
collector/CLI suites cover their own public interfaces; `browser_smoke.py` runs
the real UI in Chromium and is not run by unittest discovery. Follow the
[verification commands](user-guide.md#verification); CI owns the Playwright pin.
