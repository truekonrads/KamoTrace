# Components and design choices

KamoTrace separates case preparation from investigation. CLI commands collect
and prepare local files; the Python HTTP server opens those files and serves
the browser and MCP clients. There is no database service or frontend build.
This keeps the evidence boundary explicit and lets an offline case remain useful.

For installation and commands, use the [README](../README.md),
[preparation reference](preparation.md) and [user guide](user-guide.md).
[AGENTS.md](../AGENTS.md) holds contributor guardrails, not component specifications.

## Fresh-case unit preparation

`datasets.py` also owns the explicit `kamotrace-case-v1` JSON manifest. A case has a stable UUID, revision, durable next-unissued ordinary `source_record` and caller-named immutable units. Each raw/prepared artifact binds its case UUID, unit identity, physical-ID intervals and actual occurrence count in build metadata. IDs are persisted directly, never added through offsets. The separate manual namespace retains its own nonrecycling high-water mark. No second catalog database, occurrence-ID mapping or workflow/checkpoint service is introduced.

Admission reserves blocks of 65,536 IDs under one case writer lock before insertion, validates originals/provenance and publishes a raw unit before referencing it in the manifest. Failed builds burn reservations. Unregistered published outputs are retained rather than silently adopted or deleted. POSIX publication synchronizes files and parent directories; Windows atomic replacement has no Python directory-fsync guarantee. These are not universal power-loss guarantees.

`event_index.prepare` publishes one selected `core-v1` scalar projection per unit. Its identity depends on raw hash, exact scope, SQL semantics and DuckDB version, not other units or ordering. It excludes original/nested JSON payloads; identity/key/target/document fields needed by browsing are prepared once. SQL NULL/type/time extraction retains the original producer semantics. Raw field filters and original detail still read exact original text through stored-ID joins. Physical predicates precede JSON projection; statements admit at most 512 selected rows or approximately 4 MiB of raw text, with one oversized record attempted intact. Validation/sorting/checkpoint and native memory remain separately materialized work, not bounded by those admission limits.

`Store(case=...)` pins, verifies and attaches declared raw/prepared files read-only. It does not normalize, repair, register or implicitly omit unprepared selected units. All query consumers share its `events`/`browse_events` selection. Coverage identity is order-independent and includes case UUID, raw identities and selected scopes; enrichment, detection and GuardDuty links bind to that identity. GuardDuty snapshots themselves are allocated raw units, not sidecar rows appended with computed offsets. Findings/manual stores bind to the stable case UUID; saved query contexts additionally carry the selection identity. Acquired computer selectors use stable unit keys in case mode. An explicit reopen adopts later preparation; no hot rebind exists.

Legacy database startup fails before evidence/sidecar access with instructions to re-ingest original inputs into a new case. There is no migration, automatic legacy sidecar adoption or dual-format viewer.

## Ownership map

Python modules live in `src/kamotrace/`; frontend files are in its `static/` directory.

| Component | Responsibility |
| --- | --- |
| `cli.py`, `auto.py` | Dispatch commands and orchestrate recoverable preparation; reuse stage implementations rather than reimplementing them. |
| `download.py` | Checkpointed collection of selected CloudTrail, SSM, GuardDuty and inventory data using an existing AWS login. |
| `eks.py` | Opt-in AWS-only EKS current context and bounded existing CloudWatch log collection, hashed immutable exports and shared other-event import; no Kubernetes access. |
| `eks_pods.py` | Explicit offline historical pod-context extraction from attached EKS logs; separates caller credentials, named targets and workload metadata without changing evidence. |
| `trailcheck.py`, `ssmcheck.py`, `aws_policy.py` | Audit collection configuration/coverage and generate reviewable permission templates; never grant permissions or change AWS configuration. |
| `importer.py` | Stream CloudTrail JSON into evidence DuckDB, verify canonical hashes and provenance, and provide output locking/staging/publication helpers. |
| `other_events.py` | Stream provider-neutral JSONL into immutable DuckDB datasets and publish revisioned investigator-entered manual events separately. |
| `datasets.py` | Own the JSON case manifest, durable block reservations and immutable raw-unit registration. |
| `suzaku.py`, `guardduty.py`, `enrich.py` | Build evidence-bound derived sidecars and load them read-only for investigation. |
| `get_suzaku.py`, `get_dbip.py` | Download and verify optional external tools/data, separately from the application distribution. |
| `inventory.py`, `inventory_store.py` | Collect/analyze configuration snapshots, then index them for offline inventory and reference lookups. |
| `computers.py` | Summarize bounded historical computer facts from declared prepared acquisitions, selected by stable unit key. |
| `server.py`, `pipeline.py` | Own investigation state and REST validation/query execution; parse and compile the versioned filter language. |
| `event_index.py` | Explicitly prepare and validate per-unit scalar core outputs; verify and attach declared coverage without building at startup. |
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

`other_events.py` uses the same event-column contract for immutable JSONL units, with explicit `other` labels, origin manifests, exact JSON numbers and namespaced review keys. Store composes the declared prepared selection into one temporary `events`/`browse_events` projection used by the shared query compiler, tag/Findings joins, histograms, exports and MCP. AWS linkage loaders use that same selection and explicit CloudTrail type restrictions, so generic events cannot acquire guessed SSM or detection links. A case can contain only generic acquisitions without AWS logs.

`auto --case` admits one explicitly named raw acquisition and invokes explicit preparation. Existing completed unit artifacts are verified and reused; new units never invalidate other units. The manifest alone declares visibility. Startup cannot discover additional files or repair missing preparation. Active viewers pin their selected artifacts until explicitly reopened.

Core validation compares the source-record/hash/file/ordinal multiset and scalar projection against the selected raw scope before publication. Reuse scans ordered fixed-size SHA256 row digests, with fields cast to text before JSON-array encoding to distinguish SQL NULL, empty text and literal `null`. Complete artifact hashes and case/unit metadata are checked. This detects accidental corruption, not a malicious writer forging both artifacts and manifest. Python fetch batches do not bound native sorting, spill or total RSS.

Store attaches published raw/core artifacts `READ_ONLY` and queries them without copying core rows into a temporary table. Original JSON is joined by exact persisted `source_record`, never hashes, times or addresses. GuardDuty snapshots already occupy declared prepared units; their sidecar supplies only contextual links. Manual events stay in their separate live branch. Request-time external file access remains disabled after startup.

Manual key events persist in `<case stem>.manual.duckdb`, bound to the stable case UUID. Create/edit validates a record, holds the existing output lock, copies a positively identified manual dataset into private staging, retains the old revision and atomically publishes the replacement. Store updates its temporary manual snapshot under the query lock. Manual events use stable namespaced review keys, separate from changing `content_sha256`; imported records remain immutable. Edits require the current `updated` stamp. Revision authors are self-reported. The small investigator-authored dataset is copied per write; large external datasets use streamed immutable imports, not this write path. One Store/server must own the case. See the [public contract](user-guide.md#other-events-and-manual-key-events).

The supporting components answer different questions:

- **Suzaku:** rule matches linked under the timeline's identity constraints.
  Correlation rows need different time handling from single-event rows; see
  [linkage rules](user-guide.md#understand-how-detections-link-to-evidence).
  Unmatched or ambiguous results remain accounted for but unattached.
- **GuardDuty:** contextual leads, not exact detections of a CloudTrail event.
  Linking requires identity account, region, exact access key and the observed
  `[first, last)` interval. Raw finding JSON stays separate from CloudTrail JSON.
  Every retained snapshot also projects through the existing other-event column
  contract into the shared timeline, without changing `kamotrace-other-v1`.
  Schema 2 preserves input occurrences rather than upserting ARN; schema 1 remains
  readable without rewriting it. Namespaced canonical snapshot hashes own reviews;
  changed content does not silently inherit annotations. CloudTrail links remain
  separate, version-1 context, with bounded bidirectional detail navigation.
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

Browser event reads can register a single-use capability via
`POST /api/operations {"action":"start"}` and send its returned `token` as
`X-KamoTrace-Operation` on `/api/events`, `/api/histogram` or `/api/column-values`.
`POST /api/operations {"action":"cancel","token":"…"}` marks only that request
cancelled. A separate ownership mutex guards DuckDB `interrupt()` and the
shared Store-lock handoff; queued cancellation polls cooperatively without
interrupting the lock holder. While a cancelled request still owns the connection,
a daemon retries interruption every 50 ms: DuckDB discards an interrupt issued
before a statement starts. Every retry rechecks ownership under the same mutex
and exits at handoff, so it cannot interrupt the next request.
Cancellation is checked between query phases and
before returning results. Completed/unknown tokens cannot interrupt new work.
Unclaimed registrations expire after 60 seconds; at most 128 pending/active
capabilities are retained, and claimed tokens are removed on success/error/cancel.
Tokens are not listed or logged. Existing Host/Origin checks still apply.
The browser groups related reads, discards cancelled responses even if completion
wins the race, cancels superseded searches/pages/summaries, and retains usable
retry controls without accepting previous rows as the failed selection.
The elapsed timer includes queueing and network work. DuckDB's optional
`query_progress()` is a single-statement, connection-level percentage (or -1),
not operation-wide work accounting; no reliable ETA is exposed. Writes, exports,
SSM's Python searches and MCP transports do not opt into this cancellation API.

Store retains one validated selection in a disposable disk-backed DuckDB relation
containing only row IDs, timestamps and review hashes. Events count and filtered
histogram buckets/key positions reuse it under the existing Store lock; page
retrieval and the unfiltered overview keep their existing query paths. Compiler
SQL, bound parameters and the annotation revision identify membership, not page
number or bucket width. A different selection replaces it, and annotation/manual
writes invalidate it. Each Store owns a private coordinator database with evidence
attached read-only; filesystem access is disabled after startup as before. This
is runtime reuse, not a persistent search index, and dense selections cost disk
space proportional to matching rows without loading all payloads into Python.

Key-event prominence is the existing `key-event` tag, independent of provenance/type. Histogram queries use the shared selection compiler and aggregate the tagged count and exact first/last epoch-millisecond positions per bucket; the daily overview is deliberately unfiltered. Both charts show distinct tagged timestamps as diamonds, capped at 2,000 positions per selection/overview with explicit truncation warnings and endpoint spans for dense buckets. Counts always include all matching events. Tag writes patch rows and refresh review marks only, retaining applied counts/membership until an explicit rerun. No evidence or storage schema changes are needed for prominence.

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
At startup, optional `serve --eks-export` verifies and overlays current EKS
observations onto this same resource/relationship model, without modifying either
export. Auto passes an explicitly supplied `--eks-export` for map context;
`--kind eks --source` alone admits timeline records, not inventory context.
EKS timestamps/provenance and coverage remain separate
from the network snapshot; mismatched accounts fail. Cluster/component links are
configured relationships, not workload discovery, and EKS exposure stays Unknown.

`POST /api/eks-pods` is an explicit historical query, independent of inventory
filters. Account, region and cluster are required; namespace/name/UID equality
and inclusive-start/exclusive-end time bounds narrow the selection. Pages contain
50 observations, newest first, with totals over the full selection. On the first
valid explicit request, `eks_pods.py` streams attached EKS raw records in bounded
batches into disposable coordinator TEMP tables; startup and reference cards do
not scan logs. The original evidence stays read-only, including messages, stages
and source hashes. One audit event can yield separate caller and target rows,
each linking to its original global row ID. Namespace-only list/watch requests
and SubjectAccessReview subject copies never manufacture target/caller pods.
Source manifests and unsupported/unattributed message counts retain coverage
limitations. Conventional log-group labels do not identify cluster incarnations,
and caller credential node fields are not current pod placement.

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

`get_inventory` forwards to `POST /api/inventory`, implemented by `Inventory.query`.
Its default overview contains compact snapshot times, coverage indicators and
category availability/counts. Explicit categories support exact scope filters,
name/ID substring search, stable pages and optional complete-record details.
Unknown query fields/categories and invalid filters are rejected. Responses over
24,000 conservative serialized bytes fail without truncation; one oversized detail
remains inspectable in the browser's unchanged full `GET /api/inventory` report.
Neither inventory path scans history. `search_eks_pods` forwards to `POST /api/eks-pods` with the
same required account/region/cluster scope, exact optional filters, time bounds,
and full-selection totals. Its summary projection defaults to ten observations,
with adjustable size (1–50) and a 24,000-byte response budget. Independent coverage
pages contain ten original-event links and gap/warning counts, not full manifests;
all attached collection scopes remain explicitly labelled. Missing manifests are
counted as unknown. The browser's default full projection remains unchanged.
Inventory category availability records actual startup inputs/EKS-derived data,
not the browser report's empty placeholders. Both are read-only tools shared by HTTP and stdio;
neither makes AWS or Kubernetes calls. Original log evidence remains available
through `get_event` using the observation's global event ID.

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
