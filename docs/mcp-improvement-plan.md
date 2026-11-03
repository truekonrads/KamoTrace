# MCP improvements: implementation plan

Status: S01–S16 implemented and verified locally, 2026-11-03; not pushed or merged.

## Goal and authority

Make large-case investigation practical through MCP: bounded interactive reads,
explicit batch annotation, trustworthy review provenance, and full-data exports
through generated download links rather than enormous tool responses.

This plan incorporates an oracle review of the local `mcp-improvement-spec.md`.
That draft's private session counts, timings and historical incidents were not
independently reproduced. Implementation decisions below come from source review.
This plan supersedes the draft where they differ and is self-contained.

**Backward compatibility is not required.** Update server, MCP, browser, tests and
investigation skill together. Do not add deprecated aliases or duplicate response
formats merely to preserve old clients. However, preserve evidence and existing
investigator work: incompatible APIs do not justify losing annotations or guessing
which new content an old review describes.

## Confirmed findings

- `server.py` returns all unmatched reviews on every ordinary SSM log search,
  including zero-match results. Full outputs and repeated linked finding bodies
  further amplify responses.
- `ssm.py` hashes rendered entry rows and source data into entry IDs. Changes to
  grouping or derived decoding can detach reviews. Content-change protection is
  intentional; silently inheriting reviews on changed content is not a fix.
- SQLite reviews currently contain only entry ID, text, tags, finding and updated
  stamp. Already orphaned IDs cannot reveal their original source identities.
- Decoding currently comes from export enrichment. That decoding is already
  searchable in enhanced/both scope; automatic local decoding is absent.
- SSM reads already paginate across the selection. Explicit event writes already
  support up to 5,000 hashes. Batch SSM review editing is missing.
- Schema and note reads transfer unnecessary data. Body-only note editing leaves
  SQLite links alone but still rebuilds DuckDB review-link temp tables.
- Inventory/reference capabilities exist in the server but have no MCP wrapper.
- No current server download endpoint provides the proposed bulk export path.

## Invariants

Keep the server the sole Store owner and the MCP adapter thin. Preserve loopback
defaults, Host/Origin checks, parameter binding and allowlists. No arbitrary SQL,
filesystem paths, caller-provided fetch URLs or query-selected writes. Mutations
name explicit hashes or entry IDs and retain optimistic concurrency.

Preserve exact original evidence JSON and hashes, separate systems/plugins,
missing versus empty output, combined versus separate streams, and supplemental
versus original provenance. Derived decoding is inert plaintext, never execution.
Inventory is current configuration, not proof of incident-time identity.

## Execution model

Use the following Ralph-sized stories in dependency order. Each should fit one
focused implementation/verification iteration; split a story further if necessary.
Record actual checks and blockers alongside completed stories. Do not mark a story
complete merely because its code exists. There is no need to install a Ralph loop
runner or introduce a Node runtime dependency. The orb can execute this checklist
directly, retaining progress across context windows.

### Phase 1: bounded interactive reads and efficient edits

- [x] **S01: Separate orphan review retrieval.** Replace the unbounded search
  payload with a count and paginated orphan summaries/detail. Update the browser
  consumer directly. Verify zero-match searches with thousands of large orphan
  reviews remain small and every orphan is still retrievable.
  Implemented count-only search, explicit 25-row orphan summaries and exact detail,
  thin MCP tools and lazy browser retrieval. Contract suite: 44 tests passed;
  2,003 large Unicode orphans traversed exactly once, zero-match response <5 KB.
  Real HTTP/stdio sessions exercise orphan tools. Synthetic desktop check loaded
  25 then 26 reviews, no duplicate continuation, and rendered script-like text
  as plaintext (zero script nodes). Inspected screenshots/interaction recording.
- [x] **S02: Bound SSM search summaries.** Add allowed projections, smaller default
  pages, and bounded output/review/finding previews. Keep IDs, current review
  stamps, total, continuation and truncation metadata. Do not embed repeated full
  findings or event arrays. Verify a single huge row and Unicode-heavy results.
  MCP now requests server-owned summary projection: fixed 5-row pages, allowlisted
  fields, bounded previews and explicit truncation/counts. Browser full projection
  remains separate. Previews shrink by serialized size, never pages. HTTP contracts
  traverse all 231 IDs exactly once; real HTTP/stdio result envelopes stay <80 KB.
- [x] **S03: Retrieve full text in chunks.** Add validated field/offset/limit reads
  for large SSM text, with explicit offset units and length/digest metadata.
  Reconstruct original strings exactly across chunks. Keep pagination complete:
  fixed page sizes or cursors based on actual next positions, never dynamic page
  shrinking with old page-number arithmetic. Preserve search revision checks.
  Added exact code-point chunks (1–2,000), length/UTF-8 bytes/SHA-256, missing vs
  empty and digest-checked continuation, including preserved orphan reviews.
  Large mixed Unicode/control-character output and reviews reconstruct exactly;
  stale digests reject with 409. Contract suite: 44 tests passed, including real
  HTTP/stdio chunk reconstruction and existing search-revision rejection.
- [x] **S04: Streamline discovery and note reads.** Return compact schema metadata,
  note summaries and direct note detail without first loading all note bodies.
  Clarify evidence_read_only and annotations_writable. Use consistent object
  envelopes where changed; do not conflate distinct timestamp meanings.
  Added compact `/api/schema`, paginated `/api/notes`, direct note preview and
  body/context chunks; MCP no longer loads every note for note or tag reads.
  Verified 27 large Unicode notes, search beyond previews, explicit flags and
  HTTP/stdio skill examples. Browser's findings rendering remains unchanged.
- [x] **S05: Optimize body-only note edits.** Avoid rebuilding unchanged review-link
  temp tables. Still invalidate enhanced searches affected by body edits. Verify
  stale edits fail, links remain unchanged, and record before/after timings on
  synthetic notes linked to thousands of events before claiming a speedup.
  Body edits skip unchanged DuckDB link-table refresh, retaining log-revision
  invalidation. Synthetic 5,000-link note, three edits each: baseline medians
  2,368.21 ms vs 5.69 ms after. All 5,000 links persisted, stale edits rejected,
  search revision advanced and evidence file SHA-256 unchanged in both runs.
  These local measurements are not a general performance guarantee.
- [x] **S06: Improve query validation.** Name invalid fields/operators/sorts and
  valid choices. Accept JSON arrays for `in`, and null/omitted values for valueless
  operators in both REST and MCP. Normalize only useful, documented aliases.
  Added actionable errors, literal JSON-array membership and null/omitted
  valueless inputs; no speculative aliases. Tests distinguish a comma inside
  an array member from comma-separated legacy text. Phase checks: 45 contract
  tests passed, including both real MCP transports.

Define an explicit serialized UTF-8 response budget, initially 80,000 bytes with
headroom for MCP envelopes, rather than claiming a universal character-to-token
ratio. Budgets must include metadata and large single values; truncation must be
explicit and never prevent forward progress. Test both HTTP and stdio envelopes.

### Phase 2: preserve review provenance before changing derived content

- [x] **S07: Persist review source metadata.** Add versioned semantic source identity
  and reviewed-content identity/snapshot metadata. Backfill matched existing
  reviews only. Retain current content-addressed entry IDs unless a simpler safe
  design is established. Derived decoder versions must not become source identity.
  Added additive source/audit tables, semantic identities and reviewed-content/
  normalized-source digests. Exact matched legacy reviews backfill idempotently;
  unknown old hashes remain unresolved. Existing content IDs remain unchanged.
- [x] **S08: Surface related and unresolved reviews.** Distinguish reviews of current
  content from uniquely related reviews of changed content. Preserve unknown
  legacy orphans. Duplicate invocation/plugin identities, missing identities and
  supplemental requests must not collapse. Session requests remain individually
  identifiable, not merged under a session ID.
  Orphan tools report related-changed, ambiguous or unresolved without inheritance.
  Duplicate invocation/plugin rows remain distinct, including identical rows;
  same-event-ID requests with different content no longer overwrite one another.
  Source metadata is chunk-readable, with decoder versions excluded from identity.
- [x] **S09: Add explicit audited reattachment.** Require current review stamp and
  destination conflict checks; retain old association provenance. Recover historical
  orphans only from exact historical metadata or explicit analyst mappings. Test
  repeated migration, ambiguous mappings and destinations already reviewed.
  Added explicit reattachment with stamps, empty-destination checks, reason and
  analyst-mapping opt-in where exact metadata cannot identify one source. Old
  association/text/source retained; audit is chunk-readable. Verified four load/
  migration stages, changed output, duplicate ambiguity, stale and destination
  conflicts; real HTTP/stdio sessions exercise explicit legacy mappings.
  Contract suite: 45 tests passed; evidence hash checks remain unchanged.

Never promise automatic recovery from hashes alone. Acceptance is zero unexpected
orphans when exact historical identity exists, with unresolved cases accessible.

### Phase 3: bulk workflows, reference lookup and download links

- [x] **S10: Batch explicit SSM review edits.** Add a server endpoint and thin MCP
  mapping with per-item ok/stale/missing/invalid results. Bound item count and total
  request bytes within the existing 1 MiB limit. Define duplicate-ID behavior,
  transaction behavior and retry semantics; update selection revision after writes.
  Test mixed-result batches without echoing large review bodies.
  Shared single/batch writer, 100-item/1-MiB limits, independent per-item commits,
  all duplicate occurrences rejected, compact outcomes and revision invalidation.
  Mixed seven-item HTTP batch verifies successful items on both sides of failures,
  no failed writes, stale replay and stale search continuation; real MCP batches pass.
- [x] **S11: Expose scoped inventory references.** Reuse `/api/reference`, with
  bounded summaries, account/region scope, ambiguous matches, snapshot times and
  sources. Do not invent absent hostnames or attach a singular asset to ambiguous
  IPs. Verify missing inventory and cross-scope duplicate addresses/names.
  Added thin `lookup_reference`, bounded paginated server projection, explicit
  ambiguity/snapshot/source labels and no history scan by default. Real HTTP/stdio
  calls distinguish two owners of one private IP from an account/region-scoped
  unique result. Missing-inventory HTTP check remains explicitly not searched.
  Contract suite: 46 tests passed.
- [x] **S12: Prepare immutable NDJSON exports.** Accept the ordinary validated
  event/SSM selection and allowlisted fields, not SQL or paths. Generate a fixed
  snapshot with selection, evidence identity, analyst revision and labelled derived
  provenance. Preserve exact original evidence text when included. Use private
  staging, writer locking and safe publication for derived sidecars; never overwrite
  input evidence. Bound concurrent exports, rows/bytes and total disk consumption.
  Added privately staged, locked, no-clobber snapshots, one preparation / four
  artifacts, 50,000 rows / 32 MiB each, 128 MiB total. Manifests capture evidence,
  selection and analyst revision; original raw JSON remains exact text. A concurrent
  annotation write waits for preparation and does not leak into the snapshot.
- [x] **S13: Expose generated export download links.** Add an explicit MCP
  `create_export` tool and opaque-ID download endpoint on the existing server.
  Return readiness, expiry and, once computed, row count, bytes and SHA-256.
  Stream the prepared artifact without holding the shared Store lock during slow
  downloads. Clean up expired disposable artifacts; test bad/expired IDs,
  interrupted preparation, exact hashes, repeat downloads and access checks.
  Added thin create_export, trusted-origin opaque links and lock-free streaming.
  Ten-minute expiry, request-time/shutdown cleanup, invalid-ID and Host/Origin
  rejection verified. Failed byte/row/quota preparations leave no artifacts.
  Contract suite: 47 passed; real HTTP/stdio clients download and hash both datasets.

An export URL is not a server-local filesystem path. Construct links from a trusted
configured server base, never arbitrary Host input. Keep existing Host/Origin
checks and redact opaque IDs/query contents from logs. Do not expose ports or add
authentication changes as a side effect. Explain reachability: localhost URLs work
only for clients on that machine; keep bounded MCP reads for consumers unable to
download. A UI query link is optional inspection convenience, not a stable export.

Prefer synchronous bounded export preparation initially. Add background export
status only if measured generation times require it; never claim a download is
ready before publication. Generation must not silently mix annotation revisions.

### Phase 4: derived decoding and structured raw access

- [x] **S14: Add conservative local Base64 analysis.** Scan original command/request
  parameter string values and separate output streams. Support standard/URL-safe
  Base64, multiple spans, wrapped blocks and bounded recursion. Preserve parents,
  source fields, offsets, decoder version and original text; retain export
  derivations with separate labels. Use conservative text validation and consider
  UTF-16LE for PowerShell. Test hashes/IDs/long identifiers as false positives.
  Added labelled UTF-8/UTF-16LE standard/URL-safe spans, wrapping and parent-linked
  recursion, preserving original fields/spans and keeping decoder versions out of IDs.
  Synthetic HTTP checks accept nine expected derivations and reject hashes/IDs;
  a second decoder version retains every ID. Inspected desktop normal/limit states:
  derived script-like text remains plaintext (zero script nodes), raw stays separate.
- [x] **S15: Bound and expose derived analysis.** Limit scanned input, candidate
  size/count, depth, aggregate output and case-wide work; cache repeated parameters.
  Include accepted derivations in enhanced search, not raw scope. Report limits
  honestly. Any compression support must enforce incremental output caps before
  allocation; broad containers/ZIP support and expanded rendering are optional,
  not first-release requirements. Never label expanded text as commands proven run.
  Added per-entry/case scan, candidate, recursion, output and structural bounds,
  bounded parameter cache, honest reasons/counts and chunked analysis JSON. No
  decompression. Enhanced-only search and exact chunk reconstruction verified;
  core bounds exercised. Contract suite: 49 tests passed, including both MCP transports.
- [x] **S16: Add constrained raw scalar paths.** Reuse validated parameter-bound
  paths for projection/filtering/summaries. Bound path length/depth/index and field
  count; define missing/null, scalar/container and numeric/text behavior. Verify
  `requestParameters.name` extraction and failure classification in one query,
  injection rejection, numeric precision and both sides of time boundaries.
  Added parameter-bound raw.key.child[0] projection, filtering, sorting and summaries
  through shared SQL queries (not pipeline v1). Scalar text retains exact numeric
  lexemes using a Python accessor because DuckDB JSON extraction rounds decimals;
  its UDF runtime requires the added NumPy dependency. HTTP checks cover /doc
  failure classification, OR/time scope, precise integers/decimals, boolean/null/
  missing/container semantics, lexicographic sorting, export/histogram consistency,
  accepted/rejected path bounds and unchanged evidence-file SHA-256. Real HTTP/stdio
  MCP sessions exercise the documented query/summary examples. Browser smoke and an
  inspected pointer recording verify saved Finding reopen/edit retains raw filters,
  projections and literal comma-containing array members, keeping one matching row.

## Deferred or rejected scope

Do not add universal tag mutation, merge distinct SSM tools, rename all time fields,
or build generic asynchronous jobs without demonstrated need. Note tags can be a
later explicit relationship, not a substitute for event tags. Standard Python
`re` has no match timeout; pattern-length caps do not prevent pathological runtime.
Do not add regex search without a genuinely bounded execution strategy.

An MCP-only write token would leave REST writes accessible. Client permission
prompts are not a server security boundary, and stdio proxies the same REST API.
Keep the current local trust contract unless a separate authentication design is
explicitly requested.

## Verification and completion

For each story, add public contract coverage for plausible regressions rather than
private implementation details. Use synthetic asymmetric system/plugin fixtures,
large orphans/outputs, Unicode, concurrency and continuation completeness. A
retrieval budget test must also prove every expected item remains reachable exactly
once. Test annotation snapshots during export and evidence immutability.

Run real HTTP and stdio MCP sessions. Update
`skills/investigating-with-kamotrace/SKILL.md` for changed tools, arguments, errors
and identity rules, then exercise its examples through MCP. That skill file requires
the building-skills guidance before editing. Browser changes require rendered
synthetic desktop interaction checks and inspected captures, not syntax alone.

Run repository checks: `uv run python -m unittest discover -s tests`,
`node --check src/kamotrace/static/app.js`, `uv build`, and `git diff --check`.
There is no configured static Python typecheck gate; do not invent one solely for
Ralph terminology. Report actual checks, limitations, remaining stories and delivery
state. Keep real exports, annotations and evidence screenshots out of commits.

Final local verification (2026-11-03): 114 unittest tests passed, including 50 HTTP/
MCP contract tests; JavaScript syntax, wheel/sdist build and diff whitespace checks
passed. Full browser smoke passed with Playwright 1.64.1 and the orb's installed
Chrome executable; no JavaScript errors. Synthetic desktop normal/limit decoding,
preserved orphan retrieval and raw-filter editor/result captures were inspected,
with pointer recordings for orphan retrieval and saved-query editing. An undrained
9,901,524-byte export allowed an independent event query in 0.010 seconds; restarting
the interrupted download returned exact bytes/SHA-256. No remaining stories or
implementation blockers. Changes remain on local implement/mcp-improvements,
based on db3361b74adcec1c6a881d5649b98bc5a2086796; publishing requires authorization.
