# Pipeline language v1

Status: implemented v1 contract. Browser, REST and MCP queries share the same
validated, parameterized filtering implementation.

## Goal and scope

Provide a small, predictable language for filtering CloudTrail events. It is
inspired by piped investigation languages, but claims no SPL, KQL or LogScale
compatibility. There is no `where` keyword: each stage is implicitly a filter.

V1 supports field comparisons, explicit Boolean expressions, tags, Leads and
the existing raw-event text search. Results remain evidence events with their
original identities. No stage changes columns, creates records or aggregates.

The date selector owns time bounds. The selected interval is always
start-inclusive/end-exclusive, in the selected IANA timezone. No expression can
broaden that interval. Date comparisons and relative-time syntax are not part
of this language.

## Examples

```text
lead in ("rule-recon", "rule-console-no-mfa")
| region = "ap-southeast-1" OR region = "us-east-1"
| search "AssumeRole"
```

Read as: within the selected date range, match either Lead, AND either region,
AND the raw-event text `AssumeRole`.

```text
(event_name = "ConsoleLogin" OR event_name = "AssumeRole")
| tag = "needs-review"
```

```text
search "AccessDenied" OR search "UnauthorizedOperation"
| NOT source_ip is missing
```

```text
tag = "needs-review" AND tag = "suspicious"
```

The last example requires both tags. In contrast,
`tag in ("needs-review", "suspicious")` requires either tag.

## Pipeline and Boolean semantics

- A pipe (`|`) applies its right-hand stage to the preceding result: always AND.
- OR must be written explicitly within a stage. There is no implicit OR.
- AND may also be written within a stage. Adjacent predicates without an
  operator are invalid; whitespace does not imply AND.
- Precedence within a stage is parentheses, then NOT, then AND, then OR.
- A stage cannot recover an event excluded by an earlier stage.
- Parentheses group expressions within a stage; they cannot contain pipelines.
- Filtering preserves each source event once, even if it matches multiple tags,
  Leads or OR branches. Distinct evidence rows are not deduplicated by hash.
- An empty or whitespace-only query applies no language filter. Date bounds
  and any explicitly displayed external scopes still apply.
- Leading, trailing and repeated pipes are errors, not empty stages to ignore.

For example, `A OR B | C OR D` means `(A OR B) AND (C OR D)`.
Here A, B, C and D stand for complete predicates, not bare search terms.

## Lexical rules

- Field names are exact, case-sensitive schema keys, not display labels.
- Word operators and keywords are case-insensitive: `and` and `AND` are equal.
  The editor formats Boolean operators as uppercase and other keywords as
  lowercase.
- All values are double-quoted strings, including ASN values. Bare words,
  numeric literals and single-quoted strings are invalid in v1.
- Strings use JSON escaping: `\"`, `\\`, `\n`, `\r`, `\t`, `\b`, `\f` and
  valid `\uXXXX` sequences. Unpaired Unicode surrogates are rejected.
- A literal pipe inside a string is ordinary text: `search "left|right"`.
- Whitespace, including newlines, is permitted between tokens. A newline alone
  does not start a stage. Strings cannot contain unescaped control characters.
- No comments, interpolation, variables or executable expressions.

## Grammar

The grammar below is schematic EBNF; `string` follows the lexical rules above.
Keyword recognition must respect token boundaries.

```text
query       = [ expression, { "|", expression } ] ;
expression  = conjunction, { "OR", conjunction } ;
conjunction = unary, { "AND", unary } ;
unary       = "NOT", unary | "(", expression, ")" | predicate ;
predicate   = "search", string
            | field, ( "=" | "!=" | "contains" ), string
            | field, "in", "(", string, { ",", string }, ")"
            | field, "is", [ "not" ], ( "missing" | "empty" ) ;
```

`field` must be accepted by the semantic field registry. Not every operator is
valid for every field. Unsupported combinations are errors, never fallbacks to
raw text search.

## Fields and matching

### Scalar event fields

V1 exposes the current allowlisted event/enrichment field keys except
`time_local`: `event_name`, `event_source`, `identity`, `source_ip`, `country`,
`key_id`, `target`, `error_code`, `identity_type`, `region`, `user_agent`,
`event_id`, `document_name`, `isp`, `city`, `asn` and `ip_info`.

The server registry is authoritative; metadata and autocomplete expose the
same registry and operator capabilities. Future additions require an explicit
registry change, not arbitrary column or JSON-path access.

| Predicate | Meaning |
| --- | --- |
| `field = "value"` | Exact, case-sensitive equality; false for missing fields. |
| `field != "value"` | Complement of equality; includes missing fields. |
| `field in ("a", "b")` | Exact equality with any listed value; false for missing fields. |
| `field contains "text"` | Existing case-insensitive substring matching; false for missing fields. |
| `field is missing` | Field is null. |
| `field is not missing` | Field is not null, including an empty string. |
| `field is empty` | Field is null or the empty string, matching the existing API operator. |
| `field is not empty` | Field is neither null nor the empty string. |

Every predicate yields true or false, never SQL unknown. NOT is its Boolean
complement. Thus `NOT field contains "text"` includes missing fields. To exclude
missing values as well, add `AND field is not missing`.

`field = ""` distinguishes an actually empty string from a missing value.
`contains ""` matches every non-missing scalar value. Whitespace is not trimmed
from quoted values. Wildcards such as `*` and `%` are literal characters, not
patterns. Case-insensitive matching uses the existing DuckDB lower/contains
behavior; v1 does not promise linguistic or accent-insensitive search.

### Event tags and Leads

`tag` and `lead` are reserved virtual fields. They support only `=`, `!=` and
`in`; use NOT for other complements.

- `tag = "needs-review"` tests membership by exact tag slug.
- `lead = "rule-recon"` tests membership by exact rule/context ID, covering both
  Suzaku detections and GuardDuty contextual leads already exposed by the app.
- `in` means any listed membership, not all memberships.
- `!=` means absence of that membership; events with no memberships match.
- Two equality predicates joined by AND require both memberships.
- Unknown, well-formed slugs/IDs are valid and simply have no positive matches.
  Autocomplete can warn, but must not rewrite or reject a saved query solely
  because a membership no longer exists.
- Only evidence-linked Leads participate; unmatched or ambiguous detection rows
  must never acquire guessed event links.

Lead titles are display metadata, not identifiers: titles can change or collide.
Autocomplete searches titles but inserts the stable ID, with a friendly title
alongside the suggestion or in an accessible annotation.

### Raw-event free-text search

`search "text"` is a predicate and can appear anywhere an expression permits,
including OR and NOT expressions. It preserves current raw-event search:

- Literal, case-insensitive substring matching over stored raw event JSON,
  including the existing escaped-form matching for JSON-escaped characters.
- No tokenization, regex, wildcard expansion or online lookup.
- Does not search enrichment, investigator Findings, tags or Lead titles.
- Never parses and reserializes evidence through browser JavaScript.
- `search ""` applies no restriction; its complement matches no events.

## External scopes and legacy queries

The date selector is always external. Existing Finding, SSM command and minimum
severity scopes can remain visible external scopes in v1; this language does
not add syntax for them. They AND with the entire pipeline, never just its last
stage. The applied summary must show them, including their remove actions.

Existing saved queries retain their documented semantics: multiple legacy tags
and rules mean AND, not OR. Loading an old query must not silently change its
matching set. If converted to pipeline text, each selected tag/Lead becomes an
explicit equality joined with AND; legacy search becomes a `search` predicate.
Other legacy operators map to their equivalent predicates and complements.
Comma-separated legacy `in` values must retain their existing split/trim
semantics when converted into separately quoted values.

Conversion must preserve edge cases, not just operator names. In particular,
legacy contains operators coalesce missing values to an empty string, whereas
the DSL defines missing values explicitly. Preserve any resulting difference
for empty search strings with additional missing-value predicates. Legacy
`time_local` field filters cannot be expressed by this grammar; retain those
queries in the legacy query path with their scopes visible rather than drop
the filters or invent a date-selector conversion that changes their meaning.

Store new queries with an explicit language version of 1 and the source text,
alongside date/timezone and external scopes. Unsupported versions must produce
an explicit error. Do not reinterpret an old `search` property as DSL text.

## Editor and interaction contract

- Provide explicit **Text search** and **Pipeline** modes. Text search remains
  literal, with no quoting required. Switching to Pipeline wraps the literal
  text in a correctly escaped `search` predicate.
- Switch back without loss only when the pipeline is empty or a single search
  predicate. Otherwise explain that the expression cannot be represented as
  plain text search; do not discard clauses.
- The pipeline editor starts compact and expands for multiline input. Show one
  stage per line when formatting; never reformat on every keystroke.
- Run applies a complete draft. Enter runs; Shift+Enter inserts a newline. Do
  not run partial queries automatically. Provide a visible shortcut hint.
- Keep the existing applied/draft distinction, Revert and back/forward history.
  Results, summaries and counts describe the last successfully applied query.
- Autocomplete offers valid fields/operators, safely quoted values, tag slugs
  and stable Lead IDs. It is keyboard accessible and must not execute a query
  merely because a suggestion was accepted.
- Schema autocomplete is a discovery tool: users must not need to know schema
  keys from memory or infer them from table labels. Offer fields at the start
  of a predicate, including in an empty editor, after a pipe, and inside Boolean
  expressions. Also support explicit invocation with Ctrl+Space.
- Match field suggestions against both schema keys and human-readable labels,
  case-insensitively. Show both in each suggestion, for example
  `Operation — event_name` and `AWS service — event_source`, and insert the
  exact schema key when accepted. Labels come from server metadata, not a
  separate frontend mapping.
- Field suggestions include a brief meaning and supported operators; after a
  field is accepted, suggest only operators valid for that field. Include the
  virtual `tag` and `lead` fields and explain that they match memberships.
- While suggestions are open, arrow keys navigate, Enter accepts without
  running, and Escape dismisses without changing the draft. Normal Enter-to-run
  behavior resumes when the suggestion list is closed.
- Display a read-only applied summary; do not pretend arbitrary Boolean
  expressions round-trip into independent editable chips.
- Date changes preserve query text. Query edits preserve selected dates.
- A parse/validation failure leaves the draft intact and last successful
  results visible, explicitly marked as belonging to the previous query.
- Show an inline message with line and column, a plain-language explanation
  and the offending range. Never silently ignore an unsupported token.
- A valid query with no results is not a syntax error. Retain it and offer
  explicit editing/clearing actions; never silently relax filters.

### Sidebar and grid pivots

Sidebar shortcuts must edit visible pipeline text rather than add hidden filters.

For a query built by the shortcuts, multiple selected Leads form one
`lead in (...)` stage, and multiple tags form one `tag in (...)` stage. Adding
another item extends that list with OR semantics; removing an item removes it
from the list. Removing the final item removes the stage. Tag and Lead stages
AND with each other. Quick pivots run the resulting query as today.

The shortcut may update an existing membership stage only when it consists
solely of a positive equality or `in` predicate for that virtual field, and
there is only one such stage and no other references to that virtual field.
For example, it must not rewrite `tag = "a" AND tag = "b"` as an any-of list.

If a hand-written expression already references that virtual field in a more
complex form, the shortcut must not guess how to rewrite it. Focus the editor
and explain that the existing tag/Lead expression must be edited there.
If an unapplied draft exists, shortcuts must not overwrite or run it: ask the
user to Run or Revert first. Simple grid equality/exclusion pivots append a
new narrowing stage; label these actions accordingly.

## Execution and security contract

- Parse with a grammar, not string replacement or evaluation.
- Validate the entire syntax tree against the field/operator registry before
  generating SQL. Reuse this validation for browser, REST and MCP callers.
- Compile stages into private nested relations or equivalent safe predicates.
  A pipe's logical meaning is fixed regardless of optimizer flattening.
- Apply date/external scopes before stages. Apply final table sorting and
  pagination only after all stages. No stage-level LIMIT or ORDER BY in v1.
- Derive rows, total count, histogram and prevalence from the same compiled
  matching-event relation and parameters, never from loaded rows.
- Keep SQL identifiers/fragments application-owned and all user values bound.
  Membership predicates use existence/membership checks, not duplicating joins.
- No arbitrary SQL, functions, table names, file paths, network operations,
  mutations, or DuckDB extension access. A read-only database alone is not a
  sufficient security boundary.
- Do not add a separate query engine or a runtime Node dependency. The MCP
  adapter remains a thin client of the same server query path.

Proposed fixed v1 limits: 8,000 query characters, 20 stages, 100 predicate
occurrences, 20 nested parentheses/NOT operators, 100 values per `in` list and
2,000 decoded characters per string. Enforce input size before parsing and
depth during parsing as well as validation, so limits protect the parser too.
Boundary violations return clear errors; no truncation.

## Acceptance criteria

Use synthetic public HTTP contracts and a real MCP session for the implemented
feature. The same query must identify the same event IDs through both paths.

- OR returns the union, pipes/AND the intersection, without duplicate rows.
  Cover disjoint, overlapping and absent tag/Lead memberships.
- Mixed AND/OR and parentheses produce distinct, independently expected sets.
- NOT, inequality, null, empty string and whitespace obey the truth rules above.
- Search preserves case-insensitive and escaped raw-JSON matching, including
  quoted pipes, quotes, backslashes and Unicode.
- Both sides of the selected time boundary behave correctly, even with OR;
  summaries agree with the full matching set beyond the first results page.
- Strings containing SQL-looking text remain values; unknown fields,
  unsupported operations, malformed escapes and exceeded limits are rejected.
- Legacy saved queries reopen without changing their membership semantics.
- UI checks cover draft, successful run, parse failure, zero results, history,
  mode switching and sidebar-generated OR versus hand-written complex queries.
- Verify schema discovery by typing `Operation` and `AWS service`: suggestions
  show and insert `event_name` and `event_source`, respectively. Verify empty
  and mid-expression discovery, field-specific operators, and keyboard
  acceptance without accidentally running the draft.

## Explicitly deferred

Aggregation (`stats`), projection, renaming, sorting/take commands, joins,
subqueries written by users, unions, computed fields, arbitrary JSON paths,
numeric/range comparisons, regex, wildcard matching, functions, variables,
comments and date syntax. SSM command/output search remains its separate view;
this v1 language filters CloudTrail events only.
