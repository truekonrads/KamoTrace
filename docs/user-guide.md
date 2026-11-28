# KamoTrace user guide

[Back to the README](../README.md)

Use this guide to investigate CloudTrail events, add supporting data and save
findings. For a first-time setup, [start with the README](../README.md#get-started).
For implementation responsibilities and rationale, see
[components and design choices](architecture.md).

## Declared prepared coverage

Cases open with `serve --case case.json`, after explicit `prepare --case case.json --unit KEY`. Follow the [fresh acquisition-unit preparation reference](preparation.md#fresh-acquisition-unit-cases). A raw-complete unit may still be preparation-pending. Opening all units fails clearly when a selected unit is missing preparation; choose an explicit prepared subset with repeatable `serve --unit KEY` rather than assuming missing units disappeared. Legacy database startup is rejected without migrating evidence or adopting old sidecars.

The persistent coverage line above the query controls states selected unit/occurrence counts, partial preparation and explicitly excluded units. Counts, sorting, pagination, time buckets, exports and MCP search all refer to this pinned coverage, not all raw evidence on disk. Missing/unprepared records have not been searched; partial parser or collection coverage is a separate limitation. Numeric row IDs may have gaps and are opaque case-local locators, not counts or timestamps.

The viewer does not activate newly admitted/prepared units until reopened. Findings and manual events remain attached to the stable case identity; saved Finding query contexts additionally remember their prepared selection. Reopening a query after that selection changes reports a coverage mismatch rather than silently changing its meaning. Existing linked evidence and saved text remain available. Old formats/links are not migrated into fresh cases, and source evidence is never replaced to make a case compatible.

## Contents

- [Follow a worked investigation](#end-to-end-example)
- [Look up commands and server options](#commands)
- [Prepare a case with one command](#full-auto-preparation)
- [Download and import data manually](preparation.md)
- [Check trails and S3 log coverage](#cloudtrail-trail-check)
- [Run KamoTrace in Docker](#docker)
- [Add Suzaku detections](#suzaku-detections)
- [Add GuardDuty context](#guardduty-context)
- [Add offline IP enrichment](#ip-enrichment)
- [Browse AWS inventory and map](#aws-inventory-and-map)
- [Inspect acquired computers](#acquired-computer-cards)
- [Record findings and tag events](#findings-and-event-tags)
- [Combine other events and editable manual events](#other-events-and-manual-key-events)
- [Search and inspect CloudTrail events](#cloudtrail-workflow)
- [Browse SSM commands and output](#ssm-command-browser-desktop)
- [Check where SSM logs sessions and commands](#ssm-logging-check)
- [Connect an AI agent](#agent-access-mcp)
- [Store and back up a case](#storage-and-backups)
- [Fix common problems](#troubleshooting-and-limitations)
- [Check licences and dependencies](#open-source-components)
- [Run development checks](#verification)

## Acquired computer cards

Completed external TraceQuarry parse-only acquisitions can show **Computers / UAC imports**. Admit them with `import-uac --case case.json --unit HOST_ACQUISITION --source COMPLETED_EXPORT`, then explicitly `prepare` that unit. TraceQuarry remains an independent tool; KamoTrace never runs its parsers or recovers an unfinished archive. Cards select declared prepared acquisitions by stable unit key, not attachment order. Old `.uac.duckdb` registries are not discovered or adopted. Reopen explicitly to load newly prepared coverage; opening a card never runs preparation.

Expand the cards to inspect one import at a time, four computer/label groups per
page. The compact default shows hostname, OS, interface addresses and historical
uptime with its selected observation timestamp. **Details & provenance** retains
secondary facts, acquisition/import metadata, raw summary and AWS reasoning.
**More values** exposes additional retained values; conflicts in collapsed
secondary fields remain flagged. Click a fact for the exact original observation,
source locator and time alternatives, retaining its Event tags and Findings.

Stable host IDs, unverified label groups and unattributed observations remain
distinct within each acquisition/collection. Network peer IPs are not host
interfaces. Missing facts mean unavailable in parsed evidence, not absence.
Acquisition/import times are not substituted for historical action times.
The server inspects at most 10,000 observations per selected import, retaining
eight distinct values per field with explicit overflow. Truncation discloses
potential missing facts/groups and disables automatic AWS associations.
AWS links require a stable host ID and one complete exact account/region/instance
claim; inventory remains a separate snapshot, not incident-time state.

Parser coverage shows the retained run/source ledger, including partial,
unsupported, failed or omitted sources and interrupted preparation. Processing
completion does not prove complete collection or coverage. Undated observations
have a separate **Show only undated events** control and do not appear in dated
histograms. Native-alert ingestion is not part of this card release.

MCP uses the same Store: `describe_schema` exposes `source_coverage`, `undated`
and the read-only registry context; `search_events` with a `time_local missing`
filter finds undated observations; `get_event` returns original JSON, hashes,
provenance, Event tags and Finding IDs. No new MCP path or registry-write tool is
exposed. Registry fractional numbers are preserved in HTTP response bytes;
browser/MCP JSON parsing can round those numbers. Original evidence JSON remains
unchanged text.

## AWS inventory and map

Collect a read-only snapshot using your existing AWS login, then attach it when
opening a case:

```powershell
kamotrace inventory --profile investigation --regions all --output C:\cases\acme\inventory
kamotrace serve --case C:\cases\acme\case.json --inventory-export C:\cases\acme\inventory
# Emit the static inventory IAM policy without AWS calls:
kamotrace inventory --emit-policy C:\cases\acme\inventory-policy.json
# Or emit it alongside a normal collection, outside the snapshot directory:
kamotrace inventory --profile investigation --output C:\cases\acme\inventory-new --emit-policy C:\cases\acme\inventory-new-policy.json
```

`inventory --emit-policy PATH|-` emits the static read-only inventory identity
policy. Without `--output`, no AWS calls are made; with `--output`, collection
also runs normally. `-` sends policy JSON to stdout and summaries/warnings to
stderr. A policy file must not already exist and must be outside the snapshot
output and any input export, so manifests and source evidence remain intact.
The exact actions are in the
[combined collection IAM policy](preparation.md#aws-collection-iam-policy):
STS identity, EC2 Region/network describes and managed prefix list entry reads,
RDS describes, ELB/ELBv2 describes (including listeners, rules, targets,
attributes and tags), `iam:GetInstanceProfile`, `iam:GetAccountAuthorizationDetails`
and `iam:ListPolicies`, plus `iam:ListUsers`, `iam:ListAccessKeys`,
`iam:GetAccessKeyLastUsed`, `iam:ListMFADevices` and `iam:GetLoginProfile` for user
credential activity and authentication configuration. The inventory-only policy
grants no S3 or KMS access and does not establish effective access. Unlike the
trail/SSM checks, this policy needs no discovery audit.

The **AWS inventory** workspace shows collected systems and their network
configuration. Search and region/status filters apply to the snapshot, not the
CloudTrail time range. Select a system to inspect its addresses, assigned IAM
roles, security groups, and exposure assessment. Collection failures remain
visible as coverage gaps; a denied read does not mean the resource is absent.

With a verified `--eks-export`, cluster inspectors also show configured access
entries/policies, Pod Identity associations and their retrieval status. These
are configured references, not effective access or proof that a pod used a role.
`CONFIG_MAP` authentication prevents AWS access-entry API reads; that gap does
not imply an IAM denial or no Kubernetes access. **Show configured components**
opens a cluster/component scope with a control to restore the previous filters.
EKS exposure and load-balancer associations remain **not assessed**.

Select a cluster and **Pod observations (explicit search)** to inspect attached
EKS logs. Opening the view does not scan history. Run **Search attached pod
observations** with optional start-inclusive/end-exclusive timestamps (explicit
timezone offsets) and exact namespace, pod name or UID filters. Results show
historical observations, newest first, not current pod inventory. Times display
in the selected application timezone. **View pod activity** prepares a narrower
query; run Search explicitly. Missing UIDs leave name reuse unresolved. Each
observation links to the original event and exposes its hash, dataset and
CloudWatch provenance. Editing filters clears old results; errors never turn
into an empty successful search.
The **Identity contexts** panel beside activity shows up to 50 names/UIDs with
observation counts and first/last times across the full filtered selection,
independent of the current results page. Different roles and UIDs stay separate.
Selecting a context prepares the exact filters and focuses Search; it does not
run a query or filter by observation role. Activity includes all roles matching
the applied namespace/name/UID filters. The compact coverage strip keeps partial
coverage and measured log extent visible; expand **Collection details** for
manifests and gaps. Row details retain credential context, original hashes and
CloudWatch provenance without filling the activity table with raw metadata.

**Authenticated caller** identifies `user.extra` pod credentials, with namespace
derived only from an explicit service-account username. Credential node context
does not establish current placement. **Target pod** identifies a named audit
object reference or matching Pod response; namespace-only list/watch records
do not identify named targets. SubjectAccessReview `spec.extra` describes a
reviewed subject and is not used as caller identity. **Workload metadata** uses
explicit structured Kubernetes log fields; it needs an explicit cluster label
or a conventional EKS group path. Group-path attribution does not establish the
current cluster incarnation. Audit stages and API response codes remain separate
observations, not deduplicated request counts or proof of runtime success.
Source coverage is expandable; partial, failed, missing and not-searched data
are distinct from no matches. The visible observed log extent measures attached
messages within the selected cluster and time bounds, independent of pod filters;
it is neither the requested acquisition window nor proof of continuous coverage.
Original coverage labels remain supported without rebuilding evidence.
Combined imports retain each collection's coverage separately, including earlier
caps, warnings and failed operations. Collection details link each coverage
record to its original event and hash; a later successful collection does not
erase earlier gaps.
No result establishes that no pods exist. The
view makes no AWS/Kubernetes calls and does not infer nodes, containers, runtime
state or effective access. Unrecognized formats remain available as original
events rather than being guessed into pod observations.

The **IAM** view browses global users, roles, IAM groups and policies independently
of the network filters. Users include group membership; users, roles and groups
include inline policies and managed-policy attachments. Roles include trust
policies; customer-managed policies include all collected version documents and
the default version. Permission boundaries are retained. AWS-managed policies
are enumerated as **metadata only**: their documents are not downloaded or modified.
Group cards show collected members and policies; user cards include group policy
context. Identity cards summarize group memberships and direct/group policies
before the detailed documents. Role last-used date and region are retained when
AWS reports them; a missing value is not proof of never used. User console sign-in
timestamps come from `ListUsers.PasswordLastUsed`. Access keys include IDs,
active/inactive status and creation dates (`ListAccessKeys`), and AWS-reported
last-used date, service and region (`GetAccessKeyLastUsed`). No secret access keys
or passwords are returned. Missing timestamps do not mean never used or password
disabled. Denied/failed calls are marked unknown; a failed paginated key listing
retains collected keys but is labelled incomplete. Older exports show activity
as not collected; create a new snapshot or explicitly refresh IAM into a new
output to include it. IAM users do not have role memberships; assumable roles
are not evaluated.
This is not an effective-permissions evaluation: session/resource policies,
SCPs and other controls may restrict access. No passwords or access-key secrets
are collected. Errors and partial pagination remain visible as coverage gaps.

The IAM table exposes **Review signals**, credential/role activity, groups or
member counts, and policy counts. **Inspect** opens the same summary and policy
context directly in the inspector; identity reference cards show it from event
fields too. Expand a review signal for the key ID or policy/trust statement that
triggered it. Checks flag active keys at least 90 days old, active keys or roles
whose reported last use was at least 90 days before IAM collection, broad action
or all-resource Allow statements, and wildcard/cross-account trust principals.
Age is measured at snapshot completion, not the day you open the app. Policy
checks inspect inline and inherited group documents and only the default
customer-managed policy version; a permissions boundary is not treated as a grant.
Conditions are called out but not evaluated, and Deny statements are not Allow
signals. These are investigation leads, not confirmed vulnerabilities or an
effective-access calculation. AWS-managed documents remain unavailable; missing
activity, incomplete collection, and unavailable MFA/console-password posture
are explicit unknowns. No signals is never a declaration that an identity is safe.

User snapshots also retain enrolled MFA device metadata (`ListMFADevices`) and
console login-profile metadata (`GetLoginProfile`, never the password). A
successful empty MFA listing means no devices enrolled at collection;
`NoSuchEntity` for the login profile means no console password configured at
collection. Denied or partial reads stay unknown. A login profile without any
enrolled MFA devices is a review signal, not a claim about MFA enforcement.

In the inspector or identity card, **Load CloudTrail MFA evidence** compares
this current posture with historical records. History is loaded explicitly so
opening a reference does not block on a database scan. Successful `ConsoleLogin`
events are counted separately for `additionalEventData.MFAUsed=Yes`, `No`, and
missing/unrecognized values; failed or unknown-result sign-ins are separate.
Other events are counted by `sessionContext.attributes.mfaAuthenticated=true`,
`false`, or unknown. A session flag describes AWS credential context, not a fresh
MFA challenge for each API call; upstream IdP / Identity Center MFA may not be
represented. Supporting canonical event hashes are supplied per observed group.

The comparison reports the selected prepared coverage's event-time extent and requested
account/Region; it is independent of the active event-grid search/time filters.
That extent does not prove uninterrupted or complete log collection. IAM user
history requires exact ARN and stable user ID, excluding recreated users and
records missing that ID. Role history requires exact session-issuer ARN and
stable role ID, with sessions kept separate; an exact STS session lookup stays
limited to that session. Current enrollment does not rewrite historical MFA
observations. Missing events/fields remain unknown, never proof of no MFA.

`download` can collect the same snapshot alongside logs, or on its own:

```powershell
kamotrace download --dest C:\cases\acme\download --regions all --services cloudtrail ssm inventory
kamotrace download --dest C:\cases\iam-snapshot --regions all --services inventory
```

The snapshot is published under `DEST/inventory`, including `iam.json`, raw
responses, `report.json`, CSV network reports and a hash manifest. A verified
snapshot is reused on resume, not refreshed; use a new destination for current
configuration. Attach the completed snapshot with `serve --case CASE.json
--inventory-export DEST/inventory`; offline `auto` accepts the same attachment
flag but never collects or refreshes inventory.
Older snapshots remain readable but have no newly collected IAM details. Use a
new output, or `inventory --from-export OLD --enrich-iam --output NEW` to collect
current IAM explicitly (the authenticated account must match the original export).

Choose **Explore full window** to keep the map, filters, tables and evidence
inspector together in a full-window dialog. Close it or press Escape to return;
filters and selection are retained. Drag the map background to pan, scroll to
zoom around the pointer, or focus the map and use + / −. **Reset** (or Home)
returns to a width-fitting overview; **Fit all** fits the entire topology.
Choose **Pop out map ↗** beside **Fit all** to open only the map and inspector
in a separate tab/window. It starts with the current filters and selected
resource, if any; subsequent changes are independent of the original tab.
Use **Clear filters** in the pop-out toolbar if the inherited filters hide
the systems you want to inspect. Browser settings determine tab versus window.
Load balancers occupy the first VPC column, with other systems to their right.
Service icons identify resource types; labelled status dots distinguish
configuration assessments. Selected nodes use a blue outline.
The exposure filter separates systems with a configured public load-balancer
route from those with **no recorded public LB route**. Neither option proves
reachability or safety; missing routes may reflect collection gaps.

Inventory is a **current, non-atomic configuration snapshot**, not a reconstruction
of the incident. A permitted path means the exported configuration allows it,
not that a service was listening or a connection succeeded. No active network
probes or DNS lookups are performed. See the snapshot's limitations for network
paths the analysis cannot verify.

Use `--inventory-export FOLDER` with `serve --case` or offline `auto` to attach
an existing snapshot. AWS acquisition remains a separate `inventory` or
`download --services inventory` command.

Hover over, focus, or click an identity, machine, or IP reference in event and SSM
views to inspect known context. Click keeps a card open; Escape dismisses it.
Cards label inventory, observed CloudTrail/SSM activity, and IP lookup information
separately. Exact names and addresses can match multiple systems: account and
region narrow the results when available, and competing matches remain visible.
A reused IP is not proof that its current owner generated historical traffic.
IP cards also list every matching VPC/subnet CIDR (IPv4 or IPv6), with the network
name, ID, region and, for subnets, parent VPC and availability zone. These are
labelled **network range matches**, separate from **exact resource address
matches**: being within a CIDR does not establish resource ownership. Overlapping
ranges remain separate candidates, not a single chosen network. All inventory
context describes the collected configuration, not incident-time state.
Older reports without subnet ranges still provide their known VPC ranges; create
a new snapshot (or analyze an existing raw export into a new folder) for subnet
and IPv6 range context. No live AWS or DNS lookup occurs when opening a card.
An STS assumed-role ARN can show the corresponding collected IAM role using its
exact partition, account and role name (STS omits the IAM path). This supplies
current configuration only: it does not merge session history into the role or
prove that the same role existed at incident time. Bare names remain potentially
ambiguous, and a role known only from an EC2 profile is not used to resolve sessions.
These lookups do not change your filters, evidence, findings, or tags.

Inventory JSON, raw AWS responses, and CSV exports contain sensitive infrastructure
metadata. Keep them with the private case files, not in the source repository.

## End-to-end example

Follow a CloudTrail export from download to recorded findings. This example
uses the [synthetic case shown in the README](../README.md): someone uses
alice's access key from a VPN exit at 01:12 WIB (UTC+7) and creates a
`svc-backup` administrator user. That user stops CloudTrail, runs an SSM command
and makes a bucket public. You can also follow these steps in [Docker](#docker).

### 1. Install KamoTrace

You need Python 3.11 or later and
[uv](https://docs.astral.sh/uv/getting-started/installation/):

```powershell
uv tool install C:\path\to\KamoTrace     # from a checkout or a built wheel
```

(From a checkout you can instead prefix every command with `uv run`.)

### 2. Download the evidence

In the AWS console open **CloudTrail → Event history**, set the time range
(up to the last 90 days of management events) and
choose **Download events → Download as JSON**. You get `event_history.json`
with a top-level `Records` array. A download covers one region and up to
200,000 events. Keep it on a private local disk: events can contain secrets.

### 3. Import the events

Admit a named acquisition into a new case JSON, then explicitly prepare it.
Loading data is always a command-line step; the browser never imports files
and opens raw/prepared artifacts read-only.

```powershell
mkdir C:\cases\acme; cd C:\cases\acme
kamotrace import --source event_history.json --case case.json --unit cloudtrail-1
kamotrace prepare --case case.json --unit cloudtrail-1
```

The importer preserves nested JSON and numeric precision, hashes every record,
records every source file's hash, and never overwrites existing evidence.
A UTF-8 byte-order mark is fine. Combine regions using repeatable `--source`
arguments or pass a CloudTrail-only folder; `.json.gz` files work directly.
Case admission requires rereadable files, so retain stdin in a new file first.
See the [multi-file and stream examples](preparation.md#multiple-files-gzip-and-stdin).
Add later acquisitions under new keys; raw artifacts are never appended to.
The downloader's `--compress` option produces gzip CloudTrail and SSM exports
that `import` and `serve --ssm-export` can read directly.

### 4. Add Sigma detections (optional)

Download Suzaku once, then run it on the same export
([details](#suzaku-detections)):

```powershell
kamotrace get-suzaku
kamotrace suzaku --case case.json --source event_history.json
```
```text
"suzaku_version": "3.0.0",  "linked_rows": 300,  "no_match_rows": 0,  "ambiguous_rows": 0
```

### 5. Enrich source IPs (optional)

Download the free DB-IP Lite databases
(no account needed), or use MaxMind GeoLite2 and/or your own provider's data as
JSONL, highest priority first ([details](#ip-enrichment)):

```powershell
kamotrace get-dbip
kamotrace enrich --case case.json --geolite2 $HOME\.kamotrace\tools\dbip-lite-2026-10
```

`get-dbip` prints the folder it installed (named by DB-IP's monthly release).

### 6. Investigate in the browser

```powershell
kamotrace serve --case case.json
```

Open **http://127.0.0.1:8765**. The histogram shows the burst on 25 October,
and the **Detections** tab lists the Suzaku rules that fired. The **Source IP**
column summary (**≡** in its header) shows two rare addresses next to the
office IP. Hover one in the grid, click its funnel button and choose **is** to
pivot to it; **Back** returns. Select events with the checkboxes, label them with **Tag events**,
and record what you observed with **Add to finding**. The left sidebar lists
findings, event tags and rules as things you can browse and reopen.

### 7. Connect an agent (optional)

Install the
[agent skill](#agent-skill) and register the MCP adapter while `serve` runs:

```powershell
Copy-Item -Recurse C:\path\to\KamoTrace\skills\investigating-with-kamotrace $HOME\.claude\skills\
claude mcp add --transport http kamotrace http://127.0.0.1:8765/mcp
```

Then ask, for example: *"Use KamoTrace to check whether any access key was used
from somewhere unusual, follow what it did, and tag and note what you can
confirm."* In the run behind the screenshot, the agent:

1. called `describe_schema`, `list_detections` and
   `summarize_field("source_ip")`, which showed 198.51.100.7 and 203.0.113.50 as
   rare against the office IP;
2. searched alice's access key (`key_id` equals her key ID) with `source_ip`
   not equal to the office IP 192.0.2.10, found 7 events and checked one raw
   record's hash with `get_event`;
3. tagged them `compromised-key` and wrote a note with the query attached, separating
   what it observed from what it inferred;
4. pivoted to `identity contains svc-backup` (8 events), tagged `backdoor-user`,
   `defense-evasion` and `impact`, and wrote a second note.

Refresh the browser to review the agent's tags and notes (shown as findings), and
change or delete any you disagree with: you and the agent share one set of findings.

Leave the server running while you work. Native installations listen on loopback
by default. Access from a different computer requires a trusted
port forward or another explicitly secured arrangement. It is deliberately not
exposed on the LAN or Internet and is not a multi-user production service. Host
and Origin checks protect loopback access; there is no arbitrary-SQL API. Do not
bypass these checks or publish the evidence with an unauthenticated tunnel.

## Commands

| Command | Purpose |
| --- | --- |
| `kamotrace auto --case CASE.json --unit KEY --kind KIND --source INPUT [options]` | [Offline orchestration](#full-auto-preparation): raw admission, explicit preparation, optional supplied sidecars and `serve` |
| `kamotrace import --source FILE_OR_FOLDER... --case CASE.json --unit KEY` | Admit an immutable CloudTrail acquisition; repeat `--source` |
| `kamotrace import-other --source FILE.jsonl... --case CASE.json --unit KEY --origin TEXT` | Admit provider-neutral events with documented origin; plain or gzip JSONL |
| `kamotrace import-uac --source FOLDER --case CASE.json --unit KEY` | Admit completed external TraceQuarry parse-only output; no tool execution or discovery |
| `kamotrace prepare --case CASE.json --unit KEY [--range START END]` | Publish selected scalar preparation; repeat `--unit` or physical-ID ranges |
| `kamotrace download --dest FOLDER --regions all --start ISO --end ISO [--compress]` | Resume selected CloudTrail, SSM, GuardDuty or inventory collection with an existing AWS login; CloudTrail/SSM by default |
| `kamotrace inventory [--output FOLDER] [--emit-policy PATH\|-]` | [Current network and IAM inventory](#aws-inventory-and-map); policy-only mode without `--output` makes no AWS calls |
| `kamotrace policy [--output PATH\|-] [--bucket NAME]... [--kms-key ARN]... [--validate \| --validate-file PATH]` | [Combined collection policy](preparation.md#aws-collection-iam-policy) for CloudTrail, SSM and inventory; offline generation, optional AWS IAM Access Analyzer validation |
| `kamotrace trailcheck [--regions all] [--json PATH\|-] [--emit-policy PATH\|-] [--max-items N] [--max-s3-calls N] [--probe-buckets]` | [Read-only audit](#cloudtrail-trail-check) of trails, logging/delivery state, S3 destinations and observed log dates |
| `kamotrace get-suzaku [--version X.Y.Z]` | Download and verify the official Suzaku 3.x release for this platform |
| `kamotrace get-iwatobi [--dest FOLDER]` | Build and verify the pinned [Iwatobi forensic-export fork](#install-the-iwatobi-fork); requires Git and Rust 1.88+ |
| `kamotrace suzaku --case CASE.json --timeline FILE` | Link an offline Suzaku timeline within declared prepared coverage |
| `kamotrace guardduty --case CASE.json --snapshot-unit KEY --findings FILE [--replace]` | Admit/prepare snapshots and build [contextual GuardDuty leads](#guardduty-context) |
| `kamotrace get-dbip [--dest FOLDER]` | Download and verify the free DB-IP Lite City and ASN databases (CC BY 4.0, no account) |
| `kamotrace enrich --case CASE.json (--geolite2 FOLDER \| --jsonl FILE)...` | Add offline IP enrichment bound to declared coverage |
| `kamotrace serve --case CASE.json [--unit KEY] [options]` | Start the browser UI on `127.0.0.1` without building preparation |
| `kamotrace mcp --url http://127.0.0.1:8765` | Stdio MCP adapter for agents, backed by a running `serve` |
| `kamotrace ssmcheck [--regions all] [--json FILE\|-] [--emit-policy PATH\|-] [--max-items 200]` | [Read-only report](#ssm-logging-check) of where SSM session and command output is logged |

`kamotrace <command> --help` lists every option. `python -m kamotrace` works too.

### `serve` options

| Option | Purpose | Default |
| --- | --- | --- |
| `--case PATH` | Fresh JSON case manifest (required) | — |
| `--unit KEY` | Explicit prepared unit subset; repeatable | All units, failing if one is unprepared |
| `--enrichment PATH` | IP enrichment sidecar from `kamotrace enrich` | `<case stem>.enrichment.duckdb` if present; otherwise special-use addresses are classified and other countries show as unmapped |
| `--annotations PATH` | Notes and tags SQLite sidecar | `<case stem>.annotations.sqlite3` |
| `--detections PATH` | Suzaku detections sidecar | `<case stem>.detections.duckdb` if present |
| `--iwatobi PATH` | Retained native Iwatobi forensic JSON attached to prepared UAC occurrences | None; explicit opt-in |
| `--guardduty PATH` | GuardDuty contextual-lead sidecar | `<case stem>.guardduty.duckdb` if present |
| `--ssm-export PATH` | Consolidated SSM command/output JSON | None; optional |
| `--inventory-export FOLDER` | Current network/IAM inventory export containing `report.json` | None; optional |
| `--eks-export FOLDER` | Verified EKS export for current map context; timeline events require a prepared EKS unit | None; optional |
| `--port NUMBER` | Local listening port | `8765` |
| `--mcp-transport http\|stdio` | Serve MCP at `/mcp`, or print local stdio adapter setup commands (`serve` only) | `http` |
| `--bind ADDRESS` | Listening address; only for containers (see [Docker](#docker)) | `127.0.0.1` (`0.0.0.0` in the image) |
| `--log-level debug\|info\|warning\|error` | Application logging; see [request diagnostics](#investigating-slow-requests) | `info`, or `$KAMOTRACE_LOG_LEVEL` |

Paths are relative to your terminal's current folder unless absolute. Quote
paths containing spaces. The case manifest, its referenced artifacts and any explicitly supplied
enrichment, detections, GuardDuty or SSM input files must exist; an inventory
export must be an existing folder. The server creates the annotations file if needed.

For example, load an SSM export alongside the prepared case:

```powershell
kamotrace serve --case "C:\evidence\case.json" --ssm-export "C:\evidence\ssm_command_session_activity.enriched.json"
```

The server never calls external services. Suzaku, GuardDuty and IP enrichment
sidecars beside the case JSON are picked up automatically only when bound to
the same prepared selection. Changing a sidecar,
the inventory snapshot or the SSM export requires restarting the server.

Startup verifies and attaches only declared raw/prepared artifacts read-only. It never builds a cache, normalizes missing units or silently drops unavailable coverage. File hashing and ordered scalar integrity scans still cost time and memory. Incompatible or damaged prepared output requires explicit `prepare --rebuild`; old published artifacts remain untouched. Keep space for private preparation, retained artifacts and runtime temporary/spill storage. Keep one server owner per case and do not change attached artifacts while serving them.

Only code, synthetic tests and third-party browser assets belong in this
repository. Databases, `event_history*.json`, enrichment JSONL, `.mmdb` files and
the `data/` directory are gitignored; keep evidence outside the repository.

## Full-auto preparation

`kamotrace auto --case CASE.json --unit KEY --kind KIND --source INPUT` admits and prepares one explicitly named offline acquisition, then optionally serves the declared case. `KIND` is `cloudtrail`, `generic` (requires `--origin`), `uac` or `eks`. Use `--no-serve` for preparation only. Collection, tool installation and inventory acquisition remain independent commands; positional legacy auto startup is rejected.

| Stage | Default | Override or skip |
| --- | --- | --- |
| Raw admission | Explicit acquisition key/input identity; matching committed units reused | `--case`, `--unit`, `--kind`, `--source`, optional generic `--origin` |
| Core preparation | Selected unit only; other units remain unchanged | Use standalone `prepare` for partial physical-ID ranges |
| GuardDuty snapshots | Optional raw unit, preparation and contextual links | `--guardduty-findings FILE --snapshot-unit KEY` |
| Offline enrichment | Optional supplied lookup files | `--jsonl FILE`, `--geolite2 FOLDER` |
| Suzaku links | Optional completed offline timeline | `--timeline FILE` |
| Serve | Entire declared case, never an implicit prepared subset | `--no-serve`, `--port`, `--ssm-export`, `--inventory-export`, `--eks-export` |

Install optional tools separately with [`get-suzaku`](#download-and-run-suzaku) and [`get-dbip`](#ip-enrichment); credit DB-IP Lite data (CC BY 4.0). Run [`download`](preparation.md#download-from-an-existing-aws-login) or `eks` separately with your existing AWS login. Auto itself is offline and does not contact AWS or download tools.

### Retry and recovery

If offline auto preparation fails, fix the reported input/preparation problem
and **rerun the same command**. Collection and tool installation have separate
retry behavior:

- **Separate tool installation** reuses verified complete outputs; auto does not install or upgrade tools.
- **Standalone collection** resumes from the downloader's checkpoint. Its default end time
  is frozen at the first run, so later reruns finish the same snapshot instead
  of moving the range. A completed collection with the same options is reused
  without contacting AWS only while every export it lists is present (and S3
  objects still match their SHA-256). If one is missing, the downloader
  regenerates it from the checkpoint after checking your AWS login. Different options are refused; use
  a new case folder for a fresh snapshot.
- **Raw acquisitions** are reused only for the same unit key, source paths/hashes and options. Changed input requires a new key. Reserve blocks durably before use; a failed attempt burns its IDs. Each unit builds in unique private staging and publishes before its manifest reference. A published-but-unregistered file is retained, never silently adopted. Retrying restarts the unfinished unit, not a mid-unit checkpoint.
- **Preparation** is explicit and per unit/scope. Failure retains the previous selected artifact. A replacement partial scope replaces the old selection rather than unioning with it. Reopen the viewer to activate later preparation; startup never repairs missing outputs.
- **Enrichment, detections and GuardDuty context** are derived sidecars, written
  atomically and bound to the declared prepared selection. Standalone producers
  require `--replace` for an existing output; auto rebuilds explicitly requested
  sidecars with replacement enabled when their paths exist. It does not discover
  missing source files or run Suzaku. Changed GuardDuty inputs require a new
  snapshot unit key. Prepare every intended unit before generating sidecars;
  a changed selected scope requires regenerating sidecars, not adopting old links.
  Core preparation uses `prepare --rebuild` for an already selected scope.
  A file at a sidecar path that is not that kind of KamoTrace sidecar is never
  replaced, and no output may be one of the inputs: choose a separate output path.
  Each output is checked again just before publication; without `--replace`
  publication never overwrites a file that appeared meanwhile.
- **Standalone inventory collection** is reused only as a verified completed snapshot with matching
  scope. Existing incomplete or mismatched destinations are refused, not
  overwritten. Use a new case folder for fresh configuration, or explicitly
  attach an existing snapshot with `--inventory-export`.
- One process at a time writes each output: database/sidecar preparation commands,
  including `guardduty`, lock their outputs with `<output stem>.lock` beside them
  (auto admission/preparation holds the case writer lock). A second writer of the same
  database or sidecar, even from another case folder or with a custom
  `--output`, stops with a "being prepared by another KamoTrace process" error.
  Locks are released when the UI starts and if the process dies.

## CloudTrail trail check

`kamotrace trailcheck` reports, read-only, which CloudTrail trails exist, what
they record, whether they are logging and delivering, and which log dates are
present in their S3 buckets. Run it before collecting older evidence than
Event History's 90 days, or to judge the gaps in what you have:

```powershell
kamotrace trailcheck --profile investigation
kamotrace trailcheck --regions us-east-1 ap-southeast-1 --json C:\cases\example\trailcheck.json
kamotrace trailcheck --regions us-east-1 ap-southeast-1 --start 2026-10-01 --end 2026-10-03
kamotrace trailcheck --json - --probe-buckets > C:\cases\example\trailcheck.json
kamotrace trailcheck --profile investigation --json C:\cases\example\trail-report.json --emit-policy C:\cases\example\trail-policy.json
# Policy JSON on stdout, summary and warnings on stderr:
kamotrace trailcheck --profile investigation --emit-policy -
```

It uses your existing AWS login, as `download` does, and only calls Describe,
Get and List APIs. It changes nothing in AWS, and it lists log objects without
downloading them. The readable summary goes to stdout. `--json PATH` also
writes the full report to a new file; it refuses to overwrite an existing one.
`--json -` writes the JSON to stdout and moves the summary to stderr.

`--emit-policy PATH|-` runs the normal audit, then emits a standalone IAM identity
policy for audit and collection, scoped to configured trail buckets and probed
former buckets confirmed to have CloudTrail prefixes, not buckets containing
only other services' `AWSLogs/` paths. Object reads are intentionally bucket-wide
(`/*`) to include historical paths. Report and
policy files must have different paths and neither is overwritten.
`--emit-policy -` sends only policy JSON to stdout and the summary to stderr;
it cannot be combined with `--json -`. Unknown or partial discovery retains
placeholders and warns on stderr, including unresolved KMS keys. This adds no
GetObject or permission simulation checks and proves neither effective access
nor complete discovery or evidence. Review the
[copyable policy, placeholder instructions and cross-account/KMS cautions](preparation.md#aws-collection-iam-policy)
before attaching it. SSM destinations require the separate SSM check.

With `--start` and `--end` together, trailcheck additionally verifies each UTC
day in that inclusive range for every selected Region, using only the current
account's paths. `requested_range.locations` records each location's day results;
`requested_range.verified` is true only when every Region/day has a matching
nonempty log object. This is independent of unreadable bucket settings that may
make the overall audit partial. Verification samples at most 20 objects per day,
within the shared S3 call budget: an unverified day is not proof of absence.

`download --cloudtrail-source auto`, when given `--start`,
selects S3 when every requested Region has at least one discovered current-account
root with successful listings for all requested days. Empty days are allowed,
including Regions with no existing prefix; matching log objects on every day are
not required. Samples without matching objects and unknown samples are reported
separately, and neither empty listings nor matching samples prove complete coverage.
An omitted `--end` uses now (the first run's start time, frozen on resume).
Missing locations, unknown Region scope, or unreadable/budget-limited day listings
that leave a Region without a readable root retain Event History, with a warning
about its 90-day management-event retention. The audit is saved as `trailcheck.json`
in the collection directory, and the source choice is frozen for resume.
After the readability gate passes, every requested date at every discovered
current-account/Region root is fully listed, not just dates whose 20-object
sample verified. Failed or denied collection listings stop the run; they do
not silently remove a root from the collection. Existing history checkpoints
keep their original source on resume; use a new destination to change sources.
`download --cloudtrail-source history` disables discovery. Known destinations can
instead be collected directly with `download --cloudtrail-s3
s3://BUCKET/[prefix/]AWSLogs/[o-org/]ACCOUNT/CloudTrail/` and explicit dates.
The account must match the authenticated account. See the
[S3 download example and limitations](preparation.md#download-from-an-existing-aws-login).
Only selected UTC delivery-date folders are collected; records are then filtered
by event time. Late deliveries outside those folders are not recovered. Original
gzip objects, ETags and checksums are retained; digest validation is not performed.

The report keeps four kinds of statement apart:

| Kind | Meaning | Source |
| --- | --- | --- |
| Configured scope | What trails are set to record now: Regions, organization/global service events, management/data event selectors and exclusions, Insights, log file validation, KMS, CloudWatch Logs | `cloudtrail:DescribeTrails` (including shadow trails per Region), `GetEventSelectors`, `GetInsightSelectors` |
| Logging and delivery state | Whether each trail is logging now, when logging started or stopped, latest S3/digest delivery times and errors | `cloudtrail:GetTrailStatus` in the trail's home Region |
| Observed S3 date prefixes | Year/month prefixes found per account and Region under `[prefix/]AWSLogs/[o-org/]ACCOUNT/CloudTrail/REGION/`, the first and last observed day, and months missing between them | `s3:ListBucket` with `/` delimiters |
| Verified days | For each Region's first and last observed day, a listed object whose CloudTrail log file name matches the account, Region and date and whose size is nonzero | `s3:ListBucket` |

Prefixes and verified days are not proof of complete logs or events. A
present month can still miss hours or Regions; a gap can come from logging being
stopped, lifecycle expiry, deletion or a changed prefix. Object contents are
not read, decrypted or digest-validated. Check the logs themselves before you
rely on them as complete. Day prefixes are listed only in each Region's first
and last observed month. Months are compared only when every month listing
completed. "Configured Regions with no observed S3 prefix" compares the current
configuration with the current account's prefixes. Time zones do not apply:
CloudTrail S3 paths are UTC dates.

For each bucket it also reports Region, public access block, whether the policy
is public, whether the policy lets `cloudtrail.amazonaws.com` write and under
which conditions, default encryption, versioning, object lock and lifecycle
rules. Lifecycle expiry and transitions explain why older years may be missing
or archived.

Denied and failed checks are **unknown, not absent**. A denied Region shows
`UNKNOWN (denied)`, never "no trail". A bucket in another account that you
cannot read keeps its trail's destination, with unknown coverage. JSON
findings carry a `state`:

- `configured`: the API answered with the setting.
- `not_configured`: the API answered that it is absent, such as `NoSuchLifecycleConfiguration`.
- `denied` or `error`: unknown.

Listings carry a `coverage`: `complete`, `partial` or `unknown`.
`errors` lists `{region, api, code, state, resource}` without AWS's error
messages, which can contain ARNs.

Listing is bounded. `--max-items` (default 1000) caps each S3 prefix and bucket
listing. `--max-s3-calls` (default 2000) caps all `ListObjectsV2` calls in a run.
When a cap is reached, the affected section becomes `partial`, an entry is added
to the top-level `truncated` list, and month-gap and scope comparisons are
withheld rather than guessed. The current account is listed before other
accounts in shared or organization buckets. Exit status is 0 for a complete
report, 1 for a report with unknown or partial parts, and 2 for a usage or login
failure (no report).

By default only trail destinations are listed. `--probe-buckets` also lists
`AWSLogs/` in every other bucket in the account. This finds logs left by deleted
or changed trails in buckets at the root prefix. `AWSLogs/` folders of other
services, such as VPC Flow Logs and ELB, are shown but not treated as CloudTrail.
Custom prefixes in non-destination buckets are not guessed.

Permissions: `sts:GetCallerIdentity`, `ec2:DescribeRegions` (for `--regions
all`), `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`,
`cloudtrail:GetEventSelectors`, `cloudtrail:GetInsightSelectors`,
`s3:ListAllMyBuckets`, `s3:ListBucket`, `s3:GetBucketLocation`,
`s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicyStatus`, `s3:GetBucketPolicy`,
`s3:GetEncryptionConfiguration`, `s3:GetBucketVersioning`,
`s3:GetBucketObjectLockConfiguration` and `s3:GetLifecycleConfiguration`.
These are audit permissions, not object collection or service delivery grants;
see the [audit and download identity policy](preparation.md#aws-collection-iam-policy)
for `s3:GetObject`, CloudWatch reads and SSE-KMS `kms:Decrypt` requirements.
CloudTrail Lake, Event History and CloudWatch Logs contents are not checked.
Reports name accounts, buckets and trails: keep them private and out of Git.

## Docker

The image contains KamoTrace, its locked Python environment, **Suzaku 3.0.0**
(official release, verified against GitHub's published SHA256), and the compatible
fork builds below. No host Python, Rust, linker or parser installation is needed.
Building needs Internet access and substantial disk/RAM for Rust compilation;
subsequent parsing, import, preparation and investigation can run offline.
Geolocation databases are **not** included; use `get-dbip` explicitly or mount
your own licensed GeoLite2 data.

| Bundled tool | Source and retained provenance |
| --- | --- |
| Iwatobi | `truekonrads/iwatobi`, `d4b5f02cbd7fe7a044f8a5e1153157355489bd5b`; locked build, rules/config/source/licence and `kamotrace-download.json` under `/opt/tools/iwatobi-COMMIT` |
| TraceQuarry | `truekonrads/TraceQuarry`, `26c941fb575347c055f79a1c10ed68ba9bdb8a2d` from `kamotrace-uac`; isolated Python 3.12, tzdata, Rust 1.100.0 locked native journal helper, source and `kamotrace-install.json` under `/opt/tools/tracequarry-COMMIT` |
| Suzaku | `/tools/suzaku-3.0.0`, including rules/config/AGPL notice and checksum receipt; matching v3.0.0 source pinned at `c88eca3a03227a0d9a55d59a1c45677315cf4fc8` under `/opt/tools/suzaku-source-3.0.0`; never substituted for Iwatobi's UAC attachment contract |

Build-time installers run their synthetic native-reader and exact-reference
capability checks. Runtime `tracequarry-python` selects the bundled isolated
interpreter; `TRACEQUARRY_JOURNAL_READER` already selects its matching native helper.
`iwatobi` is on PATH. No compiler is shipped in the final stage. Suzaku is
AGPL-3.0 and Iwatobi is RPL-1.5: retain the included notices and review source and
redistribution obligations before sharing an image; KamoTrace's MIT licence does
not relicense them. Suzaku's source revision is retained in
`kamotrace-source-revision`; its GeoLite test databases and Git object database
are excluded so no geolocation databases are bundled.

### Published release images

Publishing a GitHub Release triggers `.github/workflows/release-image.yml` to
build its exact tag for **Linux amd64**, run the offline Docker qualification,
then publish `ghcr.io/truekonrads/kamotrace:TAG`. Stable releases also update
`:latest`; prereleases publish only their exact tag. Pushing a Git tag alone or
saving a draft release does not publish an image. Release tags must be valid
Docker tags (for example `v0.1.0`); `latest` is reserved.

The workflow uses GitHub's automatic `GITHUB_TOKEN` with `contents: read` and
`packages: write`; no registry password secret is needed. After the first
publication, the repository owner should check the linked GitHub package's
visibility and set it to **public** if anonymous pulls are intended. GitHub
packages can initially be private even for public repositories.

Once that release has been published, use it without building locally:

```sh
docker pull ghcr.io/truekonrads/kamotrace:v0.1.0
docker tag ghcr.io/truekonrads/kamotrace:v0.1.0 kamotrace
```

Replace `v0.1.0` with an actual published release tag. The local `kamotrace`
alias lets all commands below work unchanged; skip their `docker build` step.
Prefer an exact release tag or digest over `latest` for a repeatable tool
environment. Updating the image does not replace your case/tools volumes.

### Build and first case

These examples are shell commands for Linux/macOS with Docker's **Linux** engine
(also usable from WSL2). In PowerShell, replace `$PWD/inputs` with an absolute
Windows directory such as `C:\exports`; named volumes work unchanged. Native
Windows containers are not supported. Verified here on native Linux amd64 with
Docker Engine 29.9.3; ARM64, Docker Desktop/macOS/Windows and amd64 emulation
remain untested here.
Use `--platform linux/amd64` on both build and run if deliberately using emulation.

```sh
docker build -t kamotrace .
docker volume create kamotrace-case
docker volume create kamotrace-tools
docker run --rm --network none -v "$PWD/inputs:/input:ro" -v kamotrace-case:/case kamotrace import --source /input/event_history.json --case /case/case.json --unit cloudtrail-1
docker run --rm --network none -v kamotrace-case:/case kamotrace prepare --case /case/case.json --unit cloudtrail-1
docker run -d --name kamotrace -p 127.0.0.1:8765:8765 -v kamotrace-case:/case -v kamotrace-tools:/tools kamotrace
```

Open **http://127.0.0.1:8765** on the Docker host. The default command is
`serve --case /case/case.json`; an empty volume deliberately fails with an
actionable missing-case error rather than discovering or importing evidence.
Override it with any normal KamoTrace CLI command, including `--help`.
Originals stay in the separate read-only `/input` mount; generated raw/prepared
units, manifests, Findings/tags and derived sidecars go in the explicit writable
`/case` volume. Do **not** use an anonymous volume for case storage: retain the
same named volume or absolute bind path on every invocation.

The default UID is 10001. Fresh named volumes are writable without a root
entrypoint or recursive ownership changes. On Linux bind mounts, create a case
directory you own and add `--user "$(id -u):$(id -g)"` consistently to every run.
Do not make your original inputs writable just to fix output permissions.
Avoid running multiple viewers/writers against the same case.

### Parse and load UAC, without host dependencies

Start from an **extracted UAC directory**, not an archive. Supply the actual
year/timezone and supported accounting ABI assumptions; these are not inferred
evidence. The output directory must be new. This can be the first unit in an
empty case, or another unit in the case above (stop its viewer first).

```sh
docker run --rm --network none -v "$PWD/inputs:/input:ro" -v kamotrace-case:/case --entrypoint tracequarry-python kamotrace -m uac_parser.cli /input/uac-host-1 --parse-only --year 2025 --timezone UTC --utmp-layout linux-time32-le --acquisition-id host-1 --out /case/parsed-host-1
docker run --rm --network none -v kamotrace-case:/case kamotrace import-uac --source /case/parsed-host-1 --case /case/case.json --unit host-1
docker run --rm --network none -v kamotrace-case:/case kamotrace prepare --case /case/case.json --unit host-1
```

Review the retained `run_manifest.json` and `source_index.json`: finalized does
not mean all sources/ABIs were supported or parsed completely. Keep originals
and parsed exports. See [parser coverage and assumptions](preparation.md#set-up-tracequarry-for-uac).

### Add data and recreate the viewer

Stop and remove **only the viewer container**, not the volumes. Give each new
acquisition a new immutable unit key; do not reuse an old key for changed input.
Repeat the UAC commands with `host-2` and a new parse output, or admit another
CloudTrail export as follows. Existing units and Findings remain intact.

```sh
docker stop kamotrace
docker rm kamotrace
docker run --rm --network none -v "$PWD/inputs:/input:ro" -v kamotrace-case:/case kamotrace import --source /input/additional.json --case /case/case.json --unit cloudtrail-2
docker run --rm --network none -v kamotrace-case:/case kamotrace prepare --case /case/case.json --unit cloudtrail-2
docker run -d --name kamotrace -p 127.0.0.1:8765:8765 -v kamotrace-case:/case -v kamotrace-tools:/tools kamotrace
```

Recreation reopens all declared prepared units. An ordinary `docker restart
kamotrace` also preserves state, but does not add data itself. Stop sends SIGINT
to the exec-form Python entrypoint so it closes the Store normally; choose a
longer `docker stop --timeout 60 kamotrace` for busy cases. Back up the stopped
case volume **in full**, including every referenced artifact and sidecar. Never
run `docker volume rm kamotrace-case` or `docker compose down -v` unless you
intend to delete the case. A rebuilt image does not upgrade an existing case.

### Optional detectors and enrichment

Suzaku is already installed: no runtime download is needed. New named `/tools`
volumes inherit the bundled files; old/nonempty volumes retain their existing
contents across image upgrades, and an empty **bind** mount masks bundled tools.
For a fresh tool set use a new named tools volume, or explicitly run
`get-suzaku --version 3.0.0` into the writable tools mount. This never changes
case evidence. While the viewer is stopped:

```sh
docker run --rm --network none -v "$PWD/inputs:/input:ro" -v kamotrace-case:/case -v kamotrace-tools:/tools kamotrace suzaku --case /case/case.json --source /input/event_history.json
docker run --rm -v kamotrace-tools:/tools kamotrace get-dbip
docker run --rm --network none -v kamotrace-case:/case -v kamotrace-tools:/tools kamotrace enrich --case /case/case.json --geolite2 /tools/dbip-lite-2026-10
```

Use the actual folder printed by `get-dbip`, not the example's month. Adding
units changes selection-bound detection/enrichment identities: rebuild those
sidecars explicitly for the final selection (with `--replace` where required)
before reopening; stale sidecars fail closed. Findings/tags bind to the stable
case instead and are retained.

Run Iwatobi explicitly, with rules relative to its retained installation:

```sh
docker run --rm --network none -v "$PWD/inputs:/input:ro" -v kamotrace-case:/case --workdir /opt/tools/iwatobi-d4b5f02cbd7fe7a044f8a5e1153157355489bd5b --entrypoint iwatobi kamotrace dfir-timeline -f /input/uac-host-1/var/log/apache2/access.log -r rules/iwatobi/web/webserver/web_rapid_posts_to_php_index.yml -z UTC --forensic-output /case/iwatobi.json --evidence-manifest /input/iwatobi-evidence-manifest.json -q -K -w -Q
docker run -d --name kamotrace -p 127.0.0.1:8765:8765 -v kamotrace-case:/case kamotrace serve --case /case/case.json --iwatobi /case/iwatobi.json
```

Create a manifest matching the parsed acquisition's exact source IDs, hashes,
paths and decoded-line references as described under [native attachment](#native-iwatobi-attachments).
It is not guessed from time/IP. Stop/remove any existing `kamotrace` container
first. Browsing only reads retained results; it never runs a detector.

Inside the container the server must listen on all interfaces
(`KAMOTRACE_BIND=0.0.0.0`) so Docker can publish the port. **Always publish it
as `-p 127.0.0.1:PORT:PORT`**: there is no authentication, and a plain
`-p 8765:8765` exposes the evidence to your network. The Host/Origin checks stay
on, which means the host and container port must be the same; for another port
publish `-p 127.0.0.1:8766:8766` and pass
`serve --case /case/case.json --port 8766` after the image name.
Other containers on the same Docker
network can also reach the port; don't attach the container to shared
networks.

Agents connect to `/mcp` on the same published port (no extra port or local
KamoTrace installation). For Claude Code:

```powershell
claude mcp add --transport http kamotrace http://127.0.0.1:8765/mcp
```

or in a JSON MCP client configuration:

```json
{"mcpServers": {"kamotrace": {"url": "http://127.0.0.1:8765/mcp"}}}
```

For a stdio-only client, use
`claude mcp add kamotrace -- docker exec -i kamotrace kamotrace mcp --url http://127.0.0.1:8765`.

On Linux, add `--user "$(id -u):$(id -g)"` to `docker run` so files in the case
folder belong to you.

## Native Iwatobi attachments

### Install the Iwatobi fork

Install the optional detector separately, like Suzaku:

```sh
kamotrace get-iwatobi
```

This builds [Konrads's fork](https://github.com/truekonrads/iwatobi) at full revision
`d4b5f02cbd7fe7a044f8a5e1153157355489bd5b` from the `uac-forensic-contract`
work proposed in [upstream PR #17](https://github.com/Yamato-Security/iwatobi/pull/17).
The helper never follows a moving branch or falls back to upstream. The fork's
version string is still `1.0.0`; a stock release is not sufficient.

Prerequisites are Git, Rust 1.88+ with Cargo, a working native linker/C build
toolchain (Visual Studio C++ Build Tools for Windows MSVC; Xcode Command Line
Tools on macOS; a C compiler/linker on Linux), disk space and network access to
GitHub and Cargo dependencies. The helper does not install these prerequisites.
It runs `cargo build --release --locked`; first installation may take several
minutes. Pinning source and Cargo.lock makes inputs reproducible, not a promise
of bit-identical executables across operating systems/toolchains or a security
endorsement of the fork/dependencies. Iwatobi is separately licensed RPL-1.5.

Like `get-suzaku`, it uses `$KAMOTRACE_TOOLS` or `~/.kamotrace/tools`; `--dest`
overrides that folder. JSON stdout reports the executable and folder. Each full
revision gets its own `iwatobi-<revision>` folder, keeping the executable,
source, rules, config and licence together. `kamotrace-download.json` records
the source, revision, binary SHA256, build command and smoke result. There is no
PATH modification or implicit detector execution by `serve`.

Before publication, setup checks both forensic CLI flags and runs only the
fork's three-line synthetic example. It requires `iwatobi-forensic-1.0.0` /
`uac-1.0.0`, one complete correlation and three exact members referencing decoded
text lines 1, 2 and 3 with the supplied acquisition, collection, canonical path
and original file hash. Failed downloads/builds/capability checks clean private
staging without publishing an installation. Errors include missing prerequisites
or compiler diagnostics; existing target folders (even partial ones) are never
overwritten. Use the installed executable or choose a different `--dest` to
retry; no automatic update or rule refresh occurs.

For a synthetic check after installation, change to the reported installation
folder and run the following (PowerShell: use `.\iwatobi.exe`):

```sh
./iwatobi dfir-timeline -f docs/examples/forensic/access.log -r rules/iwatobi/web/webserver/web_rapid_posts_to_php_index.yml -z UTC --forensic-output ../synthetic-iwatobi.json --evidence-manifest docs/examples/forensic/evidence-manifest.json -q -K -w -Q
```

Use a fresh output filename; forensic bundles are not overwritten, even with
`--clobber`. Real offline scans are separate, explicit work: supply original
logs and an evidence manifest with the same acquisition/collection IDs,
canonical paths and original byte hashes used by your prepared UAC case. Use
the logs' actual timezone, not automatically your local timezone. Never scan
retained evidence just to test setup. See the installed `docs/UAC_CONTRACT.md`
for binding details. Unbound output remains valid detections but cannot attach
as exact evidence. No alerts or a successful setup says nothing about evidence
coverage or whether a system is clean.

### Open retained output

Open an already prepared case with a retained native alert bundle:

```sh
kamotrace serve --case case.json --iwatobi retained-iwatobi.json
```

This reads `iwatobi-forensic-1.0.0` / `uac-1.0.0` JSON directly. It does **not** run Iwatobi/Sigma, ingest UAC, prepare units or rewrite the bundle. `--unit` limits attachment to that declared prepared selection. It can coexist with Suzaku and an explicitly supplied `--guardduty` sidecar. No automatic bundle discovery occurs.

Native run, alert and rule IDs must be non-empty strings; an alert's `uac.run_id`, when present, must also be a non-empty string. Malformed identities are rejected at startup, not coerced into rule IDs. Optional `run.rules` and `sources` must be arrays when present, not `null`.

In **Detections**, Iwatobi-prefixed rules filter the timeline using the same lead/rule and severity filters as other detections. **Retained native Iwatobi alerts** pages all alert identities, including `no_match`, `ambiguous` and `unsupported`; linked alerts have **Original event** buttons. Original event detail shows the attached native alert identity and buttons for all linked member occurrences. These are automated leads, not investigator Findings.

Links require a supplied acquisition ID/status and exact collection ID, canonical source path, source SHA256 and the **complete physical source location**. Only the three-field locator `{kind, coordinate, line}` is supported: `kind` must be `text_line`, `coordinate` must be `decoded_decompressed_1_based` (one-based line counting in decoded/decompressed text), and `line` must be a positive integer. Additional locator fields are unsupported, never discarded to manufacture a match. Original JSON is parsed losslessly so integer line numbers are never rounded. Every reference of a member must resolve uniquely to the same occurrence; every member of an alert must resolve. Repeated text at different physical lines stays distinct. Multiple candidate occurrences remain ambiguous even when their record content is equal. There is no timestamp, IP, text-similarity or producer-ID fallback. Truncated, inexact, unbound or unsupported alerts never attach. A partial correlation stays unattached even when some members resolve.

Event provenance `source_ordinal` is the position in the normalized observation input. The original physical source line lives in the retained JSON's `uac.source_refs[].locator.line`; these line numbers need not agree. Neither is the case-global numeric event ID. Original detail retains all three without renumbering.

`GET /api/detections` includes `iwatobi` bundle SHA256, compact native run provenance, selection identity and alert/member status counts. Large native rule manifests remain in the original hash-bound bundle, not repeated in that summary. `POST /api/iwatobi` accepts optional `status`, `offset` (default 0) and `limit` (1–50, default 10), returning native IDs, ordinals, per-member statuses/candidate counts and linked `event_ids`. Bundle SHA256 + run ID + ordinal identifies a retained alert even when native IDs repeat. `GET /api/events/ID` includes `iwatobi_alerts`. MCP exposes the same reads through `list_detections`, `list_iwatobi_alerts`, `search_events` and `get_event`.

Attachment is rebuilt in disposable runtime state on explicit reopen, streaming provenance from selected prepared UAC units at startup. It scans no unselected units and makes no external requests. `no_match` means no exact occurrence in **this selection**, not a false alert or proof of absent activity. Source collection/parser gaps remain separate from match counts. Initially only this native schema and physical text-line locator are supported.

## Suzaku detections

[Suzaku](https://yamato-security.github.io/suzaku/) (Yamato Security) is a
Sigma-based threat-hunting and timeline tool for cloud logs. The Python package
does not bundle it; the Docker image includes verified Suzaku 3.0.0 (AGPL-3.0).
Supported input is Suzaku 3.x `aws-ct-timeline`
DuckDB output (`suzaku_meta` schema version 1, UTC timestamps).

### Download and run Suzaku

Run `get-suzaku` to download the latest official 3.x release for your platform
from [GitHub](https://github.com/Yamato-Security/suzaku/releases). Use
`--version 3.0.0` to choose a specific version.

The helper checks the archive against GitHub's published SHA-256. It unpacks
Suzaku and its Sigma rules into `~/.kamotrace/tools`. You can change the folder
with `$KAMOTRACE_TOOLS` or `--dest`.

```powershell
kamotrace get-suzaku
kamotrace suzaku --case C:\evidence\case.json --source C:\evidence\event_history.json
```

Without `--suzaku`, `kamotrace suzaku` runs the most recent version installed
by `get-suzaku`. Add `--min-level low` to set a minimum severity.
The checksum guards against a corrupted or altered download, not
against a compromised release. Suzaku's licence and source are at its
repository. Rerun `get-suzaku` to update; each version keeps its own folder.

### Use an existing Suzaku installation or timeline

To use your own Suzaku binary and rules:

```powershell
kamotrace suzaku --case C:\evidence\case.json --suzaku C:\tools\suzaku\suzaku-3.0.0-win-x64.exe --source C:\evidence\event_history.json --rules C:\tools\suzaku\rules
```

or import a timeline you already produced with
`suzaku aws-ct-timeline -f event_history.json -o timeline -t duckdb` (without `-l`):

```powershell
kamotrace suzaku --case C:\evidence\case.json --timeline C:\evidence\timeline.duckdb
```

KamoTrace runs Suzaku from its own folder (so its default `rules` and `config`
are found), writes its output to a temporary folder and deletes it afterwards.

### Understand how detections link to evidence

Detections are stored separately from the original records:

- Each ordinary Suzaku row is one event × rule match. It is linked to an evidence
  record only when **eventID, AWS region and event time all match exactly**. Identical
  duplicate records (same canonical hash) all receive the match. Rows matching
  no record, or several different records, are kept in the sidecar as
  `no_match`/`ambiguous` and counted, but never shown on an event.
- Suzaku 3 **correlation rules** (for example "IAM Persis Chain via User and
  Access Key Creation") report several events in one row: their eventIDs and
  regions joined by ` ¦ `, stamped with the latest member's time. Each member
  links by its exact eventID, within one of the listed regions and no later
  than that time. The row links to all its member events only when every
  member matches exactly one record; otherwise it is kept unlinked like any
  other row.
- Output goes to a separate `<case stem>.detections.duckdb`. Declared prepared
  evidence is attached read-only and never modified. An existing sidecar is
  only replaced with `--replace`.
- The sidecar records provenance: Suzaku version, command line, rules revision
  and count, timeline SHA-256, selected evidence identity and record count,
  supplied source information and linked/unmatched/ambiguous counts. In a case,
  the evidence identity is a digest of declared prepared coverage, not the hash
  of one export file; a source-file hash comparison is not proof of case membership.
  `serve` refuses a sidecar built for a different selection. Repeat `--unit KEY` on the producer
  to match an explicitly selected viewer subset.

### Review detections in the browser

In the browser, the expanded sidebar gains a **Detections** tab listing each
rule, most severe first, with its severity letter (I/L/M/H/C), ATT&CK tags (on
hover) and linked event count. Click a rule to add it to a pipeline
`lead in (...)` stage; multiple sidebar selections match any selected Lead.
Legacy saved rule scopes retain their all-of meaning. The grid's
**Sigma** column shows the most severe level and the match count on one line;
click it for the full rule list. The inspector lists an event's detections too.
A correlation rule appears on each of its member events. A note saved by an
agent with a minimum level reopens with a removable `Sigma ≥ <level>` scope.
Detections are automated leads: tag events or record a finding about what you observe.

## GuardDuty context

GuardDuty findings are optional, contextual leads alongside Suzaku detections.
Collect them separately, then admit/prepare snapshots and build context for a
prepared case:

```powershell
kamotrace download --dest C:\cases\gd-export --profile investigation --regions all --services guardduty
kamotrace guardduty --case C:\cases\example\case.json --snapshot-unit guardduty-1 --findings C:\cases\gd-export\guardduty.json
```

The importer also accepts an AWS `GetFindings` object with a `Findings` array,
or a bare findings array, without AWS access. For offline auto preparation, pass
`--guardduty-findings FILE --snapshot-unit KEY` alongside the required
`--case`, `--unit`, `--kind` and `--source`. Snapshot IDs are persisted raw
occurrences, not count-derived offsets. Adding snapshots changes the prepared
selection: generate enrichment/detections only after all intended snapshot units
are prepared. The default output is
`<case stem>.guardduty.duckdb`; `--output PATH` changes it. `--replace` rebuilds
only a recognised GuardDuty sidecar, never the original evidence. Restart
`serve` to load it automatically, or select a custom path with `--guardduty PATH`.

The **Detections** tab includes **GuardDuty context (not exact)** leads. Select
them like other Leads; pipeline predicates use `lead`, and MCP uses `query.rules`
or `query.min_level`. An association requires the finding's account to match
`userIdentity.accountId`, region, exact access key and event time within
`[EventFirstSeen, EventLastSeen)`. This does **not** establish that GuardDuty
detected that particular CloudTrail event. Missing keys/times, zero-length
intervals and unsupported resources stay unlinked, never guessed from IPs.
All findings remain in the source and sidecar. Linked raw finding JSON is
available in event details and MCP `get_event`, separately from CloudTrail JSON.

All retained findings, linked or not, appear independently in the shared Events
timeline as `event_type = "guardduty"`, labelled **derived finding snapshots**,
not original CloudTrail evidence. The **GuardDuty timeline** button in Detections
toggles that type within the current query without clearing dates or other scopes.
Queries, histograms, exports, Event tags, Findings and MCP use the same selection
and review paths as other event types. Lead/minimum-level filters still select
context-linked CloudTrail events, not GuardDuty snapshot severity; inspect/filter
the snapshot's original `raw.Severity` separately.

Timeline time is `Service.EventFirstSeen`, falling back in order to `CreatedAt`,
`UpdatedAt`, then `Service.EventLastSeen`. Without any timestamp the row has unknown
time (and is excluded by date scopes). The detail states the chosen basis; raw
observed interval, creation/update times and import/acquisition provenance remain
separate. Finding update time is not activity time. Selected IANA timezone and
start-inclusive/end-exclusive query ranges apply unchanged. Context-v1 retains
the strict observed `[first,last)` rule above: point observations remain unlinked,
even if a collected event exists at that instant. No broader heuristic or exact
reference matcher is introduced. Details offer at most 100 contextual navigation
links in either direction, with the complete association count and basis.
Timeline rows, detail headers and contextual navigation timestamps all use the
selected IANA timezone, including when opening a linked row not loaded in the grid.
Original timestamps inside raw JSON and provenance remain unchanged.

The linked-lead catalog groups GuardDuty findings by ARN and shows each distinct
retained snapshot underneath, with its own title and severity. Identical repeats
show an occurrence count; their physical timeline rows remain separate. The group
badge is the highest retained severity, not an assertion about the latest state.
Its event count is distinct contextual AWS rows, not the sum of overlapping
snapshot associations. Click a snapshot to inspect it; the group filters AWS context.
Unlinked-only findings remain available through the GuardDuty timeline shortcut.

Sample status is independent of link status: `guardduty_sample` is `sample=true`,
`sample=false` or `sample=unknown`. It accepts explicit boolean or true/false text
in `Service.AdditionalInfo.Sample` and parsed `Service.AdditionalInfo.Value.sample`;
missing, malformed or conflicting flags remain unknown, never presumed real.
The timeline summary and detail show this status. Archived status remains in raw JSON.

GuardDuty raw units preserve every input-array occurrence, including identical
duplicates and multiple updates with the same ARN. ARN identifies the provider
finding; the namespaced canonical-content review hash identifies an immutable
snapshot. Identical repeats have distinct physical rows but share reviews, as
CloudTrail duplicates do. Changed content has a new review key; it never inherits
an older snapshot's annotations automatically. `content_sha256` hashes the exact
stored JSON text. Row `id` is a persisted case-local navigation handle, not a
cross-import identity. Rebuilding contextual links does not replace raw snapshot
records or fetch history. Preserve original source exports. Fresh cases never
adopt old sidecars. Snapshot units receive ordinary reserved IDs and declared
preparation coverage. A later acquisition uses a new snapshot unit key; open an
explicit subset to exclude earlier acquisitions rather than rewriting them.

MCP example: `search_events(query={pipeline_version: 1, pipeline: 'event_type = "guardduty" | guardduty_sample = "sample=unknown"'})`.
Use `get_event(id)` for the snapshot's exact raw JSON and hash check, `guardduty`
status/time/link metadata, and `related_events` / `related_events_total` navigation.

Collection requires `guardduty:ListDetectors`, `guardduty:ListFindings` and
`guardduty:GetFindings` in addition to the default generated collection policy,
plus normal STS identity and EC2 Region discovery access when using `--regions all`.
It never enables or changes detectors. Archived findings are included; GuardDuty
generally retains findings for 90 days. `--start`/`--end` filter finding
**updatedAt**, not activity time. Omit them for retained findings through collection
start. No enabled detector and a successful empty result are reported separately;
denied calls fail collection rather than report no findings. Checkpoints resume
the original snapshot, not a live refresh; use a new destination to collect again.
`--compress` does not compress `guardduty.json`. Keep exports private.

## IP enrichment

Source IPs can be enriched offline with country, city, ASN and network, plus any
extra fields your own provider supplies. Enrichment is a labelled lookup about
an address, not evidence, and is never written into the evidence database.

Without a provider country value, **Country** shows a built-in special-use label:
`(private)` for RFC 1918 IPv4 and IPv6 unique-local addresses (`fc00::/7`),
or `(loopback)`, `(link-local)`, `(multicast)`, `(unspecified)`,
`(shared address space)` (carrier-grade NAT), `(documentation)`, `(benchmarking)`,
`(limited broadcast)`, `(site-local)`, `(reserved)` or `(special-purpose)`.
IPv4-mapped IPv6 addresses use the embedded IPv4 classification. These labels
work without a sidecar or downloads and can be filtered like other Country values;
they are address classifications, not geographic claims. Existing provider values
and attributes retain their priority. Restart the server to pick up this behavior;
there is no need to rebuild enrichment sidecars.

### Choose an IP data source

You can use either or both of these formats:

1. **GeoLite2-format `.mmdb` (convenience).** A folder with one **City** (or
   **Country**) and/or one **ASN** database, matched by file name, any case.
   - **DB-IP Lite is free and needs no account or licence key.**
     `kamotrace get-dbip` downloads the current monthly
     [IP to City Lite](https://db-ip.com/db/download/ip-to-city-lite) and
     [IP to ASN Lite](https://db-ip.com/db/download/ip-to-asn-lite) `.mmdb`
     files, checks each against the SHA-1 published on DB-IP's download page and
     its DB-IP database type, and installs them into
     `~/.kamotrace/tools/dbip-lite-YYYY-MM` (or `$KAMOTRACE_TOOLS`, or `--dest`),
     with a `kamotrace-download.json` provenance record. It is licensed
     [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): credit
     "IP Geolocation by DB-IP" (https://db-ip.com) in reports that use it.
     Lite data has lower accuracy and coverage than commercial databases. Rerun
     `get-dbip` monthly to update; each release keeps its own folder.
   - **MaxMind GeoLite2** City/Country and ASN `.mmdb` files need a free MaxMind
     account and acceptance of the
     [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula), so KamoTrace
     does not download them; put them in one folder. Commercial GeoIP2 and DB-IP
     `.mmdb` files with the same layout work too.
2. **Your own data (provider-neutral JSONL).** Convert any provider's output
   (Spur, ipinfo, an ip-api cache, an internal list) into the schema below.

```powershell
kamotrace get-dbip
kamotrace enrich --case C:\evidence\case.json --geolite2 $HOME\.kamotrace\tools\dbip-lite-2026-10
kamotrace enrich --case C:\evidence\case.json --jsonl C:\evidence\spur.jsonl --geolite2 C:\geoip --replace
```

### Combine sources and set their priority

Give `--geolite2` at most once; `--jsonl` can be repeated (with distinct file
names, since the name is the label). **Order is priority:** for
country, city, ASN and network, the first source given that has a value wins.
Extra `attributes` from every source are kept, prefixed with the source label.
The label is `geolite2` (also for DB-IP files; the recorded database type says
which) or the JSONL file name without its extension (`spur`),
and labels must be unique. Only addresses that appear as a source IP in the
evidence are stored; AWS service names such as `ec2.amazonaws.com` are skipped.

Output goes to `<case stem>.enrichment.duckdb` (or `--output`), which `serve`
loads automatically. An existing sidecar is only rebuilt with `--replace`. It
records the case and prepared selection it was built for (and `serve` refuses another),
the build time, and per source the file SHA-256 (or each `.mmdb` file's hash,
type and build date), entries, evidence IPs matched and attribute names. Repeat
`--unit KEY` to match an explicit viewer subset; regenerate after changing scope.

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

### Filter using IP information

With a sidecar loaded, the grid shows **Country**, **City**, **ASN** and
**Network / ISP** columns, plus **IP attributes** (for example
`spur.proxy_score=92; spur.tunnel=vpn-example`) when a source supplied
attributes. They work with field filters, is/is-not pivots, prevalence and
value summaries like other fields; free-text search covers raw event JSON only,
not enrichment. Proxy and VPN exits make geography misleading; it is not proof
of a person's location.

## Findings and event tags

KamoTrace records two separate kinds of review:

- A **finding** is a shared Markdown write-up linked to one or more events: an
  observation, not necessarily a confirmed conclusion. Say what you saw and what
  you infer. Findings are stored as notes; agents and the MCP tools call them
  notes (`create_note`, `list_notes` and so on).
- An **event tag** is a coloured label on individual events, such as
  `needs-review`. Tags are for grouping and filtering; they carry no text.

### Use the sidebar

The left sidebar is always present. Collapsed, it is a narrow rail of event
tags; expanded, it shows **Findings**, **Event tags** and **Detections** (when
detections are loaded) tabs, findings first. Use the **›** chevron at the top of
the rail to expand it and the **‹** chevron to collapse it again. The browser
remembers your choice.

In the collapsed rail:

- Each tag shows its colour swatch and name, cut short when long. Hover or focus
  a tag to see its full name and event count.
- Select a tag to add it to the query. Select it again to remove it. Active tags
  are highlighted and their swatch shows a check mark.
- The list scrolls when there are more tags than fit. **All tags** expands the
  sidebar on the **Event tags** tab.

### Mark key events

Key events are prominent milestones, such as suspected initial access or a change of attacker state. They are an investigator designation, not an automatic detection or a separate event type. Select existing AWS, imported other or manual events, choose **Tag events**, and check **key-event · highlight on timelines**. The tag is offered even before its first use. Uncheck it to remove prominence; other tags and Findings remain intact. A manual event is not automatically a key event.

The `key-event` tag gives rows a coloured background and edge, using the tag's editable colour. Diamonds on **Selected event frequency** show each distinct matching key-event timestamp, and the summary counts all matching key events, not only loaded rows. Coincident events share a diamond. The master **All events, daily context** strip shows key-event positions across the whole dataset, even when the current filters exclude them. Each chart is limited to the first 2,000 distinct positions; dense views explicitly warn and add first/last endpoint spans for each bucket/day. These spans do not assert continuous activity. Narrow the time range or filters for individual positions. Bucket/day boundaries use the selected timezone. Tag writes update row highlights and marks in place without clearing selection or scroll; filtered membership and counts still require **Refresh results** when marked stale. MCP changes appear when results are rerun.

Filter key events with the ordinary tag controls or `tag = "key-event"` in Pipeline mode. MCP clients use `tag_events`/`untag_events` with `tag: "key-event"` and explicit event hashes. Histogram buckets expose `key_events`, `key_first_ms` and `key_last_ms`; zero-match buckets have count 0 and null endpoints. `key_positions` contains sorted distinct `positions_ms` and a `truncated` flag; these millisecond instants are scoped to the whole filtered selection, not loaded rows.

### Browse event tags

The **Event tags** tab lists every tag, its colour and its event count across
the pinned prepared selection, not just the current query.

- Select a tag name to add it to the query. Select it again to remove it.
- Selecting several tags builds a pipeline any-of list. To require all tags,
  write explicit equality predicates joined by AND. Legacy saved tag scopes
  retain their all-of meaning.
- Select a colour swatch to change that tag's colour everywhere.

### Read and manage findings

The **Findings** tab lists shared findings, newest first. Use the search box
to find one. Its first line is its title.

Expand a finding to read it and see its oldest 25 linked events. Select an event
to open the inspector. Use these controls to work with the finding:

| Control | Action |
| --- | --- |
| **Filter to finding** | Add the finding's events to the current query as a filter |
| **All linked** | Show only the finding's events across the whole export |
| **Reopen query** | Restore the query saved when the finding was written |
| **Link/Unlink N selected** | Add or remove links to selected events |
| **Edit** or **Delete** | Change or delete the shared finding for all its linked events |

A finding must keep at least one linked event. Delete the finding instead of
removing its last link. Findings accept up to 30,000 characters. Markdown is
sanitised: scripts, raw HTML controls and embedded images are not rendered.

If another tab or an [agent](#agent-access-mcp) changes a finding after you open
it, **Save** and **Delete** will refuse to overwrite that change. Copy your
text, reopen the finding and reapply your edits.

Each **Run**, or filter using a table value, refreshes the findings and tags.
This includes notes and tags written by agents.

### Tag events and add them to findings

Use the bar above the grid to work with selected events:

- Check events, or use the header checkbox to select **loaded rows only**.
  Selection persists while scrolling and while tagging/annotating, but resets when
  the query or sort changes. Up to 5,000 events can be changed at once.
- **Tag events** (or press `T`) lists every tag with an all/some/none checkbox and
  a count such as `2/3` for the selected events. Ticking a tag that is on none or
  some adds it to all selected events (other tags are untouched); unticking a tag
  that is on all removes it from all of them. Type to search, or type a new slug
  and choose a colour to create it. Tags are lowercase ASCII letters and digits with
  hyphen separators, at most 256 characters (e.g. `needs-review`).
- **Add to finding** offers **New finding…**, which records the current query
  with it, or a list to link the selected events to an existing finding.
- Hover a row's **Tags** or **Findings** cell and click its **+** to tag or add
  just that event. The inspector's **Add to finding…** also targets only the
  event it shows, not other selected events.
- Changes update loaded rows in place: scroll position, loaded batches and the
  selection are kept. If a tag or finding scope is active and the change could alter
  which events match, a **Refresh results** notice appears instead of reloading.
- Rows stay one line high. The **Tags** column shows up to three initial-letter
  squares, or two plus `+N`; click any of them for the full tag names (each filters)
  and **Edit tags on this event**. The **Findings** column shows an icon and count;
  click it to open those findings in the sidebar.

### Store findings separately from evidence

- Reviews persist in a separate SQLite file (a sidecar), defaulting to
  `<case stem>.annotations.sqlite3` beside the case JSON. Use `--annotations`
  to override its location. Back it up along with the evidence (stop the server
  before copying it). Notes/tags are keyed by review identity, not row order.
  CloudTrail/generic content duplicates share reviews; TraceQuarry uses
  manifest-and-line occurrences. The evidence remains read-only.
  The sidecar can contain sensitive investigator notes and is gitignored. Each
  new note also stores the browser query it was written from as inert JSON,
  re-validated when reopened and bound to its original prepared selection.
  A saved query refuses silent reopening under a different selection.
- Findings/manual state binds to the stable case UUID, not a unit's hash/count
  or the current prepared selection. Adding units preserves existing reviews;
  opening a sidecar from another case or an unrecognized/old binding is refused.
  No annotation migration or adoption is performed; choose a new sidecar path
  rather than replacing old investigator state.

<a id="other-events-and-manual-key-events"></a>

## Other events and manual events

The **Events** timeline combines CloudTrail, [GuardDuty derived snapshots](#guardduty-context), imported other events and investigator-entered manual events. The **Type** column distinguishes `cloudtrail`, `guardduty`, `other` and `manual`; filter it with **+ Filter** or `event_type = "manual"` in Pipeline mode. **Operation / content** shows the AWS operation or a bounded content preview; **Service / origin** shows the AWS service or documented origin. Search covers full raw records, not only previews. The optional identity is free text, not an asserted AWS principal. [Key-event prominence](#mark-key-events) is a separate tag that can apply to any of these types.

### Import other events

Use UTF-8 JSONL, one object per nonblank line. Required fields are `date` (RFC 3339 timestamp including seconds and an explicit `Z`/offset) and non-null `content` (text, nested object/array, number or boolean). Optional `ip` must be IPv4/IPv6 and `identity` must be text; omit unknown values. No other top-level keys are accepted: place provider-specific fields inside `content`. Numbers retain their precision. Example:

```json
{"date":"2026-10-25T09:30:00+08:00","content":{"description":"Unauthorised payment","amount":123.45,"reference":"synthetic-payment"},"identity":"customer-42"}
```

```powershell
kamotrace import-other --source payments.jsonl tickets.jsonl.gz --case case.json --unit application-1 --origin "Synthetic ledger and ticket exports; converted to JSONL by the investigator"
kamotrace prepare --case case.json --unit application-1
kamotrace serve --case case.json
```

Cases may contain only other events; no CloudTrail unit is required. Imports stream in batches to a new immutable raw artifact; an invalid line rejects the entire import without publishing a partial database. Existing units are never overwritten. Every import requires an origin description; retain originals for reproducibility. Details and exports include schema version, origin, import time, source-file byte hashes/sizes and the one-based original line locator (including blank lines). Gzip hashes cover compressed bytes. Explicitly prepare new units, then reopen the server to include them; startup never imports or prepares them.

### Add and edit manual events

Choose **Add manual event**. Enter its date with timezone offset, text or JSON content, required origin/basis and optional self-reported author, IP and identity. Open a manual event and choose **Edit manual event** to change it. Nested JSON is edited as text, so opening and saving never rounds numbers through JavaScript. **Save event and refresh** explicitly reruns the current timeline selection; it does not clear filters or widen the time range. A saved event outside that selection will not appear until you adjust it.

Manual events are investigator statements, not imported source evidence. They persist in `<case stem>.manual.duckdb`, separate from raw/prepared evidence and SQLite reviews, and bind to the case UUID. Each edit retains prior content, origin, author and timestamps, viewable under **Previous revisions**. An edit must supply the current `updated` stamp; conflicting edits fail without replacing the draft. Cancel and reopen the event before reconciling a conflict. Author is self-reported, not authenticated. Deletion is not supported.

Tags and Findings work across event types. `record_sha256` remains the review key: CloudTrail uses its existing canonical hash, imported generic records use a namespaced canonical-content hash, and manual events use a stable identity that does not change when edited. Identical imported generic records share reviews; separately created manual events do not. TraceQuarry reviews identify manifest-and-line occurrences instead of merging identical content. `content_sha256` checks the current stored JSON. The inspector displays both where they differ and always renders content as plaintext. AWS-only fields and exact SSM/detection links are not invented for other events.

The case UUID binds the SQLite annotation sidecar. Reviews for records outside the selected prepared coverage remain stored. Numeric browse IDs are persisted sparse `source_record` values, not runtime attachment-order offsets; provider event IDs and review identities remain separate. Never assume counts imply a contiguous ID range. Back up the case JSON, all referenced raw/prepared artifacts, source exports, derived sidecars, `.manual.duckdb` and `.annotations.sqlite3` together with the server stopped; one server must own a case's writable state.

MCP clients use the same timeline tools and `event_type`/`origin` filters. `create_manual_event(record_json, origin, author?)` creates one manual event; `edit_manual_event(id, updated, record_json, origin, author?)` replaces a manual event while preserving its reviews. Pass exact record JSON as a string; read `get_event` before editing. Neither API accepts paths, SQL or imported-record modifications.

## CloudTrail workflow

The page is laid out for laptops: a slim top bar and the time/histogram panel
scroll away normally, while the query bar, selection actions and grid headers
stay pinned and the grid fills the rest of the window.

### Set the timezone and time range

- Choose an IANA **Timezone** above the time range (default **UTC**). The browser
  remembers your choice. It controls local timestamps, time filters and histogram
  boundaries, independently of your computer timezone or MCP clients. Changing it
  preserves the selected instants; query history and saved note queries retain it.
  Times use 24-hour `YYYY-MM-DD HH:MM:SS`. Times skipped when clocks move forward
  are rejected. For repeated times append an explicit offset, for example
  `2026-10-25 01:30:00+01:00`.
- Drag either time-slider handle or its selected band, type timestamps and press
  Enter/**Apply**, click a day in the daily context strip, or use an all /
  last-3-days / last-7-days preset relative to the end of the export.
- Ranges include the start and exclude the end: `[start, end)`. The full-export
  default includes the last event. Boundary days are partial.

### Apply a query and return to earlier results

- **Applied query.** Chips under the search box show everything the grid, counts,
  histogram and prevalence currently use: time, search, field filters, tags, a
  note and an SSM command link. Click × to remove one (the query reruns), or click
  a field filter to edit it. Typing in the search or time boxes, or an unfinished
  filter, is a **Draft** until you press **Run**/Enter; **Revert** discards it.
  **Clear all** removes every scope except the time range.
- **Back/Forward** (‹ ›, or Alt+←/→) step through applied queries: pivots, tag and
  note filters, histogram brushing and time changes. Sort order and loaded rows
  are not part of the history.

### Search and filter events

- Event searches, sorting, loading more rows and column summaries show a running
  operation panel with **elapsed time** and **Cancel**. A search's rows and
  frequency/context queries share one Cancel control. Starting another search
  cancels the superseded work. Cancellation interrupts that request's running
  DuckDB query, or removes it from the wait for the shared query connection;
  it cannot interrupt a different operation or another browser/MCP request.
  Cancellation is cooperative: a native operator or Python callback may take
  time to reach an interruption point. The panel remains until requests settle.
  If cancellation cannot be confirmed, **Retry cancel** retries it; responses
  from the cancelled operation are still discarded rather than applied.
- A cancelled/failed search keeps previous rows and labels them as not updated;
  press **Run** or **Refresh results** to retry. Loading further pages is paused
  until a successful search, so old rows cannot mix with a new selection/sort.
  Cancellation never undoes saved Findings, Event tags or manual edits.
- **ETA unavailable** is intentional. DuckDB 2.0's connection-level progress
  percentage does not reliably cover lock waiting, all statements, Python work
  and response transfer; it cannot support an honest remaining-time estimate for
  this operation. Elapsed time includes registration, queueing and responses.
  These controls cover event-query reads, not preparation/collection, exports,
  writes, SSM's in-memory searches or MCP transport cancellation.
- Search performs a case-insensitive **literal substring search of the entire
  raw event**, including nested requests/responses. `%` and `_` are not wildcards.
  Type values as they appear: quotes and backslashes match as written
  (`C:\Windows\Temp`, `-c "iex`), even though the raw JSON stores them escaped.
  Press `/` to focus it.
- **+ Filter** adds filters for operation, service, identity, IP, country, access
  key ID, target, errors, document, etc. Filters combine with AND. `is one of`
  accepts a comma-separated list of exact values (not CSV quoting). Equality is
  case-sensitive; contains/not-contains are case-insensitive.
- The SSM shortcut selects SendCommand, StartSession and CancelCommand. It does
  not include routine agent reporting or prove that commands executed.

### Pipeline queries

Choose **Pipeline** beside the search editor for explicit Boolean filtering:

```text
event_name = "SendCommand" OR event_name = "StartSession"
| source_ip in ("1.1.1.1", "8.8.8.8")
| search "ssm.amazonaws.com"
```

Each pipe means **AND**: either operation, AND either IP, AND the raw-event
substring. There is no `where` keyword. OR must be explicit within a stage;
parentheses group expressions, with NOT binding before AND and OR. The date
selector always bounds the entire pipeline.

Schema suggestions match both table labels and keys: type **Operation** to find
`event_name`, or **AWS service** to find `event_source`. Suggestions show the
meaning and valid operators; Ctrl+Space opens them explicitly. Arrow keys move
through suggestions, Enter accepts without running, and Escape dismisses.
With suggestions closed, Enter runs; Shift+Enter inserts a newline.

Use double-quoted JSON strings for values. Scalar predicates support `=`, `!=`,
`in (...)`, `contains`, `is missing`, `is not missing`, `is empty` and
`is not empty`. `search "text"` preserves literal, case-insensitive raw-event
search, including escaped JSON text. It can also be combined with OR or NOT.
Missing scalar values do not match equality, membership or contains; NOT and
inequality include their complements. `is empty` includes null and `""`;
`= ""` matches only an actual empty string. No regex or wildcard expansion.

`tag in ("needs-review", "suspicious")` matches either Event tag. For both,
write `tag = "needs-review" AND tag = "suspicious"`. Leads use `lead` and stable
rule/context IDs, offered by autocomplete with their titles. Clicking multiple
sidebar tags or Leads builds an any-of list within that category; categories
combine with AND. Shortcuts never rewrite complex hand-written Boolean logic.

Run applies the draft. Errors identify line/column and leave the previous
results visible; Revert restores the applied query. Switching from Text search
to Pipeline quotes the search and preserves existing filters. Complex pipelines
cannot switch back to plain Text search without first simplifying or clearing
the expression. Legacy saved queries retain their AND semantics, including
older local-time field filters, which remain in Text search mode.

Pipelines are filter-only: no SQL, aggregation, joins, projection or date
expressions. Findings, SSM-command links and severity scopes remain visible
outside the pipeline and AND with it. See the
[v1 language specification](pipeline-language-v1.md) for exact rules and limits.

### Sort events and compare values

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
  This works for every column, including second-resolution local timestamps.
  Touch devices show the buttons
  without hovering. Clipboard access requires browser permission on a secure origin
  (loopback qualifies); a denied copy shows a manual-copy message.

### Inspect original records and query SQL

- Click a row to open the **inspector**, a side panel that leaves the grid usable:
  original JSON, canonical record hash, the event's full tag names (each filters)
  with **Edit tags…**, its notes, and SSM command backlinks. **‹ Prev / Next ›** (or
  `K` / `J`) step through loaded rows; Escape or Close dismisses it. Numeric JSON
  tokens are never round-tripped through JavaScript floating point.
- Expand Generated SQL to inspect the executed SELECT and its bound parameters.
  Copy SQL substitutes safely quoted values. `browse_events` is a temporary,
  enriched view created by `Store` in `kamotrace/server.py`, not a table written to the
  evidence database; copied queries require that view in their SQL session.

### Explore the event timeline

- **Selected event frequency** counts the entire filtered selection, not just the
  loaded rows. Choose minute/hour/day/week presets or any custom whole-minute
  width. Buckets are aligned in the selected local time, empty buckets stay visible,
  DST days can be 23 or 25 hours and repeated-hour buckets remain distinct,
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

To collect a compatible export using an existing AWS login, use
[`kamotrace download`](preparation.md#download-from-an-existing-aws-login).
Its `ssm.json` can be passed directly to `--ssm-export`. Session records and
downloaded transcripts remain separate from the Run Command viewer.

Load the local consolidated SSM export, preferably the base64-enriched version:

```powershell
kamotrace serve --case C:\evidence\case.json --ssm-export C:\evidence\ssm_command_session_activity.enriched.json
```

The file has `account_id`, `commands`, `invocations`, `invocation_details`, and
optional `cloudtrail_records`, `coverage` and `base64_enrichment` fields. Each
command/invocation/detail is wrapped as `{ "region": "...", "record": {...} }`;
commands may additionally contain per-parameter `base64_enrichment` arrays.
Without this option, the Activity log still shows CloudTrail SSM activity;
the command browser and spreadsheet explain how to load an export for output.
Exports remain local and read-only; restart to reload.

### Search commands and switch layouts

- **SSM commands** opens a searchable, sortable list and a command/output pane.
  Search includes parameters, decoded payloads, system IDs, stdout/stderr and
  linked event identities. Results load in batches of 100. The selected time range
  and timezone filter requested time, start-inclusive/end-exclusive. Events without
  a known requested time are excluded when a time bound is applied. CloudTrail field/tag
  filters are separate from command search.
- **Spreadsheet** is an alternative, full-width command/output grid. One row
  represents a system/plugin output record; command parameters and decoded
  payloads repeat alongside each system's own stdout, stderr, status and code.
  Missing output and combined-only fallback output remain distinct. No systems
  or plugins are merged. The same command-level search, time range and timezone apply;
  matching a command keeps all of its system/plugin rows visible.
  The grid fills the window height. Resize columns, scroll horizontally, or set
  **Rows** to **Expanded** for longer snippets. Headers sort the entire matching
  result before pagination; Shift-click adds sort columns. Scroll down to load
  another 100 rows (or use **Load more rows**). Click a cell, or focus it and press Enter, to read/copy its
  full value. Click a system ID or the cell inspector's **Open command and
  CloudTrail links** to return to the detailed command browser. Switching layouts
  retains time and command search. SSM records remain JSON-backed in memory;
  this view does not import them into persistent DuckDB tables.

### Activity log and analyst interpretations

Choose **Activity log** for an oldest-first, scrolling screen log. This is a
**reconstruction, not a terminal recording**: collected command output and
CloudTrail API activity have different sources. Failed SendCommand requests
without a command ID and session operations (including port-forwarding requests)
remain visible; API acceptance does not establish that a command ran or that a
session connected. This view does not invent terminal output for sessions.
Downloaded session transcript files remain separate.

Exported command output is one entry per machine and plugin: its command input,
streams and observed status/exit code for that exact machine/plugin. A CloudTrail
request (SendCommand) whose account, region and command ID exactly match the
command is part of those entries, not a separate entry; it and other linked
events (such as GetCommandInvocation polls) sit in a collapsed **CloudTrail
provenance** section with their request parameters, raw-event links and event
tag/finding actions. The entry's context line names who requested it (identity
and source IP of that SendCommand). Requests without matching output stay their
own entries, labelled as API activity that does not prove execution.

With a Both or Raw search, matches in collected text (command input, streams,
linked request parameters) are highlighted in magenta, and the sticky lane header
counts them in the loaded entries. **Prev**/**Next**, or N and Shift+N outside
text fields, jump between matches, opening collapsed provenance as needed and
loading further entries when stepping past the last loaded match.

If saved entry reviews no longer belong to a current entry (the export changed,
or the entry is now shown within another), a notice above the log lists them
read-only. They are never attached to another entry.

Each entry retains its timestamp, account, region, command ID where available,
machine and plugin, outcome/code and exact CloudTrail links. Missing output,
collected empty streams and combined-only output are distinguished. Each entry
labels its time basis: CloudTrail time, execution/response start, command requested
time as an output fallback, or reported session start. Time bounds
apply to the entry time, start-inclusive/end-exclusive; unknown-time entries are
excluded when a bound is set.

Search is a case-insensitive literal substring over the whole selection, before
counting and paging. Choose its scope beside the search box: **Both** (default),
**Raw / context** (request/command, stdout, stderr, combined output, account,
region, machine, plugin, command ID and linked event metadata) or **Enhanced /
analyst** (the export's static decoding, saved interpretations, entry tags and
entry findings, plus tags and findings on the linked evidence events).

Scroll with the mouse wheel or Page Down as one continuous sheet: the next
100 entries load automatically before you reach the end. Existing entries,
drafts and scroll position stay in place; no expansion or pagination clicks are
needed to read collected text and saved interpretations. Entries are compact:
one heading line (time, operation, outcome, machine, plugin), one context line
(account, region, command ID, time basis), then full wrapping text in two
aligned lanes: collected evidence on the left and derived/analyst content on the
right. Long output is never clipped or placed in its own scroll box.
Only editing requires opening the editor. The footer reports progress and when all matching activity
is loaded. If a request fails, loaded entries remain readable and an explicit
**Retry loading activity** button appears rather than retrying endlessly; it
retries exactly the failed request.

If an analyst write (yours, another tab's or an agent's) could change which
entries match a Both/Enhanced search, the log stops loading further pages and
shows **Results may be out of date · Refresh search** instead of skipping or
repeating entries. Loaded entries and drafts stay; Refresh reruns the search and
returns you to the same entry if it still matches. Empty and Raw/context
searches are not affected by analyst writes.

Raw collected text stays read-only. **Edit analyst entry** opens one side
editor over the right edge of the page; the log does not move or rewrap, so you
can keep reading the raw lane. Enter de-obfuscated/enriched text, line breaks,
entry tags and an entry finding. Saving updates only that entry in place. Close
(or Escape) returns focus to the entry, so Page Down continues from there.
Drafts are kept per entry while you switch entries, layouts, tabs and searches;
**Unsaved drafts** in the editor lists them. They are not stored on disk: the
browser warns before leaving the page with unsaved drafts. You can copy raw text into
the editor, select a Base64 token and decode it as UTF-8 or UTF-16LE (PowerShell),
or decode the whole field. These are static text transformations only: nothing
is executed or fetched. Check the result and **Save analyst entry** explicitly.

Interpretations, entry tags and entry findings live in the evidence-bound SQLite
sidecar, not the export or CloudTrail database. They attach to a content-addressed
entry, so changing its source cannot silently reuse the old interpretation.
Concurrent edits from another browser or MCP agent are rejected; your draft
stays. Use **Read latest saved (keep draft)** to see the other version next to
your draft, merge it in, then choose **I merged it: save my draft over this
version** (or **Replace my draft with this version**) and save.
Entry tags/findings are distinct from event tags and shared event findings in
the sidebar. For entries with original evidence links, **Event tags** and
**Event finding** reuse those existing workflows, and the enhanced lane shows
them labelled as event tags/findings. Supplemental
entries can still have entry tags/findings without pretending they are original
CloudTrail evidence. MCP agents can read the same log and save interpretations
with `search_ssm_log`, `get_ssm_log_entry` and `edit_ssm_log_entry`.

### Interpret command output

- Commands group by **account + region + CommandId**. Each system has its own
  invocation and each plugin has its own status, response code and stdout/stderr.
  Known targets lacking invocation/output records are explicitly marked missing.
  Combined plugin output is shown when separate output details were not collected.
  Reported target counts are not inferred from the available output records.
- Original parameters and static base64 enrichment appear together. Nested decoded
  payloads are displayed as plaintext data, never evaluated as shell or HTML.
  Output may be truncated by AWS; preserved output URLs are shown but not fetched.
  Raw collected command/invocation/enrichment records are expandable at the bottom.

### Follow links to CloudTrail evidence

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

## SSM logging check

`kamotrace ssmcheck` reports, per region, what AWS Systems Manager is set up to
log and where. Use it before `download --session-s3/--session-log-group`, or to
judge what an investigation can and cannot recover. It is read-only and uses
your existing AWS login, the same way as `download`:

```powershell
kamotrace ssmcheck --profile investigation --regions all --json C:\cases\example\ssmcheck.json
kamotrace ssmcheck --profile investigation --json C:\cases\example\ssm-report.json --emit-policy C:\cases\example\ssm-policy.json
# Policy JSON on stdout, summary and warnings on stderr:
kamotrace ssmcheck --profile investigation --emit-policy -
```

The text summary goes to stdout. `--json FILE` also writes the full report to a
**new** file and refuses to overwrite one; `--json -` prints the JSON to stdout
and sends the summary to stderr. Keep reports private: they name buckets, log
groups, KMS keys and the account ID. Caller ARNs and credentials are never reported.

`--emit-policy PATH|-` runs the normal audit, then emits a standalone IAM identity
policy covering audit/collection actions and all discovered SSM output buckets,
with intentionally bucket-wide object reads to include history. It does not
discover CloudTrail destinations; use `trailcheck` for those. Policy and report
files must differ and neither is overwritten. `--emit-policy -` sends policy
JSON to stdout and the summary to stderr, and cannot be used with `--json -`.
Unknown/partial discovery retains placeholders and warns on stderr; replace
unresolved bucket and KMS key placeholders before use. Generation adds no
GetObject or permission simulation calls and assures neither effective access
nor complete discovery or evidence. See the
[example identity policy and cross-account/KMS guidance](preparation.md#aws-collection-iam-policy),
including keys used by historical objects, not just current settings.

For each region it checks:

| Area | Source | Reported as |
| --- | --- | --- |
| Session Manager preferences | `SSM-SessionManagerRunShell` document | S3 bucket/prefix and encryption requirement, CloudWatch log group, encryption and streaming, KMS key, run-as and whether a shell profile is set (not its text) |
| Custom session documents | `Owner=Self` session documents | session type and whether the document's own logging inputs, the regional preferences, or nothing (`Port`) applies |
| Observed sessions | active and history sessions | counts per document, session type, and how many recorded an S3 or CloudWatch output URL |
| Observed Run Command | recent commands | counts per S3 bucket/prefix and CloudWatch log group, and commands with only inline output |
| State Manager | associations | S3 output location per association |
| Maintenance windows | Run Command tasks | S3 and CloudWatch output settings per task; other task types are only counted |

Read the states literally:

- `configured` / `not_configured`: the API answered, and the setting is set or
  absent. A missing regional preferences document means there is no logging
  configuration from that document, not that every shell session is unlogged:
  custom `Standard_Stream` session documents can supply their own logging inputs.
  Check the document's `content_logging` basis and destinations as well as the
  regional preferences. Neither establishes historical delivery or retention.
- `observed`: what recent executions did. Run Command has **no regional output
  default**: each sender chooses a destination. Observed commands never prove
  what future commands will log.
- `denied` / `error`: the call failed (only the API name and error code are
  kept), so the setting is **unknown**, not absent.
- `truncated`: a listing reached `--max-items` (default 200 per listing per
  region), so only the most recent items were examined.

The exit status is 0 when every check completed, 1 when the report is partial
(any denied, error or truncated listing), and 2 for usage errors or an unusable
AWS login. The command never reads command or session output, and never reports
command, association or task parameter values.

Limits to keep in mind:

- Port sessions (SSH through `AWS-StartSSHSession` and port forwarding) are never
  content-logged by Session Manager.
- Logging is delivered by the SSM Agent with the instance's permissions.
  Configured logging does not prove logs were delivered, kept or readable; the
  check does not inspect the buckets or log groups themselves.
- Observations cover only history that SSM still returns, generally 30 days.

Permissions: `sts:GetCallerIdentity`, `ec2:DescribeRegions` (for `--regions all`;
if denied, only the default region is checked and the report is partial),
`ssm:GetDocument`, `ssm:ListDocuments`, `ssm:DescribeSessions`, `ssm:ListCommands`,
`ssm:ListAssociations`, `ssm:DescribeAssociation`, `ssm:DescribeMaintenanceWindows`,
`ssm:DescribeMaintenanceWindowTasks` and `ssm:GetMaintenanceWindowTask`.
These checks do not need output-read permissions. The generated policy also
includes collection permissions for a later download; it is not a service
delivery policy and does not enable SSM logging or write anything in AWS.

## Agent access (MCP)

KamoTrace lets local AI agents (Claude Code, Amp, Claude Desktop or any
[Model Context Protocol](https://modelcontextprotocol.io/) client) search the
evidence, tag/untag events and read/write notes. By default, `kamotrace serve`
uses the official MCP Python SDK over **Streamable HTTP** at
`http://127.0.0.1:8765/mcp`, sharing the web server's port. The optional
`kamotrace mcp` adapter uses **stdio**, started as a subprocess by the client.
Neither transport adds another listening port. MCP has **no authentication**
and holds no database handle.
Every tool calls the already running browser server's REST API on loopback, so
the browser and agents share one authoritative state: the same read-only
evidence connection, the same validation, and the same notes/tags sidecar.
The HTTP endpoint uses stateless JSON responses, not a persistent event stream;
GET `/mcp` returns 405 by design. See
[MCP transport and shared state](architecture.md#mcp-transport-and-shared-state)
for the bridge's design and subscription limitations.

### Connect your client

Start the browser server first (as in the [end-to-end example](#end-to-end-example)), then register
the URL with your client. Startup prints the exact URL and commands for the
selected port; use that port if you changed it with `--port`.

Claude Code:

```powershell
claude mcp add --transport http kamotrace http://127.0.0.1:8765/mcp
```

Amp:

```powershell
amp mcp add kamotrace http://127.0.0.1:8765/mcp
```

Other clients (for example Claude Desktop's `claude_desktop_config.json`, or a
project `.mcp.json`; Amp's settings file uses the key `amp.mcpServers`):

```json
{
  "mcpServers": {
    "kamotrace": {
      "url": "http://127.0.0.1:8765/mcp"
    }
  }
}
```

For a local subprocess connection, start `serve --case CASE.json` with
`--mcp-transport stdio`. This disables `/mcp` and prints commands to register the
stdio adapter instead:

```powershell
amp mcp add kamotrace -- kamotrace mcp --url http://127.0.0.1:8765
claude mcp add kamotrace -- kamotrace mcp --url http://127.0.0.1:8765
```

The stdio adapter also works while HTTP MCP is enabled. It requires `kamotrace`
on the agent's PATH (`uv tool install`); otherwise replace `kamotrace mcp ...`
with `uv run --directory C:\path\to\KamoTrace kamotrace mcp ...`.
Its `--url` only accepts `http://127.0.0.1:<port>` or `http://localhost:<port>`, and
the adapter ignores system proxies. If the browser server is not running, tools
return a "cannot reach" error; start it and retry.

### Understand agent access

There is no authentication: any local process that can start
the adapter, or reach the loopback server directly, can read evidence and change
notes and tags, just like the browser. Native installations listen on
`127.0.0.1` by default; containers need the [Docker safeguards](#docker).
The server keeps its Host/Origin checks and CSP. The adapter sends no `Origin`
and the server accepts it as a local, same-host client. There is no SQL, file path
or network-fetch tool. Agents
cannot modify the CloudTrail evidence; they can only add, change or remove
notes and tags in the sidecar, so back it up as usual. Treat agent changes like
your own: review them in the sidebar's **Findings** and **Event tags** tabs.

### Identify events and handle note conflicts

Tags and notes attach to `record_sha256`, the review identity. CloudTrail and
generic records use canonical content hashes (identical duplicates share reviews);
TraceQuarry uses manifest-and-line occurrences, and manual events keep a stable
identity across revisions. `id` is a persisted case-local `source_record` locator
for acquired evidence, not a source ordinal, provider ID or count. IDs may have
gaps and do not change with attachment order. Use returned IDs to fetch raw detail.
Write tools change only the hashes passed to them, 1 to 5,000 per call; there is no "tag the whole
query" tool, so an agent must page through results and pass the events it means.
Note edits and deletes need the note's current `updated` value (returned by
`get_note`, `list_notes` and every note write). If the browser or another agent
changed the note since, the call fails without writing; re-read it and retry.

### Look up MCP tools

| Tool | What it does |
| --- | --- |
| `describe_schema` | Compact fields, operators, `pipeline_fields` and version, sorts, page sizes, time bounds and explicit evidence-read-only/annotations-writable flags. Takes `timezone` (default `UTC`); set `include_timezones=true` for supported IANA zones. Use summaries for prevalence. Call first. |
| `search_events` | `query` (search, filters, `pipeline`/`pipeline_version`, all-of tags/rules, minimum level, note, SSM command, start/end and timezone) plus sort, page and size. Returns the full filtered total and one page with hashes, tags and note IDs. External query properties AND with the whole pipeline. |
| `summarize_field` | Top/bottom five values, distinct count and total for a field across the whole filtered result. |
| `event_histogram` | Counts per `query.timezone`-aligned bucket (empty buckets included, at most 2,000), with epoch-millisecond boundaries. |
| `get_event` | Exact stored raw JSON by `id`, its `record_sha256`, a recomputed hash check, timeline `event_time_ms`, linked SSM commands and separate linked GuardDuty finding JSON. Derived GuardDuty events include sample/time/link metadata and contextual `related_events`. |
| `list_tags` / `tag_events` / `untag_events` | Tags with event counts; add or remove one tag on explicit hashes. Adding is additive and keeps an existing tag's colour (new tags default to the browser's colour). |
| `list_notes` / `get_note` / `read_note_text` | Searchable, paginated note summaries (25/page, follow `next_page`), direct note preview with linked-event page, and exact body/context chunks. `get_note` takes `timezone` (default `UTC`) for linked events. Read truncated bodies fully before editing. |
| `create_note` / `edit_note` / `delete_note` | Markdown notes (sanitised when the browser renders them). `create_note` can record the agent's query so **Reopen query** works in the browser. |
| `link_note_events` / `unlink_note_events` | Add or remove linked events; a note keeps at least one. |
| `list_detections` | Suzaku rules and labelled GuardDuty contextual leads, with linked event counts and separate provenance. GuardDuty ARN groups include distinct `snapshots` with detail IDs, titles, severity, occurrence counts and contextual AWS counts; the group severity is highest retained, not latest. `run` is null without Suzaku; `guardduty` is null without GuardDuty. Takes no arguments; filter events using `query.rules` (all must match) or `query.min_level` in `search_events`, `summarize_field` or `event_histogram`. GuardDuty context is not an exact event match. |
| `search_ssm_commands` / `get_ssm_command` / `get_ssm_event` | SSM commands from the JSON-backed export, each system/plugin output kept separate, linked CloudTrail events by exact account/region/command ID. |
| `search_ssm_log` / `get_ssm_log_entry` / `read_ssm_log_text` | Fixed 5-row summary pages with optional allowlisted `fields`, exact summary lookup and full text in chunks. Previews carry truncation metadata; linked-event metadata is retrieved as `field="events"`. Follow `next_page`, passing the search revision for non-empty enhanced/both continuations. |
| `list_ssm_orphan_reviews` / `get_ssm_orphan_review` | Preserved, unattached reviews: 25 summaries/page and exact preview lookup. Ordinary searches return only a count. Complete review text remains available in chunks. |
| `edit_ssm_log_entry` | Save an explicit entry's interpretation text, entry tags and entry finding using its current `updated` stamp (null for a new review). Stale writes fail; raw evidence and event tags/findings are not changed. |
| `reattach_ssm_review` | Explicit, audited reattachment from an orphan to a current entry with no review. Requires the orphan stamp and an analyst reason; unknown/ambiguous identities additionally require an explicit analyst mapping. Never overwrites destination work. |
| `edit_ssm_log_entries` | 1–100 explicit edits within 1 MiB. Independent per-item commits, `ok/stale/missing/invalid` results; all duplicate-ID occurrences are invalid. Retry rejected items after rereading; replayed successful stamps are stale. |
| `lookup_reference` | Scoped `identity/machine/ip` summaries with sources, snapshot times, ambiguity and pagination. History is not searched unless explicitly requested; current configuration is not incident-time identity. Missing inventory is labelled, and no online lookup is triggered. |
| `get_inventory` | No arguments returns compact snapshot times, coverage indicators and category availability/counts. Select `category` for paginated identity/status summaries; add `include_details=true` for complete selected configuration/provenance. Optional exact `account`, `region`, `kind`, `resource_id` filters AND with case-insensitive name/ID `search`. `page` defaults to 1; `size` defaults to 25 (1–100); follow `next_page`. `loaded=false` means no attached snapshot. Does not scan logs or contact AWS. |
| `search_eks_pods` | Historical pod observations from attached EKS logs. Requires exact `account`, `region`, `cluster`; optional exact `namespace`, `pod`, `uid`, inclusive `start`/exclusive `end` (ISO timestamps with offsets), `page` (default 1) and `size` (default 10, 1–50). Returns full-selection `total`, `next_page`, complete observation rows, up to `size` identity `contexts` with `total_contexts`, and compact coverage. `coverage_page` separately pages ten coverage-event links; follow `coverage_next_page`. Read original observations and manifests with `get_event(id)`. Caller credentials, target pods and workload metadata stay distinct; this is not live pod inventory or proof of placement. |
| `create_export` | Immutable NDJSON snapshot of an event `query` or SSM `ssm_selection` with allowlisted fields. Returns readiness, row/byte counts, SHA-256, expiry and an opaque download URL, never a filesystem path. |

EKS configuration requires a verified `--eks-export` at server startup. Historical
pod searches require a prepared EKS acquisition in the selected case coverage;
use `auto --case CASE.json --unit KEY --kind eks --source FOLDER --no-serve`
to admit and prepare a verified existing export. `--eks-export` attaches current
configuration separately; it does not admit timeline logs. No result is proof that
no pods exist: inspect coverage, unsupported messages and missing UIDs. Inventory
is collection-time AWS configuration, not incident-time state or effective access.

Inventory categories are `resources` (including EKS clusters/components), `vpcs`,
`subnets`, `security_groups`, `relationships`, `forwarding_paths`, `listener_actions`,
`errors`, `eks_coverage`, `metadata`, `iam.users`, `iam.roles`, `iam.groups`,
`iam.policies`, `iam.aws_managed_policies`, `iam.profiles`, `iam.errors` and
`iam.metadata`. `available` means the category was supplied, not that collection
succeeded or was complete. EKS-only startup does not mark absent network/IAM
categories as supplied; legacy empty browser placeholders do not establish
availability. Overview counts cover entire categories; selected
pages report the full filtered `total`. Categories absent from older exports are
unavailable, not evidence of no resources. Metadata/profile dictionaries become
`id`/`value` rows; select `include_details=true` to retrieve nested values.

Search matches top-level names, IDs/ARNs (including stable IAM user/role/group/policy
IDs, listener/rule and target-group identifiers) and relationship endpoints, not nested
policies, messages or configuration. `resource_id` matches exact IDs/ARNs or
relationship endpoints. IAM rows without a region use `global`; other unknown
regions do not match a region filter. Sorting is stable by region, identifiers,
then source position. Filters, nondefault paging and details require a category.
For example, discover clusters with
`get_inventory(category="resources", kind="EKS cluster")`, then pass the selected
row's `id` as `resource_id` with `include_details=true`. Access/Pod Identity
observations stay in cluster details; collection operations are in `eks_coverage`.

Inventory query results have a conservative 24,000-byte serialized JSON limit,
leaving room for MCP's text and structured copies. Oversized pages fail explicitly;
reduce `size`, narrow the scope or use summaries. A single oversized detail must
be inspected in the browser's full report; no records or values are silently cut.
The shared `POST /api/inventory` implements this query contract. The browser's
existing full `GET /api/inventory` remains unchanged.

MCP pod searches use the shared `POST /api/eks-pods` with `projection="summary"`.
Observation rows are not text-truncated. Coverage summaries contain total attached
datasets, `datasets_without_coverage` (unknown coverage), total coverage records,
and ten `coverage_records` links per coverage page, in attachment/source order.
Each link carries `id`, `record_sha256`, time, dataset index, operation count,
operation-gap count and warning count (null when unavailable). Coverage links
describe **all attached EKS collections**, not just the selected cluster/time;
read their original events for collection bounds, warnings and failure details.
No full manifests are repeated in MCP search results. Coverage paging is independent
of observation paging. Both retain full totals and never turn missing coverage
into a completeness claim. Summary responses over 24,000 conservative serialized
bytes fail explicitly: reduce `size` or narrow filters; a single oversized
observation remains inspectable in original evidence or the browser. The browser's
default full projection retains its existing manifests and 50-row pages.

Exports prepare synchronously, with one preparation at a time, at most 50,000
rows / 32 MiB each and four artifacts / 128 MiB per server. Narrow the selection
or fields after a limit error; no partial download becomes ready. The first NDJSON
line is a manifest with selection, evidence identity, analyst revision and labelled
derived provenance. Original `raw_json` is an exact stored **string**, not reparsed
JSON; supplemental SSM JSON is reconstructed and labelled separately. Later analyst
edits never alter a prepared export. Downloads do not hold the Store lock.
Links expire after ten minutes; disposable files are reclaimed on the next export
request/download or server shutdown once no active reader remains. Expired links
reject new downloads immediately, but an active download retains its artifact's
quota charge until its final reader closes, including disconnect/error paths.
Slow downloads can therefore prevent new exports rather than bypass the disk cap.
Restarting the server invalidates all links.
The default trusted link base is loopback; `serve --export-base-url https://trusted-origin`
can configure a trusted origin, without changing binding or access checks. Never
derive links from incoming Host headers. Loopback links work only for clients on
the server machine; consumers unable to download can still use bounded MCP reads.

Review provenance is persisted separately from content-addressed IDs. Only exact
current matches can backfill legacy metadata; unknown old hashes remain unresolved.
Orphan retrieval distinguishes uniquely related changed content from ambiguous or
unresolved sources, without inheriting the interpretation. Machine/plugin duplicates
remain distinct, and original/supplemental requests are not merged under session IDs.
Use chunk fields `review.source` and `review.history` for exact metadata and the
reattachment audit. A semantic match is not evidence that old analysis fits new content.

SSM summary and text reads target a serialized UTF-8 response budget of 80,000
bytes including MCP envelopes. Text chunks allow 1–2,000 Unicode code points,
not UTF-8 bytes or JavaScript UTF-16 units; follow `next_offset` to null, quoting
the first `sha256` on later chunks to reject changes. Length, UTF-8 byte length
and digest describe the full string; missing and empty remain distinct. Browser
activity lanes retain their full projection separately. Event filters accept
JSON string arrays for `in` (commas in array members are literal); valueless
empty/missing operators accept null or omitted values. Invalid fields/operators/
sorts name the rejected value and valid choices, not guessed aliases.

Event queries also accept constrained scalar paths such as
`raw.requestParameters.name` or `raw.resources[0].ARN` in ordinary filters,
sorters and field summaries. Add `query.raw_fields` to project a map of those
paths to `{value, json_type}` in event rows and exports. For example, combine
`{"field":"raw.requestParameters.name","op":"eq","value":"/doc"}`
with `{"field":"error_code","op":"not_missing"}` to classify failed
requests for that exact parameter. External filters and time bounds constrain
every pipeline OR branch; raw paths are not pipeline v1 field syntax.
Paths allow ASCII identifier keys and explicit array indices only: 256 characters,
eight key/index steps, indices 0–1000 and ten distinct paths across projection,
filters, summaries and sorting. No wildcard, quoted key, SQL or arbitrary JSONPath.
Scalar values are text: numbers retain their exact original lexemes, booleans
are `true`/`false`, sorting is lexicographic and numeric range/coercion operators
are unavailable. Missing paths have null `json_type`; JSON null is `NULL`, and
containers retain `OBJECT`/`ARRAY`, all with no scalar value. Missing operators
therefore include nulls and containers; empty operators also include the empty
string. Strings, numbers and booleans have types `STRING`, `NUMBER` and `BOOLEAN`.
Extraction uses a precision-preserving scalar accessor (DuckDB's Python UDF
requires NumPy); filtering, counts, grouping and ordering remain in the shared SQL
query path. Raw evidence and canonical hashes are never rewritten. Saved Finding
contexts preserve raw projections, filters and literal JSON-array members.
Interactive raw projections and raw-value summaries reject responses exceeding
24,000 bytes of conservative ASCII JSON, leaving headroom for the 80,000-byte
MCP envelopes. They never truncate a value or merge summary groups. Narrow the
selection, reduce projections/page size, or use `create_export` to retrieve exact
values; exports use the same validated selection without this interactive cap.
Predicates, grouping, counts and histogram selection remain exact.

Local Base64 analysis scans original command/request parameter string values and
separate stdout/stderr/combined streams. It accepts conservative printable UTF-8
or PowerShell-like UTF-16LE, standard/URL-safe spans, line wrapping and two decoding
levels. Hex hashes, AWS IDs, binary and ordinary identifiers are not assumed payloads;
short/ambiguous values may deliberately remain undecoded. It never executes,
fetches or decompresses anything. Supplied export derivations retain a separate
label. Accepted local derivations are searched in enhanced/both scope, never raw.
`read_ssm_log_text(field="analysis")` returns chunked JSON containing parents,
source fields, exact original spans (code-point offsets within the source string,
or within the parent's decoded text), decoder version and limit metadata.
Summaries carry only counts, truncation and reasons; full exports can include `analysis`.
Per entry: 65,536 input code points, 16,384-character candidates, 32 candidates,
16 KiB accepted text, 512 source nodes / depth 16 and 32 linked request sources.
Per case: 16 Mi input code points, 4,096 candidates, 1 MiB accepted text and 10,000
entries. Repeated parameter scans are cached (128 entries); cached work still
counts toward case limits. Incomplete analysis is explicitly labelled, not a
claim of no encoded content. Decoder changes do not change source/review IDs.

### Set query times and treat results as untrusted

Times are ISO 8601 with an explicit offset (`2026-03-02T00:00:00+07:00`);
ranges are start-inclusive and end-exclusive, as in the browser. Set
`query.timezone` (default `UTC`) for local result timestamps, `time_local` filters,
prevalence and histogram boundaries, e.g. `{"timezone":"Asia/Singapore"}`.
`describe_schema(timezone="Asia/Singapore")` returns bounds in that zone; it does
not change subsequent queries or the browser preference. Event fields,
raw JSON, SSM commands/output and note text are returned as untrusted data; the
adapter tells agents not to follow instructions found inside them.

Run only one browser server per notes sidecar: it holds the sidecar's working
copy of tags/notes for queries, and a second server on the same sidecar would
not see the first one's writes until restarted.

### Agent skill

The [investigation skill](../skills/investigating-with-kamotrace/SKILL.md)
teaches agents how to use these tools well: the query model and selectable timezone
boundaries, which identity to write to and which to cite, the
orient → narrow → verify → pivot → record loop, tag reuse, note conflicts, SSM
output and detections, and the error messages. It also covers the safety rules:
evidence is untrusted, writes go only to explicit events, and leads are not
findings. Install it where your agent looks for skills, for example:

```powershell
# Claude Code (all projects): copy the folder into your personal skills
Copy-Item -Recurse C:\path\to\KamoTrace\skills\investigating-with-kamotrace $HOME\.claude\skills\
# Amp (all projects): run from the checkout; Amp expects a relative local path
cd C:\path\to\KamoTrace
amp skill add ./skills/investigating-with-kamotrace --global
```

To scope it to one case instead, put it in that case folder's
`.claude/skills/` or `.agents/skills/`.

## Storage and backups

| Data | Where it lives | Written by the browser? |
| --- | --- | --- |
| Case identity, units, coverage and ID reservations | One case JSON, written by admission/preparation commands | No |
| Raw events/provenance and prepared scalar coverage | Immutable per-unit artifacts referenced by the case JSON | No; opened read-only |
| Annotations, event links and coloured tags | `<case stem>.annotations.sqlite3` (or `--annotations`), bound to case UUID | Yes (browser and MCP agents, through the same server) |
| Manual events and revision history | `<case stem>.manual.duckdb`, bound to case UUID | Yes (browser and MCP agents) |
| Suzaku detections and their provenance | `<case stem>.detections.duckdb` (or `--detections`), bound to prepared selection | No; read-only, rebuilt from Suzaku output |
| GuardDuty contextual links and provenance | `<case stem>.guardduty.duckdb` (or `--guardduty`), bound to prepared selection; snapshots are raw/prepared units | No; read-only, derived from finding JSON |
| Current network/IAM configuration and coverage | Inventory export folder (passed with `--inventory-export`), including raw responses, report and manifest | No; loaded at startup |
| SSM commands, outputs and enrichment | Original JSON export, loaded into memory | No; **not imported into persistent DuckDB tables** |
| IP enrichment and its provenance | `<case stem>.enrichment.duckdb` (or `--enrichment`), bound to prepared selection | No; read-only, rebuilt from DB-IP/GeoLite2 `.mmdb` and/or JSONL; no online lookups |
| SSM-to-CloudTrail query links | Temporary DuckDB table | Memory only; rebuilt on startup |

Stop the server before backup. Keep the case JSON, every referenced raw/prepared
artifact, Findings/manual state, derived sidecars, source exports and lookup files
together. Do not delete retained artifacts or reset ID reservations to close gaps.
The running browser server does not collect AWS data or refresh exports: prepare
new data with the CLI and restart to reload it. It does not fetch output URLs
or run shell commands. See [evidence and state ownership](architecture.md#evidence-derived-context-and-investigator-state)
for why these files remain separate.

## Troubleshooting and limitations

Known bugs and open limitations, with workarounds, are tracked in
[known limitations](BUGS.md).

### Investigating slow requests

Reference cards open using loaded inventory and IP enrichment only, without
scanning CloudTrail or waiting for the event-query lock. **Load event history**
explicitly calculates scoped CloudTrail counts and first/last seen;
**Load command history** adds the loaded SSM command associations for a machine.
Until requested, history is labelled **not searched**, not absent. Existing REST
callers retain historical results by default; `POST /api/reference` accepts
`include_history: false` for the reference-only path and reports `history_included`.

A small duck progress ring follows the pointer while a query or reference-card
lookup is pending. It appears only after 180 ms and stays until all overlapping
requests finish, including response parsing. With no pointer in the page it
appears below the top bar instead. It does not block clicks, and reduced-motion
preferences disable its animation.

`kamotrace serve --case case.json --log-level debug` enables detailed
application timings. Set `KAMOTRACE_LOG_LEVEL=debug` in the environment instead
when launching through `kamotrace auto`. The default is `info`; `warning` and
`error` reduce output. Debug logging is limited to KamoTrace, not third-party
HTTP/MCP libraries.

At info level, each Store operation logs when it is queued, starts, and finishes.
`lock_wait_ms` is time waiting behind another Store operation; `execution_ms`
is time holding the lock; `total_ms` includes both. For example, an explicitly
requested history lookup may be waiting behind an event count rather than
running a slow lookup itself.
Request summaries include status and elapsed time through writing the response.
The response's `X-Request-ID` header correlates these records with the browser
Network panel. Debug records add query/count/page and JSON serialization timings;
reference-card subqueries can also be followed by their thread name.

Startup logs time enrichment, SSM, inventory, detections and metadata separately.
Debug startup snapshots report DuckDB-managed bytes by tag, **not process RSS**.
Snapshots are totals at that stage, not additive allocations. Large `BASE_TABLE`
values can be cached evidence pages rather than enrichment rows. The server
retains its existing 2 GB DuckDB memory budget; reducing a cache budget can make
queries slower and is not a substitute for measuring the workload.

After startup, a background monitor samples memory every **30 seconds**. Debug
records include process RSS, system total/available bytes and, where readable,
Linux unified cgroup (v2) usage, limits and estimated available bytes. Ancestor
limits are considered, and inactive file cache is treated as reclaimable.
`pressure_scope` identifies the system or cgroup with the least proportional
headroom. Unavailable cgroup metrics are labelled `unknown`; non-Linux and
legacy cgroup v1 environments still get system and process readings via psutil.

Two consecutive samples with **10% or less headroom** produce a warning, with
at most one reminder every **five minutes** while pressure remains low. Two
consecutive samples at **15% or more** produce an info-level recovery message.
The gap avoids flapping around one threshold. Unknown samples do not count as
pressure or recovery. High RSS alone does not trigger a warning; this is a
headroom heuristic, not proof that KamoTrace caused pressure or an OOM forecast.

At debug level the monitor also samples DuckDB memory categories if the Store
lock is immediately available; otherwise it logs `duckdb=skipped_busy`. It never
waits behind an active query. Sampling stops before database connections close.
No per-request memory deltas or automatic cache/budget changes are made.

New timing records use fixed operation/route names and omit query text,
parameters, record IDs, IPs, identities and request/response payloads. Existing
startup messages still contain local file paths. Review logs before sharing.

### Common problems

- **Missing case or preparation:** admit original exports with `import`,
  `import-other` or `import-uac --case CASE.json --unit KEY`, then run
  `prepare --case CASE.json --unit KEY` and `serve --case CASE.json`.
  Startup does not adopt old databases or build missing preparation. To open
  a deliberate prepared subset, repeat `serve --unit KEY`; otherwise all units
  must be prepared. Rebuild incompatible/damaged derived output explicitly
  with `prepare --rebuild`; original evidence remains untouched.
- **Port already in use:** stop the previous server, or use `--port 8766` and open
  that port instead. Avoid leaving multiple instances on the same port.
- **No SSM commands:** supply `--ssm-export` with the consolidated format described
  above, then check the requested-time range. Individual AWS API response files
  are not a substitute for the consolidated export.
- **Countries unmapped:** run `kamotrace enrich` (private and service addresses
  stay unmapped), or pass `--enrichment` if the sidecar is elsewhere. A sidecar
  built for another prepared selection is refused: rebuild it with `--replace`. IP geography
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
Review screenshots and exports before sharing them. Run the
[development checks](#verification) before changing or distributing the app.

## Open-source components

KamoTrace is released under the [MIT licence](../LICENSE). Suzaku is a separate,
AGPL-3.0 tool, installed explicitly for Python users and included in Docker.
Iwatobi (RPL-1.5) and TraceQuarry retain their own licences and pinned sources
in the Docker image; those licences are not replaced by KamoTrace's MIT licence.

[DuckDB](https://duckdb.org/) handles local event queries;
[Tabulator](https://github.com/olifolkerd/tabulator) provides the grids and
[noUiSlider](https://github.com/leongersen/noUiSlider) provides the time slicer.
Markdown notes use Marked and DOMPurify for parsing and sanitisation.

Vendored, unmodified browser assets: `tabulator-tables@6.3.1` JS/CSS and
`nouislider@15.8.1` JS/CSS, obtained from the matching npm packages through
jsDelivr. Both MIT licences are in `src/kamotrace/static/vendor/`. No runtime dependency on
jsDelivr; no package manager is needed to serve the app.

Markdown uses vendored `marked@15.0.12` (MIT) and `dompurify@3.2.7`
(Apache-2.0 or MPL-2.0); their licences are also in `src/kamotrace/static/vendor/`.

The interface typeface is [Geist](https://vercel.com/font): the unmodified
variable `Geist-Variable.woff2` and `GeistMono-Variable.woff2` from the
`geist@1.9.0` npm package, self-hosted so the app works offline. They are
licensed under the SIL Open Font License 1.1, in `GEIST-LICENSE.txt` in the same folder.

Topology diagrams use a small, unmodified subset of the free official
[AWS architecture icons](https://aws.amazon.com/architecture/icons/) (2026-07-31
package), served locally with no external requests. AWS permits these assets
for architecture diagrams; they are AWS assets, not MIT-licensed KamoTrace code.
Source paths and usage attribution are in `static/vendor/aws-icons/NOTICE.md`.

## Verification

### Read CI results

GitHub Actions runs the HTTP/MCP contract suite on Python 3.14 (matching the
Dockerfile) for pushes and pull requests, plus JavaScript syntax and package-build
checks. A separate Docker job builds both pinned forks and Suzaku, then runs
`tests/docker_smoke.py` against the real image, offline, with synthetic evidence.
Jobs use the pinned Ubuntu 24.04 runner.
A Chromium smoke test opens the real app with disposable synthetic evidence,
verifies all five events render, then searches and checks the three matching
`SendCommand` rows. Each run uploads `browser-test-results` (screenshots, log
and Playwright trace) and contract logs, retained for 14 days. Open
the workflow run's summary for the download link; browser failures also capture
`failure.png` when a page is available. No private evidence or secrets are used.

### Run the browser check locally

Playwright is a test dependency, not an app dependency:

```powershell
uv run --locked --with playwright==1.64.1 python -m playwright install chromium
uv run --locked --with playwright==1.64.1 python tests/browser_smoke.py
```

Results are written to the ignored `test-results/` directory. On Linux, add
`--with-deps` to the browser installation command if system libraries are missing.

### Run package and contract checks

```powershell
uv run python -m unittest discover -s tests
node --check src/kamotrace/static/app.js
uv build
docker build -t kamotrace .
python tests/docker_smoke.py --image kamotrace
```

Only the optional JavaScript syntax check needs Node. There is no Node build.
The unit tests never download Suzaku or DB-IP. The separate Docker build downloads
Suzaku and fork sources; its smoke test exercises real parsing, explicit admission
and preparation, search, exact Iwatobi attachment, a real Suzaku run, additive
loading, persisted Findings/tags, container recreation/restart, clean stop,
read-only inputs and the published loopback port's Host check. `get-dbip` remains
an optional manual network check, never part of the image or synthetic tests.

### Understand test coverage

Tests use synthetic records and a disposable database built through the bundled importer,
real HTTP requests, asymmetric Jakarta-midnight boundaries, combined filters,
literal search (including quotes and backslashes), sorting, invalid input,
cross-origin rejection, BOM-prefixed inputs, sidecar-to-evidence binding, exact JSON
integers, local histogram boundaries/custom widths/empty buckets, and a database
SHA-256 before/after check. Coverage also includes annotation/tag persistence,
stale note edit/delete rejection, SSM account/region linkage, multiple
systems/plugins, missing/combined output, spreadsheet search/sorting, and
real HTTP and stdio MCP client sessions (search, tag/untag, note create/edit/link/unlink,
invalid input, raw-hash check) whose writes are checked through the browser API,
and Suzaku import (exact eventID/region/time linkage, correlation rows linked to
every member or not at all, unmatched rows kept but not shown, rule AND filters,
minimum level, refusal to overwrite) against the
DuckDB schema Suzaku 3.0.0 writes. Offline auto tests cover explicit admission,
preparation, retries, writer contention and rejection of unsupported startup. Collection
and tool download tests exercise the standalone commands rather than online auto.
They never modify the real CloudTrail evidence database. For contributor
ownership and design rationale, see [components and design choices](architecture.md);
for safety and recurring-mistake guardrails, see [AGENTS.md](../AGENTS.md).
