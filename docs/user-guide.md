# KamoTrace user guide

[Back to the README](../README.md)

Use this guide to investigate CloudTrail events, add supporting data and save
findings. For a first-time setup, [start with the README](../README.md#get-started).

## Contents

- [Follow a worked investigation](#end-to-end-example)
- [Look up commands and server options](#commands)
- [Prepare a case with one command](#full-auto-preparation)
- [Check trails and S3 log coverage](#cloudtrail-trail-check)
- [Run KamoTrace in Docker](#docker)
- [Add Suzaku detections](#suzaku-detections)
- [Add offline IP enrichment](#ip-enrichment)
- [Browse AWS inventory and map](#aws-inventory-and-map)
- [Record findings and tag events](#findings-and-event-tags)
- [Search and inspect CloudTrail events](#cloudtrail-workflow)
- [Browse SSM commands and output](#ssm-command-browser-desktop)
- [Check where SSM logs sessions and commands](#ssm-logging-check)
- [Connect an AI agent](#agent-access-mcp)
- [Store and back up a case](#storage-and-backups)
- [Fix common problems](#troubleshooting-and-limitations)
- [Check licences and dependencies](#open-source-components)
- [Run development checks](#verification)

## AWS inventory and map

Collect a read-only snapshot using your existing AWS login, then attach it when
opening a case:

```powershell
kamotrace inventory --profile investigation --regions all --output C:\cases\acme\inventory
kamotrace serve --database C:\cases\acme\case.duckdb --inventory-export C:\cases\acme\inventory
```

The **AWS inventory** workspace shows collected systems and their network
configuration. Search and region/status filters apply to the snapshot, not the
CloudTrail time range. Select a system to inspect its addresses, assigned IAM
roles, security groups, and exposure assessment. Collection failures remain
visible as coverage gaps; a denied read does not mean the resource is absent.

Inventory is a **current, non-atomic configuration snapshot**, not a reconstruction
of the incident. A permitted path means the exported configuration allows it,
not that a service was listening or a connection succeeded. No active network
probes or DNS lookups are performed. See the snapshot's limitations for network
paths the analysis cannot verify.

Online `kamotrace auto` also prepares inventory. Use `--skip-inventory` to omit it,
or `--inventory-export FOLDER` to attach an existing snapshot. Offline preparation
with `--source` or `--skip-download` does not collect inventory from AWS.

Hover over, focus, or click an identity, machine, or IP reference in event and SSM
views to inspect known context. Click keeps a card open; Escape dismisses it.
Cards label inventory, observed CloudTrail/SSM activity, and IP lookup information
separately. Exact names and addresses can match multiple systems: account and
region narrow the results when available, and competing matches remain visible.
A reused IP is not proof that its current owner generated historical traffic.
An assumed-role session is not silently matched to an IAM role by its name.
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

Import into a new evidence database. Loading data is always a command-line
step; the browser never imports files and opens the database read-only.

```powershell
mkdir C:\cases\acme; cd C:\cases\acme
kamotrace import --source event_history.json --database case.duckdb
```
```text
"records": 320,  "all_record_hashes_verified": true,  "source_sha256": "...", ...
```

The importer preserves nested JSON and numeric precision, hashes every record,
records every source file's hash, and refuses to overwrite an existing database.
A UTF-8 byte-order mark is fine. Combine regions using repeatable `--source`
arguments or pass a CloudTrail-only folder; `.json.gz` files and binary stdin
(`--source -`) work too. See the [multi-file and stream examples](../README.md#multiple-files-gzip-and-stdin).
Existing databases are never appended to; select the whole set for a new import.
The downloader's `--compress` option produces gzip CloudTrail and SSM exports
that `import` and `serve --ssm-export` can read directly.

### 4. Add Sigma detections (optional)

Download Suzaku once, then run it on the same export
([details](#suzaku-detections)):

```powershell
kamotrace get-suzaku
kamotrace suzaku --database case.duckdb --source event_history.json
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
kamotrace enrich --database case.duckdb --geolite2 $HOME\.kamotrace\tools\dbip-lite-2026-10
```

`get-dbip` prints the folder it installed (named by DB-IP's monthly release).

### 6. Investigate in the browser

```powershell
kamotrace serve --database case.duckdb
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
| `kamotrace auto CASE_FOLDER [options]` | [Full-auto](#full-auto-preparation): tools, AWS download, import, enrichment, detections, then `serve`; rerun to resume |
| `kamotrace import --source FILE_OR_FOLDER... --database NEW.duckdb` | Combine CloudTrail JSON/gzip exports; repeat `--source`, or use `-` for binary stdin |
| `kamotrace download --dest FOLDER --regions all --start ISO --end ISO [--compress]` | Resume CloudTrail/SSM collection with an existing AWS login; optional gzip output |
| `kamotrace trailcheck [--regions all] [--json PATH\|-] [--max-items N] [--max-s3-calls N] [--probe-buckets]` | [Read-only audit](#cloudtrail-trail-check) of trails, logging/delivery state, S3 destinations and observed log dates |
| `kamotrace get-suzaku [--version X.Y.Z]` | Download and verify the official Suzaku 3.x release for this platform |
| `kamotrace suzaku --database DB (--source FILE [--suzaku EXE] \| --timeline FILE)` | Run or import Suzaku detections into `<database>.detections.duckdb` |
| `kamotrace get-dbip [--dest FOLDER]` | Download and verify the free DB-IP Lite City and ASN databases (CC BY 4.0, no account) |
| `kamotrace enrich --database DB (--geolite2 FOLDER \| --jsonl FILE)...` | Add offline IP enrichment into `<database>.enrichment.duckdb` |
| `kamotrace serve --database DB [options]` | Start the browser UI on `127.0.0.1` |
| `kamotrace mcp --url http://127.0.0.1:8765` | Stdio MCP adapter for agents, backed by a running `serve` |
| `kamotrace ssmcheck [--regions all] [--json FILE\|-] [--max-items 200]` | [Read-only report](#ssm-logging-check) of where SSM session and command output is logged |

`kamotrace <command> --help` lists every option. `python -m kamotrace` works too.

### `serve` options

| Option | Purpose | Default |
| --- | --- | --- |
| `--database PATH` | Imported evidence database (required) | — |
| `--enrichment PATH` | IP enrichment sidecar from `kamotrace enrich` | `<database stem>.enrichment.duckdb` if present; otherwise special-use addresses are classified and other countries show as unmapped |
| `--annotations PATH` | Notes and tags SQLite sidecar | `<database stem>.annotations.sqlite3` |
| `--detections PATH` | Suzaku detections sidecar | `<database stem>.detections.duckdb` if present |
| `--ssm-export PATH` | Consolidated SSM command/output JSON | None; optional |
| `--port NUMBER` | Local listening port | `8765` |
| `--mcp-transport http\|stdio` | Serve MCP at `/mcp`, or print local stdio adapter setup commands; also accepted by `auto` | `http` |
| `--bind ADDRESS` | Listening address; only for containers (see [Docker](#docker)) | `127.0.0.1` (`0.0.0.0` in the image) |

Paths are relative to your terminal's current folder unless absolute. Quote
paths containing spaces. The evidence database and any explicitly supplied
enrichment, detections or SSM input files must exist. The server creates the
annotations file if needed.

For example, load an SSM export alongside the evidence database:

```powershell
kamotrace serve --database "C:\evidence\case.duckdb" --ssm-export "C:\evidence\ssm_command_session_activity.enriched.json"
```

The server never calls external services. Detections and IP enrichment sidecars
beside the database are picked up automatically. Changing enrichment, detections
or the SSM export requires restarting the server.

Only code, synthetic tests and third-party browser assets belong in this
repository. Databases, `event_history*.json`, enrichment JSONL, `.mmdb` files and
the `data/` directory are gitignored; keep evidence outside the repository.

## Full-auto preparation

`kamotrace auto CASE_FOLDER` prepares a whole case with one command. It runs the
other commands' code in dependency order, printing `[N/7 stage]` progress to stderr:

| Stage | Default | Override or skip |
| --- | --- | --- |
| 1. `get-suzaku` | Newest Suzaku installed in the tools folder; otherwise download and verify the latest 3.x | `--suzaku EXE`, `--suzaku-version X.Y.Z` (that exact version, installed or downloaded), `--timeline FILE`, `--skip-suzaku` |
| 2. `get-dbip` | Newest complete DB-IP Lite folder in the tools folder; otherwise download and verify | `--geolite2 FOLDER` and/or `--jsonl FILE` (earlier wins), `--skip-enrich` |
| 3. `download` | `CASE_FOLDER/download`, all enabled regions, CloudTrail and SSM, maximum available history; with explicit dates, S3 only after every Region/day is verified | `--download-dir`, `--profile`, `--regions`, `--start`, `--end`, `--cloudtrail-source auto\|history`, `--services`, `--compress`, `--progress`, `--session-s3`, `--session-log-group`; `--source FILE...` or `--skip-download` to use existing data |
| 4. `import` | `CASE_FOLDER/case.duckdb` from `cloudtrail.json[.gz]` | `--database` |
| 5. `enrich` | `<database stem>.enrichment.duckdb` from DB-IP Lite | as stage 2 |
| 6. `suzaku` | `<database stem>.detections.duckdb`, running Suzaku on the imported CloudTrail file | `--rules`, `--min-level` |
| 7. `serve` | `127.0.0.1:8765`, with the downloaded SSM export | `--port`, `--ssm-export FILE` (with existing data), `--no-serve` |

The tools folder defaults to `$KAMOTRACE_TOOLS` or `~/.kamotrace/tools`
(`--tools`), so installed tools are shared between cases. Tools are set up
before collection, so a tool problem appears before a long download. Suzaku
and DB-IP Lite are still downloaded only from their official sources and
verified as described for [`get-suzaku`](#download-and-run-suzaku) and
[IP enrichment](#ip-enrichment). Credit DB-IP Lite data (CC BY 4.0).

AWS access uses your existing login, exactly as [`download`](../README.md#download-from-an-existing-aws-login)
does; there is no login prompt, so it is safe for unattended use with `--no-serve`
and `--progress log`. `--services` must include `cloudtrail`. Running Suzaku needs a
single CloudTrail file or folder; with several `--source` files, pass `--timeline`
or `--skip-suzaku`.

### Retry and recovery

If a stage fails or you press Ctrl+C, the command stops with a nonzero status
and names the stage. Fix the cause, such as an expired AWS login, and **rerun the same
command**. Each stage checks what already exists:

- **Tools** are reused only when complete: Suzaku installs are published
  atomically, and a DB-IP folder counts only once its download record lists
  both verified files.
- **Collection** resumes from the downloader's checkpoint. Its default end time
  is frozen at the first run, so later reruns finish the same snapshot instead
  of moving the range. A completed collection with the same options is reused
  without contacting AWS only while every export it lists is present (and S3
  objects still match their SHA-256). If one is missing, the downloader
  regenerates it from the checkpoint after checking your AWS login; with
  `--skip-download` the run refuses instead. Different options are refused; use
  a new case folder for a fresh snapshot.
- **Evidence** is imported only after the collection is marked complete. An existing
  database is reused only if its recorded source files and SHA-256 hashes match
  the current inputs; otherwise the run stops and the database is never overwritten.
  Every database and sidecar is built in a new private folder beside it,
  `.<name>.<random>.staging`, and published by an atomic rename. A folder left
  by a killed run is removed on the next run, but only if it is positively
  KamoTrace's: it has the staging marker for that output, holds only regular
  staging files and contains no input. Anything else, including files named
  like an old `case.duckdb.building`, is left alone. `auto` refuses, before
  writing anything, any input, download folder or tools folder inside a folder
  named `.<name>.staging`, since a later stage could remove it.
- **Enrichment and detections** are derived sidecars, written atomically.
  They are reused only if they are bound to this evidence database. Enrichment
  must also have the same source files and hashes. Detections must have the same
  CloudTrail input and the same Suzaku executable, rules, config and
  `--min-level` (or the same `--timeline` hash). Otherwise they are rebuilt.
  Rules updated in place in Suzaku's own `rules` folder count as a change.
  To force a rebuild anyway, pass `--rebuild-sidecars`.
  A file at a sidecar path that is not that kind of KamoTrace sidecar is never
  replaced, and no output may be one of the inputs: move it or pick another `--database`.
  Each output is checked again just before publication; without `--replace`
  publication never overwrites a file that appeared meanwhile.
- One process at a time writes each output: `auto`, `import`, `enrich` and
  `suzaku` lock every path they publish with `<output stem>.lock` beside it
  (`auto` locks the database and both sidecars). A second writer of the same
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
```

It uses your existing AWS login, as `download` does, and only calls Describe,
Get and List APIs. It changes nothing in AWS, and it lists log objects without
downloading them. The readable summary goes to stdout. `--json PATH` also
writes the full report to a new file; it refuses to overwrite an existing one.
`--json -` writes the JSON to stdout and moves the summary to stderr.

With `--start` and `--end` together, trailcheck additionally verifies each UTC
day in that inclusive range for every selected Region, using only the current
account's paths. `requested_range.locations` records each location's day results;
`requested_range.verified` is true only when every Region/day has a matching
nonempty log object. This is independent of unreadable bucket settings that may
make the overall audit partial. Verification samples at most 20 objects per day,
within the shared S3 call budget: an unverified day is not proof of absence.

Dated `auto` (both dates explicitly supplied) and `download --cloudtrail-source auto`
use this result to select S3; otherwise they retain Event History and warn about
its 90-day management-event retention. The audit is saved as `trailcheck.json`
in the collection directory, and the source choice is frozen for resume.
After the presence gate passes, every requested date at every discovered
current-account/Region root is fully listed, not just dates whose 20-object
sample verified. Failed or denied collection listings stop the run; they do
not silently remove a root from the collection. Existing history checkpoints
keep their original source, even when resuming a pre-S3 dated auto run with the
new default. Completed legacy cases still reuse without AWS calls.
`auto --cloudtrail-source history` disables discovery. Known destinations can
instead be collected directly with `download --cloudtrail-s3
s3://BUCKET/[prefix/]AWSLogs/[o-org/]ACCOUNT/CloudTrail/` and explicit dates.
The account must match the authenticated account. See the
[S3 download example and limitations](../README.md#download-from-an-existing-aws-login).
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
CloudTrail Lake, Event History and CloudWatch Logs contents are not checked.
Reports name accounts, buckets and trails: keep them private and out of Git.

## Docker

The image contains KamoTrace and all its Python dependencies. It does not
contain Suzaku (AGPL-3.0) or IP geolocation data: `get-suzaku` and `get-dbip`
download Suzaku and the free DB-IP Lite databases into a persistent `/tools`
volume, or you mount your own GeoLite2 folder. Build it from a checkout:

```powershell
docker build -t kamotrace C:\path\to\KamoTrace
```

Put the export and any optional JSONL or SSM files in a case folder and mount it
at `/case`. In these commands, `kamotrace` is the Docker image name. The image
already starts the KamoTrace command:

```powershell
docker run --rm -v C:\case:/case kamotrace import --source /case/event_history.json --database /case/case.duckdb
docker run --rm -v kamotrace-tools:/tools kamotrace get-suzaku
docker run --rm -v C:\case:/case -v kamotrace-tools:/tools kamotrace suzaku --database /case/case.duckdb --source /case/event_history.json
docker run --rm -v kamotrace-tools:/tools kamotrace get-dbip
docker run --rm -v C:\case:/case -v kamotrace-tools:/tools kamotrace enrich --database /case/case.duckdb --geolite2 /tools/dbip-lite-2026-10
docker run --rm --name kamotrace -p 127.0.0.1:8765:8765 -v C:\case:/case kamotrace serve --database /case/case.duckdb
```

Then open **http://127.0.0.1:8765**. Sidecars (notes/tags, detections,
enrichment) are written beside the database in the case folder, so stop the
container before backing it up. The evidence database is still opened read-only.

Inside the container the server must listen on all interfaces
(`KAMOTRACE_BIND=0.0.0.0`) so Docker can publish the port. **Always publish it
as `-p 127.0.0.1:PORT:PORT`**: there is no authentication, and a plain
`-p 8765:8765` exposes the evidence to your network. The Host/Origin checks stay
on, which means the host and container port must be the same; for another port
use `--port 8766 -p 127.0.0.1:8766:8766`. Other containers on the same Docker
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

## Suzaku detections

[Suzaku](https://yamato-security.github.io/suzaku/) (Yamato Security) is a
Sigma-based threat-hunting and timeline tool for cloud logs. KamoTrace does not
bundle it (Suzaku is AGPL-3.0). Supported input is Suzaku 3.x `aws-ct-timeline`
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
kamotrace suzaku --database C:\evidence\case.duckdb --source C:\evidence\event_history.json
```

Without `--suzaku`, `kamotrace suzaku` runs the most recent version installed
by `get-suzaku`. Add `--min-level low` to set a minimum severity.
The checksum guards against a corrupted or altered download, not
against a compromised release. Suzaku's licence and source are at its
repository. Rerun `get-suzaku` to update; each version keeps its own folder.

### Use an existing Suzaku installation or timeline

To use your own Suzaku binary and rules:

```powershell
kamotrace suzaku --database C:\evidence\case.duckdb --suzaku C:\tools\suzaku\suzaku-3.0.0-win-x64.exe --source C:\evidence\event_history.json --rules C:\tools\suzaku\rules
```

or import a timeline you already produced with
`suzaku aws-ct-timeline -f event_history.json -o timeline -t duckdb` (without `-l`):

```powershell
kamotrace suzaku --database C:\evidence\case.duckdb --timeline C:\evidence\timeline.duckdb
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
- Output goes to a separate `<database stem>.detections.duckdb`. The evidence
  database is attached read-only and never modified. An existing sidecar is
  only replaced with `--replace`.
- The sidecar records provenance: Suzaku version, command line, rules revision
  and count, timeline SHA-256, evidence source SHA-256 and record count, whether
  `--source` matches the imported file, and linked/unmatched/ambiguous counts.
  `serve` refuses a sidecar built for a different evidence database.

### Review detections in the browser

In the browser, the expanded sidebar gains a **Detections** tab listing each
rule, most severe first, with its severity letter (I/L/M/H/C), ATT&CK tags (on
hover) and linked event count. Click a rule to add it to the query as a
`Sigma: <rule>` scope; several rule scopes must all match, like tags. The grid's
**Sigma** column shows the most severe level and the match count on one line;
click it for the full rule list. The inspector lists an event's detections too.
A correlation rule appears on each of its member events. A note saved by an
agent with a minimum level reopens with a removable `Sigma ≥ <level>` scope.
Detections are automated leads: tag events or record a finding about what you observe.

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
kamotrace enrich --database C:\evidence\case.duckdb --geolite2 $HOME\.kamotrace\tools\dbip-lite-2026-10
kamotrace enrich --database C:\evidence\case.duckdb --jsonl C:\evidence\spur.jsonl --geolite2 C:\geoip --replace
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

### Browse event tags

The **Event tags** tab lists every tag, its colour and its event count across
the whole database, not just the current query.

- Select a tag name to add it to the query. Select it again to remove it.
- If you select several tags, events must have all of them to match. Each active
  tag also appears as a removable chip above the grid.
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
  `<evidence-stem>.annotations.sqlite3` beside the DuckDB file. Use `--annotations`
  to override its location. Back it up along with the evidence (stop the server
  before copying it). Notes/tags are keyed by canonical record SHA-256, not row
  order; identical canonical records share reviews. The evidence remains read-only.
  The sidecar can contain sensitive investigator notes and is gitignored. Each
  new note also stores the browser query it was written from (as inert JSON that
  is re-validated when reopened); older sidecars gain that column automatically
  and their existing notes simply have no saved query.
- The first time a sidecar is opened, it records which evidence database it
  belongs to (the import's source hash and record count), older sidecars
  included. Opening it with a different database is refused, so one case's
  notes can't be mixed into another's.

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
[`kamotrace download`](../README.md#download-from-an-existing-aws-login).
Its `ssm.json` can be passed directly to `--ssm-export`. Session records and
downloaded transcripts remain separate from the Run Command viewer.

Load the local consolidated SSM export, preferably the base64-enriched version:

```powershell
kamotrace serve --database C:\\evidence\\case.duckdb --ssm-export C:\evidence\ssm_command_session_activity.enriched.json
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
```

The text summary goes to stdout. `--json FILE` also writes the full report to a
**new** file and refuses to overwrite one; `--json -` prints the JSON to stdout
and sends the summary to stderr. Keep reports private: they name buckets, log
groups, KMS keys and the account ID. Caller ARNs and credentials are never reported.

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
  absent. A region without the preferences document has never saved
  Session Manager preferences, so shell sessions there are not logged.
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

```text
agent client -- HTTP --> /mcp ---------> loopback REST API
agent client -- stdio -> kamotrace mcp -> loopback REST API
browser tab --------------------------> loopback REST API
                                              |
                                        one shared Store
                                              |
                         evidence/detections DuckDB (read-only)
                         notes/tags SQLite sidecar (writable)
```

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

For a local subprocess connection, start `serve` (or `auto`) with
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

Tags and notes attach to `record_sha256`, the canonical SHA-256
of the original record (identical duplicate records share it, as in the browser).
`id` is the record's 1-based position in the imported export. It is stable for
that evidence database and is used to fetch raw detail. Write tools change only
the hashes passed to them, 1 to 5,000 per call; there is no "tag the whole
query" tool, so an agent must page through results and pass the events it means.
Note edits and deletes need the note's current `updated` value (returned by
`get_note`, `list_notes` and every note write). If the browser or another agent
changed the note since, the call fails without writing; re-read it and retry.

### Look up MCP tools

| Tool | What it does |
| --- | --- |
| `describe_schema` | Filter fields, operators, sort fields, page sizes, facet values, supported IANA timezones, time bounds and tags. Takes `timezone` (default `UTC`). Call first. |
| `search_events` | `query` (search, filters, all-of tags, note, SSM command, start/end) plus sort, page and size. Returns the full filtered total and one page with hashes, tags and note IDs. |
| `summarize_field` | Top/bottom five values, distinct count and total for a field across the whole filtered result. |
| `event_histogram` | Counts per `query.timezone`-aligned bucket (empty buckets included, at most 2,000), with epoch-millisecond boundaries. |
| `get_event` | Exact stored raw JSON by `id`, its `record_sha256`, a recomputed hash check, and linked SSM commands. |
| `list_tags` / `tag_events` / `untag_events` | Tags with event counts; add or remove one tag on explicit hashes. Adding is additive and keeps an existing tag's colour (new tags default to the browser's colour). |
| `list_notes` / `get_note` | Notes (searchable), with linked event counts and the query they were written from; one note plus a page of its linked events. `get_note` takes `timezone` (default `UTC`) for those events. |
| `create_note` / `edit_note` / `delete_note` | Markdown notes (sanitised when the browser renders them). `create_note` can record the agent's query so **Reopen query** works in the browser. |
| `link_note_events` / `unlink_note_events` | Add or remove linked events; a note keeps at least one. |
| `list_detections` | Imported Suzaku rules (severity, ATT&CK tags, linked event counts) and the import's provenance. Takes no arguments; to search a rule's events use `query.rules` (all must match) or `query.min_level` in `search_events`, `summarize_field` or `event_histogram`. |
| `search_ssm_commands` / `get_ssm_command` / `get_ssm_event` | SSM commands from the JSON-backed export, each system/plugin output kept separate, linked CloudTrail events by exact account/region/command ID. |

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
| CloudTrail events and provenance | Imported DuckDB file | No; opened read-only |
| Annotations, event links and coloured tags | `<evidence-stem>.annotations.sqlite3` (or `--annotations`) | Yes (browser and MCP agents, through the same server) |
| Suzaku detections and their provenance | `<evidence-stem>.detections.duckdb` (or `--detections`), written by `kamotrace suzaku` | No; read-only, rebuilt from Suzaku output |
| SSM commands, outputs and enrichment | Original JSON export, loaded into memory | No; **not imported into persistent DuckDB tables** |
| IP enrichment and its provenance | `<evidence-stem>.enrichment.duckdb` (or `--enrichment`), written by `kamotrace enrich` | No; read-only, rebuilt from DB-IP/GeoLite2 `.mmdb` and/or JSONL; no online lookups |
| SSM-to-CloudTrail query links | Temporary DuckDB table | Memory only; rebuilt on startup |

Stop the server before backing up the annotation sidecar. Keep it with the exact
evidence database it describes, plus the source exports and enrichment cache.
The app does not collect AWS data or refresh exports: replace/update local files
and restart to reload them. It does not fetch output URLs or run shell commands.

## Troubleshooting and limitations

Known bugs and open limitations, with workarounds, are tracked in
[known limitations](BUGS.md).

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
Review screenshots and exports before sharing them. Run the
[development checks](#verification) before changing or distributing the app.

## Open-source components

KamoTrace is released under the [MIT licence](../LICENSE). Suzaku is a separate,
AGPL-3.0 tool that you install yourself; KamoTrace only runs it or reads its output.

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

## Verification

### Read CI results

GitHub Actions runs the HTTP/MCP contract suite on Python 3.14 (matching the
Dockerfile) for pushes and pull requests, plus JavaScript syntax, package-build
and Docker image-build checks. Jobs use the pinned Ubuntu 24.04 runner.
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
```

Only the optional JavaScript syntax check needs Node. There is no Node build.
The unit tests never download Suzaku or DB-IP; check `get-suzaku`, `get-dbip`
and a real Suzaku run in the container by hand, on synthetic data.

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
DuckDB schema Suzaku 3.0.0 writes. Full-auto tests run every stage on stubbed AWS
and tool downloads: a target-only run that fails mid-collection, resumes with the
same frozen range, then reruns as a no-op; stage failures, refreshed sidecars,
refusal of different evidence and of concurrent runs.
They never modify the real CloudTrail evidence database. For contributor
architecture and evidence-handling rules, see [AGENTS.md](../AGENTS.md).
