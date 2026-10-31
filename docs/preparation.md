# Data preparation reference

For the shortest path from AWS login to an AI-assisted investigation,
[start with the README](../README.md#get-started). This reference covers auto
options, collection limits and the individual preparation steps.

## Prerequisites

You need:

- Python 3.11 or later
- [uv](https://docs.astral.sh/uv/getting-started/installation/)
- a local copy of this repository
- an AWS login for collection, or a CloudTrail JSON export with a top-level `Records` array

The commands below use PowerShell and example Windows paths. Replace the paths
with your own. For containers, follow the [Docker instructions](user-guide.md#docker).

### 1. Install KamoTrace

```powershell
uv tool install C:\path\to\KamoTrace
```

If you are working from the checkout without installing the command, use
`uv run kamotrace` instead of `kamotrace` in the steps below.

#### Full-auto: one command from AWS login to browser

After logging in with your normal AWS tooling, `kamotrace auto` runs steps 2–5
for you, in dependency order, and then opens the server:

```powershell
kamotrace auto C:\cases\example
```

It installs and verifies Suzaku and DB-IP Lite (unless already installed),
downloads CloudTrail and SSM from all enabled regions (maximum available history),
imports `case.duckdb`, adds IP enrichment and Suzaku detections, collects a current
network inventory in `TARGET/inventory`, and starts the
UI on http://127.0.0.1:8765. Every default can be overridden, for example
`--profile investigation --start 2026-10-01 --end 2026-10-02`, `--source FILE`
to skip AWS, `--skip-suzaku`, or `--no-serve` for unattended use. If anything
fails or you interrupt it, **rerun the same command**: completed work is kept,
including the collection's frozen time range. See
[full-auto preparation](user-guide.md#full-auto-preparation) for all
options and recovery rules.

With explicit `--start` **and** `--end`, auto first runs trailcheck and prefers
S3 only if it verifies a matching nonempty CloudTrail log object for **every
requested Region and UTC day**, for the authenticated account. Missing, denied
or budget-limited verification keeps Event History (90-day management-event
retention only); it does not claim that S3 logs are absent. Use
`--cloudtrail-source history` to disable this check. Without both dates, auto
keeps its existing Event History behavior. The source decision and discovered
locations are frozen in the checkpoint; the audit is saved as `download/trailcheck.json`.
Once the presence gate passes, collection fully lists every requested day at
every discovered current-account/Region root, including roots whose sample
found no matching object. A denied collection listing stops the run rather than
silently dropping that root. Existing history checkpoints, including those from
before S3 support, retain their original source on resume; use a new destination
to collect a different source.

#### Current AWS network inventory

```powershell
kamotrace inventory --profile investigation --regions all --output C:\cases\example\inventory
# Reanalyze an existing standalone or KamoTrace export, without any AWS calls:
kamotrace inventory --from-export C:\cases\example\inventory --output C:\cases\example\inventory-analysis
```

The collector uses read-only EC2, RDS, ELB/ELBv2 and assigned IAM instance-profile
lookups in one authenticated account. `--regions` defaults to all enabled regions.
It preserves API response pages under `raw/`, regional inputs under `regions/`,
collection identity/timestamps in `collection.json`, IAM lookup timestamps in
`iam.json`, and SHA-256/size provenance in `manifest.json`. Reports retain the
standalone export's `report.json` shape and CSV tables; the browser presentation
is provided by KamoTrace rather than a generated `network-map.html`.
`--collect-only` omits analysis; reanalyze into a **different** output folder later.
`--from-export` is entirely offline unless `--enrich-iam` explicitly opts into IAM
lookups (which must authenticate to the exported account). Original inputs are
copied byte-for-byte, not updated. Every output must be a new folder: it is privately
staged and published atomically while holding the shared writer lock.

This is **current configuration, not historical incident-time evidence**. Collection
is non-atomic across services/regions. Allowed/Restricted means exported SG, route
and ACL configuration permits a modeled path, not that a connection succeeds or a
service listens. Direct exposure is separate from exposure through load balancers.
Backend validation is intentionally limited (currently same-VPC IPv4 TCP NLB paths
with client IP preservation and no frontend SG); other modes and missing evidence
remain Unknown. Host firewalls, authentication, WAF, CloudFront, API Gateway and
Global Accelerator are not assessed. Full modeling limitations and API errors are
included in the report. Completion records mean collection finished, **not** that
every API call was authorized or successful. Exports contain sensitive infrastructure
metadata and are not encrypted.

Online `auto` collects this snapshot by default and passes it to `serve` using
`--inventory-export FOLDER`. `--skip-inventory` opts out. Offline `auto --source`
and `auto --skip-download` never collect inventory or make inventory AWS calls;
pass `--inventory-export FOLDER` to show an existing snapshot instead. Tool downloads
and IP enrichment retain their separate existing defaults. Auto reuses only a
completed, hash-verified inventory with matching requested regions/profile; it
does not refresh an existing snapshot or recheck its account through AWS on resume.
Use a new TARGET for a fresh configuration snapshot. An unknown, changed, partial
or differently scoped inventory folder is refused, never overwritten.

### 2. Get your CloudTrail export

In the AWS console:

1. Open **CloudTrail → Event history**.
2. Choose your time range.
3. Choose **Download events → Download as JSON**.

A download contains management events from one region, from the last 90 days,
with up to 200,000 events. Keep it on a private local disk: events can contain
credentials and personal information.

Alternatively, use the resumable CLI downloader below to combine regions.
The importer also accepts multiple regional exports, folders of S3 trail logs,
gzip files and stdin; see [importing multiple files or a stream](#multiple-files-gzip-and-stdin).

#### Download from an existing AWS login

Log in first using your normal AWS tooling (for example, `aws sso login --profile investigation`).
KamoTrace uses boto3's existing credential chain, optionally selected with `--profile`;
it does not perform an interactive login or save credentials. All AWS calls are read-only.
The bundled SDK dependency includes CRT support for credentials created by `aws login`.

```powershell
kamotrace download --profile investigation --dest C:\cases\example\download --regions all --start 2026-10-01 --end 2026-10-02
```

To download a known S3 trail instead of Event History, point at the
`CloudTrail/` root, **before** the Region/date directories (repeat
`--cloudtrail-s3` for multiple roots):

```powershell
kamotrace download --profile investigation --dest C:\cases\example\s3-download --regions ap-southeast-1 us-east-1 --start 2026-10-01 --end 2026-10-02 --services cloudtrail --cloudtrail-s3 s3://example-trail-logs/audit/AWSLogs/123456789012/CloudTrail/
```

Use your authenticated account ID in the path. Organization paths such as
`AWSLogs/o-example/123456789012/CloudTrail/` also work. Both dates are required.
This direct mode does not require trail discovery permissions; it needs
`s3:GetBucketLocation`, `s3:ListBucket`, `s3:GetObject` and, for KMS-encrypted
objects, `kms:Decrypt`. Alternatively `download --cloudtrail-source auto` uses
the same trailcheck gate as dated auto mode (including its Describe/Get/List permissions).

S3 collection lists all pages under the selected UTC delivery-date folders,
downloads only matching nonempty account/Region/date `.json.gz` log files,
and filters records by the inclusive event-time range. Original compressed
objects, ETags and SHA-256 hashes are retained under `logs/`; the importable
`cloudtrail.json` preserves numeric precision, removes identical records and
keeps differing records even when they share an event ID. Log objects are
parsed but not CloudTrail digest-validated. **Late deliveries into folders
outside the requested dates are not included**, and presence of a log object
does not establish complete delivery. No CloudTrail Lake, Insights or digest
objects are collected. Completed listings are snapshots, not refreshed on resume.

- `--regions all` selects enabled regions in the current account/partition
  (requires `ec2:DescribeRegions`). Or choose explicit regions, e.g.
  `--regions ap-southeast-1 us-east-1`. Set your AWS default region for the
  partition you use; if unset, the bootstrap region is `us-east-1`.
- Both endpoints are **inclusive**. Dates mean UTC: the example includes
  October 1 and 2 in full, through `2026-10-02T23:59:59.999999Z`.
  ISO timestamps must have `Z` or an offset, e.g. `2026-10-01T08:00:00+08:00`.
  This collection convention is separate from the viewer's end-exclusive filters.
- Omit `--start` and `--end` to download the maximum available history through
  collection start time. A warning is printed even with `--progress off`: CloudTrail
  Event History retains only 90 days; SSM command/terminated session history generally
  retains 30 days, though older active sessions may be available. Expired data cannot
  be recovered, and collection can be large and slow. Either endpoint can also be
  supplied alone: omitted start means all available history (CloudTrail queries the
  90 days ending at the end time), and omitted end means collection start time.
  The default end time is saved in the checkpoint and reused on resume, not advanced.
  In the manifest, `start: null` means no requested lower bound; service retention
  limits still apply.
- Both CloudTrail and SSM are selected by default. Use `--services cloudtrail`
  or `--services ssm` to collect only one. The range selects event time,
  command request time or session start time, not sessions merely overlapping it.
- Add `--compress` to gzip generated CloudTrail, SSM and CloudWatch JSON exports.
  Output names become `cloudtrail.json.gz`, `ssm.json.gz` and `logs/*.json.gz`;
  original S3 object bytes are preserved; the manifest and checkpoint are not compressed.
  Both `import` and `serve --ssm-export` read gzip directly.
- `--progress auto` (default) fills the terminal bar with 🦆 emojis and shows UTC timestamped
  tick logs when redirected. Force `bar`, `log` (batch/headless), or `off`.
  Progress goes to stderr; the bar measures completed region/service work, not
  a guessed event total. Page/cache counts and S3 transfer ticks show activity.
  Below the bar, each busy worker has its own line.
  The CloudTrail ETA is rough. AWS gives no page totals, so each region's remaining
  pages are estimated: a running daily batch is projected from how much of its day
  the newest-first events have covered, and unstarted days use the region's median
  finished day (checkpoint replays included). Time comes from that region's own pace
  of pages fetched from AWS, never replays, and the slowest region is reported.
  The bar shows `estimating` until every unfinished region has fetched 10 pages over
  10 seconds, or while a batch is already larger than usual but under 10% through its
  day. A busy hour later in a day can still exceed the estimate. SSM has no ETA
  (`SSM ETA unknown`). When CloudTrail finishes, the ETA becomes its elapsed time.
  CloudTrail page updates include the requested UTC range: each daily batch can
  contain multiple API pages of up to 50 events, not one date range per page.
  Set `$env:KAMOTRACE_NO_EMOJI = "1"` in PowerShell, or
  `KAMOTRACE_NO_EMOJI=1` in your shell environment, for an ASCII-only bar.
  Any nonempty value disables emoji; logs always use plain text.

Rerun the **same command and destination** after interruption or renewing your
login. SQLite checkpoints commit every API page and cursor, including empty
pages. CloudTrail is split into daily batches; expired cursors restart only
their batch and duplicate event IDs are removed within each region. Regions are
collected concurrently, and within each region CloudTrail and SSM run at the same
time (their API quotas are separate), so SSM history near its 30-day limit is not
left waiting behind a long CloudTrail download. Two daily CloudTrail batches per
region run at once; they share that region's pace of at most one LookupEvents call
start every 0.55 s (AWS allows two per second per account and region, shared with
other tools using the same account). Output order does not depend on timing. The
first failure, including a missing SSM, S3, CloudWatch Logs or KMS permission, stops
all workers after their in-flight call or S3 block and is reported. SDK retries
handle transient failures/throttling. Interrupted S3 objects restart, while
completed objects are reused only when both their saved ETag and local SHA-256
match. Conflicting ETags across listings stop collection without replacing the
collected bytes; use a new destination for a fresh snapshot. Older checkpoints
without ETag bindings re-download those objects using `IfMatch` before trusting them.
Resume refuses a different
account/partition, range, regions, services, compression or log locations. Use a new destination
for a fresh snapshot: completed requests are not refreshed, including active
commands/sessions or logs delivered later. Do not run two collectors in one directory.

The destination contains `cloudtrail.json` (one importable `Records` array:
original Event History JSON, or precision-preserving S3 records backed by original gzip objects), `ssm.json` (commands, per-system/plugin outputs,
active and historical session records), `logs/`, `manifest.json` (coverage and log
source/file mapping), and `checkpoint.sqlite`. Keep the whole directory private
and outside Git (or under ignored `data/`). Import and browse with:

```powershell
kamotrace import --source C:\cases\example\download\cloudtrail.json --database C:\cases\example\case.duckdb
kamotrace serve --database C:\cases\example\case.duckdb --ssm-export C:\cases\example\download\ssm.json
```

CloudTrail Event History provides available **management events from the last
90 days**, not data events, S3 trails or Lake. SSM Run Command and terminated
session history generally retain **30 days**. Commands include inline outputs
(which AWS may truncate) plus output from their configured S3/CloudWatch destinations.
For existing interactive session transcripts, add repeatable
`--session-s3 s3://BUCKET/PREFIX/` and/or `--session-log-group GROUP` options.
S3 objects must contain an exact selected session ID as a path component or
`SESSION-ID.log` filename; CloudWatch streams use the session ID prefix.
Only transcripts for sessions still returned by SSM are collected. Choose
prefixes/groups appropriate to the selected regions; custom layouts are not inferred.
Session transcripts are saved separately, **not displayed in the command viewer**.
Logging must already have been enabled; SSH/port-forwarding sessions have no
transcripts. Empty results do not prove no activity occurred.
To find the configured transcript and command output locations first, run the
read-only [`kamotrace ssmcheck`](user-guide.md#ssm-logging-check).

Permissions depend on collection: `sts:GetCallerIdentity`, `cloudtrail:LookupEvents`,
`ssm:ListCommands`, `ssm:ListCommandInvocations`, `ssm:GetCommandInvocation`,
`ssm:DescribeSessions`, plus `s3:ListBucket`/`s3:GetObject`,
`logs:FilterLogEvents` and `kms:Decrypt` where the log destinations require them.
Permission failures stop with a nonzero status and leave resumable checkpoints;
`manifest.json` is marked complete only after all selected collection succeeds.
Missing, expired or not-yet-delivered logs cannot be recovered by this command.

#### Check trail configuration and S3 log coverage

Event History covers only 90 days. Older events, data events and complete
records live in S3 trail logs, if a trail was configured. To see what exists
before you collect or import, run this read-only check:

```powershell
kamotrace trailcheck --profile investigation --json C:\cases\example\trailcheck.json
```

Add `--start 2026-10-01 --end 2026-10-02 --regions ap-southeast-1 us-east-1`
to verify every requested Region/day, not only the first and last observed days.
The JSON `requested_range.verified` reports this presence check independently
of the overall audit's `complete` flag; unreadable bucket settings can still
make the overall report partial.

The report shows each trail's Region scope, event selectors, logging and
delivery state, and its S3 bucket's restrictions: public access block, policy,
encryption, versioning and lifecycle. It also shows the year/month date
prefixes observed per account and Region in S3. Observed prefixes are not proof
of complete logs; denied checks are reported as unknown, not absent. Exit status
1 means a partial report. Details and options are in
[CloudTrail trail check](user-guide.md#cloudtrail-trail-check).

### 3. Import the events

Put `event_history.json` in a case folder, then run:

```powershell
Set-Location C:\cases\example
kamotrace import --source event_history.json --database case.duckdb
```

The importer preserves the original records and JSON numeric precision. It
records the source file's SHA-256 hash and a canonical hash for each record.
It refuses to overwrite an existing database.

#### Multiple files, gzip and stdin

Combine regional files into **one new database in one invocation**, without
manually merging JSON. Mix plain JSON and gzip inputs; `--source` is repeatable
and also accepts several paths after it:

```powershell
kamotrace import --source C:\cases\example\us-east-1.json --source C:\cases\example\ap-southeast-1.json.gz --database C:\cases\example\combined.duckdb
```

For many S3 trail files, pass a **CloudTrail-only folder**. It is searched
recursively for `.json` and `.json.gz` files in sorted path order:

```powershell
kamotrace import --source C:\cases\example\trail-logs --database C:\cases\example\combined.duckdb
```

Or pipe one complete `{"Records": [...]}` document into `--source -` (POSIX shell):

```sh
gzip -dc cloudtrail.json.gz | kamotrace import --source - --database case.duckdb
```

Stdin also accepts gzip bytes directly, so decompression is optional. Use a
binary-preserving pipe; older PowerShell text pipelines may change bytes.
Concatenating several JSON documents is not a merge: pass them as separate sources.
Do not pass a whole downloader directory containing SSM/manifest/log JSON as a
CloudTrail folder; use its `cloudtrail.json` or `cloudtrail.json.gz` explicitly.

Imports never append to or replace existing evidence. To keep regions separate,
import each file into its own database; to combine them, select the entire file
set when creating a new database. All records, including duplicates across
overlapping files, are preserved with their original `awsRegion`. Each event has
`source_file` and a one-based `source_ordinal`; `import_sources` and `build_info`
retain each source's byte hash, size, record count and global record range.
Single-source identity remains that source's SHA-256 (of compressed bytes for
gzip); multi-source identity hashes the ordered source hashes, not local paths.
Changing input order changes the identity because it changes global record IDs.
Stdin is spooled to private temporary disk for hashing and independent record
verification, then deleted. Keep your original inputs for reproducibility and
Suzaku; a stdin import cannot recreate the incoming original file for you.

### 4. Add GeoIP information

Enrich source IP addresses before investigating. Country, city and network
information can help you spot unusual activity. The free DB-IP Lite databases
need no account or licence key:

```powershell
kamotrace get-dbip
```

Use the folder printed by `get-dbip` in the next command. This example uses the
October 2026 release; replace the path with your downloaded folder:

```powershell
kamotrace enrich --database case.duckdb --geolite2 "$HOME\.kamotrace\tools\dbip-lite-2026-10"
```

Lookups run offline and the original evidence stays unchanged. IP geography is
not proof of a person's location. See [IP enrichment](user-guide.md#ip-enrichment)
for MaxMind GeoLite2, other providers and combining data sources.

For additional context, you can also [add Suzaku detections](user-guide.md#suzaku-detections)
based on Sigma rules. This optional step highlights activity to investigate;
detections are leads, not confirmed findings.

### 5. Open the browser

```powershell
kamotrace serve --database case.duckdb
```

Open **http://127.0.0.1:8765** on the computer running KamoTrace. Leave the
server running while you investigate. It loads the IP enrichment and Suzaku
detection files beside `case.duckdb` automatically when they are present.
Startup logs on stderr show timestamped loading stages and sidecar paths before
the server accepts requests, followed by the total startup time and ready URL.
MCP is served at **http://127.0.0.1:8765/mcp** on the same port by default.
Startup prints the URL and Amp/Claude Code setup commands. For a local subprocess
connection instead, use `--mcp-transport stdio`; startup then prints the stdio
registration commands. Both `serve` and `auto` accept this option.
If startup is slow, the last stage message identifies the work still in progress.

### 6. Find events and save findings

1. Choose a **Timezone** and time range. The default timezone is UTC.
2. Enter a search term or use **+ Filter**, then choose **Run**.
3. Select a row to inspect the original JSON and record hash.
4. Select event checkboxes and use **Add to finding** or **Tag events**.
5. Review findings and event tags in the left sidebar. Collapsed, it shows your
   tags as one-click filters; expand it with **›**.

Counts and charts cover all matching events, not just the rows loaded in the
grid. Time ranges include the start and exclude the end.

Read the [CloudTrail guide](user-guide.md#cloudtrail-workflow) for detailed
search, filter and timeline controls.

For AI-assisted investigation, return to the
[README quick start](../README.md#2-connect-your-ai-assistant) or read the
[MCP setup guide](user-guide.md#agent-access-mcp).
