# Data preparation reference

For the shortest path from AWS login to an AI-assisted investigation,
[start with the README](../README.md#get-started). This reference covers auto
options, collection limits and the individual preparation steps.

## Fresh acquisition-unit cases

The explicit `--case` path separates raw admission, preparation and viewing. It does not migrate or overwrite older databases, Findings or sidecars. Choose a new manifest path and re-ingest from original exports. Do not pass an individual raw unit to `serve --database`.

```powershell
kamotrace import --case C:\case\case.json --unit aws-acquisition-1 --source C:\exports\cloudtrail.json
kamotrace import-other --case C:\case\case.json --unit generic-acquisition-1 --source C:\exports\events.jsonl --origin "Application export"
kamotrace import-uac --case C:\case\case.json --unit host-acquisition-1 --source C:\exports\completed-parse-only
kamotrace prepare --case C:\case\case.json --unit aws-acquisition-1 --unit generic-acquisition-1 --unit host-acquisition-1
kamotrace serve --case C:\case\case.json
```

Each caller-chosen unit key identifies one immutable acquisition. A retry with the same key and identical source paths, hashes and options reuses its raw artifact. Changed inputs require a new key. A deliberately new acquisition keeps duplicate occurrences even if its bytes match an older acquisition. CloudTrail/generic content duplicates share content-based reviews; TraceQuarry review identities remain manifest-and-line occurrences. Provider event IDs are separate from the numeric browse ID.

`prepare --unit KEY` prepares the whole raw unit by default. For one selected unit, repeat `--range START END` to select sorted, disjoint, nonadjacent half-open intervals on persisted `source_record` IDs. IDs may have gaps: counts are actual occurrences, not interval lengths. An explicit partial preparation replaces the selected output; it does not union with the previous scope. `--rebuild` publishes a new output for an already selected scope when transformation/engine compatibility changes or a derived file is damaged. Old published files are retained.

Serving without `--unit` selects all registered units and fails if any lacks compatible preparation. Repeat `serve --unit KEY` to deliberately open a prepared subset. The browser, REST metadata and MCP `describe_schema` disclose the same pinned coverage, partial preparation and excluded units. Unprepared is not searched, not evidence of no activity. Reopen the viewer to activate later preparation.

The offline convenience path uses the same admission and preparation owners:

```powershell
kamotrace auto --case C:\case\case.json --unit eks-acquisition-1 --kind eks --source C:\exports\completed-eks --no-serve
kamotrace guardduty --case C:\case\case.json --snapshot-unit alerts-acquisition-1 --findings C:\exports\guardduty.json
kamotrace enrich --case C:\case\case.json --jsonl C:\lookups\provider.jsonl
kamotrace suzaku --case C:\case\case.json --timeline C:\exports\timeline.duckdb
```

`auto --case` accepts `cloudtrail`, `generic` (with `--origin`), `uac` or `eks`; it performs no AWS collection or online tool installation. Optional `--guardduty-findings` plus `--snapshot-unit` admits/prepares snapshots before optional `--jsonl`/`--geolite2` enrichment and `--timeline` linking. Complete AWS/EKS collection separately with the existing collector. SSM command/output remains JSON-backed; pass `serve --ssm-export` or `auto --case --ssm-export` for exact command links.

Sidecar producers accept repeatable `--unit` selections matching the viewer. A sidecar bound to a different prepared scope fails closed; regenerate it rather than adopting legacy links. GuardDuty snapshots are allocated ordinary IDs as raw units and prepared explicitly, not appended with count-derived offsets. Prepare all intended snapshot units before generating other sidecars, since adding snapshots changes the selected coverage identity. Findings/manual events bind to the stable case UUID, independent of selection changes; saved Finding queries additionally bind to their original prepared selection and refuse silent reopening on a different one.

One case writer holds the existing fail-fast lock. ID blocks are persisted before use; interrupted builds burn reservations. Artifacts are validated, closed and published before their manifest reference. Failed replacements leave the old selected output intact. Published-but-unregistered artifacts are retained and never adopted merely because they exist; inspect the stopped command's output and case directory. Retrying restarts the unfinished unit/scope from private staging, not a mid-unit checkpoint. Do not delete evidence or reset the high-water counter to reclaim gaps.

Manifest/artifact publication fsyncs files and, on POSIX, their parent directories. Windows lacks Python directory fsync; atomic replacement is not a universal filesystem/power-loss guarantee. Qualification covers process interruption and injected I/O failures. Cold startup still hashes evidence and validates prepared fields; bounded Python batches do not bound total DuckDB/native RSS, spill, validation or checkpoint work.

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

#### Offline admission and preparation with auto

After collecting exports separately, `auto` admits and prepares one named
acquisition, then starts the viewer unless `--no-serve` is supplied:

```powershell
kamotrace auto --case C:\cases\example\case.json --unit cloudtrail-1 --kind cloudtrail --source C:\exports\cloudtrail.json --no-serve
kamotrace serve --case C:\cases\example\case.json
```

It does not collect AWS data or install tools. Supply completed lookup files or
a Suzaku timeline explicitly when needed. See [full-auto preparation](user-guide.md#full-auto-preparation)
for supported options and retry rules, and the standalone collection steps below
for AWS permissions, coverage and checkpoint behavior.

#### AWS-only EKS context and existing logs

EKS is opt-in and never connects to a Kubernetes API endpoint, node or pod.
`kamotrace eks` collects current cluster configuration (including Auto Mode
compute settings), access entries/associated policies, Pod Identity associations,
managed nodegroups, Fargate profiles, add-ons and identity-provider configurations.
These are collection-time observations, not incident-time state, effective access
or an enumeration of Kubernetes workloads/RBAC/aws-auth. Log-group retention,
storage class, KMS metadata and stream metadata are also retained. Group discovery
is independent of current clusters, so conventional groups for deleted clusters
can still be read.

```powershell
# Current context only; no log bodies:
kamotrace eks --output C:\cases\example\eks-context --regions ap-southeast-3
# Existing conventional /aws/eks/*/cluster logs, start inclusive / end EXCLUSIVE:
kamotrace eks --output C:\cases\example\eks --regions ap-southeast-3 --start 2026-10-01T00:00:00Z --end 2026-10-02T00:00:00Z
# An explicitly named existing workload group can be added with:
# --log-group ap-southeast-3:/aws/containerinsights/example/application
# Verified offline admission and preparation, no AWS calls:
kamotrace auto --case C:\cases\example\case.json --unit eks-1 --kind eks --source C:\cases\example\eks --no-serve
kamotrace serve --case C:\cases\example\case.json --eks-export C:\cases\example\eks
```

`serve --eks-export FOLDER` (also accepted by offline `auto`) supplies the verified export to
the existing AWS inventory and map. For startup, this flag
adds current EKS context, alongside optional `--inventory-export NETWORK_FOLDER`.
The context overlay is offline and read-only; neither source snapshot is rewritten.
Clusters, managed node groups, Fargate profiles and add-ons are map resources,
linked by exact account/region/cluster configuration. Cluster details retain
access-entry, access-policy, Pod Identity and other collected EKS observations.
ARNs, API operations, acquisition timestamps and source hashes remain inspectable.
Network and EKS collection times are shown separately; different accounts are
rejected. Without network inventory, EKS still displays, but VPC/subnet/SG details
remain uncollected. Public/private endpoint flags and configured CIDRs are shown
as configuration, never verified reachability or effective access. EKS resources
remain `Unknown` in the exposure assessment; links do not assert pod placement
or traffic. `--eks-export` alone does not attach timeline logs: retain the
prepared EKS acquisition for those. Context changes take effect only at startup.

Without both EKS bounds, only current metadata is collected. Existing workload
logs hosted by CloudWatch can be read without node access, but are not discovered
automatically: name them explicitly. All existing streams in a selected group are
eligible; no logging is enabled and no IAM changes are made. Only Standard groups
use `FilterLogEvents`; other storage classes are reported as unsupported, not empty.
No S3 archive bodies, Config history or CloudTrail are collected by this command;
existing CloudTrail collection remains separate. No future logging setting can
recreate absent historical logs.

Before reading log bodies, standalone `eks` warns on
stderr when selected groups in a region report at least **1 GB (1,000,000,000
bytes)** of combined CloudWatch `storedBytes`. This is current group-wide
storage, **not** a requested-window or download-size estimate. Missing size
metadata and undiscovered groups are not counted; no warning does not establish
that the window is small. The warning is retained in the export manifest and
coverage observation. Inventory-only runs do not warn. Collection continues
with the existing limits, without a confirmation prompt or extra AWS requests.
See AWS's [log-group metadata contract](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_LogGroup.html).

The initial global limits are 2,000 EKS/Logs API requests, 100,000 imported log
events and 100 MiB of log-message bytes (`--max-calls`, `--max-events`,
`--max-bytes`). Identity/region discovery and SDK
retries are additional requests. Raw acquisition can exceed the byte budget by
one CloudWatch page (up to 1 MiB), plus JSON/metadata overhead. Raw and imported
copies both use disk. Responses are streamed to files, not accumulated as a log
history in memory. Groups/regions are processed in sorted order: a global limit
can leave later sources unread. Adjust explicit limits in a **new export/target**
when broader acquisition is needed. Retrieval/list operations and any denied,
unsupported, token-loop or budget-limited results remain in `manifest.json` and
in a searchable coverage observation. An empty retrieved window does not prove
logging was enabled or delivery complete throughout it. Current storage figures
are group-wide, not estimates for the selected window. Read APIs may incur AWS
request/data charges; this collector does not issue Logs Insights queries or exports.

Exports contain hashed `raw.jsonl` API envelopes and `events.jsonl`, published
atomically to a new folder. Interruptions before publication discard private
staging; rerun to recollect, not to resume an expired page token. A published
partial-coverage snapshot is immutable. Offline `auto --kind eks --source FOLDER`
verifies the export and admits its events into a named unit in the one case JSON,
then explicitly prepares that unit. Browse IDs are persisted `source_record`
values, not offsets calculated from attachment order or row counts. Reservations
may leave gaps; never renumber evidence to close them. Existing viewers do not
reload new units live. Reopen with `serve --case` after preparing all intended
units, and regenerate sidecars whose prepared selection has changed. Keep the
case JSON and every referenced raw/prepared artifact together; no old database
or sidecar is discovered or adopted as a case acquisition.

The timeline calls these records **other** events with origin
`AWS EKS context and CloudWatch logs (AWS APIs only)`. Current API observations
use acquisition time; log rows use the CloudWatch event timestamp, retaining
event ID, stream, ingestion time and opaque original message. JSON inside a log
message stays text, preserving its numbers and audit stages without guessed
CloudTrail links. Check both the original message's timestamps/identity and the
envelope before drawing conclusions. Messages may contain sensitive workload data.

The inventory inspector's **Pod observations** search derives historical context
offline from attached EKS logs without rewriting their messages. It separates
authenticated `user.extra` caller pod credentials from named `objectRef` targets
and explicit structured workload metadata. Namespace-only list/watch records do
not enumerate named pods; SubjectAccessReview subject fields are not caller
identity. Retained coverage rows supply collection bounds and gaps. No manifest
means unknown coverage, not complete history. See the
[analyst workflow](user-guide.md#aws-inventory-and-map).

Required read actions are `sts:GetCallerIdentity`, `ec2:DescribeRegions` (only
with `all`), EKS `ListClusters`, `DescribeCluster`, `ListAccessEntries`,
`DescribeAccessEntry`, `ListAssociatedAccessPolicies`,
`ListPodIdentityAssociations`, `DescribePodIdentityAssociation`,
`ListNodegroups`, `DescribeNodegroup`, `ListFargateProfiles`,
`DescribeFargateProfile`, `ListAddons`, `DescribeAddon`,
`ListIdentityProviderConfigs`, `DescribeIdentityProviderConfig`, plus
`logs:DescribeLogGroups`, `logs:DescribeLogStreams`, and `logs:FilterLogEvents`
when reading bodies. The command does not request `eks:AccessKubernetesApi` or
log unmasking. Review any needed permissions with your AWS administrator; the
existing combined `kamotrace policy` template does not yet include this opt-in
collector. See the official [EKS authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_eks.html),
[EKS control-plane logging](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html),
[FilterLogEvents pagination and original messages](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_FilterLogEvents.html),
and [CloudWatch log classes](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch_Logs_Log_Classes.html).

#### Current AWS network inventory

```powershell
kamotrace inventory --profile investigation --regions all --output C:\cases\example\inventory
# Reanalyze an existing standalone or KamoTrace export, without any AWS calls:
kamotrace inventory --from-export C:\cases\example\inventory --output C:\cases\example\inventory-analysis
# Static inventory identity policy only: no AWS calls or snapshot required:
kamotrace inventory --emit-policy C:\cases\example\inventory-policy.json
# Or collect normally and also emit a policy outside the snapshot folder:
kamotrace inventory --profile investigation --output C:\cases\example\inventory-new --emit-policy C:\cases\example\inventory-new-policy.json
```

The collector uses read-only EC2, RDS, ELB/ELBv2 and assigned IAM instance-profile
lookups in one authenticated account. `--regions` defaults to all enabled regions.
`--emit-policy PATH|-` emits the static inventory action set: without `--output`
it makes no AWS calls; with `--output` it also performs the normal snapshot.
Use `--emit-policy -` for standalone policy JSON on stdout (summary/warnings go
to stderr). A policy file must be new and outside both the snapshot output and
any input export, preserving their manifests and evidence. The inventory policy
needs no S3 or KMS actions and does not test effective access. See the
[combined example identity policy](#aws-collection-iam-policy) for exact actions.
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

Each collected IAM user's `activity` includes current MFA device metadata
(`mfa_devices`, with `mfa_status` of `collected` or `unknown`) and login-profile
metadata (`login_profile` on success, with `login_profile_status` of `collected`,
`not_configured` or `unknown`). `GetLoginProfile` returning `NoSuchEntity` positively
means no login profile is configured; denied or other failed reads remain unknown
with explicit errors. Partial MFA pages are retained but their status is unknown.
These read-only calls return neither passwords nor MFA secrets. They describe
current posture, not whether MFA was used for a historical CloudTrail event.

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

Collect inventory separately, then pass `--inventory-export FOLDER` to
`serve --case` or offline `auto` to show that existing snapshot. Neither command
collects or refreshes inventory. Use a new output folder for a fresh configuration
snapshot; existing exports are never overwritten.

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
the trailcheck readability gate described in the [user guide](user-guide.md#cloudtrail-trail-check),
including its Describe/Get/List permissions.

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
other tools using the same account). S3 objects download with up to eight workers
per active listing (CloudTrail or SSM); regions/services still run independently.
Each listing page finishes before advancing to the next page, and overlapping
listings serialize access to the same object. Output order does not depend on
timing. The first failure, including a missing SSM, S3, CloudWatch Logs or KMS permission, stops
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
kamotrace import --source C:\cases\example\download\cloudtrail.json --case C:\cases\example\case.json --unit cloudtrail-1
kamotrace prepare --case C:\cases\example\case.json --unit cloudtrail-1
kamotrace serve --case C:\cases\example\case.json --ssm-export C:\cases\example\download\ssm.json
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

See the [collection IAM policy](#aws-collection-iam-policy) below for audit and
download permissions, including S3 destinations and KMS-encrypted objects.
Permission failures stop with a nonzero status and leave resumable checkpoints;
`manifest.json` is marked complete only after all selected collection succeeds.
Missing, expired or not-yet-delivered logs cannot be recovered by this command.

#### AWS collection IAM policy

Generate one policy for **CloudTrail, SSM and inventory** before granting access:

```powershell
# Offline template with explicit bucket/key placeholders; no AWS login needed:
kamotrace policy --output C:\cases\example\combined-policy.json
# Supply every CloudTrail/SSM bucket and current/historical S3 encryption key:
kamotrace policy --bucket example-trail-logs --bucket example-ssm-output --kms-key arn:aws:kms:us-east-1:123456789012:key/00000000-0000-0000-0000-000000000001 --output C:\cases\example\scoped-policy.json
# Validate the reviewed file with AWS IAM Access Analyzer (does not change it):
kamotrace policy --validate-file C:\cases\example\scoped-policy.json --profile investigation --region us-east-1
```

`policy` reuses the collectors' permission lists and deduplicates actions,
bucket names and key ARNs. Repeat `--bucket` and `--kms-key` as needed. It does
not discover destinations: get them from `trailcheck`/`ssmcheck` reports or the
resource owner, including historical destinations and keys. Missing resources
become `REPLACE_WITH_...` placeholders. Use `--no-kms` instead of `--kms-key`
only when **none** of the required S3 objects use SSE-KMS. `--partition` accepts
`aws` (default), `aws-us-gov` or `aws-cn`. Bucket inputs must be names, not URLs,
prefixes or wildcards; key inputs must be full key ARNs in that partition.
The policy grants bucket-wide object reads, and uses `Resource: "*"` for
metadata/CloudWatch reads; review and narrow those scopes where appropriate.

`--output` defaults to `-` (policy JSON on stdout, diagnostics on stderr).
Existing files are never overwritten. This command **does not attach a policy**
or change AWS resources: an administrator must review and grant it to the
investigation role/user through their normal IAM process.

For validation, either add `--validate` during generation or use
`--validate-file PATH` after editing the saved policy. File validation cannot
be combined with generation options and never rewrites the file. Unresolved
`REPLACE_WITH_` placeholders prevent AWS validation. Validation sends the policy
document to AWS IAM Access Analyzer using `--profile`/`--region` or the SDK's
normal configuration; the validating principal separately needs
`access-analyzer:ValidatePolicy` on `Resource: "*"`. This permission is not
included in the collection policy because collection does not use it.
All paginated findings (errors, security warnings, warnings and suggestions)
are printed to stderr. Exit status is **0** for successful generation, or
requested validation with no findings; **1** for validation findings or unresolved
placeholders; **2** for usage, file or AWS failures. A generated file remains
available even if validation subsequently fails. Broad portable permissions may
produce findings that need administrator review; they are not silently ignored.

Access Analyzer checks **policy syntax and security recommendations, not effective
access**. After the administrator grants the reviewed policy, use the same role
to rerun `trailcheck`, `ssmcheck` and `inventory`, then collect the selected logs
with `download`. Check reports for denied/unknown results: audit success
alone does not test S3 object reads or KMS decryption. A successful download tests
only the selected, available objects, not missing/expired logs or all possible
destinations. Cross-account policies, SCPs and other explicit denies still apply.

The following is an example **identity policy for the investigator's AWS role or
user**, covering `trailcheck`, `ssmcheck` and `download` (CloudTrail Event History,
S3 trail logs, SSM history/output and configured S3/CloudWatch transcripts), plus
the current network snapshot collected by standalone `inventory`.
It grants no AWS writes and is **not a service delivery policy**: it does not
enable logging or grant CloudTrail or the SSM Agent permission to deliver logs.
Omit the `ReadNetworkInventory` statement if not collecting inventory;
the other statements cover log collection.

Replace every uppercase placeholder before attaching the policy. Use `aws`,
`aws-us-gov` or `aws-cn` for `PARTITION` as appropriate. The arrays illustrate
multiple CloudTrail and SSM buckets and KMS keys: for a single bucket/key, keep
only its entry; for more, add entries. Repeat each bucket in both the bucket
and object resource arrays, and deduplicate shared destinations. These are
bucket names, not S3 URLs or prefixes. Use full KMS **key ARNs**, including the
key owner's account and Region, not aliases or bare key IDs.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AuditAndCollectServiceMetadata",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ec2:DescribeRegions",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:GetEventSelectors",
        "cloudtrail:GetInsightSelectors",
        "cloudtrail:LookupEvents",
        "ssm:GetDocument",
        "ssm:ListDocuments",
        "ssm:DescribeSessions",
        "ssm:ListCommands",
        "ssm:ListCommandInvocations",
        "ssm:GetCommandInvocation",
        "ssm:ListAssociations",
        "ssm:DescribeAssociation",
        "ssm:DescribeMaintenanceWindows",
        "ssm:DescribeMaintenanceWindowTasks",
        "ssm:GetMaintenanceWindowTask",
        "s3:ListAllMyBuckets",
        "logs:FilterLogEvents"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ReadNetworkInventory",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "ec2:DescribeRegions",
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeRouteTables",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeNetworkAcls",
        "ec2:GetManagedPrefixListEntries",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeRules",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "elasticloadbalancing:DescribeTags",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "elasticloadbalancing:DescribeTargetGroupAttributes",
        "iam:GetInstanceProfile",
        "iam:GetAccountAuthorizationDetails",
        "iam:ListPolicies",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:ListMFADevices",
        "iam:GetLoginProfile"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AuditAndListLogBuckets",
      "Effect": "Allow",
      "Action": [
        "s3:ListBucket",
        "s3:GetBucketLocation",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPolicy",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketObjectLockConfiguration",
        "s3:GetLifecycleConfiguration"
      ],
      "Resource": [
        "arn:PARTITION:s3:::CLOUDTRAIL_BUCKET_1",
        "arn:PARTITION:s3:::CLOUDTRAIL_BUCKET_2",
        "arn:PARTITION:s3:::SSM_OUTPUT_BUCKET_1",
        "arn:PARTITION:s3:::SSM_OUTPUT_BUCKET_2"
      ]
    },
    {
      "Sid": "ReadHistoricalLogObjects",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": [
        "arn:PARTITION:s3:::CLOUDTRAIL_BUCKET_1/*",
        "arn:PARTITION:s3:::CLOUDTRAIL_BUCKET_2/*",
        "arn:PARTITION:s3:::SSM_OUTPUT_BUCKET_1/*",
        "arn:PARTITION:s3:::SSM_OUTPUT_BUCKET_2/*"
      ]
    },
    {
      "Sid": "DecryptCollectedS3Objects",
      "Effect": "Allow",
      "Action": "kms:Decrypt",
      "Resource": [
        "arn:PARTITION:kms:REGION:KEY_OWNER_ACCOUNT_ID:key/CLOUDTRAIL_KEY_ID",
        "arn:PARTITION:kms:REGION:KEY_OWNER_ACCOUNT_ID:key/SSM_OUTPUT_KEY_ID",
        "arn:PARTITION:kms:REGION:KEY_OWNER_ACCOUNT_ID:key/HISTORICAL_KEY_ID"
      ]
    }
  ]
}
```

The service metadata statement uses `Resource: "*"` for this portable example;
where supported, an administrator can scope actions such as SSM document reads
and CloudWatch `logs:FilterLogEvents` to the relevant resource ARNs. Region
discovery in `download` and the checks needs `ec2:DescribeRegions` with
`--regions all`; online inventory also uses it to validate explicit Regions.
S3 SDK operations
do not always match IAM action names: `ListObjectsV2` needs `s3:ListBucket`,
`ListBuckets` needs `s3:ListAllMyBuckets`, and `GetBucketEncryption` needs
`s3:GetEncryptionConfiguration`.

Bucket-wide listing and object reads are intentional: historical logs may use
older prefixes, account paths or output layouts. In shared or organization
buckets, this can authorize reads beyond the investigated account. Review that
scope with the owner; narrow it only if you know all required historical paths.
`--probe-buckets` additionally needs listing access to other buckets it probes;
add those bucket ARNs if they are outside the example's destinations.

For **SSE-KMS S3 objects**, `s3:GetObject` alone is insufficient: the collector
also needs `kms:Decrypt` on every key used by the selected objects, and the key
policy or grant must permit that use. Today's trail key or bucket default is
not an inventory of historical object keys. Changed destinations, old keys and
unreadable encryption settings may leave required keys unknown; obtain their
full ARNs from the bucket/key owner and retain access to old keys. A Session
Manager `kmsKeyId` can describe session encryption, not the S3 object's SSE-KMS
key; do not treat it as proof of which object key to authorize. CloudWatch Logs
retrieval uses `logs:FilterLogEvents`; its at-rest KMS delivery configuration is
separate from the collector's S3 decrypt permission.

For cross-account buckets, the bucket owner must also authorize the collecting
principal through an appropriate bucket policy; attaching this identity policy
does not change the bucket policy or make owner-only settings readable. For
cross-account KMS use, the key owner's key policy/grant and the collecting
principal's identity policy must both allow decryption. Explicit denies in
identity/resource policies, AWS Organizations SCPs, permissions boundaries and
session policies can still block access. These example allows do not override
those controls or establish effective access.

##### Generate a policy from an audit

Both checks accept `--emit-policy PATH|-`. They run their **normal audit first**,
then emit a standalone IAM identity policy, separate from the JSON report:

```powershell
kamotrace trailcheck --profile investigation --json C:\cases\example\trailcheck.json --emit-policy C:\cases\example\trail-policy.json
kamotrace ssmcheck --profile investigation --json C:\cases\example\ssmcheck.json --emit-policy C:\cases\example\ssm-policy.json
# Send only the policy JSON to stdout; summary and warnings go to stderr:
kamotrace trailcheck --profile investigation --json C:\cases\example\trailcheck-stdout.json --emit-policy -
kamotrace ssmcheck --profile investigation --emit-policy -
```

File outputs are never overwritten: choose new report and policy paths, and
the two paths must differ. `--emit-policy -` moves the readable summary to
stderr and cannot be combined with `--json -` (both would need stdout).
Warnings go to stderr, not inside the standalone IAM policy.

Each check's policy covers audit/collection actions and scopes S3 access to its
discovered log buckets, with bucket-wide `/*` object reads to include history,
not just currently configured prefixes. For `trailcheck`, object reads cover
configured trail buckets and probed former buckets **confirmed to have CloudTrail
prefixes**; buckets with only other services' `AWSLogs/` paths are excluded.
Trail and SSM checks discover different destinations; neither alone inventories
both services. Review both reports and pass all required buckets/keys to
`kamotrace policy` for a combined policy, or use the example above. Unknown,
denied or truncated discovery keeps explicit placeholders and emits warnings;
replace unresolved bucket and KMS key placeholders, including historical keys,
before use. Even a complete audit cannot identify every historical destination
or encryption key; a default warning reminds you of these historical omissions.

Policy generation adds **no GetObject calls or permission simulation checks**.
An audit can return a partial report and still emit a useful policy draft, but
generation neither tests object reads/decryption nor assures effective access,
complete discovery, delivered logs or complete evidence. Review the report's
unknowns and limits as well as the policy. Neither command changes AWS IAM.

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
kamotrace import --source event_history.json --case case.json --unit cloudtrail-1
kamotrace prepare --case case.json --unit cloudtrail-1
```

The importer preserves the original records and JSON numeric precision. It
records the source file's SHA-256 hash and a canonical hash for each record.
Raw admission never overwrites evidence; preparation is a separate derived artifact.

#### Multiple files, gzip and stdin

Combine regional files into **one acquisition in one invocation**, without
manually merging JSON. Mix plain JSON and gzip inputs; `--source` is repeatable
and also accepts several paths after it:

```powershell
kamotrace import --source C:\cases\example\us-east-1.json --source C:\cases\example\ap-southeast-1.json.gz --case C:\cases\example\case.json --unit regional-1
```

For many S3 trail files, pass a **CloudTrail-only folder**. It is searched
recursively for `.json` and `.json.gz` files in sorted path order:

```powershell
kamotrace import --source C:\cases\example\trail-logs --case C:\cases\example\case.json --unit s3-trail-1
```

Fresh-case admission requires rereadable input files, not stdin. Save a stream
to a new evidence file first (POSIX shell):

```sh
gzip -dc cloudtrail.json.gz > retained-cloudtrail.json
kamotrace import --source retained-cloudtrail.json --case case.json --unit stream-1
```

Gzip files can also be admitted directly without decompression. Use
binary-preserving tooling when saving a stream; older PowerShell text pipelines may change bytes.
Concatenating several JSON documents is not a merge: pass them as separate sources.
Do not pass a whole downloader directory containing SSM/manifest/log JSON as a
CloudTrail folder; use its `cloudtrail.json` or `cloudtrail.json.gz` explicitly.

Imports never append to or replace existing evidence. To keep regions separate,
admit each file under its own unit key; to combine them, select the entire file
set for one acquisition. Explicitly prepare every intended unit before serving.
All records, including duplicates across
overlapping files, are preserved with their original `awsRegion`. Each event has
`source_file` and a one-based `source_ordinal`; `import_sources` and `build_info`
retain each source's byte hash, size, record count and global record range.
Single-source identity remains that source's SHA-256 (of compressed bytes for
gzip); multi-source identity hashes the ordered source hashes, not local paths.
Changing input order changes the acquisition identity. The case also binds
source paths, kind and options to its unit key. Browse IDs are persisted sparse
`source_record` values, never inferred from counts or attachment offsets.
Keep original inputs for reproducibility and Suzaku.

#### Other-event JSONL

Use `kamotrace import-other --source events.jsonl --case case.json --unit application-1 --origin "Where these events came from and how they were converted"` for arbitrary non-CloudTrail records, then `kamotrace prepare --case case.json --unit application-1`. Each line requires `date` (RFC 3339 with offset) and non-null `content`; optional `ip` and `identity` are strings. Nested content remains JSON with exact numbers. The command streams plain/gzip JSONL into a new immutable raw artifact, retaining file hashes and original line numbers; invalid records fail the whole import. Open with `kamotrace serve --case case.json`; a case need not contain CloudTrail. See [other events and editable manual key events](user-guide.md#other-events-and-manual-key-events) for the schema, provenance and backup rules. Investigator-entered manual events use a separate revisioned DuckDB and do not modify imported evidence.

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
kamotrace enrich --case case.json --geolite2 "$HOME\.kamotrace\tools\dbip-lite-2026-10"
```

Lookups run offline and the original evidence stays unchanged. IP geography is
not proof of a person's location. See [IP enrichment](user-guide.md#ip-enrichment)
for MaxMind GeoLite2, other providers and combining data sources.

For additional context, you can also [add Suzaku detections](user-guide.md#suzaku-detections)
based on Sigma rules. This optional step highlights activity to investigate;
detections are leads, not confirmed findings.

### 5. Open the browser

```powershell
kamotrace serve --case case.json
```

Open **http://127.0.0.1:8765** on the computer running KamoTrace. Leave the
server running while you investigate. It loads the IP enrichment and Suzaku
detection files beside `case.json` automatically when present and bound to the
same declared prepared selection. Startup only verifies and attaches; it never
prepares missing units or adopts old databases/sidecars.
Startup logs on stderr show timestamped loading stages and sidecar paths before
the server accepts requests, followed by the total startup time and ready URL.
MCP is served at **http://127.0.0.1:8765/mcp** on the same port by default.
Startup prints the URL and Amp/Claude Code setup commands. For a local subprocess
connection instead, use `--mcp-transport stdio`; startup then prints the stdio
registration commands. This option belongs to `serve`, not `auto`.
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
