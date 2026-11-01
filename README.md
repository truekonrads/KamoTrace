![KamoTrace: a duck follows its tracks through the waves into a storm cloud full of yokai](docs/kamotrace-banner.jpg)

# <img src="docs/kamotrace-icon.png" alt="" width="40" height="40"> KamoTrace

**From AWS login to an AI-assisted investigation in one command.**

KamoTrace collects CloudTrail and SSM activity, adds threat detections and IP
context, and serves a local investigation workspace. Use the browser yourself
or connect an AI assistant through MCP to investigate and record evidence-linked
findings. Original CloudTrail records stay read-only; findings and tags live
separately.

## Get started

You need Python 3.11+, [uv](https://docs.astral.sh/uv/getting-started/installation/)
and a local checkout of this repository. No database server, Docker or Node.js
build is required. These examples use PowerShell; replace the paths and AWS
profile with your own.

### 1. Run auto mode

Install KamoTrace, log in with your usual AWS tooling, then choose a new case folder:

```powershell
uv tool install C:\path\to\KamoTrace
aws sso login --profile investigation
kamotrace auto C:\cases\example --profile investigation
```

**Auto handles the preparation:** collect CloudTrail and SSM across enabled
regions, import the events, add Suzaku Sigma detections and offline DB-IP Lite
enrichment, collect a current network inventory, then start the browser UI and MCP.
Suzaku and DB-IP Lite are downloaded and verified if needed.

Open **http://127.0.0.1:8765** on the computer running KamoTrace. Leave the command
running while you investigate. Interrupted? **Rerun the same command** to resume;
use a new case folder for a fresh collection.

By default, collection requests the maximum available history: CloudTrail Event
History retains 90 days of management events; SSM command and terminated session
history generally retain 30 days. For a specific window, add
`--start 2026-10-01 --end 2026-10-02` (both UTC dates included). With `--start`,
auto prefers discovered S3 trail locations with readable listings for every requested
Region, allowing empty days and unused Regions; otherwise it uses Event History.
Empty days are reported, not treated as proof of missing logs or complete coverage.
Omit `--end` to collect through now
(the first run's start time, frozen on resume). Neither source guarantees complete coverage.

Already have a CloudTrail JSON export? Skip AWS collection:

```powershell
kamotrace auto C:\cases\offline --source C:\exports\cloudtrail.json
```

See [auto options and recovery](docs/user-guide.md#full-auto-preparation) or
the [manual preparation and collection reference](docs/preparation.md) for more control.

### GuardDuty alerts

Opt in to retained GuardDuty findings alongside the normal collection and enrichment:

```powershell
kamotrace auto C:\cases\example-gd --profile investigation --services cloudtrail ssm guardduty
```

Or download findings separately and enrich an existing evidence database:

```powershell
kamotrace download --dest C:\cases\gd-export --profile investigation --regions all --services guardduty
kamotrace guardduty --database C:\cases\example\case.duckdb --findings C:\cases\gd-export\guardduty.json
```

Existing AWS `GetFindings` JSON (`Findings` array), or a bare findings array, works
offline too. Auto accepts `--guardduty-findings FILE` with existing CloudTrail inputs.
The derived `<database>.guardduty.duckdb` sidecar is picked up by `serve` on restart
(or pass `--guardduty PATH`). Use `--replace` to rebuild a recognised GuardDuty
sidecar; original evidence is never modified. Auto reuses verified unchanged inputs.

The **Detections** tab and MCP `list_detections` / `query.rules` include explicitly
labelled **GuardDuty context (not exact)** leads. Context requires the finding's
account to match `userIdentity.accountId`, region and exact access key, within
`[EventFirstSeen, EventLastSeen)`. It does not establish that GuardDuty detected
that particular CloudTrail event. Missing keys/times, zero-length intervals and
other resource types remain unlinked, not guessed from IPs. All findings and their
raw JSON remain in the source and sidecar; linked finding JSON is also available
in event details and MCP `get_event`, separately from original CloudTrail JSON.

Collection uses only `guardduty:ListDetectors`, `guardduty:ListFindings` and
`guardduty:GetFindings` (plus the normal STS identity and, for `--regions all`,
EC2 region discovery permissions). It never enables or changes a detector.
Archived findings are included. `--start` / `--end` select **finding updatedAt**,
not the activity's event time; omit them for all retained findings up to collection
start. GuardDuty generally retains findings for 90 days. No enabled detector is
reported separately from an empty findings list; denied calls fail collection,
never masquerade as no findings. Downloads resume from checkpoints, not live sync;
use a new destination to refresh. `--compress` does not compress `guardduty.json`.
Treat exports as sensitive security data.

### Offline machine-role detection

Run the built-in Python/SQL rule independently of Suzaku and GuardDuty:

```powershell
kamotrace detect --database C:\cases\example\case.duckdb --network-context C:\cases\network-context.json
```

This writes `<database>.native.duckdb`; restart `serve` to load it alongside
Suzaku and GuardDuty leads. Use `--replace` to rebuild a recognised native sidecar.
The original evidence remains read-only. Each rule lives in its own Python module;
the initial rule is `kamotrace:ec2-credentials-unexpected-source`.

Supply offline network context with an explicit provenance description and a
start-inclusive/end-exclusive validity interval. For example (synthetic values):

```json
{
  "source": "Reviewed historical egress configuration for this investigation",
  "valid_from": "2026-10-01T00:00:00Z",
  "valid_until": "2026-10-02T00:00:00Z",
  "instances": [
    {
      "account": "123456789012",
      "instance_id": "i-0123456789abcdef0",
      "expected_egress": ["198.51.100.0/24"]
    }
  ]
}
```

Optionally add `aws_prefixes`, a nonempty array of IPv4/IPv6 CIDRs from a supplied
AWS address-range snapshot relevant to that interval. `instances` can be omitted
for an AWS-range-only assessment. Copy both `prefixes[].ip_prefix` and
`ipv6_prefixes[].ipv6_prefix` from an AWS snapshot; retain its date/source in
`source`. In AWS-range-only mode, a missing address family is unassessable, not
an outside-AWS match.
The tool does not fetch ranges, infer historical configuration from current
inventory, or verify the supplied snapshot's completeness. Do not use today's
ranges to assert historical ownership. Treat context and sidecars as sensitive.

The rule requires `AssumedRole` plus CloudTrail's explicit
`userIdentity.sessionContext.ec2RoleDelivery` value `1.0` or `2.0`; an `i-…`
session name alone is insufficient. It flags public source IPs outside the
instance's expected egress, or outside supplied AWS ranges when no expected-egress
exception applies. Expected non-AWS gateways are allowed. Successful and denied
calls are both assessed. Service-mediated calls, private/non-IP sources, missing
context and events outside the interval are counted separately. Unmarked role
events are counted but not guessed to be EC2 credentials. Without context the
rule reports **skipped**, distinct from a completed run with zero matches.

Matches are medium-severity **KamoTrace** leads, not GuardDuty findings or proof
of theft, non-AWS ownership, another account's ownership, or another physical
machine. Shared NATs/proxies can conceal misuse. The Detections tab and MCP
rule/severity filters include matches. MCP `list_detections` adds `native` run
metadata with rule version, context/hash and assessment counts; `get_event` adds
`native_detections` containing `rule_id` and `details_json` (reasons, source,
session/access key and API error), separate from original evidence JSON.

### Offline anomaly passes

Add three independent, explainable passes without fitting a model or supplying
training data:

```powershell
kamotrace detect --database C:\cases\example\case.duckdb --anomalies
```

Use `--replace` if the native sidecar already exists. This **rebuilds**, not
appends to, `<database>.native.duckdb`; include `--network-context` again to keep
the machine-role assessment in the same run. Restart `serve` afterwards.
The existing Detections tab and MCP rule filters include these low-severity
**KamoTrace statistical leads**, not GuardDuty/Suzaku rules or proof of compromise:

| Rule | What is unusual? | Default support and thresholds |
| --- | --- | --- |
| `kamotrace:conditional-rarity` | An identity's operation (`eventSource:eventName`), source ASN or country | At most 1% of its recorded events with that dimension known; at least 100 known events and 8 observed windows |
| `kamotrace:volume-spike` | Recorded event or failure counts, overall per identity and separately per operation, ASN and country | At least 8 other observed windows; count at least 10 events or 5 failures; robust score at least 6 and fold at least 3 |
| `kamotrace:breadth-spike` | Distinct operations, services, regions or resource ARNs within an identity's window | At least 8 other observed windows; at least 5 distinct values; robust score at least 6 and fold at least 3 |

Each rule has its own Python module in `src/kamotrace/rules/`. DuckDB supplies
exact counts; Python computes median/MAD statistics. Window scores are
`(observed - reference median) / max(1, 1.4826 × reference MAD)`;
fold is `observed / max(1, reference median)`. Both thresholds and the minimum
count must pass. Failure spikes count events with an API error, **not failure
rates**; their leads attach only to failed calls. Breadth leads describe group
activity, not the security meaning of an individual API call. Resource breadth
reads every `resources[].ARN`, not resource names guessed from parameters.

Windows default to five UTC minutes, start-inclusive/end-exclusive;
`--bucket-minutes 1` (or another integer from 1 to 1440) changes that size.
These are **retrospective** comparisons with other observations in the same
case, including later activity, not chronological alerts. The scored window is
left out of its spike baseline. Rarity is an empirical frequency over the case,
including the rare events themselves, reported as frequency and `rarity_bits`.
The three signals are not summed into a probability or a combined risk score.

Safeguards and limitations:

- Group by identity account, identity type and assumed-role session issuer ARN;
  otherwise use the recorded ARN, principal ID or username. Sessions/access keys
  stay in the raw records. Without an issuer ARN, role sessions are not guessed
  to belong together. Unknown identities and invalid timestamps are counted and
  excluded, not pooled into a fabricated identity.
- Deduplicate by canonical record SHA-256 before counting. Statistical leads
  attach to the first source-record representative; all evidence copies remain
  unchanged. Omit the first and last observed bucket per identity account because
  collection may cover only part of those buckets.
- Never fill silent time gaps with zero activity. A missing operation/ASN/country
  counts as zero only in an otherwise observed window for that identity with
  that dimension known. Resource breadth uses only windows with recorded resource
  ARNs. Observed activity still does **not** establish complete log collection.
- Reuse `<database>.enrichment.duckdb` if present, or supply `--enrichment FILE`.
  Its evidence identity is validated and its provenance/hash recorded. Without
  enrichment, operation/volume/breadth analyses still run; unknown ASN/country
  and special-address country labels are excluded. No online lookups occur.
  ASN and country often describe the same change; they are correlated context,
  not independent corroboration.
- Sparse history is insufficient evidence of normality. Inspect
  `list_detections.native.rules[].assessment` support/skipped-candidate counts
  and `native.analysis` exclusions, bucket settings and enrichment provenance.
  Sustained unusual activity can become common within this dataset; deployments,
  automation and incomplete collection can also produce leads. No detection
  accuracy or statistical significance is claimed.

Use `search_events(query={"rules": ["kamotrace:volume-spike"]})`, then
`get_event(id=...)`. Each `native_detections[].details_json` includes separate
signals with identity, dimension, observed counts, reference counts/median/MAD,
score, window boundaries and thresholds. Check those explanations and the raw
events before recording a finding. Older native sidecars require a rebuild with
`kamotrace detect ... --replace`; original evidence is never migrated or changed.

### 2. Connect your AI assistant

Auto serves MCP at **http://127.0.0.1:8765/mcp** alongside the browser. Keep it
running and register the connection with your assistant:

```powershell
# Amp
amp mcp add kamotrace http://127.0.0.1:8765/mcp
# Or Claude Code
claude mcp add --transport http kamotrace http://127.0.0.1:8765/mcp
```

[Install the investigation skill](docs/user-guide.md#agent-skill) to give your
assistant KamoTrace's investigation workflow and evidence-handling rules.
[Other clients and stdio setup](docs/user-guide.md#connect-your-client) are also supported.

### 3. Start an investigation

Try one of these prompts in your connected assistant:

> Investigate critical and high-severity alerts. Follow the related activity,
> tag relevant events and save evidence-linked findings. Separate confirmed
> observations from hypotheses.

> Use the event histogram to identify elevated operation counts. Compare spikes
> with surrounding activity, identify the operations and identities driving them,
> and investigate whether they look suspicious. Save your findings.

> Investigate SSM sessions for suspicious access. Correlate sessions with
> CloudTrail activity and inspect available command output. Record supporting
> evidence and flag missing logs rather than assuming no activity occurred.

Review the assistant's **Findings** and event tags in the browser. Detections
are leads, not proof; session transcripts must already have been logged and are
not displayed in the command viewer. See [SSM logging and collection](docs/preparation.md#download-from-an-existing-aws-login).

![Synthetic MCP-assisted investigation with tagged events and AI-written findings](docs/kamotrace-investigation.png)

[Follow the worked investigation](docs/user-guide.md#end-to-end-example), or
[investigate manually](docs/user-guide.md#cloudtrail-workflow) using search,
filters, value counts and the timeline.

## Keep evidence safe

- **Keep access local.** The server has no authentication. Do not expose it to
  your network. For containers, follow the [Docker guide](docs/user-guide.md#docker).
- **Check your AI provider's data policy.** KamoTrace runs locally, but your
  assistant may send evidence to its provider. Review AI findings before relying on them.
- **Preserve and back up the case.** Keep original exports, the evidence database
  and its sidecars private and together. Run one server per annotations file;
  stop it before [backing up](docs/user-guide.md#storage-and-backups).
- **Know the limits.** Missing logs do not prove no activity. IP geography is not
  proof of a person's location. Network inventory is current configuration,
  not historical incident-time evidence.

## Further reading

- [User guide](docs/user-guide.md): browser controls, detections, enrichment, SSM and MCP tools.
- [Data preparation](docs/preparation.md): downloads, permissions, S3 trails, imports and inventory.
- [Troubleshooting](docs/user-guide.md#troubleshooting-and-limitations) and [known limitations](docs/BUGS.md).
- [Development checks](docs/user-guide.md#verification) and [contributor guidance](AGENTS.md).

## Licence and credits

KamoTrace uses the [MIT licence](LICENSE). Suzaku is a separate AGPL-3.0 tool;
it is not bundled. Geolocation data is not bundled either. If you use DB-IP Lite
in reports, credit [IP Geolocation by DB-IP](https://db-ip.com) under
[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
See [component licences](docs/user-guide.md#open-source-components).

*Kamo* (鴨) is Japanese for duck. KamoTrace follows the tracks (跡) through your
CloudTrail logs.
