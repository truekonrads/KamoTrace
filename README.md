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
`--start 2026-10-01 --end 2026-10-02` (both UTC dates included). With both dates,
auto prefers S3 trail logs only after verifying log presence for every requested
region/day; otherwise it uses Event History. Neither source guarantees complete coverage.

Already have a CloudTrail JSON export? Skip AWS collection:

```powershell
kamotrace auto C:\cases\offline --source C:\exports\cloudtrail.json
```

See [auto options and recovery](docs/user-guide.md#full-auto-preparation) or
the [manual preparation and collection reference](docs/preparation.md) for more control.

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
