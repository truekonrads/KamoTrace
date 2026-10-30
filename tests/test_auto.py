"""Full-auto CLI contracts: real stages on synthetic data, stubbed AWS and tool downloads (no network)."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch
import zipfile

from boto3.session import Session
from botocore.stub import Stubber
import duckdb

from kamotrace import get_dbip, get_suzaku
from kamotrace.cli import main
from kamotrace.importer import build as import_evidence, database_lock, write_lock
from kamotrace.suzaku import import_timeline

# Stands in for Suzaku 3.x: one high rule per record, written with the schema Suzaku 3.0.0 writes.
FAKE_SUZAKU = """#!{python}
import gzip, json, sys
from pathlib import Path
import duckdb
if Path(__file__).with_name("FAIL").exists():
    sys.exit("synthetic Suzaku failure")
args = sys.argv[1:]
data = Path(args[args.index("-f") + 1]).read_bytes()
records = json.loads(gzip.decompress(data) if data[:2] == b"\\x1f\\x8b" else data)["Records"]
if "-m" in args and args[args.index("-m") + 1] == "critical":
    records = []  # Its only rule is high
out = duckdb.connect(str(Path(args[args.index("-o") + 1]).with_suffix(".duckdb")))
out.execute(\"\"\"CREATE TYPE suzaku_level AS ENUM ('informational','low','medium','high','critical');
    CREATE TABLE timeline("Timestamp" TIMESTAMP, RuleTitle VARCHAR, "Level" suzaku_level, EventName VARCHAR,
        AwsRegion VARCHAR, EventID VARCHAR, RuleAuthor VARCHAR, Tactics VARCHAR[], TechniqueIDs VARCHAR[],
        OtherTags VARCHAR[], RuleID VARCHAR);
    CREATE TABLE suzaku_meta(schema_version INTEGER, suzaku_version VARCHAR, command VARCHAR,
        timestamp_tz VARCHAR, rules_version VARCHAR, rules_count BIGINT)\"\"\")
for r in records:
    out.execute("INSERT INTO timeline VALUES (?, 'Synthetic', 'high', ?, ?, ?, 'test', [], [], [], 'rule-auto')",
                [r["eventTime"].replace("T", " ").rstrip("Z"), r["eventName"], r["awsRegion"], r["eventID"]])
out.execute("INSERT INTO suzaku_meta VALUES (1, '3.0.0', 'aws-ct-timeline', 'UTC', 'synthetic', 1)")
out.close()
"""


def record(name, stamp, ip="192.0.2.10", region="us-east-1"):
    return {"eventID": name, "eventTime": stamp, "eventSource": "sts.amazonaws.com", "eventName": "GetCallerIdentity",
            "awsRegion": region, "sourceIPAddress": ip, "recipientAccountId": "123456789012",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123456789012:user/alice"}}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def mmdb(path, database_type, data):
    from mmdb_writer import MMDBWriter
    from netaddr import IPSet
    writer = MMDBWriter(4, database_type)
    writer.insert_network(IPSet(["192.0.2.0/24"]), data)
    writer.to_db_file(str(path))
    return path.read_bytes()


@unittest.skipIf(sys.platform == "win32", "the stand-in Suzaku is a POSIX script")
class AutoContract(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.root = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.tools = self.root / "tools"
        self.stack.enter_context(patch.dict(os.environ, {"KAMOTRACE_TOOLS": str(self.tools), "KAMOTRACE_BIND": ""}))
        os.environ.pop("KAMOTRACE_BIND")
        # The browser server is constructed for real (validating every sidecar), but never listens.
        self.http = self.stack.enter_context(patch("kamotrace.server.ThreadingHTTPServer"))

    def run_auto(self, *argv, status=0):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                result = main(["auto", *map(str, argv)])
            except SystemExit as exit:  # Usage errors, before any stage runs
                result = exit.code
        self.assertEqual(result, status, stderr.getvalue())
        return stdout.getvalue(), stderr.getvalue()

    def suzaku_archive(self):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as bundle:
            bundle.writestr(f"suzaku-3.0.0-{get_suzaku.platform_tag()}", FAKE_SUZAKU.format(python=sys.executable))
        return archive.getvalue()

    def fake_network(self):
        """Serve synthetic GitHub and DB-IP responses through the real verification code."""
        work = self.root / "network"
        work.mkdir()
        tag = get_suzaku.platform_tag()
        archive = self.suzaku_archive()
        city = mmdb(work / "city.mmdb", "DBIP-City-Lite", {"country": {"iso_code": "NL", "names": {"en": "Netherlands"}}})
        asn = mmdb(work / "asn.mmdb", "DBIP-ASN-Lite (compat=GeoLite2-ASN)", {"autonomous_system_number": 64500})
        responses = {
            get_suzaku.RELEASES + "?per_page=30": json.dumps([{"tag_name": "v3.0.0", "draft": False, "prerelease": False,
                "assets": [{"name": f"suzaku-3.0.0-{tag}.zip", "size": len(archive), "browser_download_url": "https://x.invalid/s.zip",
                            "digest": "sha256:" + hashlib.sha256(archive).hexdigest()}]}]).encode(),
            "https://x.invalid/s.zip": archive}
        for kind, data in (("city", city), ("asn", asn)):
            url = f"https://download.db-ip.com/free/dbip-{kind}-lite-2026-10.mmdb.gz"
            responses[get_dbip.PAGES[kind]] = (f"<dt>SHA1SUM</dt><dd>{hashlib.sha1(data).hexdigest()}</dd>"
                                               f"<a href='{url}'>MMDB</a>").encode()
            responses[url] = gzip.compress(data)
        self.requests = []

        def get(url):
            self.requests.append(url)
            return io.BytesIO(responses[url])
        self.stack.enter_context(patch("kamotrace.get_suzaku.get", get))
        self.stack.enter_context(patch("kamotrace.get_dbip.get", get))

    def test_target_only_run_fails_resumes_with_frozen_range_then_reuses_everything(self):
        self.fake_network()
        sdk = Session(aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name="us-east-1")
        clients = {name: sdk.client(name, region_name="us-east-1") for name in ("sts", "ec2", "cloudtrail", "ssm")}
        stubs = {name: self.stack.enter_context(Stubber(client)) for name, client in clients.items()}
        # CloudTrail and SSM run concurrently: the first run's planned CloudTrail failure waits until SSM
        # has finished, so FIFO stubs stay deterministic and the resume must reuse SSM's saved pages.
        ssm_done, gated = threading.Event(), [True]

        class Gate:
            def __init__(self, client):
                self.client = client

            def __getattr__(self, name):
                return getattr(self.client, name)

            def lookup_events(self, **request):
                if gated[0] and request["StartTime"] == batches[3][0]:
                    ssm_done.wait(10)
                return self.client.lookup_events(**request)

            def describe_sessions(self, **request):
                try:
                    return self.client.describe_sessions(**request)
                finally:
                    if request["State"] == "History":
                        ssm_done.set()
        gates = {name: Gate(clients[name]) for name in ("cloudtrail", "ssm")}
        session = Mock(region_name="us-east-1")
        session.client.side_effect = lambda service, region_name, **kw: gates.get(service, clients[service])
        self.stack.enter_context(patch("kamotrace.download.boto3.Session", return_value=session))
        self.stack.enter_context(patch("kamotrace.download.clock.sleep"))
        self.stack.enter_context(patch("kamotrace.download.WINDOW_WORKERS", 1))  # Stubber answers in FIFO order.
        end = datetime.fromisoformat("2026-10-30T06:00:00+00:00")
        now = [end]

        class ClockMeta(type):
            def __instancecheck__(cls, value):
                return isinstance(value, datetime)

        class Clock(datetime, metaclass=ClockMeta):
            @classmethod
            def now(cls, tz=None):
                return now[0]
        self.stack.enter_context(patch("kamotrace.download.datetime", Clock))

        def identity():
            stubs["sts"].add_response("get_caller_identity", {"Account": "123456789012", "UserId": "synthetic",
                                      "Arn": "arn:aws:sts::123456789012:assumed-role/reader/session"}, {})
        # Default maximum history: 90 daily CloudTrail batches ending at the first run's start time.
        batches = [(end - timedelta(days=90 - i), end - timedelta(days=89 - i)) for i in range(90)]
        events = {0: [record("earliest", "2026-08-01T06:00:00Z")], 89: [record("latest", "2026-10-30T05:59:59Z", "198.51.100.7")]}

        def lookup(index):
            stubs["cloudtrail"].add_response("lookup_events", {"Events": [
                {"EventId": e["eventID"], "EventTime": datetime.fromisoformat(e["eventTime"].replace("Z", "+00:00")),
                 "CloudTrailEvent": json.dumps(e)} for e in events.get(index, [])]},
                {"StartTime": batches[index][0], "EndTime": batches[index][1], "MaxResults": 50})

        target = self.root / "case"
        identity()
        stubs["ec2"].add_response("describe_regions", {"Regions": [{"RegionName": "us-east-1"}]}, {"AllRegions": False})
        for index in range(3):
            lookup(index)
        stubs["cloudtrail"].add_client_error("lookup_events", "ExpiredTokenException", expected_params={
            "StartTime": batches[3][0], "EndTime": batches[3][1], "MaxResults": 50})
        stubs["ssm"].add_response("list_commands", {"Commands": []}, {"Filters": [
            {"key": "InvokedBefore", "value": "2026-10-30T06:00:01Z"}], "MaxResults": 50})
        for state in ("Active", "History"):
            stubs["ssm"].add_response("describe_sessions", {"Sessions": []}, {"State": state, "Filters": [
                {"key": "InvokedBefore", "value": "2026-10-30T06:00:01Z"}], "MaxResults": 100})
        _, log = self.run_auto(target, status=1)
        gated[0] = False
        stubs["ssm"].assert_no_pending_responses()
        self.assertIn("stopped during download", log)
        self.assertIn("rerun the same command", log)
        self.assertIn("maximum available history", log)
        # Tools were set up first and verified; nothing downstream of the failed collection exists.
        self.assertEqual(get_suzaku.installed(self.tools).parent.name, "suzaku-3.0.0")
        self.assertTrue((self.tools / "dbip-lite-2026-10" / "kamotrace-download.json").is_file())
        self.assertFalse(json.loads((target / "download" / "manifest.json").read_text())["complete"])
        self.assertFalse((target / "case.duckdb").exists())
        # An import killed mid-write leaves only its private, unpublished staging folder: it is removed.
        abandoned = target / ".case.duckdb.killed.staging"
        abandoned.mkdir()
        (abandoned / "kamotrace-staging.json").write_text(json.dumps({"output": str(target / "case.duckdb")}))
        (abandoned / "staging.duckdb").write_bytes(b"partial")
        fetched = list(self.requests)

        now[0] = end + timedelta(days=2)  # Rerunning later must not move the frozen collection range.
        identity()
        for index in range(3, 90):
            lookup(index)
        out, log = self.run_auto(target)  # SSM's pages replay from the checkpoint: no SSM stubs remain.
        self.assertEqual(self.requests, fetched)  # Installed tools are reused, not downloaded again.
        self.assertIn("Removed abandoned staging folder .case.duckdb.killed.staging", log)
        self.assertFalse(abandoned.exists())
        self.assertIn("2 Suzaku detections", out)
        for stub in stubs.values():
            stub.assert_no_pending_responses()
        database = target / "case.duckdb"
        connection = duckdb.connect(str(database), read_only=True)
        try:
            self.assertEqual(connection.execute("SELECT list(event_id ORDER BY event_id) FROM events").fetchone()[0],
                             ["earliest", "latest"])
        finally:
            connection.close()
        self.assertEqual(json.loads((target / "download" / "manifest.json").read_text())["end"], "2026-10-30T06:00:00Z")
        args = self.http.call_args.args
        self.assertEqual(args[0], ("127.0.0.1", 8765))
        self.assertEqual(args[1].keywords["store"].commands.path, target / "download" / "ssm.json")
        run = args[1].keywords["store"].enrichment_run
        self.assertEqual((run["evidence_ips"], run["sources"][0]["evidence_ips_matched"]), (2, 1))  # DB-IP covers 192.0.2.0/24
        self.http.return_value.serve_forever.assert_called_once()

        # A complete case reruns without AWS (no stubs are queued), downloads or rewriting any file.
        before = {p.name: digest(p) for p in target.glob("case.*duckdb")}
        self.assertEqual(sorted(before), ["case.detections.duckdb", "case.duckdb", "case.enrichment.duckdb"])
        _, log = self.run_auto(target)
        self.assertIn("reused without contacting AWS", log)
        self.assertEqual({p.name: digest(p) for p in target.glob("case.*duckdb")}, before)
        self.assertEqual(self.requests, fetched)

        # A complete manifest is not trusted when its published exports are gone: the downloader
        # regenerates them from the checkpoint (only the login check reaches AWS) on the frozen range.
        exports = {name: (target / "download" / name).read_bytes() for name in ("cloudtrail.json", "ssm.json")}
        for name in exports:
            (target / "download" / name).unlink()
            _, log = self.run_auto(target, "--skip-download", "--no-serve", status=1)
            self.assertIn(f"missing published exports ['{name}']", log)
            identity()
            _, log = self.run_auto(target, "--no-serve")
            self.assertIn(f"regenerating missing ['{name}']", log)
            self.assertIn("verified existing", log)  # Identical regenerated bytes: evidence reused, not rebuilt
            self.assertEqual((target / "download" / name).read_bytes(), exports[name])
            for stub in stubs.values():
                stub.assert_no_pending_responses()
        self.assertEqual(json.loads((target / "download" / "manifest.json").read_text())["end"], "2026-10-30T06:00:00Z")
        self.assertEqual({p.name: digest(p) for p in target.glob("case.*duckdb")}, before)
        # --ssm-export replaces the collection's SSM export, so its absence does not block reuse.
        replacement = self.root / "ssm-copy.json"
        replacement.write_bytes(exports["ssm.json"])
        (target / "download" / "ssm.json").unlink()
        self.run_auto(target, "--skip-download", "--ssm-export", replacement, "--no-serve")

    def test_existing_inputs_stage_failure_resume_refresh_and_refusals(self):
        archive = self.root / "suzaku.zip"
        archive.write_bytes(self.suzaku_archive())
        self.tools.mkdir()
        suzaku = get_suzaku.install(archive, "sha256:" + digest(archive), "3.0.0", get_suzaku.platform_tag(), self.tools)
        source = self.root / "events.json.gz"
        source.write_bytes(gzip.compress(json.dumps({"Records": [
            record("e1", "2026-10-01T00:00:00Z"), record("e2", "2026-10-01T00:00:01Z", "203.0.113.5")]}).encode()))
        geo = self.root / "geo.jsonl"
        geo.write_text(json.dumps({"ip": "192.0.2.10", "country": "Netherlands"}), encoding="utf-8")
        target = self.root / "case"
        options = (target, "--source", source, "--jsonl", geo, "--no-serve")

        (suzaku.parent / "FAIL").touch()
        _, log = self.run_auto(*options, status=1)
        self.assertIn("stopped during suzaku", log)
        self.assertIn("synthetic Suzaku failure", log)
        database = target / "case.duckdb"
        evidence, enrichment = digest(database), digest(target / "case.enrichment.duckdb")
        self.assertFalse((target / "case.detections.duckdb").exists())
        self.assertEqual(list(target.glob(".*.staging")), [])

        (suzaku.parent / "FAIL").unlink()
        _, log = self.run_auto(*options)
        self.assertIn("verified existing", log)
        self.assertIn("case.enrichment.duckdb is current; reused", log)
        self.assertIn(f"kamotrace serve --database {database}", log)
        self.assertEqual((digest(database), digest(target / "case.enrichment.duckdb")), (evidence, enrichment))
        detections = duckdb.connect(str(target / "case.detections.duckdb"), read_only=True)
        try:
            self.assertEqual(json.loads(detections.execute("SELECT metadata FROM suzaku_run").fetchone()[0])["linked_rows"], 2)
        finally:
            detections.close()
        self.http.assert_not_called()

        # Changed enrichment input rebuilds only that derived sidecar.
        geo.write_text(json.dumps({"ip": "203.0.113.5", "country": "Japan"}), encoding="utf-8")
        _, log = self.run_auto(*options)
        self.assertIn("building case.enrichment.duckdb", log)
        self.assertIn("case.detections.duckdb is current; reused", log)
        self.assertNotEqual(digest(target / "case.enrichment.duckdb"), enrichment)
        self.assertEqual(digest(database), evidence)

        # Suzaku's options are part of the sidecar's identity: a changed minimum level, rules or
        # executable reruns it, and unchanged options reuse it.
        def linked():
            connection = duckdb.connect(str(target / "case.detections.duckdb"), read_only=True)
            try:
                return json.loads(connection.execute("SELECT metadata FROM suzaku_run").fetchone()[0])["linked_rows"]
            finally:
                connection.close()
        _, log = self.run_auto(*options, "--min-level", "critical")
        self.assertIn("running", log)
        self.assertEqual(linked(), 0)
        _, log = self.run_auto(*options, "--min-level", "critical")
        self.assertIn("case.detections.duckdb is current; reused", log)
        rules = self.root / "rules"
        rules.mkdir()
        (rules / "a.yml").write_text("title: a", encoding="utf-8")
        _, log = self.run_auto(*options, "--rules", rules)  # Default level again, and a rules folder
        self.assertIn("running", log)
        self.assertEqual(linked(), 2)
        (rules / "a.yml").write_text("title: changed", encoding="utf-8")
        _, log = self.run_auto(*options, "--rules", rules)
        self.assertIn("running", log)
        with suzaku.open("a") as script:  # A different Suzaku executable
            script.write("# rebuilt\n")
        _, log = self.run_auto(*options, "--rules", rules)
        self.assertIn("running", log)
        # Suzaku's own rules and config folders (e.g. after `suzaku update-rules`) count too.
        for folder in ("rules", "config"):
            self.run_auto(*options)
            (suzaku.parent / folder).mkdir(exist_ok=True)
            (suzaku.parent / folder / "x.yml").write_text(folder, encoding="utf-8")
            _, log = self.run_auto(*options)
            self.assertIn("running", log, folder)
        self.assertEqual(digest(database), evidence)

        # A pinned version is never satisfied by another installed one; an unavailable pin fails the run.
        releases = json.dumps([{"tag_name": "v3.0.0", "draft": False, "prerelease": False, "assets": []}]).encode()
        with patch("kamotrace.get_suzaku.get", lambda url: io.BytesIO(releases)):
            _, log = self.run_auto(*options, "--suzaku-version", "3.99.0", status=2)
        self.assertIn("No Suzaku 3.99.0 release", log)
        self.assertIn("stopped during get-suzaku", log)
        _, log = self.run_auto(*options, "--suzaku-version", "3.0.0")
        self.assertIn(f"using installed {suzaku}", log)

        # Derived outputs never replace files that are not positively that kind of sidecar, nor any input.
        other = self.root / "other.json"
        other.write_text(json.dumps({"Records": [record("unrelated", "2026-09-01T00:00:00Z")]}), encoding="utf-8")
        for sidecar in ("case.detections.duckdb", "case.enrichment.duckdb"):
            (target / sidecar).unlink()
            import_evidence(other, target / sidecar)  # Unrelated evidence sitting at a sidecar path
            before = digest(target / sidecar)
            _, log = self.run_auto(*options, status=1)
            self.assertIn(f"{sidecar} exists but is not a KamoTrace", log)
            self.assertEqual(digest(target / sidecar), before)
            # The standalone commands refuse it too, even with --replace.
            command = (["enrich", "--jsonl", str(geo)] if "enrichment" in sidecar else
                       ["suzaku", "--source", str(source), "--suzaku", str(suzaku)])
            with redirect_stderr(io.StringIO()) as stderr, self.assertRaises(SystemExit):
                main([*command, "--database", str(database), "--replace"])
            self.assertIn("is not a KamoTrace", stderr.getvalue())
            self.assertEqual(digest(target / sidecar), before)
            (target / sidecar).unlink()
            self.run_auto(*options)
        timeline = target / "case.detections.duckdb"
        before = digest(timeline)
        _, error = self.run_auto(target, "--source", source, "--timeline", timeline, "--skip-enrich", "--no-serve", status=2)
        self.assertIn("is an input but also a path this run writes", error)
        self.assertEqual(digest(timeline), before)
        # The standalone command is guarded too: here the input is a genuine sidecar, so only aliasing refuses.
        with self.assertRaisesRegex(ValueError, "is also an input"):
            import_timeline(database, timeline, timeline, replace=True)
        self.assertEqual(digest(timeline), before)

        # Different evidence for an existing case is refused; the original database is untouched.
        source.write_bytes(gzip.compress(json.dumps({"Records": [record("other", "2026-10-02T00:00:00Z")]}).encode()))
        _, log = self.run_auto(*options, status=1)
        self.assertIn("imported from different inputs", log)
        self.assertEqual(digest(database), evidence)

    def test_database_lock_and_live_staging_are_respected(self):
        source = self.root / "events.json"
        source.write_text(json.dumps({"Records": [record("e1", "2026-10-01T00:00:00Z")]}), encoding="utf-8")
        database = self.root / "shared" / "case.duckdb"
        options = ("--source", source, "--database", database, "--skip-suzaku", "--skip-enrich", "--no-serve")
        # Another case folder preparing the same database, and a standalone import, are refused alike.
        with database_lock(database):
            _, log = self.run_auto(self.root / "one", *options, status=1)
            self.assertIn("being prepared by another KamoTrace", log)
            with self.assertRaises(BlockingIOError):
                import_evidence(source, database)
        # case.db and case.duckdb share sidecar paths, so they share the lock as well.
        with database_lock(database.with_suffix(".db")):
            _, log = self.run_auto(self.root / "one", *options, status=1)
            self.assertIn("being prepared by another KamoTrace", log)
            self.assertNotIn("renew your AWS login", log)
        self.assertFalse(database.exists())
        # Predictably named files beside the outputs are never treated as KamoTrace staging: unrelated
        # evidence at the old .building/.wal names, used as an input or not, survives every run.
        legacy = [database.with_suffix(".duckdb.building"), database.with_suffix(".duckdb.building.wal")]
        for path in legacy:
            path.parent.mkdir(exist_ok=True)
            path.write_text(json.dumps({"Records": [record("legacy", "2026-09-01T00:00:00Z")]}), encoding="utf-8")
        before = {path: digest(path) for path in legacy}
        self.run_auto(self.root / "one", "--source", legacy[1], *options[2:])
        database.unlink()

        def staging_folder(name, output=database, extra=None):
            folder = database.parent / name
            folder.mkdir()
            (folder / "kamotrace-staging.json").write_text(json.dumps({"output": str(output)}), encoding="utf-8")
            (folder / "staging.duckdb").write_bytes(b"partial")
            if extra:
                (folder / extra).write_text("analyst notes", encoding="utf-8")
            return folder
        # Only folders positively ours (name, marker for this output, only our files, no input inside) go.
        foreign = staging_folder(".case.duckdb.foreign.staging", extra="notes.txt")
        other = staging_folder(".case.duckdb.other.staging", output=database.with_suffix(".db"))
        # An allowed file name that is really a directory of someone's data is not ours either.
        nested = staging_folder(".case.duckdb.nested.staging")
        (nested / "staging.duckdb.wal").mkdir()
        (nested / "staging.duckdb.wal" / "evidence.json").write_text("keep me", encoding="utf-8")
        holds_input = staging_folder(".case.duckdb.input.staging")
        wal_input = holds_input / "staging.duckdb.wal"
        wal_input.write_text(json.dumps({"Records": [record("w", "2026-09-01T00:00:00Z")]}))
        import_evidence(wal_input, database)  # Standalone import keeps its own input's folder
        self.assertTrue(all(folder.exists() for folder in (foreign, other, nested, holds_input)))
        self.assertEqual((nested / "staging.duckdb.wal" / "evidence.json").read_text(), "keep me")
        database.unlink()
        # auto refuses such inputs up front, since a later stage could reclaim the folder.
        before_input = digest(wal_input)
        _, error = self.run_auto(self.root / "one", "--source", wal_input, *options[2:], status=2)
        self.assertIn("inside a KamoTrace staging folder", error)
        self.assertEqual(digest(wal_input), before_input)
        self.assertFalse(database.exists())
        self.assertEqual({path: digest(path) for path in legacy}, before)

        # A writer that is still running holds the lock, so its staging folder is never touched. Once it
        # is killed (SIGKILL: no cleanup ran), the lock is released and the folder is recovered.
        writer = subprocess.Popen([sys.executable, "-c", "import sys\n"
                                   "import duckdb\n"
                                   "from kamotrace.importer import staging, write_lock\n"
                                   "lock = write_lock(sys.argv[1]); lock.__enter__()\n"
                                   "folder = staging(sys.argv[1]); building = folder.__enter__()\n"
                                   "c = duckdb.connect(str(building)); c.execute('CREATE TABLE t AS SELECT range a FROM range(100000)')\n"
                                   "print(building.parent, flush=True); sys.stdin.read()", str(database)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.addCleanup(writer.stdout.close)
        self.addCleanup(writer.stdin.close)
        live = Path(writer.stdout.readline().strip())
        self.assertTrue((live / "staging.duckdb").exists())
        _, log = self.run_auto(self.root / "two", *options, status=1)
        self.assertIn("being prepared by another KamoTrace", log)
        with self.assertRaises(BlockingIOError):
            import_evidence(source, database)
        self.assertTrue((live / "staging.duckdb").exists())
        writer.kill()
        writer.wait()
        _, log = self.run_auto(self.root / "two", *options)
        self.assertIn(f"Removed abandoned staging folder {live.name}", log)
        self.assertFalse(live.exists())
        connection = duckdb.connect(str(database), read_only=True)
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM events").fetchone()[0], 1)
        finally:
            connection.close()
        self.assertEqual({path: digest(path) for path in legacy}, before)

    def test_sidecar_outputs_are_locked_staged_privately_and_rechecked(self):
        source = self.root / "events.json"
        source.write_text(json.dumps({"Records": [record("e1", "2026-10-01T00:00:00Z")]}), encoding="utf-8")
        geo = self.root / "geo.jsonl"
        geo.write_text(json.dumps({"ip": "192.0.2.10", "country": "Netherlands"}), encoding="utf-8")
        databases = [self.root / name / "case.duckdb" for name in ("a", "b")]
        for database in databases:
            import_evidence(source, database)
        output = databases[0].with_suffix(".enrichment.duckdb")
        # Unrelated evidence at the old predictable staging names is never deleted, with or without --replace.
        legacy = [output.with_suffix(".duckdb.building"), databases[0].with_suffix(".detections.duckdb.building")]
        for path in legacy:
            import_evidence(source, path)
        wal = output.with_suffix(".duckdb.building.wal")
        wal.write_bytes(b"wal")
        legacy.append(wal)
        before = {path: digest(path) for path in legacy}

        def enrich_cli(database, *extra):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as stderr:
                try:
                    return main(["enrich", "--database", str(database), "--jsonl", str(geo), *map(str, extra)]), ""
                except SystemExit as exit:
                    return exit.code, stderr.getvalue()
        self.assertEqual(enrich_cli(databases[0])[0], None)
        self.assertEqual(enrich_cli(databases[0], "--replace")[0], None)
        self.assertEqual({path: digest(path) for path in legacy}, before)

        # Another database's run targeting the same output (custom --output, or this case's default
        # sidecar) is refused while the output is being written, by auto or a standalone command.
        published = digest(output)
        with write_lock(output):
            status, error = enrich_cli(databases[1], "--output", output, "--replace")
            self.assertEqual(status, 2)
            self.assertIn("being prepared by another KamoTrace", error)
            _, log = self.run_auto(self.root / "a", "--source", source, "--jsonl", geo, "--skip-suzaku",
                                   "--no-serve", status=1)
            self.assertIn("being prepared by another KamoTrace", log)
        self.assertEqual(digest(output), published)

        # The final publication check: an output that appears during the build is not replaced (even
        # with replace=True, since it is not a sidecar), and no staging folder is left behind.
        from kamotrace import enrich
        real = enrich.read_jsonl
        for replace in (False, True):
            target = self.root / f"appearing-{replace}.duckdb"

            def appear(path, target=target):
                target.write_bytes(b"someone else's file")
                return real(path)
            with patch("kamotrace.enrich.read_jsonl", appear), self.assertRaises((FileExistsError, ValueError)):
                enrich.build(databases[1], target, [("jsonl", geo)], replace=replace)
            self.assertEqual(target.read_bytes(), b"someone else's file")
        self.assertEqual(list(self.root.rglob(".*.staging")), [])
        self.assertEqual({path: digest(path) for path in legacy}, before)
        # Cross-stage: a --source inside a folder the enrichment stage could reclaim (its marker names this
        # case's enrichment output) is refused before anything runs, and its bytes are kept.
        case = self.root / "cross"
        reclaimable = case / ".case.enrichment.duckdb.saved.staging"
        reclaimable.mkdir(parents=True)
        (reclaimable / "kamotrace-staging.json").write_text(json.dumps({"output": str(case / "case.enrichment.duckdb")}))
        hidden = reclaimable / "staging.duckdb"
        hidden.write_text(source.read_text(), encoding="utf-8")
        before_hidden = digest(hidden)
        _, error = self.run_auto(case, "--source", hidden, "--jsonl", geo, "--skip-suzaku", "--no-serve", status=2)
        self.assertIn("inside a KamoTrace staging folder", error)
        self.assertEqual(digest(hidden), before_hidden)
        self.assertFalse((case / "case.duckdb").exists())
        # The same through a --source folder that contains it (found only when expanded): stops before import.
        hidden.rename(reclaimable / "events.json")
        hidden = reclaimable / "events.json"
        _, log = self.run_auto(case, "--source", case, "--jsonl", geo, "--skip-suzaku", "--no-serve", status=1)
        self.assertIn("inside a KamoTrace staging folder", log)
        self.assertEqual(digest(hidden), before_hidden)
        self.assertFalse((case / "case.duckdb").exists())
        # Publication itself never clobbers without replace, whatever happened since the last check.
        from kamotrace.importer import publish
        staged, existing = self.root / "staged.duckdb", self.root / "existing.duckdb"
        staged.write_bytes(b"new")
        existing.write_bytes(b"old")
        with self.assertRaises(FileExistsError):
            publish(staged, existing)
        self.assertEqual(existing.read_bytes(), b"old")
        # Lock files are write paths too: an input there is refused before anything is touched.
        lock_input = self.root / "a" / "case.lock"
        lock_input.write_text(source.read_text(), encoding="utf-8")
        before = digest(lock_input)
        _, error = self.run_auto(self.root / "a", "--source", lock_input, "--skip-suzaku", "--skip-enrich",
                                 "--no-serve", status=2)
        self.assertIn("is an input but also a path this run writes", error)
        self.assertEqual(digest(lock_input), before)

    def test_skip_download_requires_a_completed_collection_and_no_aws(self):
        target = self.root / "case"
        (target / "download").mkdir(parents=True)
        (target / "download" / "manifest.json").write_text(json.dumps({"complete": False, "services": ["cloudtrail"]}))
        (target / "download" / "cloudtrail.json").write_text(json.dumps({"Records": [record("e1", "2026-10-01T00:00:00Z")]}))
        _, log = self.run_auto(target, "--skip-download", "--skip-suzaku", "--skip-enrich", "--no-serve", status=1)
        self.assertIn("no completed collection", log)
        self.assertFalse((target / "case.duckdb").exists())
        _, error = self.run_auto(target, "--services", "ssm", status=2)
        self.assertIn("must include cloudtrail", error)


if __name__ == "__main__":
    unittest.main()
