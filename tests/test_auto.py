"""Full-auto CLI contracts: real stages on synthetic data, stubbed AWS and tool downloads (no network)."""
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

from boto3.session import Session
from botocore.stub import Stubber
import duckdb

from kamotrace import get_dbip, get_suzaku
from kamotrace.cli import main

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
        session = Mock(region_name="us-east-1")
        session.client.side_effect = lambda service, region_name, **kw: clients[service]
        self.stack.enter_context(patch("kamotrace.download.boto3.Session", return_value=session))
        self.stack.enter_context(patch("kamotrace.download.clock.sleep"))
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
        _, log = self.run_auto(target, status=1)
        self.assertIn("stopped during download", log)
        self.assertIn("rerun the same command", log)
        self.assertIn("maximum available history", log)
        # Tools were set up first and verified; nothing downstream of the failed collection exists.
        self.assertEqual(get_suzaku.installed(self.tools).parent.name, "suzaku-3.0.0")
        self.assertTrue((self.tools / "dbip-lite-2026-10" / "kamotrace-download.json").is_file())
        self.assertFalse(json.loads((target / "download" / "manifest.json").read_text())["complete"])
        self.assertFalse((target / "case.duckdb").exists())
        # An import killed mid-write leaves only its unpublished staging file; it must not be trusted.
        (target / "case.duckdb.building").write_bytes(b"partial")
        fetched = list(self.requests)

        now[0] = end + timedelta(days=2)  # Rerunning later must not move the frozen collection range.
        identity()
        for index in range(3, 90):
            lookup(index)
        stubs["ssm"].add_response("list_commands", {"Commands": []}, {"Filters": [
            {"key": "InvokedBefore", "value": "2026-10-30T06:00:01Z"}], "MaxResults": 50})
        for state in ("Active", "History"):
            stubs["ssm"].add_response("describe_sessions", {"Sessions": []}, {"State": state, "Filters": [
                {"key": "InvokedBefore", "value": "2026-10-30T06:00:01Z"}], "MaxResults": 100})
        out, log = self.run_auto(target)
        self.assertEqual(self.requests, fetched)  # Installed tools are reused, not downloaded again.
        self.assertIn("removing unfinished import case.duckdb.building", log)
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
        self.assertEqual(list(target.glob("*.building*")), [])

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

        # Different evidence for an existing case is refused; the original database is untouched.
        source.write_bytes(gzip.compress(json.dumps({"Records": [record("other", "2026-10-02T00:00:00Z")]}).encode()))
        _, log = self.run_auto(*options, status=1)
        self.assertIn("imported from different inputs", log)
        self.assertEqual(digest(database), evidence)

        # A second concurrent run on the same case is refused before touching anything.
        lock = sqlite3.connect(target / ".kamotrace-auto.lock", timeout=0, isolation_level=None)
        self.addCleanup(lock.close)
        lock.execute("PRAGMA locking_mode=EXCLUSIVE")
        lock.execute("BEGIN EXCLUSIVE")
        _, log = self.run_auto(*options, status=1)
        self.assertIn("another `kamotrace auto` run", log)

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
