"""Public download CLI contracts against AWS SDK-validated synthetic responses (no AWS access)."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta
from decimal import Decimal
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

from boto3.session import Session
from botocore.exceptions import ClientError
from botocore.response import StreamingBody
from botocore.stub import Stubber
import simplejson

from kamotrace.cli import main
from kamotrace.download import Progress
from kamotrace.importer import build
from kamotrace.server import Store


def dt(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


class DownloadContract(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.dict(os.environ, {"KAMOTRACE_NO_EMOJI": ""}))
        self.stack.enter_context(patch("kamotrace.download.shutil.get_terminal_size", return_value=os.terminal_size((200, 24))))
        self.folder = Path(self.stack.enter_context(tempfile.TemporaryDirectory())) / "download"
        sdk = Session(aws_access_key_id="synthetic", aws_secret_access_key="synthetic", region_name="us-east-1")
        self.clients, self.stubs = {}, {}
        for service, region in [("sts", "us-east-1"), ("ec2", "us-east-1"),
                ("cloudtrail", "us-east-1"), ("cloudtrail", "ap-southeast-1"),
                ("ssm", "us-east-1"), ("logs", "us-east-1"), ("s3", "us-east-1")]:
            client = sdk.client(service, region_name=region)
            self.clients[service, region] = client
            self.stubs[service, region] = self.stack.enter_context(Stubber(client))
        session = Mock(region_name="us-east-1")
        session.client.side_effect = lambda service, region_name, **kw: self.clients[service, region_name]
        self.stack.enter_context(patch("kamotrace.download.boto3.Session", return_value=session))
        self.stack.enter_context(patch("kamotrace.download.clock.sleep"))
        # Stubber answers in strict FIFO order; concurrent daily windows have their own test.
        self.stack.enter_context(patch("kamotrace.download.WINDOW_WORKERS", 1))
        self.start = dt("2026-10-01T00:00:00Z")
        self.end = dt("2026-10-01T23:59:59.999999Z")
        self.filters = [{"key": "InvokedAfter", "value": "2026-09-30T23:59:59Z"},
                        {"key": "InvokedBefore", "value": "2026-10-02T00:00:00Z"}]

    def identity(self, account="123456789012"):
        self.stubs["sts", "us-east-1"].add_response("get_caller_identity", {
            "Account": account, "Arn": f"arn:aws:sts::{account}:assumed-role/reader/new-login", "UserId": "synthetic"}, {})

    def run_cli(self, *options, status=0, tty=False, bounds=True):
        stdout, stderr = io.StringIO(), io.StringIO()
        stderr.isatty = lambda: tty
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = main(["download", "--dest", str(self.folder), "--regions", "us-east-1",
                           *(["--start", "2026-10-01", "--end", "2026-10-01"] if bounds else []), *options])
        self.assertEqual(result, status, stderr.getvalue())
        return stdout.getvalue(), stderr.getvalue()

    def test_progress_bar_uses_two_rows_and_replaces_previous_update(self):
        for emoji in (True, False):
            with self.subTest(emoji=emoji), patch.dict(os.environ, {"KAMOTRACE_NO_EMOJI": "" if emoji else "1"}), \
                    patch("kamotrace.download.shutil.get_terminal_size", return_value=os.terminal_size((120, 24))):
                stderr = io.StringIO()
                message = "us-east-1: lookup_events 2026-10-01T00:00:00Z to 2026-10-01T23:59:59.999999Z page 3 saved"
                with redirect_stderr(stderr):
                    progress = Progress("bar")
                    progress.total, progress.done, progress.pages = 6, 2, 3
                    progress.tick(message)
                    first = stderr.getvalue()
                    progress.tick("Done")
                    progress.close()
                summary, detail = first.split("\n")
                self.assertIn("2/6 jobs 3 pages (0 cached)", summary)
                self.assertEqual(detail, "\r\033[2K" + message + "\033[J")
                self.assertLessEqual(len(summary.replace("\r\033[2K", "")) + summary.count("🦆"), 119)
                update_summary, update_detail = stderr.getvalue()[len(first):].split("\n", 1)
                self.assertTrue(update_summary.startswith("\r\033[1A\r\033[2K"))
                self.assertEqual(update_detail, "\r\033[2KDone\033[J\n")

    def test_progress_bar_shows_one_line_per_busy_worker(self):
        stderr = io.StringIO()

        def frames():
            return [frame.split("\n") for frame in stderr.getvalue().split("\033[J")[:-1]]

        # Workers stay alive until the end: an exited thread's identifier may be reused.
        pool = ThreadPoolExecutor(max_workers=5)
        self.addCleanup(pool.shutdown)
        idle = [threading.Event() for _ in range(5)]
        workers = iter(range(5))

        def tick(message, then_idle=False):
            ticked, worker = threading.Event(), next(workers)

            def work():
                progress.tick(message)
                if then_idle:
                    progress.idle()
                ticked.set()
                idle[worker].wait()  # Occupy this thread so later ticks come from other threads.
            pool.submit(work)
            ticked.wait()

        self.addCleanup(lambda: [event.set() for event in idle])
        with redirect_stderr(stderr):
            progress = Progress("bar")
            progress.total = 2
            tick("us-east-1: lookup_events 2026-10-02 page 1 saved")
            tick("us-east-1: lookup_events 2026-10-01 page 7 saved", then_idle=True)
            tick("ap-southeast-1: describe_sessions page 1 saved")
            tick("us-east-1: lookup_events 2026-10-03 page 1 saved")
        first, second, third, fourth = frames()
        self.assertEqual(len(first), 1 + 1)
        self.assertEqual(second, ["\r\033[1A\r\033[2K" + second[0].split("\r\033[2K")[-1],
                                  "\r\033[2Kus-east-1: lookup_events 2026-10-01 page 7 saved",
                                  "\r\033[2Kus-east-1: lookup_events 2026-10-02 page 1 saved"])
        # The finished worker's line is gone; lines are grouped by Region, then oldest window.
        self.assertTrue(third[0].startswith("\r\033[2A\r\033[2K"))
        self.assertEqual([line.removeprefix("\r\033[2K") for line in third[1:]],
                         ["ap-southeast-1: describe_sessions page 1 saved",
                          "us-east-1: lookup_events 2026-10-02 page 1 saved"])
        self.assertEqual(len(fourth), 1 + 3)
        # More workers than terminal rows collapse into a count instead of scrolling the bar away.
        with redirect_stderr(stderr), patch("kamotrace.download.shutil.get_terminal_size",
                                            return_value=os.terminal_size((200, 4))):
            tick("us-west-2: lookup_events 2026-10-01 page 1 saved")
        fifth = frames()[-1]
        self.assertTrue(fifth[0].startswith("\r\033[3A\r\033[2K"))
        self.assertEqual([line.removeprefix("\r\033[2K") for line in fifth[1:]],
                         ["ap-southeast-1: describe_sessions page 1 saved", "... 3 more workers"])

    def test_eta_uses_slowest_region_pace_and_ignores_checkpoint_replays(self):
        now = [0.0]
        stderr = io.StringIO()
        with patch("kamotrace.download.clock.monotonic", lambda: now[0]), redirect_stderr(stderr):
            progress = Progress("log")
            progress.total = 6
            progress.plan(["quiet", "busy", "resumed"], 10, ssm=True)

            def window(region, seconds, cached=False):
                progress.window_started()
                now[0] += seconds
                progress.tick("page", page=cached)
                progress.window_done(region)

            self.assertEqual(progress.eta(), "CloudTrail ETA estimating; SSM ETA unknown")
            for _ in range(6):  # Replayed from the checkpoint in no time.
                window("resumed", 0, cached=True)
            for _ in range(10):
                window("quiet", 1)
            window("busy", 49)
            # One measured window is not a pace, and the resumed Region has none yet.
            self.assertEqual(progress.eta(), "CloudTrail ETA estimating; SSM ETA unknown")
            window("busy", 50)
            window("resumed", 6)
            # Six instant checkpoint replays must not count as measured AWS pace.
            self.assertEqual(progress.eta(), "CloudTrail ETA estimating; SSM ETA unknown")
            window("resumed", 6)
            # busy: 8 left at 111 s / 2 windows = 444 s, slower than resumed's 2 left at 6 s each.
            # An aggregate rate (14 fetched windows in 111 s) would claim about a minute.
            self.assertEqual(progress.eta(), "CloudTrail ETA ~7m (rough); SSM ETA unknown")
            now[0] += 3000  # A stalled Region lengthens its own estimate: 8 × 3111 / 2 s.
            self.assertEqual(progress.eta(), "CloudTrail ETA ~3h30m (rough); SSM ETA unknown")
            for _ in range(8):
                window("busy", 30)
            window("resumed", 6)
            window("resumed", 6)
            self.assertEqual(progress.eta(), "CloudTrail done in 56m; SSM ETA unknown")
            progress.tick("SSM complete", done=6)
            self.assertEqual(progress.eta(), "CloudTrail done in 56m")
        self.assertIn("6/6 region/services | 30 pages (6 cached) | CloudTrail done in 56m | SSM complete",
                      stderr.getvalue())

    def test_optional_bounds_collect_available_history_warn_and_resume_fixed_snapshot(self):
        now = [self.end]

        class ClockMeta(type):
            def __instancecheck__(cls, value):
                return isinstance(value, datetime)

        class Clock(datetime, metaclass=ClockMeta):
            @classmethod
            def now(cls, tz=None):
                return now[0]

        for options in [(), ("--end", "2026-10-01"), ("--start", "2026-10-01")]:
            with self.subTest(options=options), patch("kamotrace.download.datetime", Clock):
                self.folder = self.folder.parent / ("download-" + str(len(options)) + (options[0] if options else ""))
                now[0] = self.end
                lower = self.start if "--start" in options else self.end - timedelta(days=90)
                first_stamp = lower.isoformat()
                boundary = self.event("earliest", first_stamp)
                last = self.event("latest", "2026-10-01T23:59:59.999999Z")
                after = self.event("outside", "2026-10-02T00:00:00Z")
                self.identity()
                stub = self.stubs["cloudtrail", "us-east-1"]
                while lower < self.end:
                    upper = min(lower + timedelta(days=1), self.end)
                    events = [boundary] if lower.isoformat() == first_stamp else []
                    if upper == self.end:
                        events += [last, after]
                    stub.add_response("lookup_events", {"Events": events},
                                      {"StartTime": lower, "EndTime": upper, "MaxResults": 50})
                    lower = upper
                filters = self.filters if "--start" in options else [self.filters[1]]
                ssm = self.stubs["ssm", "us-east-1"]
                ssm.add_response("list_commands", {"Commands": []}, {"Filters": filters, "MaxResults": 50})
                for state in ("Active", "History"):
                    # An active session can predate both services' usual history retention.
                    ssm.add_response("describe_sessions", {"Sessions": [
                        {"SessionId": "older-active", "StartDate": self.end - timedelta(days=120)},
                        {"SessionId": "at-end", "StartDate": self.end},
                        {"SessionId": "after-end", "StartDate": self.end + timedelta(microseconds=1)}]},
                        {"State": state, "Filters": filters, "MaxResults": 100})
                _, log = self.run_cli(*options, "--progress", "off", bounds=False)
                self.assertEqual("Warning:" in log, "--start" not in options)
                if "--start" not in options:
                    self.assertIn("maximum available history", log)
                    self.assertIn("90 days", log)
                    self.assertIn("30 days", log)
                records = json.loads((self.folder / "cloudtrail.json").read_text())["Records"]
                self.assertEqual([record["eventID"] for record in records], ["earliest", "latest"])
                document = json.loads((self.folder / "ssm.json").read_text())
                self.assertEqual([s["record"]["SessionId"] for s in document["sessions"]],
                                 ["at-end"] if "--start" in options else ["older-active", "at-end"])
                manifest = json.loads((self.folder / "manifest.json").read_text())
                self.assertEqual(manifest["end"], "2026-10-01T23:59:59.999999Z")
                self.assertEqual(manifest["start"], "2026-10-01T00:00:00Z" if "--start" in options else None)
                # Advancing the clock must not change the snapshot or make resume fail.
                now[0] += timedelta(days=2)
                self.identity()
                self.run_cli(*options, "--progress", "off", bounds=False)
                self.assertEqual(json.loads((self.folder / "manifest.json").read_text())["end"], manifest["end"])
                for stub in self.stubs.values():
                    stub.assert_no_pending_responses()

    def event(self, name, stamp):
        raw = ('{"eventID":"' + name + '","eventTime":"' + stamp + '",'
               '"eventSource":"ssm.amazonaws.com","eventName":"SendCommand",'
               '"awsRegion":"us-east-1","recipientAccountId":"123456789012",'
               '"requestParameters":{"number":9007199254740993.123456789},'
               '"responseElements":{"command":{"commandId":"11111111-1111-1111-1111-111111111111"}}}')
        return {"EventId": name, "EventTime": dt(stamp), "CloudTrailEvent": raw}

    def test_resume_expired_cursor_empty_page_precision_and_progress(self):
        self.identity()
        stub = self.stubs["cloudtrail", "us-east-1"]
        params = {"StartTime": self.start, "EndTime": self.end, "MaxResults": 50}
        first = self.event("first", "2026-10-01T00:00:00Z")
        last = self.event("last", "2026-10-01T23:59:59.999999Z")
        outside = self.event("outside", "2026-10-02T00:00:00Z")
        stub.add_response("lookup_events", {"Events": [first], "NextToken": "old"}, params)
        stub.add_client_error("lookup_events", "ExpiredToken", expected_params={**params, "NextToken": "old"})
        _, log = self.run_cli("--services", "cloudtrail", "--progress", "log", status=1)
        self.assertIn("page 1 saved", log)
        self.assertIn("1 pages (0 cached) | CloudTrail ETA estimating |", log)
        self.assertNotIn("SSM", log)
        self.assertIn("lookup_events 2026-10-01T00:00:00Z to 2026-10-01T23:59:59.999999Z page 1 saved", log)
        self.assertNotIn("requesting", log)
        self.assertNotIn("\r", log)
        self.assertFalse(json.loads((self.folder / "manifest.json").read_text())["complete"])
        self.identity()
        stub.add_client_error("lookup_events", "InvalidNextTokenException", expected_params={**params, "NextToken": "old"})
        stub.add_response("lookup_events", {"Events": [first], "NextToken": "new"}, params)
        stub.add_response("lookup_events", {"Events": [], "NextToken": "final"}, {**params, "NextToken": "new"})
        stub.add_response("lookup_events", {"Events": [last, outside]}, {**params, "NextToken": "final"})
        _, bar = self.run_cli("--services", "cloudtrail", "--progress", "bar")
        self.assertIn("🦆", bar)
        self.assertIn("[" + "🦆" * 10 + "]", bar)
        self.assertNotIn("#", bar)
        self.assertIn("lookup_events 2026-10-01T00:00:00Z to 2026-10-01T23:59:59.999999Z page 3 saved", bar)
        self.assertIn("1/1 jobs | CloudTrail done in <1m | ", bar)
        self.assertNotIn("requesting", bar)
        source = self.folder / "cloudtrail.json"
        records = simplejson.loads(source.read_text(), use_decimal=True)["Records"]
        self.assertEqual([r["eventID"] for r in records], ["first", "last"])
        self.assertEqual(records[0]["requestParameters"]["number"], Decimal("9007199254740993.123456789"))
        self.assertIn(first["CloudTrailEvent"], source.read_text())
        # Completed collection resumes entirely from disk, including output regeneration.
        self.identity()
        _, quiet = self.run_cli("--services", "cloudtrail", "--progress", "off")
        self.assertNotIn("page", quiet)
        self.assertTrue(json.loads((self.folder / "manifest.json").read_text())["complete"])
        self.identity()
        with patch.dict(os.environ, {"KAMOTRACE_NO_EMOJI": "1"}):
            _, ascii_bar = self.run_cli("--services", "cloudtrail", "--progress", "bar")
        self.assertNotIn("🦆", ascii_bar)
        self.assertIn("[####################]", ascii_bar)
        self.identity()
        _, auto_log = self.run_cli("--services", "cloudtrail")
        self.assertIn("page 1 cached", auto_log)
        self.assertIn("lookup_events 2026-10-01T00:00:00Z to 2026-10-01T23:59:59.999999Z page 1 cached", auto_log)
        self.assertNotIn("\r", auto_log)
        self.assertNotIn("🦆", auto_log)
        self.identity()
        _, auto_bar = self.run_cli("--services", "cloudtrail", tty=True)
        self.assertIn("🦆", auto_bar)
        stub.assert_no_pending_responses()
        # The resulting JSON is accepted by the real importer.
        build(source, self.folder / "case.duckdb")

    def test_ssm_downloads_cloudwatch_output_from_aws_default_group(self):
        self.identity()
        command_id = "11111111-1111-1111-1111-111111111111"
        command = {"CommandId": command_id, "RequestedDateTime": self.start,
                   "DocumentName": "AWS-RunShellScript",
                   "CloudWatchOutputConfig": {"CloudWatchOutputEnabled": True}}
        stub = self.stubs["ssm", "us-east-1"]
        stub.add_response("list_commands", {"Commands": [command]},
                          {"Filters": self.filters, "MaxResults": 50})
        stub.add_response("list_command_invocations", {"CommandInvocations": []},
                          {"CommandId": command_id, "Details": True, "MaxResults": 50})
        self.cw_pages("/aws/ssm/AWS-RunShellScript", command_id + "/", "default group output")
        for state in ("Active", "History"):
            stub.add_response("describe_sessions", {"Sessions": []},
                              {"State": state, "Filters": self.filters, "MaxResults": 100})

        self.run_cli("--services", "ssm", "--progress", "off")

        manifest = json.loads((self.folder / "manifest.json").read_text())
        self.assertTrue(manifest["complete"])
        self.assertEqual(len(manifest["logs"]), 1)
        log = manifest["logs"][0]
        self.assertEqual(log["log_group"], "/aws/ssm/AWS-RunShellScript")
        exported = json.loads((self.folder / log["file"]).read_text())
        self.assertEqual([event["message"] for event in exported["events"]], ["default group output"])
        for stub in self.stubs.values():
            stub.assert_no_pending_responses()

    def test_ssm_multiple_instances_plugins_sessions_and_stored_logs(self):
        self.identity()
        self.stubs["cloudtrail", "us-east-1"].add_response("lookup_events", {
            "Events": [self.event("linked", "2026-10-01T00:00:00Z")]},
            {"StartTime": self.start, "EndTime": self.end, "MaxResults": 50})
        stub = self.stubs["ssm", "us-east-1"]
        command_id = "11111111-1111-1111-1111-111111111111"
        command = {"CommandId": command_id, "RequestedDateTime": self.start,
                   "DocumentName": "AWS-RunShellScript", "OutputS3BucketName": "synthetic-logs",
                   "OutputS3KeyPrefix": "commands", "CloudWatchOutputConfig": {
                       "CloudWatchOutputEnabled": True, "CloudWatchLogGroupName": "command-logs"}}
        stub.add_response("list_commands", {"Commands": [command], "NextToken": "more"},
                          {"Filters": self.filters, "MaxResults": 50})
        stub.add_response("list_commands", {"Commands": [{**command, "CommandId": "22222222-2222-2222-2222-222222222222",
                          "RequestedDateTime": dt("2026-10-02T00:00:00Z")}]},
                          {"Filters": self.filters, "MaxResults": 50, "NextToken": "more"})
        for i, plugins in [(1, ["shell", "second"]), (2, ["shell"])]:
            params = {"CommandId": command_id, "Details": True, "MaxResults": 50}
            if i == 2:
                params["NextToken"] = "instance2"
            stub.add_response("list_command_invocations", {"CommandInvocations": [{
                "CommandId": command_id, "InstanceId": f"i-{i:017d}",
                "CommandPlugins": [{"Name": name, "Output": "combined"} for name in plugins]}],
                **({"NextToken": "instance2"} if i == 1 else {})}, params)
        for i, plugin, output, error in [(1, "shell", "alpha", ""), (1, "second", "", "failure"), (2, "shell", "beta", "")]:
            detail = {"CommandId": command_id, "InstanceId": f"i-{i:017d}", "PluginName": plugin}
            stub.add_response("get_command_invocation", {**detail, "StandardOutputContent": output,
                              "StandardErrorContent": error}, detail)
        prefix = "commands/" + command_id + "/"
        self.s3_page(prefix, prefix + "i-1/stdout", b"full command output", interrupt=True)
        self.cw_pages("command-logs", command_id + "/", "command output", expired=True)
        for state, sessions in [("Active", [{"SessionId": "alice-session", "StartDate": self.start}]),
                                ("History", [{"SessionId": "bob-session", "StartDate": self.end}])]:
            params = {"State": state, "Filters": self.filters, "MaxResults": 100}
            if state == "History":
                stub.add_response("describe_sessions", {"Sessions": [], "NextToken": "sessions"}, params)
                params = {**params, "NextToken": "sessions"}
            stub.add_response("describe_sessions", {"Sessions": sessions},
                              params)
        self.cw_pages("session-logs", "alice-session", "alice transcript")
        self.cw_pages("session-logs", "bob-session", "bob transcript")
        self.s3_page("sessions/", "sessions/bob-session.log", b"bob s3 transcript", extra_key="sessions/not-bob-session.log")
        options = ("--compress", "--session-s3", "s3://synthetic-logs/sessions/", "--session-log-group", "session-logs")
        self.run_cli(*options, status=1)
        self.assertFalse(json.loads((self.folder / "manifest.json").read_text())["complete"])
        self.identity()
        self.run_cli(*options, status=1)
        self.identity()
        self.run_cli(*options)
        document = json.loads(gzip.decompress((self.folder / "ssm.json.gz").read_bytes()))
        self.assertEqual(len(document["commands"]), 1)
        self.assertEqual(len(document["invocations"]), 2)
        self.assertEqual([(d["record"]["StandardOutputContent"], d["record"]["StandardErrorContent"])
                          for d in document["invocation_details"]], [("alpha", ""), ("", "failure"), ("beta", "")])
        self.assertEqual([s["record"]["SessionId"] for s in document["sessions"]], ["alice-session", "bob-session"])
        manifest = json.loads((self.folder / "manifest.json").read_text())
        self.assertEqual(len(manifest["logs"]), 5)
        for log in manifest["logs"]:
            data = (self.folder / log["file"]).read_bytes()
            if "sha256" in log:
                self.assertEqual(hashlib.sha256(data).hexdigest(), log["sha256"])
            else:
                self.assertTrue(log["file"].endswith(".json.gz"))
                self.assertEqual(len(json.loads(gzip.decompress(data))["events"]), 1)
        transcript = next(log for log in manifest["logs"] if log.get("key") == "sessions/bob-session.log")
        target = self.folder / transcript["file"]
        target.write_bytes(b"x" * target.stat().st_size)  # Same-size corruption must not count as complete.
        self.stubs["s3", "us-east-1"].add_response("get_object", {
            "Body": StreamingBody(io.BytesIO(b"bob s3 transcript"), 17)},
            {"Bucket": "synthetic-logs", "Key": "sessions/bob-session.log", "IfMatch": '"synthetic-etag"'})
        cloudtrail_bytes = (self.folder / "cloudtrail.json.gz").read_bytes()
        self.identity()
        self.run_cli(*options)
        self.assertEqual(target.read_bytes(), b"bob s3 transcript")
        self.assertEqual((self.folder / "cloudtrail.json.gz").read_bytes(), cloudtrail_bytes)
        self.assertFalse((self.folder / "cloudtrail.json").exists())
        build(self.folder / "cloudtrail.json.gz", self.folder / "case.duckdb")
        store = Store(self.folder / "case.duckdb", ssm_export=self.folder / "ssm.json.gz")
        self.addCleanup(store.connection.close)
        self.addCleanup(store.reviews.close)
        self.assertEqual(len(store.commands.sheet({})["data"]), 3)
        for stub in self.stubs.values():
            stub.assert_no_pending_responses()

    def test_s3_cache_rejects_same_size_version_change_across_listings(self):
        self.identity()
        stub = self.stubs["ssm", "us-east-1"]
        stub.add_response("list_commands", {"Commands": []}, {"Filters": self.filters, "MaxResults": 50})
        for state in ("Active", "History"):
            stub.add_response("describe_sessions", {"Sessions": [
                {"SessionId": "bob-session", "StartDate": self.start}] if state == "History" else []},
                {"State": state, "Filters": self.filters, "MaxResults": 100})
        s3 = self.stubs["s3", "us-east-1"]
        for prefix, etag in [("sessions/", '"version-A"'), ("sessions/bob-session", '"version-B"')]:
            s3.add_response("list_objects_v2", {"Contents": [
                {"Key": "sessions/bob-session.log", "Size": 3, "ETag": etag}]},
                {"Bucket": "synthetic-logs", "Prefix": prefix})
            if etag == '"version-A"':
                s3.add_response("get_object", {"Body": StreamingBody(io.BytesIO(b"old"), 3)},
                    {"Bucket": "synthetic-logs", "Key": "sessions/bob-session.log", "IfMatch": etag})
        options = ("--services", "ssm", "--progress", "off",
                   "--session-s3", "s3://synthetic-logs/sessions/",
                   "--session-s3", "s3://synthetic-logs/sessions/bob-session")

        _, error = self.run_cli(*options, status=1)
        self.assertIn("S3 object version conflict", error)
        self.assertFalse(json.loads((self.folder / "manifest.json").read_text())["complete"])
        files = list((self.folder / "logs").glob("*.bin"))
        self.assertEqual([file.read_bytes() for file in files], [b"old"])
        self.assertFalse((self.folder / "ssm.json").exists())
        # The version binding must survive a restart without fetching or relabelling the object.
        self.identity()
        _, error = self.run_cli(*options, status=1)
        self.assertIn("S3 object version conflict", error)
        self.assertEqual(files[0].read_bytes(), b"old")

        # Emulate an older checkpoint: matching size/hash alone cannot establish an ETag binding.
        with sqlite3.connect(self.folder / "checkpoint.sqlite") as checkpoint:
            checkpoint.executescript("""
                CREATE TABLE legacy_objects (name TEXT PRIMARY KEY, sha256 TEXT NOT NULL);
                INSERT INTO legacy_objects SELECT name, sha256 FROM objects;
                DROP TABLE objects;
                ALTER TABLE legacy_objects RENAME TO objects;
            """)
        s3.add_response("get_object", {"Body": StreamingBody(io.BytesIO(b"old"), 3)},
            {"Bucket": "synthetic-logs", "Key": "sessions/bob-session.log", "IfMatch": '"version-A"'})
        self.identity()
        _, error = self.run_cli(*options, status=1)
        self.assertIn("S3 object version conflict", error)
        self.assertEqual(files[0].read_bytes(), b"old")
        for stub in self.stubs.values():
            stub.assert_no_pending_responses()

    def s3_page(self, prefix, key, data, extra_key=None, interrupt=False):
        objects = [{"Key": key, "Size": len(data), "ETag": '"synthetic-etag"'}]
        if extra_key:
            objects.append({"Key": extra_key, "Size": 1, "ETag": '"other"'})
        stub = self.stubs["s3", "us-east-1"]
        stub.add_response("list_objects_v2", {"Contents": [], "NextContinuationToken": "objects"},
                          {"Bucket": "synthetic-logs", "Prefix": prefix})
        stub.add_response("list_objects_v2", {"Contents": objects},
                          {"Bucket": "synthetic-logs", "Prefix": prefix, "ContinuationToken": "objects"})
        if interrupt:
            stub.add_client_error("get_object", "ExpiredToken", expected_params={
                "Bucket": "synthetic-logs", "Key": key, "IfMatch": '"synthetic-etag"'})
        stub.add_response("get_object", {"Body": StreamingBody(io.BytesIO(data), len(data))},
                          {"Bucket": "synthetic-logs", "Key": key, "IfMatch": '"synthetic-etag"'})

    def cw_pages(self, group, prefix, message, expired=False):
        stub = self.stubs["logs", "us-east-1"]
        params = {"logGroupName": group, "logStreamNamePrefix": prefix}
        stub.add_response("filter_log_events", {"events": [], "nextToken": "logs"}, params)
        if expired:
            stub.add_client_error("filter_log_events", "ExpiredToken", expected_params={**params, "nextToken": "logs"})
            stub.add_client_error("filter_log_events", "InvalidParameterException", "The specified nextToken has expired",
                                  expected_params={**params, "nextToken": "logs"})
            stub.add_response("filter_log_events", {"events": [], "nextToken": "logs"}, params)
        stub.add_response("filter_log_events", {"events": [{"eventId": "one", "message": message,
                          "logStreamName": prefix, "timestamp": 1790812800000}]}, {**params, "nextToken": "logs"})

    def test_all_regions_daily_batches_offsets_and_wrong_account(self):
        self.identity()
        self.stubs["ec2", "us-east-1"].add_response("describe_regions", {"Regions": [
            {"RegionName": "us-east-1"}, {"RegionName": "ap-southeast-1"}]}, {"AllRegions": False})
        boundary = self.event("boundary", "2026-10-02T00:00:00Z")
        for region in ("ap-southeast-1", "us-east-1"):
            for lower, upper in [(self.start, dt("2026-10-02T00:00:00Z")),
                                 (dt("2026-10-02T00:00:00Z"), dt("2026-10-02T00:00:01Z"))]:
                self.stubs["cloudtrail", region].add_response("lookup_events", {"Events": [boundary]},
                    {"StartTime": lower, "EndTime": upper, "MaxResults": 50})
        _, log = self.run_cli("--regions", "all", "--start", "2026-10-01T08:00:00+08:00",
                             "--end", "2026-10-02T08:00:01+08:00", "--services", "cloudtrail")
        self.assertIn("lookup_events 2026-10-01T00:00:00Z to 2026-10-02T00:00:00Z page 1 saved", log)
        self.assertIn("lookup_events 2026-10-02T00:00:00Z to 2026-10-02T00:00:01Z page 1 saved", log)
        records = json.loads((self.folder / "cloudtrail.json").read_text())["Records"]
        self.assertEqual(len(records), 2)  # Dedup within a region, not across regions.
        before = (self.folder / "manifest.json").read_bytes()
        self.identity("999999999999")
        _, error = self.run_cli("--services", "cloudtrail", status=1)
        self.assertIn("same AWS account", error)
        self.assertEqual((self.folder / "manifest.json").read_bytes(), before)

    def test_regions_and_daily_windows_run_concurrently_with_regional_pace(self):
        regions = ("ap-southeast-1", "us-east-1")
        # Every first page waits until all four windows (two Regions x two days) are in flight at once.
        barrier = threading.Barrier(4, timeout=10)
        failing = []

        class CloudTrail:  # Thread-safe stand-in: Stubber's FIFO responses cannot be answered concurrently.
            def __init__(fake, region):
                fake.region = region

            def lookup_events(fake, StartTime, EndTime, MaxResults, NextToken=None):
                day = StartTime.date().isoformat()
                if NextToken is None:
                    barrier.wait()
                    return {"Events": [self.event(f"{fake.region}-{day}", day + "T12:00:00Z")], "NextToken": "more"}
                if (fake.region, day) in failing:
                    raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "synthetic"}}, "LookupEvents")
                # Shared inclusive window boundary: returned by both days, kept once per Region.
                return {"Events": [self.event("boundary", "2026-10-02T00:00:00Z")]}

        for region in regions:
            self.clients["cloudtrail", region] = CloudTrail(region)
        options = ("--regions", *regions, "--start", "2026-10-01", "--end", "2026-10-02", "--services", "cloudtrail")
        self.stack.enter_context(patch("kamotrace.download.WINDOW_WORKERS", 2))
        with patch("kamotrace.download.clock.sleep") as sleep, \
                patch("kamotrace.download.clock.monotonic", return_value=100.0):
            self.identity()
            self.run_cli(*options, "--progress", "off", bounds=False)
        records = json.loads((self.folder / "cloudtrail.json").read_text())["Records"]
        self.assertEqual([record["eventID"] for record in records], [
            "ap-southeast-1-2026-10-01", "ap-southeast-1-2026-10-02", "boundary",
            "boundary", "us-east-1-2026-10-01", "us-east-1-2026-10-02"])
        # Both windows of a Region share one pace (not one per worker, not one for all Regions).
        self.assertEqual(sorted(round(call.args[0], 6) for call in sleep.call_args_list),
                         [0, 0, 0.55, 0.55, 1.1, 1.1, 1.65, 1.65])
        expected = (self.folder / "cloudtrail.json").read_bytes()

        # One window's failure stops the other workers, is reported itself, and resumes to identical output.
        self.folder = self.folder.parent / "failed-then-resumed"
        failing.append(("us-east-1", "2026-10-02"))
        self.identity()
        _, error = self.run_cli(*options, "--progress", "off", bounds=False, status=1)
        self.assertIn("AccessDeniedException", error)
        self.assertNotIn("stopped by another worker", error)
        self.assertFalse(json.loads((self.folder / "manifest.json").read_text())["complete"])
        failing.clear()
        self.identity()
        self.run_cli(*options, "--progress", "off", bounds=False)
        self.assertEqual((self.folder / "cloudtrail.json").read_bytes(), expected)

    def test_invalid_range_is_rejected_before_aws_access(self):
        for options in [("--start", "2026-10-02"), ("--start", "2026-10-01T12:00:00"),
                        ("--regions", "all", "us-east-1")]:
            with self.subTest(options=options):
                self.run_cli(*options, status=1)
                self.assertFalse(self.folder.exists())


if __name__ == "__main__":
    unittest.main()
