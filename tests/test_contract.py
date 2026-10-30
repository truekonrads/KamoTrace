"""HTTP, MCP and Suzaku contract tests with a disposable, real CloudTrail DuckDB database."""
from datetime import datetime, timezone
from functools import partial
import gc
import gzip
import hashlib
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
from queue import Empty, Queue
import subprocess
import sys
import tempfile
import threading
import unittest
import warnings
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import anyio
from mcp import Client, StdioServerParameters

import duckdb

from kamotrace.importer import build
from kamotrace.server import Handler, Store
from kamotrace.enrich import build as enrich
from kamotrace.suzaku import import_timeline


class BrowserContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.database = root / "events.duckdb"
        source = root / "events.json"
        events = []
        # Asymmetric values around Jakarta midnight distinguish UTC, inclusive-end and local bugs.
        for i, (stamp, operation, ip) in enumerate([
            ("2026-10-24T16:59:59Z", "SendCommand", "1.1.1.1"),
            ("2026-10-24T17:00:00Z", "StartSession", "1.1.1.1"),
            ("2026-10-25T01:02:03Z", "SendCommand", "8.8.8.8"),
            ("2026-10-25T16:59:59Z", "SendCommand", "1.1.1.1"),
            ("2026-10-25T17:00:00Z", "UpdateInstanceInformation", "8.8.8.8"),
        ]):
            events.append({"eventID": f"event-{i}", "eventTime": stamp, "eventName": operation,
                "eventSource": "ssm.amazonaws.com", "sourceIPAddress": ip,
                "awsRegion": "ap-southeast-3", "eventCategory": "Management", "readOnly": False,
                "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/alice", "accessKeyId": "AKIAEXAMPLE"},
                "requestParameters": {"number": 9007199254740993, "instanceId": "i-example"}})
        events[1]["userAgent"] = 'powershell -c "& C:\\Temp\\a.ps1"'  # Stored JSON-escaped as \" and \\
        for index in (0, 2, 3):
            events[index]["recipientAccountId"] = "123" if index != 3 else "different-account"
            events[index]["responseElements"] = {"command": {"commandId": "command-multi"}}
        source.write_text(json.dumps({"Records": events}), encoding="utf-8")
        build(source, cls.database)
        geo = root / "geo.jsonl"
        geo.write_text('\n'.join(json.dumps({"ip": ip, "country": country, "as_org": "test"})
            for ip, country in [("1.1.1.1", "Germany"), ("8.8.8.8", "Indonesia")]), encoding="utf-8")
        # Written to the default <database>.enrichment.duckdb path, which Store discovers itself.
        enrich(cls.database, cls.database.with_suffix(".enrichment.duckdb"), [("jsonl", geo)])
        cls.before = hashlib.sha256(cls.database.read_bytes()).hexdigest()
        cls.ssm_export = root / "ssm.json"
        command = {"CommandId": "command-multi", "DocumentName": "AWS-RunShellScript", "RequestedDateTime": "2026-10-24T17:00:00Z",
                   "Status": "Failed", "TargetCount": 3, "InstanceIds": ["i-alpha", "i-beta", "i-missing"],
                   "Parameters": {"commands": ["echo c3ludGhldGlj | base64 -d"]}}
        supplement = {**events[2], "eventID": "supplement-only", "eventName": "GetCommandInvocation",
                      "requestParameters": {"commandId": "command-multi", "instanceId": "i-beta"}, "responseElements": None}
        cls.ssm_export.write_text(json.dumps({"account_id": "123", "commands": [
            {"region": "ap-southeast-3", "record": command, "base64_enrichment": [{"parameter": "commands", "value_index": 0,
                "decodings": [{"status": "decoded_utf8", "kind": "inline_echo", "decoded_text": "synthetic", "nested_decodings": []}]}]},
            {"region": "us-east-1", "record": {**command, "InstanceIds": ["i-other"], "TargetCount": 1,
                "Parameters": {"commands": ["different region"]}}}],
            "invocations": [{"region": "ap-southeast-3", "record": {"CommandId": "command-multi", "InstanceId": instance,
                "Status": status, "CommandPlugins": [{"Name": "shell", "Output": "combined fallback", "Status": status}]
                    + ([{"Name": "fallback-step", "Output": "mixed stdout/stderr", "Status": "TimedOut", "ResponseCode": 7}]
                       if instance == "i-beta" else [])}}
                for instance, status in [("i-alpha", "Success"), ("i-beta", "Failed")]],
            "invocation_details": [{"region": "ap-southeast-3", "record": {"CommandId": "command-multi", "InstanceId": instance,
                "PluginName": plugin, "Status": status, "ResponseCode": code, "StandardOutputContent": stdout, "StandardErrorContent": stderr}}
                for instance, plugin, status, code, stdout, stderr in [
                    ("i-alpha", "shell", "Success", 0, "alpha stdout <script>neverRun()</script>", ""),
                    ("i-beta", "shell", "Failed", 9, "beta stdout", "beta stderr"),
                    ("i-alpha", "second-step", "Success", 0, "alpha second plugin", "")]],
            "cloudtrail_records": [events[0], supplement]}), encoding="utf-8")
        cls.store = Store(cls.database, ssm_export=cls.ssm_export)
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=cls.store))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()
        cls.server.server_close()
        cls.store.reviews.close()
        cls.store.connection.close()
        assert hashlib.sha256(cls.database.read_bytes()).hexdigest() == cls.before
        cls.temp.cleanup()

    def call(self, path, body=None, headers=None):
        request = Request(self.url + path, data=None if body is None else json.dumps(body).encode(),
            headers={"Content-Type": "application/json", **(headers or {})})
        try:
            with urlopen(request, timeout=15) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_serve_reports_startup_progress_and_ready_url(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = subprocess.Popen([sys.executable, "-m", "kamotrace", "serve",
                "--database", str(self.database), "--ssm-export", str(self.ssm_export),
                "--annotations", str(Path(temporary) / "reviews.sqlite3"), "--bind", "127.0.0.1", "--port", "0"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            lines = Queue()

            def read_output():
                for line in process.stdout:
                    lines.put(line)
                lines.put(None)

            reader = threading.Thread(target=read_output, daemon=True)
            reader.start()
            output = ""
            try:
                while True:
                    try:
                        line = lines.get(timeout=30)
                    except Empty:
                        self.fail("No startup progress for 30 seconds:\n" + output)
                    self.assertIsNotNone(line, "Server exited before becoming ready:\n" + output)
                    output += line
                    if line.startswith("KamoTrace: http://"):
                        url = line.split()[1]
                        break
                for stage in ("Opening evidence database (read-only)", "Validating findings/tags evidence identity",
                              "Loading IP enrichment", "Loading and linking SSM commands", "Loading Suzaku detections",
                              "Calculating event counts", "Binding HTTP server", "Startup complete in"):
                    self.assertIn(stage, output)
                self.assertIn(str(self.database), output)
                self.assertIn(str(self.database.with_suffix(".enrichment.duckdb")), output)
                self.assertIn(str(self.ssm_export), output)
                self.assertRegex(output, r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{4} INFO")
                with urlopen(url + "/api/meta", timeout=15) as response:
                    self.assertEqual(json.load(response)["total"], 5)
            finally:
                process.terminate()
                process.wait(timeout=15)
                reader.join(timeout=15)
                process.stdout.close()

    def test_import_multiple_regions_gzip_streams_and_provenance(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sources = root / "regions"
            sources.mkdir()
            first = (b'{"eventID":"regional-a","eventTime":"2026-10-01T00:00:00Z",'
                     b'"eventSource":"ssm.amazonaws.com","awsRegion":"us-east-1",'
                     b'"requestParameters":{"number":9007199254740993.123456789}}')
            second = first.replace(b'regional-a', b'regional-b').replace(b'us-east-1', b'ap-southeast-1')
            a, b = sources / "a.json", sources / "b.json.gz"
            a.write_bytes(b'\xef\xbb\xbf{"Records":[' + first + b']}')
            b.write_bytes(gzip.compress(b'{"Records":[' + second + b',' + first + b']}', mtime=0))
            (sources / "ignore.txt").write_text("Not evidence")
            database = root / "combined.duckdb"
            command = [sys.executable, "-m", "kamotrace", "import"]
            result = subprocess.run([*command, "--source", str(a), "--source", str(b),
                                     "--database", str(database)], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual((report["records"], report["distinct_event_ids"]), (3, 2))
            self.assertEqual([(s["source_sha256"], s["source_records"], s["first_record"], s["last_record"])
                              for s in report["sources"]], [
                (hashlib.sha256(a.read_bytes()).hexdigest(), 1, 1, 1),
                (hashlib.sha256(b.read_bytes()).hexdigest(), 2, 2, 3)])
            with duckdb.connect(str(database), read_only=True) as connection:
                self.assertEqual(connection.execute("""SELECT source_record, source_file, source_ordinal,
                    record_sha256 FROM events ORDER BY source_record""").fetchall(), [
                    (1, str(a), 1, hashlib.sha256(first).hexdigest()),
                    (2, str(b), 1, hashlib.sha256(second).hexdigest()),
                    (3, str(b), 2, hashlib.sha256(first).hexdigest())])
                self.assertIn("9007199254740993.123456789", connection.execute(
                    "SELECT raw_event::VARCHAR FROM events WHERE source_record=1").fetchone()[0])
            # Folder expansion is deterministic; input order matters to sidecar record IDs.
            for inputs, same in [([str(sources)], True), ([str(b), str(a)], False)]:
                result = subprocess.run([*command, "--source", *inputs, "--database", str(root / f"ordered-{same}.duckdb")],
                                        capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout)["source_sha256"] == report["source_sha256"], same)
            # A real pipe is nonseekable; gzip is recognized without a filename or suffix.
            for source, count in [(a, 1), (b, 2)]:
                streamed = subprocess.run([*command, "--source", "-", "--database", str(root / f"stdin-{count}.duckdb")],
                                          input=source.read_bytes(), capture_output=True)
                self.assertEqual(streamed.returncode, 0, streamed.stderr)
                stdin_report = json.loads(streamed.stdout)
                self.assertEqual(stdin_report["source_file"], "<stdin>")
                self.assertEqual(stdin_report["source_sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
                self.assertTrue(stdin_report["all_record_hashes_verified"])
                self.assertEqual(stdin_report["records"], count)
            before = hashlib.sha256(database.read_bytes()).hexdigest()
            refused = subprocess.run([*command, "--source", str(a), "--database", str(database)], capture_output=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)
            compressed_ssm = root / "ssm.json.gz"
            compressed_ssm.write_bytes(gzip.compress(self.ssm_export.read_bytes(), mtime=0))
            store = Store(database, ssm_export=compressed_ssm)
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}"
                request = Request(url + "/api/events", data=json.dumps({"filters": [
                    {"field": "region", "op": "eq", "value": "ap-southeast-1"}]}).encode(),
                    headers={"Content-Type": "application/json"})
                with urlopen(request) as response:
                    self.assertEqual([e["event_id"] for e in json.load(response)["data"]], ["regional-b"])
                with urlopen(Request(url + "/api/ssm", data=b"{}", headers={"Content-Type": "application/json"})) as response:
                    self.assertEqual(json.load(response)["total"], 2)
            finally:
                server.shutdown()
                thread.join()
                server.server_close()
                store.reviews.close()
                store.connection.close()

    def test_import_rejects_bad_members_without_publishing_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            valid = root / "valid.json"
            valid.write_text('{"Records":[{"eventID":"ok"}]}')
            invalid = root / "invalid.json.gz"
            packed = gzip.compress(valid.read_bytes())
            for content in [packed[:-5], b'{"commands":[]}', b'{"Records":{}}', b'{"Records":[42]}',
                            b'{"Records":[{}]} {"Records":[]}']:
                invalid.write_bytes(content)
                database = root / "bad.duckdb"
                result = subprocess.run([sys.executable, "-m", "kamotrace", "import", "--source", str(valid),
                                         str(invalid), "--database", str(database)], capture_output=True)
                self.assertNotEqual(result.returncode, 0, content)
                self.assertNotIn(b"Traceback", result.stderr)
                self.assertFalse(database.exists())
                self.assertFalse(database.with_suffix(".duckdb.building").exists())

    def test_annotations_tags_persistence_and_selection(self):
        rows = self.call("/api/events", {"sorters": [{"field": "time_local", "dir": "asc"}]})[1]["data"]
        hashes = [r["record_sha256"] for r in rows]
        note = "## Investigate\n\n**SSM** on two events; `<script>` is evidence text."
        def write(**body):
            status, result = self.call("/api/reviews", body)
            self.assertEqual(status, 200, result)
            return result
        write(action="annotate", hashes=[hashes[1], hashes[3]], body=note)
        notes = self.call("/api/reviews")[1]["annotations"]
        self.assertEqual([(n["body"], n["events"]) for n in notes], [(note, 2)])
        nid = notes[0]["id"]
        write(action="tag", hashes=[hashes[0], hashes[1], hashes[3]], slug="needs-review", color="#bd4032")
        write(action="tag", hashes=[hashes[1], hashes[2]], slug="ssm", color="#3366bb")
        selection = {"tags": ["needs-review", "ssm"]}
        result = self.call("/api/events", selection)[1]
        self.assertEqual([r["event_id"] for r in result["data"]], ["event-1"])
        self.assertEqual(result["data"][0]["annotations"], [nid])
        self.assertEqual(len(result["data"][0]["tags"]), 2)
        self.assertEqual(self.call("/api/histogram", selection)[1]["total"], 1)
        self.assertEqual(self.call("/api/column-values", {**selection, "field": "event_name", "value": "StartSession"})[1], {"total": 1, "events": 1})
        self.assertEqual(self.call("/api/events", {"annotation_id": nid})[1]["last_row"], 2)
        self.assertEqual(self.call("/api/events", {**selection, "search": "event-3"})[1]["last_row"], 0)
        # A separate Store reconstructs filters and reviews from persistent sidecar data.
        reopened = Store(self.database)
        try:
            self.assertEqual(reopened.query(selection)["last_row"], 1)
            self.assertEqual(reopened.reviews_list()["annotations"][0]["body"], note)
        finally:
            reopened.connection.close()
            reopened.reviews.close()
        for slug in ("Uppercase", "bad space", "x" * 257, "-prefix", ""):
            self.assertEqual(self.call("/api/reviews", {"action": "tag", "hashes": hashes[:1], "slug": slug, "color": "#112233"})[0], 400)
        self.assertEqual(self.call("/api/reviews", {"action": "annotate", "hashes": [hashes[0], "unknown"], "body": "no"})[0], 400)
        self.assertEqual(self.call("/api/reviews", {"action": "annotate", "hashes": hashes[:1], "body": " "})[0], 400)
        # Notes keep the query they were written from, can gain/lose evidence, and counts are events.
        context = {"start": 1, "end": 2, "search": "event-1", "filters": [], "tags": ["ssm"]}
        status, created = self.call("/api/reviews", {"action": "annotate", "hashes": [hashes[4]], "body": "Second", "context": context})
        self.assertEqual(status, 200, created)
        second = created["id"]
        listed = {n["id"]: n for n in self.call("/api/reviews")[1]["annotations"]}
        self.assertEqual((listed[second]["context"], listed[second]["events"], listed[nid]["context"]), (context, 1, None))
        write(action="link", id=second, hashes=[hashes[0], hashes[4]])
        self.assertEqual(self.call("/api/events", {"annotation_id": second})[1]["last_row"], 2)
        write(action="unlink", id=second, hashes=[hashes[4]])
        self.assertEqual([r["event_id"] for r in self.call("/api/events", {"annotation_id": second})[1]["data"]], ["event-0"])
        status, result = self.call("/api/reviews", {"action": "unlink", "id": second, "hashes": [hashes[0]]})
        self.assertEqual(status, 400, result)  # The last link stays; deleting the note is explicit.
        self.assertEqual(self.call("/api/events", {"annotation_id": second})[1]["last_row"], 1)
        for bad in ({"action": "link", "id": 999, "hashes": hashes[:1]}, {"action": "annotate", "hashes": hashes[:1], "body": "x", "context": []},
                    {"action": "color", "slug": "missing-tag", "color": "#112233"}, {"action": "color", "slug": "ssm", "color": "red"}):
            self.assertEqual(self.call("/api/reviews", bad)[0], 400, bad)
        write(action="color", slug="needs-review", color="#00aa11")
        tags = {t["slug"]: t for t in self.call("/api/reviews")[1]["tags"]}
        self.assertEqual((tags["needs-review"]["color"], tags["needs-review"]["events"], tags["ssm"]["events"]), ("#00aa11", 3, 2))
        self.assertEqual(self.call("/api/events", {"tags": ["needs-review"]})[1]["data"][0]["tags"][0]["color"], "#00aa11")
        listed = {n["id"]: n for n in self.call("/api/reviews")[1]["annotations"]}
        write(action="delete", id=second, updated=listed[second]["updated"])
        stale = listed[nid]["updated"]
        edited = write(action="edit", id=nid, body="Updated **finding**", updated=stale)
        # The browser and agents share the sidecar: a writer holding an older version cannot clobber it.
        for bad in ({"action": "edit", "id": nid, "body": "Lost update", "updated": stale},
                    {"action": "edit", "id": nid, "body": "No version"}, {"action": "delete", "id": nid, "updated": stale},
                    {"action": "edit", "id": 999, "body": "x", "updated": stale}):
            self.assertEqual(self.call("/api/reviews", bad)[0], 400, bad)
        self.assertEqual(self.call("/api/reviews")[1]["annotations"][0]["body"], "Updated **finding**")
        write(action="untag", hashes=[hashes[1]], slug="ssm")
        self.assertEqual(self.call("/api/events", selection)[1]["last_row"], 0)
        write(action="delete", id=nid, updated=edited["updated"])
        self.assertEqual(self.call("/api/events", {"annotation_id": nid})[1]["last_row"], 0)
        self.assertEqual(self.call("/api/reviews")[1]["annotations"], [])

    def test_mcp_stdio_session_shares_the_browser_servers_reviews(self):
        # A real MCP client session over stdio. The adapter holds no database handle: every agent
        # write must be visible through the browser's own API immediately, and vice versa.
        def rest(path, body=None):
            status, result = self.call(path, body)
            self.assertEqual(status, 200, result)
            return result

        async def session():
            params = StdioServerParameters(command=sys.executable, args=["-m", "kamotrace", "mcp", "--url", self.url])
            async with Client(params) as client:
                async def tool(name, **arguments):
                    result = await client.call_tool(name, arguments)
                    return ("error", result.content[0].text) if result.is_error else result.structured_content

                names = {t.name for t in (await client.list_tools()).tools}
                self.assertLessEqual({"describe_schema", "search_events", "get_event", "tag_events", "untag_events",
                                      "create_note", "edit_note", "link_note_events", "unlink_note_events",
                                      "search_ssm_commands", "get_ssm_command"}, names)
                self.assertEqual(await tool("list_detections"), {"run": None, "rules": []})
                schema = await tool("describe_schema")
                self.assertIn("not_missing", schema["operators"])
                self.assertEqual(schema["timezone"], "UTC")
                self.assertEqual(schema["first_event"], "2026-10-24T16:59:59+00:00")
                singapore = await tool("describe_schema", timezone="Asia/Singapore")
                self.assertEqual(singapore["first_event"], "2026-10-25T00:59:59+08:00")
                self.assertIn("America/New_York", singapore["timezones"])
                local_query = {"timezone": "Asia/Singapore", "filters": [
                    {"field": "time_local", "op": "eq", "value": "2026-10-25 00:59:59"}]}
                local_result = await tool("search_events", query=local_query)
                self.assertEqual([e["event_id"] for e in local_result["events"]], ["event-0"])
                self.assertEqual((await tool("summarize_field", field="time_local", query=local_query))["top"],
                                 [{"value": "2026-10-25 00:59:59", "events": 1}])
                self.assertEqual((await tool("event_histogram", query=local_query))["total"], 1)
                # Jakarta day 2026-10-25: 16:59:59Z is inside, 17:00:00Z is the exclusive end.
                day = {"timezone": "Asia/Jakarta", "start": "2026-10-25T00:00:00+07:00", "end": "2026-10-26T00:00:00+07:00",
                       "filters": [{"field": "event_name", "op": "eq", "value": "SendCommand"}]}
                found = await tool("search_events", query=day, sort=[{"field": "time_local", "dir": "asc"}])
                self.assertEqual((found["total"], [e["event_id"] for e in found["events"]]), (2, ["event-2", "event-3"]))
                hashes = [e["record_sha256"] for e in found["events"]]
                detail = await tool("get_event", id=found["events"][0]["id"])
                self.assertTrue(detail["raw_json_matches_hash"])
                self.assertIn("9007199254740993", detail["raw_json"])

                rest("/api/reviews", {"action": "tag", "slug": "browser-made", "color": "#123456", "hashes": hashes[:1]})
                tagged = await tool("tag_events", tag="browser-made", hashes=hashes[1:], color="#ffffff")
                self.assertEqual((tagged["events"], tagged["color"]), (2, "#123456"))  # Additive; colour kept.
                self.assertEqual((await tool("untag_events", tag="browser-made", hashes=hashes[:1]))["events"], 1)
                self.assertEqual([e["event_id"] for e in rest("/api/events", {"tags": ["browser-made"]})["data"]], ["event-3"])

                created = await tool("create_note", body="Agent **note**", hashes=hashes[:1], query=day)
                listed = {n["id"]: n for n in rest("/api/reviews")["annotations"]}[created["id"]]
                start_ms = datetime(2026, 10, 24, 17, tzinfo=timezone.utc).timestamp() * 1000
                self.assertEqual((listed["body"], listed["context"]["start"], listed["events"]), ("Agent **note**", start_ms, 1))
                self.assertEqual(listed["context"]["timezone"], "Asia/Jakarta")
                edited = await tool("edit_note", id=created["id"], body="Edited", updated=created["updated"])
                stale = await tool("edit_note", id=created["id"], body="Lost update", updated=created["updated"])
                self.assertEqual(stale[0], "error")
                self.assertIn("changed since", stale[1])
                self.assertEqual((await tool("link_note_events", id=created["id"], hashes=hashes[1:]))["events"], 2)
                self.assertEqual(rest("/api/events", {"annotation_id": created["id"]})["last_row"], 2)
                unlinked = await tool("unlink_note_events", id=created["id"], hashes=hashes[1:])
                self.assertEqual(unlinked["events"], 1)
                self.assertEqual((await tool("unlink_note_events", id=created["id"], hashes=hashes[:1]))[0], "error")
                note = await tool("get_note", id=created["id"])
                self.assertEqual((note["body"], note["linked"]["total"], note["updated"]), ("Edited", 1, unlinked["updated"]))
                singapore_note = await tool("get_note", id=created["id"], timezone="Asia/Singapore")
                self.assertEqual(singapore_note["linked"]["events"][0]["time_local"], "2026-10-25 09:02:03")
                self.assertGreater(unlinked["updated"], edited["updated"])

                for name, arguments, message in (
                        ("search_events", {"query": {"filters": [{"field": "raw_event", "op": "eq"}]}}, "Unknown filter field"),
                        ("search_events", {"size": 7}, ""), ("tag_events", {"tag": "Bad Tag", "hashes": hashes}, "lowercase"),
                        ("tag_events", {"tag": "x", "hashes": ["not-an-event"]}, "Unknown event hash"),
                        ("search_events", {"query": {"start": "2026-10-25T00:00:00"}}, "timezone"),
                        ("describe_schema", {"timezone": "not/a-zone"}, "Unknown timezone"),
                        ("search_events", {"query": {"timezone": "not/a-zone"}}, "Unknown timezone")):
                    result = await tool(name, **arguments)
                    self.assertEqual(result[0], "error", (name, arguments))
                    self.assertIn(message, result[1])

                commands = await tool("search_ssm_commands", search="synthetic")
                self.assertEqual([c["region"] for c in commands["data"]], ["ap-southeast-3"])
                command = await tool("get_ssm_command", key=commands["data"][0]["key"])
                self.assertEqual(sorted(s["instance_id"] for s in command["systems"]), ["i-alpha", "i-beta", "i-missing"])
                self.assertEqual((await tool("delete_note", id=created["id"], updated=note["updated"]))["deleted"], True)
                self.assertNotIn(created["id"], [n["id"] for n in rest("/api/reviews")["annotations"]])

        anyio.run(session)

    def test_suzaku_detections_link_exactly_and_filter_like_tags(self):
        # A Suzaku 3.x `aws-ct-timeline -t duckdb` file, with the schema Suzaku 3.0.0 actually writes.
        root = Path(self.temp.name)
        timeline = root / "suzaku.duckdb"
        out = duckdb.connect(str(timeline))
        out.execute("""CREATE TYPE suzaku_level AS ENUM ('informational','low','medium','high','critical');
            CREATE TABLE timeline("Timestamp" TIMESTAMP, RuleTitle VARCHAR, "Level" suzaku_level, EventName VARCHAR,
                AwsRegion VARCHAR, EventID VARCHAR, RuleAuthor VARCHAR, Tactics VARCHAR[], TechniqueIDs VARCHAR[],
                OtherTags VARCHAR[], RuleID VARCHAR);
            CREATE TABLE suzaku_meta(schema_version INTEGER, suzaku_version VARCHAR, command VARCHAR,
                timestamp_tz VARCHAR, rules_version VARCHAR, rules_count BIGINT)""")
        out.executemany("INSERT INTO timeline VALUES (?,?,?,?,?,?,'synthetic',?,?,[],?)", [
            ("2026-10-24 16:59:59", "Send command", "high", "SendCommand", "ap-southeast-3", "event-0", ["Exec"], ["T1651"], "rule-high"),
            ("2026-10-24 16:59:59", "Low rule", "low", "SendCommand", "ap-southeast-3", "event-0", [], [], "rule-low"),
            ("2026-10-25 01:02:03", "Low rule", "low", "SendCommand", "ap-southeast-3", "event-2", [], [], "rule-low"),
            # Same eventID, wrong region / wrong instant: must not link to event-3.
            ("2026-10-25 16:59:59", "Low rule", "low", "SendCommand", "us-east-1", "event-3", [], [], "rule-low"),
            ("2026-10-25 17:00:00", "Low rule", "low", "SendCommand", "ap-southeast-3", "event-3", [], [], "rule-low"),
            # Correlation rows: member eventIDs joined by " ¦ ", stamped with the latest member's time.
            ("2026-10-25 01:02:03", "Chain", "critical", "SendCommand", "ap-southeast-3", "event-2 ¦ event-0", [], [], "rule-chain"),
            ("2026-10-25 01:02:03", "Chain", "critical", "SendCommand", "ap-southeast-3", "event-0 ¦ event-missing", [], [], "rule-chain"),
            ("2026-10-25 01:02:03", "Chain", "critical", "SendCommand", "ap-southeast-3", "event-0 ¦ event-4", [], [], "rule-chain")])
        out.execute("INSERT INTO suzaku_meta VALUES (1, '3.0.0', 'aws-ct-timeline', 'UTC', 'abc', 2)")
        out.close()
        sidecar = root / "events.detections.duckdb"
        run = import_timeline(self.database, timeline, sidecar)
        # The partial chain (a member is missing) and the one with a member after its time do not link.
        self.assertEqual((run["linked_rows"], run["no_match_rows"], run["ambiguous_rows"], run["suzaku_version"]),
                         (4, 4, 0, "3.0.0"))
        with self.assertRaises(FileExistsError):
            import_timeline(self.database, timeline, sidecar)
        with self.assertLogs("kamotrace.suzaku", level="INFO") as startup:
            store = Store(self.database, detections=sidecar)
        try:
            # The linked correlation row expands to two evidence matches: five rows to copy, not four.
            self.assertIn("Copying 5 linked Suzaku detections", "\n".join(startup.output))
            self.assertIn("Loaded 5 linked Suzaku detections", "\n".join(startup.output))
            ids = lambda body: [r["event_id"] for r in store.query({**body, "sorters": [{"field": "time_local", "dir": "asc"}]})["data"]]
            self.assertEqual(ids({"rules": ["rule-low"]}), ["event-0", "event-2"])
            self.assertEqual(ids({"rules": ["rule-low", "rule-high"]}), ["event-0"])  # every rule must match
            self.assertEqual(ids({"min_level": "medium"}), ["event-0", "event-2"])
            self.assertEqual(ids({"rules": ["rule-chain"]}), ["event-0", "event-2"])  # every member event
            row = store.query({"rules": ["rule-high"]})["data"][0]
            self.assertEqual([(d["rule_id"], d["level"]) for d in row["detections"]],
                             [("rule-chain", "critical"), ("rule-high", "high"), ("rule-low", "low")])
            self.assertEqual(row["detections"][1]["techniques"], ["T1651"])
            self.assertEqual({r["rule_id"]: r["events"] for r in store.detections_list()["rules"]}, {"rule-chain": 2, "rule-high": 1, "rule-low": 2})
            with self.assertRaises(ValueError):
                store.query({"min_level": "severe"})
        finally:
            store.connection.close()
            store.reviews.close()
        # Without detections the same filter is valid and simply matches nothing.
        self.assertEqual(self.call("/api/events", {"rules": ["rule-low"]})[1]["last_row"], 0)
        self.assertEqual(self.call("/api/detections")[1], {"run": None, "rules": []})

    def test_large_detection_sidecar_preserves_all_rules_and_lists(self):
        sidecar = Path(self.temp.name) / "bulk.detections.duckdb"
        info = json.loads(self.store.connection.execute("SELECT metadata FROM build_info").fetchone()[0])
        run = {"schema_version": 1, "evidence_source_sha256": info["source_sha256"], "evidence_records": 5}
        out = duckdb.connect(str(sidecar))
        try:
            out.execute("CREATE TABLE suzaku_run (metadata JSON)")
            out.execute("INSERT INTO suzaku_run VALUES (?)", [json.dumps(run)])
            # More than one transfer batch, with a partial final batch. Only the last rule links to event-2.
            out.execute("""CREATE TABLE detections AS SELECT
                CASE WHEN i = 8204 THEN 3 ELSE 1 END::BIGINT AS source_record,
                'bulk-' || i AS rule_id, 'Synthetic 雲 ' || i AS rule_title,
                'high' AS level, 3::TINYINT AS level_rank,
                CASE WHEN i % 2 = 0 THEN [] ELSE ['Exec', 'Discovery'] END::VARCHAR[] AS tactics,
                CASE WHEN i % 2 = 0 THEN NULL ELSE ['T1651'] END::VARCHAR[] AS technique_ids,
                CASE WHEN i = 8192 THEN 'no_match' ELSE 'linked' END AS link_status
                FROM range(8205) t(i)""")
        finally:
            out.close()
        before = hashlib.sha256(sidecar.read_bytes()).hexdigest()
        store = Store(self.database, detections=sidecar)
        server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, store=store))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            def request(path, body=None):
                req = Request(f"http://127.0.0.1:{server.server_port}" + path,
                              data=json.dumps(body).encode() if body is not None else None,
                              headers={"Content-Type": "application/json"})
                with urlopen(req, timeout=15) as response:
                    return json.load(response)

            rules = {r["rule_id"]: r for r in request("/api/detections")["rules"]}
            self.assertEqual(set(rules), {f"bulk-{i}" for i in range(8205) if i != 8192})
            self.assertEqual((rules["bulk-8193"]["title"], rules["bulk-8193"]["tactics"],
                              rules["bulk-8193"]["techniques"]), ("Synthetic 雲 8193", ["Exec", "Discovery"], ["T1651"]))
            self.assertEqual((rules["bulk-8204"]["tactics"], rules["bulk-8204"]["techniques"]), ([], None))
            rows = request("/api/events", {"rules": ["bulk-8204"]})["data"]
            self.assertEqual([r["event_id"] for r in rows], ["event-2"])
            self.assertEqual([d["rule_id"] for d in rows[0]["detections"]], ["bulk-8204"])
        finally:
            server.shutdown()
            thread.join()
            server.server_close()
            store.connection.close()
            store.reviews.close()
        self.assertEqual(hashlib.sha256(sidecar.read_bytes()).hexdigest(), before)

    def test_enrichment_layers_geolite2_and_neutral_jsonl_by_priority(self):
        from mmdb_writer import MMDBWriter
        from netaddr import IPSet
        root = Path(self.temp.name) / "enrichment"
        (root / "geolite2").mkdir(parents=True)
        source = root / "events.json"
        # With a UTF-8 byte-order mark, as Windows PowerShell 5.1 writes; the JSONL below has one too.
        source.write_text("\ufeff" + json.dumps({"Records": [{"eventID": f"e{i}", "eventTime": "2026-10-24T01:00:00Z",
            "eventName": "GetCallerIdentity", "eventSource": "sts.amazonaws.com", "sourceIPAddress": ip,
            "awsRegion": "us-east-1", "userIdentity": {"type": "IAMUser"}}
            for i, ip in enumerate(["192.0.2.10", "198.51.100.7", "2001:db8::1", "ec2.amazonaws.com"])]}), encoding="utf-8")
        database = root / "case.duckdb"
        build(source, database)
        before = hashlib.sha256(database.read_bytes()).hexdigest()
        for kind, data in (("City", {"country": {"iso_code": "NL", "names": {"en": "Netherlands"}},
                                     "city": {"names": {"en": "Amsterdam"}}}),
                           ("ASN", {"autonomous_system_number": 64500, "autonomous_system_organization": "Example Hosting"})):
            writer = MMDBWriter(4, f"GeoLite2-{kind}")  # IPv4-only: the IPv6 lookup must not fail the run
            writer.insert_network(IPSet(["192.0.2.0/24", "198.51.100.0/24"]), data)
            writer.to_db_file(str(root / "geolite2" / f"GeoLite2-{kind}.mmdb"))
        spur = root / "spur.jsonl"
        spur.write_text("\ufeff" + "\n".join(json.dumps(r) for r in [
            {"ip": "198.51.100.7", "country": "Germany", "attributes": {"proxy_score": 92, "tunnel": "vpn-example"}},
            {"ip": "2001:0db8:0000::1", "as_org": "IPv6 Example", "attributes": {"residential": False}},
            {"ip": "203.0.113.99", "country": "Unused"}]), encoding="utf-8")
        output = root / "case.enrichment.duckdb"
        # The JSONL is given first, so it overrides GeoLite2 where both have a value.
        run = enrich(database, output, [("jsonl", spur), ("geolite2", root / "geolite2")])
        self.assertEqual([(s["label"], s["evidence_ips_matched"], s["entries_not_in_evidence"]) for s in run["sources"]],
                         [("spur", 2, 1), ("geolite2", 2, 0)])
        self.assertEqual(run["evidence_ips"], 3)  # ec2.amazonaws.com is not an address
        store = Store(database)
        try:
            rows = {r["source_ip"]: (r["country"], r["city"], r["asn"], r["isp"], r["ip_info"])
                    for r in store.query({"size": 25})["data"]}
            self.assertEqual(store.meta["enrichment"]["sources"][0]["attribute_keys"], ["proxy_score", "residential", "tunnel"])
            self.assertEqual(store.query({"filters": [{"field": "country", "op": "eq", "value": "Germany"}]})["last_row"], 1)
        finally:
            store.connection.close()
            store.reviews.close()
        self.assertEqual(rows, {
            "192.0.2.10": ("Netherlands", "Amsterdam", "AS64500", "Example Hosting", None),
            "198.51.100.7": ("Germany", "Amsterdam", "AS64500", "Example Hosting", "spur.proxy_score=92; spur.tunnel=vpn-example"),
            "2001:db8::1": ("(unmapped / service / private)", None, None, "IPv6 Example", "spur.residential=false"),
            "ec2.amazonaws.com": ("(unmapped / service / private)", None, None, None, None)})
        self.assertEqual(hashlib.sha256(database.read_bytes()).hexdigest(), before)
        # Invalid JSONL is rejected with its line; nothing replaces the existing sidecar.
        for line in ('{"ip": "999.1.1.1"}', '{"ip": "192.0.2.10", "score": 1}',
                     '{"ip": "192.0.2.10", "attributes": {"bad key": 1}}', '{"ip": "192.0.2.10", "asn": "AS1"}'):
            spur.write_text(line, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "spur.jsonl:1"):
                enrich(database, output, [("jsonl", spur)], replace=True)
        with self.assertRaises(FileExistsError):
            enrich(database, output, [("jsonl", spur)])
        store = Store(database)
        try:
            self.assertEqual(store.query({"filters": [{"field": "country", "op": "eq", "value": "Germany"}]})["last_row"], 1)
        finally:
            store.connection.close()
            store.reviews.close()
        # A sidecar is bound to its evidence database.
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always", ResourceWarning)
            with self.assertRaisesRegex(ValueError, "different evidence database"):
                Store(self.database, output)
            gc.collect()
        self.assertEqual([str(w.message) for w in caught if issubclass(w.category, ResourceWarning)], [])

    def test_get_suzaku_installs_only_verified_safe_archives(self):
        import zipfile
        from kamotrace.get_suzaku import install, installed
        tools = Path(self.temp.name) / "tools"
        tools.mkdir()
        def archive(name, members):
            path = tools.parent / name
            with zipfile.ZipFile(path, "w") as bundle:
                for member, data in members.items():
                    bundle.writestr(member, data)
            return path, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
        good, digest = archive("suzaku-3.0.0-lin-x64-gnu.zip", {"suzaku-3.0.0-lin-x64-gnu": "binary", "rules/a.yml": "x"})
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            install(good, "sha256:" + "0" * 64, "3.0.0", "lin-x64-gnu", tools)
        evil, evil_digest = archive("evil.zip", {"suzaku-x": "binary", "../outside.txt": "x"})
        with self.assertRaisesRegex(RuntimeError, "unsafe path"):
            install(evil, evil_digest, "3.0.1", "lin-x64-gnu", tools)
        self.assertFalse((tools.parent / "outside.txt").exists())
        self.assertIsNone(installed(tools))  # Failed installs leave nothing behind
        newer, newer_digest = archive("suzaku-3.10.0.zip", {"suzaku-3.10.0-lin-x64-gnu": "binary"})
        install(good, digest, "3.0.0", "lin-x64-gnu", tools)
        install(newer, newer_digest, "3.10.0", "lin-x64-gnu", tools)
        # Versions compare numerically (3.10 > 3.9 > 3.0), and only verified installs are listed.
        self.assertEqual(installed(tools), tools / "suzaku-3.10.0" / "suzaku-3.10.0-lin-x64-gnu")
        self.assertEqual(sorted(p.name for p in tools.iterdir()), ["suzaku-3.0.0", "suzaku-3.10.0"])

    def test_get_dbip_installs_only_verified_dbip_databases(self):
        import gzip
        from mmdb_writer import MMDBWriter
        from netaddr import IPSet
        from kamotrace.enrich import read_geolite2
        from kamotrace.get_dbip import install, release
        # Shaped like DB-IP's download page: the CSV block (with its own SHA-1) precedes the MMDB block.
        page = """<dt>SHA1SUM</dt><dd class="small">""" + "c" * 40 + """</dd></dl>
            <a href='https://download.db-ip.com/free/dbip-city-lite-2026-10.csv.gz'>CSV</a>
            <dt>SHA1SUM</dt>\n<dd class="small">""" + "a" * 40 + """</dd>\n</dl>
            <a href='https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz' class='btn'>MMDB</a>"""
        self.assertEqual(release(page, "city"),
                         ("https://download.db-ip.com/free/dbip-city-lite-2026-10.mmdb.gz", "2026-10", "a" * 40))
        with self.assertRaisesRegex(RuntimeError, "No MMDB download"):
            release(page, "asn")
        root = Path(self.temp.name) / "dbip"
        folder = root / "dbip-lite-2026-10"
        folder.mkdir(parents=True)
        def compressed(kind, database_type, data):
            plain = root / f"{kind}.mmdb"
            writer = MMDBWriter(4, database_type)
            writer.insert_network(IPSet(["192.0.2.0/24"]), data)
            writer.to_db_file(str(plain))
            packed = root / f"{kind}.mmdb.gz"
            packed.write_bytes(gzip.compress(plain.read_bytes()))
            return packed, hashlib.sha1(plain.read_bytes()).hexdigest()
        city, city_sha1 = compressed("city", "DBIP-City-Lite", {"country": {"iso_code": "ID", "names": {"en": "Indonesia"}}})
        with self.assertRaisesRegex(RuntimeError, "does not match"):
            install(city, "0" * 40, "city", "2026-10", folder)
        other, other_sha1 = compressed("other", "GeoLite2-City", {})
        with self.assertRaisesRegex(RuntimeError, "unexpected database type"):
            install(other, other_sha1, "city", "2026-10", folder)
        self.assertEqual(list(folder.iterdir()), [])  # Failed installs leave nothing behind
        asn, asn_sha1 = compressed("asn", "DBIP-ASN-Lite (compat=GeoLite2-ASN)", {"autonomous_system_number": 64500})
        install(city, city_sha1, "city", "2026-10", folder)
        install(asn, asn_sha1, "asn", "2026-10", folder)
        # enrich finds DB-IP's lower-case file names on case-sensitive file systems too.
        rows, provenance = read_geolite2(folder, ["192.0.2.1"])
        self.assertEqual(rows["192.0.2.1"][:4], ("Indonesia", "ID", None, 64500))
        self.assertEqual([p["file"] for p in provenance], ["dbip-city-lite-2026-10.mmdb", "dbip-asn-lite-2026-10.mmdb"])

    def test_older_annotation_sidecar_is_migrated_additively(self):
        import sqlite3
        path = Path(self.temp.name) / "old.sqlite3"
        old = sqlite3.connect(path)
        old.executescript("""CREATE TABLE annotations(id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT NOT NULL, updated TEXT NOT NULL);
            CREATE TABLE annotation_events(annotation_id INTEGER, hash TEXT NOT NULL, PRIMARY KEY(annotation_id, hash));
            INSERT INTO annotations VALUES (1, 'kept', '2026-10-25T00:00:00+00:00');""")
        rows = self.call("/api/events", {})[1]["data"]
        old.execute("INSERT INTO annotation_events VALUES (1, ?)", (rows[0]["record_sha256"],))
        old.commit()
        old.close()
        store = Store(self.database, annotations=path)
        try:
            self.assertEqual([(n["body"], n["context"], n["events"]) for n in store.reviews_list()["annotations"]], [("kept", None, 1)])
        finally:
            store.connection.close()
            store.reviews.close()
        # Opening it binds the sidecar to this evidence; another case's database is refused.
        source = Path(self.temp.name) / "other.json"
        source.write_text(json.dumps({"Records": [{"eventID": "x", "eventTime": "2026-10-24T00:00:00Z"}]}), encoding="utf-8")
        build(source, Path(self.temp.name) / "other.duckdb")
        with self.assertRaisesRegex(ValueError, "different evidence database"):
            Store(Path(self.temp.name) / "other.duckdb", annotations=path)

    def test_ssm_groups_systems_plugins_enrichment_and_exact_event_links(self):
        status, result = self.call("/api/ssm", {})
        self.assertEqual(status, 200)
        self.assertEqual(result["total"], 2)
        key = next(r["key"] for r in result["data"] if r["region"] == "ap-southeast-3")
        data = self.call("/api/ssm-detail", {"key": key})[1]
        systems = {s["instance_id"]: s for s in data["systems"]}
        self.assertEqual(set(systems), {"i-alpha", "i-beta", "i-missing"})
        self.assertEqual([d["StandardOutputContent"] for d in systems["i-alpha"]["details"]],
                         ["alpha stdout <script>neverRun()</script>", "alpha second plugin"])
        self.assertEqual(systems["i-beta"]["details"][0]["StandardErrorContent"], "beta stderr")
        self.assertEqual(systems["i-beta"]["details"][0]["ResponseCode"], 9)
        self.assertEqual(systems["i-missing"]["details"], [])
        self.assertEqual(data["base64_enrichment"][0]["decodings"][0]["decoded_text"], "synthetic")
        self.assertEqual({e["event_id"] for e in data["events"]}, {"event-0", "event-2", "supplement-only"})
        self.assertEqual(len(data["events"]), 3)  # Duplicate local/export event is not counted twice.
        local = next(e for e in data["events"] if e["event_id"] == "event-0")
        self.assertEqual(local["source"], "DuckDB")
        detail = self.call(f'/api/events/{local["id"]}')[1]
        self.assertEqual(detail["ssm_commands"], [{"key": key, "command_id": "command-multi"}])
        self.assertEqual(self.call("/api/events", {"command_key": key})[1]["last_row"], 2)
        self.assertEqual(self.call("/api/histogram", {"command_key": key})[1]["total"], 2)
        supplement = next(e for e in data["events"] if e["id"] is None)
        event = self.call("/api/ssm-event", {"key": supplement["key"]})[1]
        self.assertEqual(json.loads(event["raw_json"])["eventID"], "supplement-only")
        for term in ("beta stderr", "synthetic", "i-beta"):
            self.assertEqual(self.call("/api/ssm", {"search": term})[1]["total"], 1)
        self.assertEqual(self.call("/api/ssm", {"start": "2026-10-25T00:00:00+07:00", "end": "2026-10-25T00:00:01+07:00"})[1]["total"], 2)
        self.assertEqual(self.call("/api/ssm", {"end": "2026-10-25T00:00:00+07:00"})[1]["total"], 0)
        twin = next(r["key"] for r in result["data"] if r["region"] == "us-east-1")
        self.assertEqual(self.call("/api/ssm-detail", {"key": twin})[1]["events"], [])
        for body in ({"sort": "bad"}, {"direction": "bad"}, {"search": []}, {"page": 0}):
            self.assertEqual(self.call("/api/ssm", body)[0], 400)
        self.assertEqual(self.call("/api/ssm-detail", {"key": "unknown"})[0], 400)

    def test_ssm_spreadsheet_preserves_each_system_plugin_and_output_provenance(self):
        status, result = self.call("/api/ssm-sheet", {"search": "beta stderr",
            "sorters": [{"field": "instance_id", "dir": "asc"}, {"field": "plugin", "dir": "asc"}]})
        self.assertEqual(status, 200)
        self.assertEqual((result["total"], result["commands"]), (5, 1))
        rows = result["data"]
        self.assertEqual([(r["instance_id"], r["plugin"]) for r in rows],
            [("i-alpha", "second-step"), ("i-alpha", "shell"), ("i-beta", "fallback-step"), ("i-beta", "shell"), ("i-missing", None)])
        self.assertEqual(len({r["row_id"] for r in rows}), 5)
        alpha, beta, fallback, missing = rows[1], rows[3], rows[2], rows[4]
        self.assertEqual((alpha["response_code"], alpha["stdout"], alpha["stderr"]),
            (0, "alpha stdout <script>neverRun()</script>", ""))
        self.assertEqual((beta["response_code"], beta["stdout"], beta["stderr"]), (9, "beta stdout", "beta stderr"))
        self.assertEqual((fallback["response_code"], fallback["stdout"], fallback["stderr"], fallback["combined_output"], fallback["output_state"]),
            (7, None, None, "mixed stdout/stderr", "Combined only"))
        self.assertEqual((missing["response_code"], missing["stdout"], missing["output_state"]), (None, None, "No output collected"))
        self.assertEqual(alpha["parameters"], "commands:\necho c3ludGhldGlj | base64 -d")
        self.assertEqual(alpha["decoded"], "commands[0] [decoded_utf8]:\nsynthetic")
        self.assertEqual(alpha["events"], 3)
        self.assertEqual(self.call("/api/ssm-detail", {"key": alpha["key"]})[1]["command_id"], "command-multi")
        self.assertEqual(self.call("/api/ssm-sheet", {"end": "2026-10-25T00:00:00+07:00"})[1]["total"], 0)
        self.assertEqual(self.call("/api/ssm-sheet", {"start": "2026-10-25T00:00:00+07:00"})[1]["total"], 6)
        for body in ({"sorters": [{"field": "bad", "dir": "asc"}]}, {"page": 0}, {"search": []}):
            self.assertEqual(self.call("/api/ssm-sheet", body)[0], 400)

    def test_time_slice_and_full_dataset_sort_pagination(self):
        body = {"timezone": "Asia/Jakarta", "start": "2026-10-25T00:00:00+07:00", "end": "2026-10-26T00:00:00+07:00",
                "sorters": [{"field": "time_local", "dir": "asc"}]}
        status, data = self.call("/api/events", body)
        self.assertEqual(status, 200)
        self.assertEqual([r["event_id"] for r in data["data"]], ["event-1", "event-2", "event-3"])
        self.assertEqual(data["last_row"], 3)
        self.assertEqual(data["data"][0]["time_local"], "2026-10-25 00:00:00")
        _, empty = self.call("/api/events", {**body, "page": 2, "size": 25})
        self.assertEqual(empty["data"], [])
        self.assertEqual(empty["last_row"], 3)
        _, meta = self.call("/api/meta")
        self.assertEqual(meta["timezone"], "UTC")
        self.assertEqual([r["total"] for r in meta["histogram"]], [2, 3])
        _, local_meta = self.call("/api/meta", {"timezone": "Asia/Jakarta"})
        self.assertEqual([r["total"] for r in local_meta["histogram"]], [1, 3, 1])

    def test_combined_filters_and_literal_search(self):
        filters = [{"field": "event_name", "op": "in", "value": "SendCommand, StartSession"},
                   {"field": "country", "op": "eq", "value": "Germany"}]
        _, data = self.call("/api/events", {"filters": filters, "search": "I-EXAMPLE"})
        self.assertEqual(data["last_row"], 3)
        self.assertEqual({r["event_id"] for r in data["data"]}, {"event-0", "event-1", "event-3"})
        for literal in ["%' OR 1=1 --", "_", "<script>"]:
            _, empty = self.call("/api/events", {"search": literal})
            self.assertEqual(empty["last_row"], 0)
        # Quotes and backslashes are found as typed, not only in their JSON-escaped form.
        for literal in ['-c "& C:\\temp\\A.ps1"', "C:\\Temp\\a.ps1", '"&']:
            _, found = self.call("/api/events", {"search": literal})
            self.assertEqual([r["event_id"] for r in found["data"]], ["event-1"], literal)
        self.assertEqual(found["data"][0]["user_agent"], 'powershell -c "& C:\\Temp\\a.ps1"')

    def test_validation_and_same_origin_boundary(self):
        for body in [{"sorters": [{"field": "time_local;DROP TABLE events", "dir": "asc"}]},
                     {"filters": [{"field": "raw_event", "op": "eq", "value": "x"}]},
                     {"start": "2026-10-25T00:00:00"},
                     {"start": "2026-10-26T00:00:00+07:00", "end": "2026-10-25T00:00:00+07:00"},
                     {"size": 100000}]:
            self.assertEqual(self.call("/api/events", body)[0], 400)
        self.assertEqual(self.call("/api/meta", headers={"Origin": "https://attacker.invalid"})[0], 403)
        self.assertEqual(self.call("/api/meta", headers={"Host": "attacker.invalid"})[0], 403)

    def test_duck_sprite_is_served_without_opening_arbitrary_paths(self):
        with urlopen(self.url + "/konami-duck.png", timeout=15) as response:
            self.assertEqual(response.status, 200)
            self.assertEqual(response.headers.get_content_type(), "image/png")
            self.assertTrue(response.read().startswith(b"\x89PNG\r\n\x1a\n"))
        self.assertEqual(self.call("/server.py")[0], 404)
        self.assertEqual(self.call("/konami-duck.png", headers={"Origin": "https://attacker.invalid"})[0], 403)

    def test_raw_event_retains_large_integer_and_record_hash(self):
        _, data = self.call("/api/events", {"search": "event-2"})
        record = data["data"][0]
        _, detail = self.call(f"/api/events/{record['id']}")
        self.assertIn("9007199254740993", detail["raw_json"])
        self.assertEqual(detail["record_sha256"], hashlib.sha256(detail["raw_json"].encode()).hexdigest())
        self.assertEqual(self.call("/api/events/999999")[0], 404)

    def test_column_frequencies_use_full_filtered_selection(self):
        body = {"timezone": "Asia/Jakarta", "field": "event_name", "start": "2026-10-25T00:00:00+07:00",
                "end": "2026-10-26T00:00:00+07:00", "search": "I-EXAMPLE",
                "filters": [{"field": "country", "op": "eq", "value": "Germany"}],
                "page": 2, "size": 25}
        status, data = self.call("/api/column-values", body)
        self.assertEqual(status, 200)
        self.assertEqual(data, {"top": [{"value": "SendCommand", "events": 1},
                                        {"value": "StartSession", "events": 1}],
                                "bottom": [{"value": "SendCommand", "events": 1},
                                           {"value": "StartSession", "events": 1}],
                                "total": 2, "distinct_values": 2})
        _, all_rows = self.call("/api/column-values", {"field": "event_name"})
        self.assertEqual(all_rows["top"][0], {"value": "SendCommand", "events": 3})
        self.assertEqual(all_rows["bottom"][0], {"value": "StartSession", "events": 1})
        _, missing = self.call("/api/column-values", {**body, "field": "error_code"})
        self.assertEqual(missing["top"], [{"value": None, "events": 2}])
        _, times = self.call("/api/column-values", {**body, "field": "time_local"})
        self.assertEqual(times["top"][0]["value"], "2026-10-25 00:00:00")
        _, empty = self.call("/api/column-values", {**body, "search": "no-such-event"})
        self.assertEqual(empty, {"top": [], "bottom": [], "total": 0, "distinct_values": 0})
        self.assertEqual(self.call("/api/column-values", {"field": "event_name;DROP TABLE events"})[0], 400)

    def test_exact_cell_filters_and_missing_values(self):
        for field, op, value, expected in [
            ("event_name", "eq", "SendCommand", 3),
            ("event_name", "neq", "SendCommand", 2),
            ("event_name", "eq", "Send", 0),
            ("error_code", "eq", "", 0),
            ("error_code", "neq", "", 5),
            ("error_code", "missing", "", 5),
            ("error_code", "not_missing", "", 0),
            ("time_local", "eq", "2026-10-24 17:00:00", 1),
        ]:
            with self.subTest(field=field, op=op, value=value):
                status, data = self.call("/api/events", {"filters": [
                    {"field": field, "op": op, "value": value}]})
                self.assertEqual(status, 200)
                self.assertEqual(data["last_row"], expected)

    def test_cell_prevalence_is_exact_and_keeps_filtered_denominator(self):
        body = {"field": "event_name", "value": "SendCommand",
                "start": "2026-10-25T00:00:00+07:00", "end": "2026-10-26T00:00:00+07:00",
                "search": "I-EXAMPLE", "page": 2, "size": 25}
        self.assertEqual(self.call("/api/column-values", body), (200, {"total": 3, "events": 2}))
        _, filtered = self.call("/api/column-values", {**body, "filters": [
            {"field": "country", "op": "eq", "value": "Germany"}]})
        self.assertEqual(filtered, {"total": 2, "events": 1})
        for value in ("Send", "sendcommand", "SendCommand' OR 1=1 --"):
            self.assertEqual(self.call("/api/column-values", {**body, "value": value})[1],
                             {"total": 3, "events": 0})
        for value, expected in [(None, 3), ("", 0)]:
            self.assertEqual(self.call("/api/column-values", {
                **body, "field": "error_code", "value": value})[1], {"total": 3, "events": expected})
        self.assertEqual(self.call("/api/column-values", {**body, "search": "no-such-event"})[1],
                         {"total": 0, "events": 0})
        self.assertEqual(self.call("/api/column-values", {**body, "value": []})[0], 400)

    def test_timezone_selection_and_dst_bucket_ranges(self):
        for zone, local in (("UTC", "2026-10-24 16:59:59"),
                            ("Asia/Singapore", "2026-10-25 00:59:59"),
                            ("Asia/Kathmandu", "2026-10-24 22:44:59")):
            body = {"timezone": zone, "filters": [{"field": "time_local", "op": "eq", "value": local}]}
            status, result = self.call("/api/events", body)
            self.assertEqual(status, 200, result)
            self.assertEqual([r["event_id"] for r in result["data"]], ["event-0"])
            self.assertEqual(self.call("/api/column-values", {**body, "field": "time_local", "value": local}),
                             (200, {"total": 1, "events": 1}))
        for endpoint in ("/api/events", "/api/histogram", "/api/column-values", "/api/meta"):
            for bad in ("not/a-zone", "UTC'; DROP TABLE events; --", None, []):
                self.assertEqual(self.call(endpoint, {"timezone": bad, "field": "time_local"})[0], 400)

        zone = "Europe/London"
        body = {"timezone": zone, "start": "2026-10-25T00:30:00Z", "end": "2026-10-25T01:45:00Z",
                "bucket_minutes": 60}
        status, histogram = self.call("/api/histogram", body)
        self.assertEqual(status, 200, histogram)
        self.assertEqual([r["bucket_start_local"] for r in histogram["data"]], ["2026-10-25 01:00:00"] * 2)
        self.assertEqual([r["events"] for r in histogram["data"]], [0, 1])
        self.assertEqual([r["start_ms"] for r in histogram["data"]], [1792886400000, 1792890000000])
        for row in histogram["data"]:
            bounds = {k: datetime.fromtimestamp(row[k + "_ms"] / 1000, timezone.utc).isoformat()
                      for k in ("start", "end")}
            self.assertEqual(self.call("/api/events", {"timezone": zone, **bounds})[1]["last_row"], row["events"])
        for start, end, hours, total in (("2026-03-29T00:00:00Z", "2026-03-29T23:00:00Z", 23, 0),
                                         ("2026-10-24T23:00:00Z", "2026-10-26T00:00:00Z", 25, 3)):
            _, daily = self.call("/api/histogram", {"timezone": zone, "start": start, "end": end})
            self.assertEqual(len(daily["data"]), 1)
            row = daily["data"][0]
            self.assertEqual((row["end_ms"] - row["start_ms"]) / 3600000, hours)
            self.assertEqual(row["events"], total)

    def test_histogram_uses_all_filters_local_buckets_and_zero_fills(self):
        body = {"timezone": "Asia/Jakarta", "start": "2026-10-25T00:00:00+07:00", "end": "2026-10-27T00:00:00+07:00",
                "bucket_minutes": 1440, "filters": [
                    {"field": "event_name", "op": "in", "value": "SendCommand,StartSession"},
                    {"field": "country", "op": "eq", "value": "Germany"}]}
        status, daily = self.call("/api/histogram", body)
        self.assertEqual(status, 200)
        self.assertEqual([{k: r[k] for k in ("bucket_start_local", "events")} for r in daily["data"]], [
            {"bucket_start_local": "2026-10-25 00:00:00", "events": 2},
            {"bucket_start_local": "2026-10-26 00:00:00", "events": 0}])
        self.assertEqual(daily["total"], 2)
        _, custom = self.call("/api/histogram", {
            "timezone": "Asia/Jakarta",
            "start": "2026-10-25T08:00:00+07:00", "end": "2026-10-25T11:00:00+07:00",
            "bucket_minutes": 90})
        self.assertEqual([{k: r[k] for k in ("bucket_start_local", "events")} for r in custom["data"]], [
            {"bucket_start_local": "2026-10-25 07:30:00", "events": 1},
            {"bucket_start_local": "2026-10-25 09:00:00", "events": 0},
            {"bucket_start_local": "2026-10-25 10:30:00", "events": 0}])
        for width in (0, "1;DROP TABLE events", 1.5):
            self.assertEqual(self.call("/api/histogram", {**body, "bucket_minutes": width})[0], 400)
        self.assertEqual(self.call("/api/histogram", {**body, "bucket_minutes": 1})[0], 400)


if __name__ == "__main__":
    unittest.main()
